"""test_server.py
"""

import asyncio
import pytest
import grpc
from unittest.mock import MagicMock, AsyncMock
from app.grpc import server
from app.grpc.session import SessionManager
from app.shared.security.crypto import set_cc_state
from app.shared.db.session import AsyncSessionLocal
from app.shared.db.models import ClientRecord, SystemConfig
from app.shared.services.pairing import PairingCode
from app.Protobuf.Client import (
    HandshakeScReq_pb2,
    ClientRegisterCsReq_pb2,
    ClientCommandDeliverScReq_pb2,
    ConfigUploadScReq_pb2,
    AuditScReq_pb2,
)
from app.Protobuf.Server import (
    HandshakeScRsp_pb2,
    ClientRegisterScRsp_pb2,
    ClientCommandDeliverScRsp_pb2,
    ConfigUploadScRsp_pb2,
    AuditScRsp_pb2,
)
from app.Protobuf.Enum import Retcode_pb2, CommandTypes_pb2


# Mock Context Helper
def get_mock_context(metadata: list = None, peer: str = "ipv4:127.0.0.1:12345"):
    ctx = MagicMock(spec=grpc.aio.ServicerContext)
    ctx.invocation_metadata.return_value = metadata or []
    ctx.peer.return_value = peer
    ctx.abort = AsyncMock()
    return ctx


@pytest.mark.asyncio
async def test_tenant_interceptor_exemptions():
    """测试 gRPC 拦截器的白名单放行及 CC 防御拦截逻辑。"""
    sm = SessionManager()
    interceptor = server.TenantInterceptor(sm)

    # 1. CC 攻击激活下，豁免方法依然被拦截
    set_cc_state(True)
    details = MagicMock()
    details.method = "/Handshake/BeginHandshake"
    details.invocation_metadata = []

    async def continuation(details):
        return MagicMock()

    with pytest.raises(grpc.aio.AbortError) as exc:
        await interceptor.intercept_service(continuation, details)
    assert exc.value.code() == grpc.StatusCode.UNAVAILABLE

    # 恢复 CC 状态
    set_cc_state(False)


@pytest.mark.asyncio
async def test_tenant_interceptor_session_auth(test_superadmin_user):
    """测试 gRPC 拦截器的会话鉴权与多租户隔离拦截逻辑。"""
    sm = SessionManager()
    interceptor = server.TenantInterceptor(sm)

    # 生成合法的 Session ID
    sid = await sm.create_session("test-account-00000000", "client-uid-test")

    # 场景: 拦截非白名单方法，但提供了有效 session 且无 Authority
    details = MagicMock()
    details.method = "/Command/ListenCommand"
    details.invocation_metadata = [("session", sid)]

    # 模拟 handler 处理器
    handler = MagicMock()
    handler.unary_unary = None
    handler.unary_stream = None
    handler.stream_unary = None
    handler.stream_stream = AsyncMock(return_value="stream_result")
    handler.request_deserializer = MagicMock()
    handler.response_serializer = MagicMock()

    async def continuation(details):
        return handler

    wrapped_handler = await interceptor.intercept_service(continuation, details)
    assert wrapped_handler is not None

    # 执行包装后的 stream_stream 处理器，验证上下文
    res = await wrapped_handler.stream_stream("request_iterator", "context")
    assert res == "stream_result"

    # 场景: 拦截非白名单方法，提供非法 session -> 抛出 UNAUTHENTICATED
    details_invalid = MagicMock()
    details_invalid.method = "/Command/ListenCommand"
    details_invalid.invocation_metadata = [("session", "invalid-sid")]

    with pytest.raises(grpc.aio.AbortError) as exc:
        await interceptor.intercept_service(continuation, details_invalid)
    assert exc.value.code() == grpc.StatusCode.UNAUTHENTICATED


@pytest.mark.asyncio
async def test_handshake_servicer():
    """测试握手服务的安全校验分支。"""
    sm = SessionManager()
    servicer = server.HandshakeServicer(sm)

    # 1. 尝试握手不存在的客户端 -> 返回 ClientNotFound
    req = HandshakeScReq_pb2.HandshakeScBeginHandShakeReq(
        ClientUid="non-existent-uid",
        ClientMac="AA-BB-CC-DD-EE-FF",
        ChallengeTokenEncrypted="xyz",
    )
    ctx = get_mock_context()
    res = await servicer.BeginHandshake(req, ctx)
    assert res.Retcode == Retcode_pb2.ClientNotFound

    # 2. 插入一个合法物理客户端记录
    async with AsyncSessionLocal() as db:
        db.add(
            ClientRecord(
                uid="valid-client-uid", client_id="c1", mac="AA-BB-CC-DD-EE-FF"
            )
        )
        await db.commit()

    # MAC 地址不匹配测试 -> InvalidRequest
    req_wrong_mac = HandshakeScReq_pb2.HandshakeScBeginHandShakeReq(
        ClientUid="valid-client-uid",
        ClientMac="WRONG-MAC",
        ChallengeTokenEncrypted="xyz",
    )
    res_wrong_mac = await servicer.BeginHandshake(req_wrong_mac, ctx)
    assert res_wrong_mac.Retcode == Retcode_pb2.InvalidRequest

    # GPG 解密失败测试 -> ServerInternalError
    req_decrypt_fail = HandshakeScReq_pb2.HandshakeScBeginHandShakeReq(
        ClientUid="valid-client-uid",
        ClientMac="AA-BB-CC-DD-EE-FF",
        ChallengeTokenEncrypted="bad-encrypted-data",
    )
    res_decrypt_fail = await servicer.BeginHandshake(req_decrypt_fail, ctx)
    assert res_decrypt_fail.Retcode == Retcode_pb2.ServerInternalError

    # 3. CompleteHandshake 测试
    # 未被接受的分支 -> HandshakeClientRejected
    req_complete_reject = (
        HandshakeScRsp_pb2.HandshakeScCompleteHandshakeReq(Accepted=False)
    )
    ctx_complete = get_mock_context(metadata=[("cuid", "valid-client-uid")])
    res_complete = await servicer.CompleteHandshake(
        req_complete_reject, ctx_complete
    )
    assert res_complete.Retcode == Retcode_pb2.HandshakeClientRejected

    # 无挑战记录的分支 -> InvalidRequest
    req_complete_accept = (
        HandshakeScRsp_pb2.HandshakeScCompleteHandshakeReq(Accepted=True)
    )
    res_complete_accept = await servicer.CompleteHandshake(
        req_complete_accept, ctx_complete
    )
    assert res_complete_accept.Retcode == Retcode_pb2.InvalidRequest


@pytest.mark.asyncio
async def test_client_register_servicer_pairing():
    """测试客户端注册服务的配对拦截流程。"""
    sm = SessionManager()
    servicer = server.ClientRegisterServicer(sm)

    # 1. 启用配对功能配置
    async with AsyncSessionLocal() as db:
        # 清除已有配对配置
        from sqlalchemy import delete

        await db.execute(delete(SystemConfig).where(SystemConfig.key == "pairing_enabled"))
        db.add(SystemConfig(key="pairing_enabled", value="true"))
        await db.commit()

    req = ClientRegisterCsReq_pb2.ClientRegisterCsReq(
        ClientUid="new-client-uid-pairing",
        ClientId="c2",
        ClientMac="22-33-44-55-66-77",
    )
    ctx = get_mock_context()

    # 需要配对码拦截 -> PairingRequired
    res = await servicer.Register(req, ctx)
    assert res.Retcode == Retcode_pb2.PairingRequired
    assert "配对码" in res.Message

    # 2. 审批通过后，注册成功
    # 提取生成的配对请求验证码
    async with AsyncSessionLocal() as db:
        from sqlalchemy import select

        stmt = select(PairingCode).where(
            PairingCode.client_uid == "new-client-uid-pairing"
        )
        record = (await db.execute(stmt)).scalar_one()
        code = record.code

        # 审批配对
        from app.shared.services.pairing import approve_pairing

        await approve_pairing(db, code, "approve")

    # 重新注册，应该注册成功
    res_ok = await servicer.Register(req, ctx)
    assert res_ok.Retcode == Retcode_pb2.Registered


@pytest.mark.asyncio
async def test_client_register_servicer_unregister():
    """测试物理客户端解绑/注销服务流程。"""
    sm = SessionManager()
    servicer = server.ClientRegisterServicer(sm)

    # 尝试非法注销（会话无效）
    req = ClientRegisterCsReq_pb2.ClientRegisterCsReq(
        ClientUid="some-client-uid"
    )
    ctx = get_mock_context(metadata=[("session", "invalid-session-token")])
    await servicer.UnRegister(req, ctx)
    ctx.abort.assert_called_with(
        grpc.StatusCode.UNAUTHENTICATED, "会话鉴权失败，无法解绑"
    )


@pytest.mark.asyncio
async def test_command_deliver_servicer():
    """测试长连接指令推送通道的指令下发、双向流心跳逻辑。"""
    sm = SessionManager()
    servicer = server.ClientCommandDeliverServicer(sm)

    # 构造有效 session 并设置为在线
    sid = await sm.create_session("test-account-00000000", "client-uid-test")

    # 1. 测试 ListenCommand 鉴权失败分支
    ctx_fail = get_mock_context(metadata=[("session", "invalid-sid")])
    res_iterator_fail = servicer.ListenCommand(None, ctx_fail)
    with pytest.raises(Exception):  # 应该直接被 context.abort 截断
        async for _ in res_iterator_fail:
            pass

    # 2. 测试 ListenCommand 双向流正常逻辑
    ctx_ok = get_mock_context(metadata=[("session", sid)])

    # 构造请求迭代器，发送一个 Ping，随后结束流
    async def request_generator():
        yield ClientCommandDeliverScReq_pb2.ClientCommandDeliverScReq(
            Type=CommandTypes_pb2.Ping
        )
        # 稍等一会儿
        await asyncio.sleep(0.1)

    # 启动监听流
    stream = servicer.ListenCommand(request_generator(), ctx_ok)

    # 异步接收流推送
    async def receive_stream():
        async for resp in stream:
            assert resp.Type == CommandTypes_pb2.Pong
            break  # 收到 Pong 即断开

    # 运行流接收
    await asyncio.wait_for(receive_stream(), timeout=5)

    # 3. 推送普通指令测试
    # 模拟注入普通指令
    await servicer.send_command(
        "test-account-00000000", "client-uid-test", "dummy_command_msg"
    )


@pytest.mark.asyncio
async def test_config_upload_and_audit():
    """测试配置上报和审计日志上报服务的接口。"""
    sm = SessionManager()
    config_servicer = server.ConfigUploadServicer(sm)
    audit_servicer = server.AuditServicer(sm)

    # 1. 未授权会话 -> InvalidRequest
    ctx_fail = get_mock_context(metadata=[("session", "invalid-sid")])
    res_cfg = await config_servicer.UploadConfig(MagicMock(), ctx_fail)
    assert res_cfg.Retcode == Retcode_pb2.InvalidRequest

    res_audit = await audit_servicer.LogEvent(MagicMock(), ctx_fail)
    assert res_audit.Retcode == Retcode_pb2.InvalidRequest

    # 2. 授权会话成功上报
    sid = await sm.create_session("test-account-00000000", "client-uid-test")
    ctx_ok = get_mock_context(metadata=[("session", sid)])

    req_cfg = ConfigUploadScReq_pb2.ConfigUploadScReq(
        RequestGuidId="some-guid", Payload="{'setting': 'test'}"
    )
    res_cfg_ok = await config_servicer.UploadConfig(req_cfg, ctx_ok)
    assert res_cfg_ok.Retcode == Retcode_pb2.Success

    req_audit = AuditScReq_pb2.AuditScReq(
        Event=1, Payload=b"audit-data", TimestampUtc=1700000000
    )
    res_audit_ok = await audit_servicer.LogEvent(req_audit, ctx_ok)
    assert res_audit_ok.Retcode == Retcode_pb2.Success


@pytest.mark.asyncio
async def test_serve_grpc_bootstrap():
    """测试 gRPC 服务器的引导和安全停止动作。"""
    # 运行启动
    srv, cmd_s, mgr = await server.serve_grpc()
    assert srv is not None
    assert cmd_s is not None
    assert mgr is not None

    # 关闭服务器
    await srv.stop(grace=None)
