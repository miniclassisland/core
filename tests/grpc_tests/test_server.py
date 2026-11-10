"""test_server.py"""

import asyncio
from datetime import datetime, timezone
import json
import pytest
import grpc
from typing import Any
from unittest.mock import MagicMock, AsyncMock, patch
from sqlalchemy import select, delete

from app.grpc import server
from app.grpc.session import SessionManager
from app.shared.security.crypto import set_cc_state
from app.shared.db.session import AsyncSessionLocal
from app.shared.db.models import (
    Account,
    ClientRecord,
    ConfigUploadRecord,
    PairingCode,
    PreRegisteredClient,
    SystemConfig,
)
from app.Protobuf.Client import (
    HandshakeScReq_pb2,
    ClientRegisterCsReq_pb2,
    ClientCommandDeliverScReq_pb2,
    ConfigUploadScReq_pb2,
    AuditScReq_pb2,
)
from app.Protobuf.Enum import Retcode_pb2, CommandTypes_pb2


def get_mock_context(metadata: list | None = None, peer: str = "ipv4:127.0.0.1:12345"):
    ctx = MagicMock(spec=grpc.aio.ServicerContext)
    ctx.invocation_metadata.return_value = metadata or []
    ctx.peer.return_value = peer
    ctx.abort = AsyncMock()
    return ctx


async def _empty_req_iter():
    for _ in ():
        yield None


@pytest.mark.asyncio
async def test_tenant_interceptor_all_branches(test_superadmin_user):
    """测试 gRPC 拦截器的白名单、CC 防御、租户解析及 4 种 RPC handler 包装分支。"""
    sm = SessionManager()
    interceptor = server.TenantInterceptor(sm)

    # 1. CC 攻击激活下，豁免方法依然被拦截
    set_cc_state(True)
    details = MagicMock()
    details.method = "/Handshake/BeginHandshake"
    details.invocation_metadata = []

    async def continuation_dummy(d):
        return MagicMock()

    with pytest.raises(grpc.aio.AbortError) as exc:
        await interceptor.intercept_service(continuation_dummy, details)
    assert exc.value.args[0] == grpc.StatusCode.UNAVAILABLE
    set_cc_state(False)

    # 2. 创建租户和有效 Session（带 Bearer 前缀）
    async with AsyncSessionLocal() as db:
        db.add(
            Account(
                id="acct-grpc-1",
                name="G1",
                slug="grpc-school",
                api_key="k",
                is_active=True,
                registration_mode="pre_reg",
                created_at=datetime.now(timezone.utc),
            )
        )
        await db.commit()

    sid = await sm.create_session("acct-grpc-1", "client-uid-test")

    # continuation 返回 None 分支
    details_none = MagicMock()
    details_none.method = "/Handshake/BeginHandshake"
    details_none.invocation_metadata = [
        ("tenant-slug", "grpc-school"),
        ("authorization", f"Bearer {sid}"),
    ]

    async def continuation_none(d):
        return None

    assert await interceptor.intercept_service(continuation_none, details_none) is None

    # 测试 unary_unary, unary_stream (generator & non-generator), stream_unary, stream_stream 及 fallback handler
    for mode in (
        "unary_unary",
        "unary_stream_gen",
        "unary_stream_coro",
        "stream_unary",
        "stream_stream",
        "empty",
    ):
        h = MagicMock()
        h.unary_unary = None
        h.unary_stream = None
        h.stream_unary = None
        h.stream_stream = None
        h.request_deserializer = MagicMock()
        h.response_serializer = MagicMock()

        if mode == "unary_unary":
            h.unary_unary = AsyncMock(return_value="uu_ok")
        elif mode == "unary_stream_gen":

            async def _agen(req, ctx):
                yield "us_gen_ok"

            h.unary_stream = _agen
        elif mode == "unary_stream_coro":
            h.unary_stream = AsyncMock(return_value="us_coro_ok")
        elif mode == "stream_unary":
            h.stream_unary = AsyncMock(return_value="su_ok")
        elif mode == "stream_stream":
            h.stream_stream = AsyncMock(return_value="ss_ok")

        async def _cont(d, _h=h):
            return _h

        wrapped: Any = await interceptor.intercept_service(_cont, details_none)
        if mode == "unary_unary":
            assert await wrapped.unary_unary("r", "c") == "uu_ok"
        elif mode == "unary_stream_gen":
            items = [x async for x in wrapped.unary_stream("r", "c")]
            assert items == ["us_gen_ok"]
        elif mode == "unary_stream_coro":
            assert await wrapped.unary_stream("r", "c") == "us_coro_ok"
        elif mode == "stream_unary":
            assert await wrapped.stream_unary("r", "c") == "su_ok"
        elif mode == "stream_stream":
            assert await wrapped.stream_stream("r", "c") == "ss_ok"
        elif mode == "empty":
            assert wrapped is h

    # 非白名单方法无 slug 但有有效 session (从 session 解析 tenant_id)
    details_sid_only = MagicMock()
    details_sid_only.method = "/Command/ListenCommand"
    details_sid_only.invocation_metadata = [("session", sid)]
    h_uu = MagicMock()
    h_uu.unary_unary = AsyncMock(return_value="ok")
    h_uu.unary_stream = None
    h_uu.stream_unary = None
    h_uu.stream_stream = None
    w_sid: Any = await interceptor.intercept_service(
        AsyncMock(return_value=h_uu), details_sid_only
    )
    assert await w_sid.unary_unary("r", "c") == "ok"

    # 非法 session -> UNAUTHENTICATED
    details_invalid = MagicMock()
    details_invalid.method = "/Command/ListenCommand"
    details_invalid.invocation_metadata = [("session", "invalid-sid")]
    with pytest.raises(grpc.aio.AbortError) as exc2:
        await interceptor.intercept_service(continuation_dummy, details_invalid)
    assert exc2.value.args[0] == grpc.StatusCode.UNAUTHENTICATED


@pytest.mark.asyncio
async def test_handshake_servicer():
    """测试握手服务的所有安全校验及成功分支。"""
    sm = SessionManager()
    servicer = server.HandshakeServicer(sm)
    ctx = get_mock_context()

    # 1. 不存在的客户端 -> ClientNotFound
    req = HandshakeScReq_pb2.HandshakeScBeginHandShakeReq(
        ClientUid="non-existent-uid",
        ClientMac="AA-BB-CC-DD-EE-FF",
        ChallengeTokenEncrypted="xyz",
    )
    assert (
        await servicer.BeginHandshake(req, ctx)
    ).Retcode == Retcode_pb2.ClientNotFound

    # 2. 插入客户端记录（含禁用状态与正常状态）
    async with AsyncSessionLocal() as db:
        db.add_all(
            [
                ClientRecord(
                    uid="valid-client-uid",
                    account_id="acct-hs-1",
                    client_id="c1",
                    mac="AA-BB-CC-DD-EE-FF",
                    is_disabled=False,
                    registered_at=datetime.now(timezone.utc),
                ),
                ClientRecord(
                    uid="disabled-client-uid",
                    account_id="acct-hs-1",
                    client_id="c2",
                    mac="AA-BB-CC-DD-EE-FF",
                    is_disabled=True,
                    registered_at=datetime.now(timezone.utc),
                ),
            ]
        )
        await db.commit()

    # 禁用客户端 BeginHandshake -> InvalidRequest
    req_dis = HandshakeScReq_pb2.HandshakeScBeginHandShakeReq(
        ClientUid="disabled-client-uid",
        ClientMac="AA-BB-CC-DD-EE-FF",
        ChallengeTokenEncrypted="xyz",
    )
    assert (
        await servicer.BeginHandshake(req_dis, ctx)
    ).Retcode == Retcode_pb2.InvalidRequest

    # MAC 不匹配 -> InvalidRequest
    req_wrong_mac = HandshakeScReq_pb2.HandshakeScBeginHandShakeReq(
        ClientUid="valid-client-uid",
        ClientMac="WRONG-MAC",
        ChallengeTokenEncrypted="xyz",
    )
    assert (
        await servicer.BeginHandshake(req_wrong_mac, ctx)
    ).Retcode == Retcode_pb2.InvalidRequest

    # GPG 解密失败 -> ServerInternalError
    req_decrypt_fail = HandshakeScReq_pb2.HandshakeScBeginHandShakeReq(
        ClientUid="valid-client-uid",
        ClientMac="AA-BB-CC-DD-EE-FF",
        ChallengeTokenEncrypted="bad-encrypted-data",
    )
    assert (
        await servicer.BeginHandshake(req_decrypt_fail, ctx)
    ).Retcode == Retcode_pb2.ServerInternalError

    # GPG 解密成功 -> Success
    with patch.object(sm, "decrypt_challenge", return_value="challenge-ok"):
        res_begin_ok = await servicer.BeginHandshake(req_decrypt_fail, ctx)
        assert res_begin_ok.Retcode == Retcode_pb2.Success
        assert res_begin_ok.ChallengeTokenDecrypted == "challenge-ok"

    # CompleteHandshake: 禁用客户端 -> InvalidRequest
    ctx_dis = get_mock_context(metadata=[("cuid", "disabled-client-uid")])
    req_comp_ok = HandshakeScReq_pb2.HandshakeScCompleteHandshakeReq(Accepted=True)
    assert (
        await servicer.CompleteHandshake(req_comp_ok, ctx_dis)
    ).Retcode == Retcode_pb2.InvalidRequest

    # CompleteHandshake: 成功建立 Session
    ctx_complete = get_mock_context(metadata=[("cuid", "valid-client-uid")])
    res_comp_success = await servicer.CompleteHandshake(req_comp_ok, ctx_complete)
    assert res_comp_success.Retcode == Retcode_pb2.Success
    assert res_comp_success.SessionId != ""

    # CompleteHandshake: 未被接受 -> HandshakeClientRejected
    req_complete_reject = HandshakeScReq_pb2.HandshakeScCompleteHandshakeReq(
        Accepted=False
    )
    assert (
        await servicer.CompleteHandshake(req_complete_reject, ctx_complete)
    ).Retcode == Retcode_pb2.HandshakeClientRejected

    # CompleteHandshake: 无挑战记录 -> InvalidRequest
    assert (
        await servicer.CompleteHandshake(req_comp_ok, ctx_complete)
    ).Retcode == Retcode_pb2.InvalidRequest


@pytest.mark.asyncio
async def test_client_register_servicer_all_modes():
    """测试客户端注册服务的禁用拦截、pre_reg 拦截、预注册匹配（含 preset_profile）及配对审批流程。"""
    sm = SessionManager()
    servicer = server.ClientRegisterServicer(sm)
    ctx = get_mock_context()

    async with AsyncSessionLocal() as db:
        db.add(
            Account(
                id="acct-reg-mode",
                name="RegMode",
                slug="reg-mode",
                api_key="k",
                is_active=True,
                registration_mode="pre_reg",
                created_at=datetime.now(timezone.utc),
            )
        )
        db.add(
            ClientRecord(
                uid="disabled-reg-uid",
                account_id="acct-reg-mode",
                is_disabled=True,
                registered_at=datetime.now(timezone.utc),
            )
        )
        await db.commit()

    # 1. 已禁用设备注册 -> InvalidRequest
    res_dis = await servicer.Register(
        ClientRegisterCsReq_pb2.ClientRegisterCsReq(ClientUid="disabled-reg-uid"), ctx
    )
    assert res_dis.Retcode == Retcode_pb2.InvalidRequest

    # 2. pre_reg 模式下未预注册设备被拒 -> InvalidRequest
    tok = server.tenant_ctx.set("acct-reg-mode")
    try:
        res_prereg_deny = await servicer.Register(
            ClientRegisterCsReq_pb2.ClientRegisterCsReq(
                ClientUid="unlisted-uid", ClientId="Room-999", ClientMac="11-11"
            ),
            ctx,
        )
        assert res_prereg_deny.Retcode == Retcode_pb2.InvalidRequest

        # 3. 添加 PreRegisteredClient（带 preset_profile）并验证自动绑定与预设应用
        async with AsyncSessionLocal() as db:
            db.add(
                PreRegisteredClient(
                    id="pre-1",
                    account_id="acct-reg-mode",
                    label="Room 101 PC",
                    class_identity="Room-101",
                    mac_address="AA-11-22",
                    is_enabled=True,
                    preset_profile_json=json.dumps({"class_plan": "cp_101"}),
                    created_at=datetime.now(timezone.utc),
                )
            )
            await db.commit()

        res_prereg_ok = await servicer.Register(
            ClientRegisterCsReq_pb2.ClientRegisterCsReq(
                ClientUid="listed-uid-101", ClientId="Room-101", ClientMac="AA-11-22"
            ),
            ctx,
        )
        assert res_prereg_ok.Retcode == Retcode_pb2.Registered

        # 3b. max_clients 配额超限 -> InvalidRequest
        from app.shared.services.quota import set_quota

        async with AsyncSessionLocal() as db:
            await set_quota("acct-reg-mode", "max_clients", 1, db)
            db.add(
                PreRegisteredClient(
                    id="pre-2",
                    account_id="acct-reg-mode",
                    label="Room 102 PC",
                    class_identity="Room-102",
                    mac_address="AA-11-23",
                    is_enabled=True,
                    created_at=datetime.now(timezone.utc),
                )
            )
            await db.commit()

        res_quota_deny = await servicer.Register(
            ClientRegisterCsReq_pb2.ClientRegisterCsReq(
                ClientUid="listed-uid-102", ClientId="Room-102", ClientMac="AA-11-23"
            ),
            ctx,
        )
        assert res_quota_deny.Retcode == Retcode_pb2.InvalidRequest
        assert "max_clients" in res_quota_deny.Message

        # 3c. Cross-tenant ClientUid hijacking rejected -> InvalidRequest
        async with AsyncSessionLocal() as db:
            db.add(
                ClientRecord(
                    uid="other-tenant-uid",
                    account_id="another-account-id",
                    registered_at=datetime.now(timezone.utc),
                )
            )
            await db.commit()
        res_cross_uid = await servicer.Register(
            ClientRegisterCsReq_pb2.ClientRegisterCsReq(
                ClientUid="other-tenant-uid", ClientId="Room-101", ClientMac="AA-11-22"
            ),
            ctx,
        )
        assert res_cross_uid.Retcode == Retcode_pb2.InvalidRequest
    finally:
        server.tenant_ctx.reset(tok)

    # 4. 启用全局配对功能配置 -> PairingRequired -> 审批后 Registered
    async with AsyncSessionLocal() as db:
        await db.execute(
            delete(SystemConfig).where(SystemConfig.key == "pairing_enabled")
        )
        db.add(
            SystemConfig(
                key="pairing_enabled",
                value="true",
                updated_at=datetime.now(timezone.utc),
            )
        )
        await db.commit()

    req = ClientRegisterCsReq_pb2.ClientRegisterCsReq(
        ClientUid="new-client-uid-pairing",
        ClientId="c2",
        ClientMac="22-33-44-55-66-77",
    )
    res = await servicer.Register(req, ctx)
    assert res.Retcode == Retcode_pb2.PairingRequired

    async with AsyncSessionLocal() as db:
        record = (
            await db.execute(
                select(PairingCode).where(
                    PairingCode.client_uid == "new-client-uid-pairing"
                )
            )
        ).scalar_one()
        record.approved = True
        record.status = "approved"
        await db.commit()

    res_ok = await servicer.Register(req, ctx)
    assert res_ok.Retcode == Retcode_pb2.Registered

    # 4b. 已完成配对注册的同一硬件设备重复调用 Register 免重复配对 -> Registered
    res_re_ok = await servicer.Register(req, ctx)
    assert res_re_ok.Retcode == Retcode_pb2.Registered

    # 4c. 攻击者使用不同 MAC 尝试接管已注册设备的 ClientUid -> InvalidRequest
    req_bad_mac = ClientRegisterCsReq_pb2.ClientRegisterCsReq(
        ClientUid="new-client-uid-pairing",
        ClientId="c2",
        ClientMac="FF-FF-FF-FF-FF-FF",
    )
    res_bad_mac = await servicer.Register(req_bad_mac, ctx)
    assert res_bad_mac.Retcode == Retcode_pb2.InvalidRequest
    assert "MAC" in res_bad_mac.Message

    # 4d. _REGISTER_LOCKS 超上限时自动清理未加锁条目
    with patch.object(server, "_MAX_REGISTER_LOCKS", 0):
        server._REGISTER_LOCKS["stale-tenant-lock"] = asyncio.Lock()
        res_evict = await servicer.Register(req, ctx)
        assert res_evict.Retcode == Retcode_pb2.Registered


@pytest.mark.asyncio
async def test_client_register_servicer_unregister():
    """测试物理客户端解绑/注销服务流程（失败与成功分支）。"""
    sm = SessionManager()
    servicer = server.ClientRegisterServicer(sm)

    # 1. 会话无效
    req = ClientRegisterCsReq_pb2.ClientRegisterCsReq(ClientUid="some-client-uid")
    ctx = get_mock_context(metadata=[("session", "invalid-session-token")])
    await servicer.UnRegister(req, ctx)
    ctx.abort.assert_called_with(
        grpc.StatusCode.UNAUTHENTICATED,
        "Session authentication failed, unable to unregister",
    )

    # 2. 会话有效且存在 ClientRecord -> 成功删除并下线
    async with AsyncSessionLocal() as db:
        db.add(
            ClientRecord(
                uid="unreg-client-uid",
                account_id="acct-unreg",
                registered_at=datetime.now(timezone.utc),
            )
        )
        await db.commit()

    sid = await sm.create_session("acct-unreg", "unreg-client-uid")
    ctx_ok = get_mock_context(metadata=[("session", sid)])

    # 2a. 租户不匹配时拒绝解绑 (lines 533-537)
    sid_wrong_tid = await sm.create_session("other-tenant-id", "unreg-client-uid")
    ctx_wrong_tid = get_mock_context(metadata=[("session", sid_wrong_tid)])
    await servicer.UnRegister(
        ClientRegisterCsReq_pb2.ClientRegisterCsReq(ClientUid="unreg-client-uid"),
        ctx_wrong_tid,
    )
    ctx_wrong_tid.abort.assert_called_with(
        grpc.StatusCode.PERMISSION_DENIED,
        "Device does not belong to this tenant",
    )

    res_ok = await servicer.UnRegister(
        ClientRegisterCsReq_pb2.ClientRegisterCsReq(ClientUid="unreg-client-uid"),
        ctx_ok,
    )
    assert res_ok.Retcode == Retcode_pb2.Success


@pytest.mark.asyncio
async def test_command_deliver_servicer():
    """测试长连接指令推送通道的指令下发、双向流心跳、节流、禁用拦截与主动断开逻辑。"""
    sm = SessionManager()
    servicer = server.ClientCommandDeliverServicer(sm)

    # 1. ListenCommand 鉴权失败分支
    ctx_fail = get_mock_context(metadata=[("session", "invalid-sid")])
    async for _ in servicer.ListenCommand(None, ctx_fail):
        pass
    ctx_fail.abort.assert_called_with(
        grpc.StatusCode.UNAUTHENTICATED, "Session validation failed, listening rejected"
    )

    # 2. ListenCommand 设备被禁用分支
    async with AsyncSessionLocal() as db:
        db.add_all(
            [
                ClientRecord(
                    uid="cmd-disabled-uid",
                    account_id="acct-cmd",
                    is_disabled=True,
                    registered_at=datetime.now(timezone.utc),
                ),
                ClientRecord(
                    uid="client-uid-test",
                    account_id="test-account-00000000",
                    is_disabled=False,
                    registered_at=datetime.now(timezone.utc),
                ),
            ]
        )
        await db.commit()

    sid_dis = await sm.create_session("acct-cmd", "cmd-disabled-uid")
    ctx_dis = get_mock_context(metadata=[("session", sid_dis)])
    async for _ in servicer.ListenCommand(_empty_req_iter(), ctx_dis):
        pass
    ctx_dis.abort.assert_called_with(
        grpc.StatusCode.PERMISSION_DENIED, "Device is disabled by administrator"
    )

    # 2b. ListenCommand 租户不匹配分支 (lines 593-597)
    sid_mismatch = await sm.create_session("wrong-tenant-id", "client-uid-test")
    ctx_mismatch = get_mock_context(metadata=[("session", sid_mismatch)])
    async for _ in servicer.ListenCommand(_empty_req_iter(), ctx_mismatch):
        pass
    ctx_mismatch.abort.assert_called_with(
        grpc.StatusCode.PERMISSION_DENIED, "Device does not belong to this tenant"
    )

    # 3. ListenCommand 双向流正常逻辑（含重连旧队列未下发指令迁移、连续 Ping 节流、QueueFull 容错、非 Ping 上行指令及 disconnect_client 退出）
    sid = await sm.create_session("", "client-uid-test")
    ctx_ok = get_mock_context(metadata=[("session", sid)])
    stale_q: asyncio.Queue = asyncio.Queue()
    from app.Protobuf.Server import ClientCommandDeliverScRsp_pb2

    pending_restart = ClientCommandDeliverScRsp_pb2.ClientCommandDeliverScRsp(
        RetCode=Retcode_pb2.Success, Type=CommandTypes_pb2.RestartApp
    )
    stale_q.put_nowait(pending_restart)
    servicer.client_queues["test-account-00000000:client-uid-test"] = stale_q

    async def request_generator():
        yield ClientCommandDeliverScReq_pb2.ClientCommandDeliverScReq(
            Type=CommandTypes_pb2.Ping
        )
        # 紧接着第二个 Ping 触发 _MIN_PING_INTERVAL 节流分支
        yield ClientCommandDeliverScReq_pb2.ClientCommandDeliverScReq(
            Type=CommandTypes_pb2.Ping
        )
        # 发送非 Ping 类型触发 uplink 日志分支
        yield ClientCommandDeliverScReq_pb2.ClientCommandDeliverScReq(
            Type=CommandTypes_pb2.Pong
        )
        # 测试 read_task 中 queue.put_nowait QueueFull 分支 (lines 662-663)
        q_stream = servicer.client_queues.get("test-account-00000000:client-uid-test")
        if q_stream is not None:
            with (
                patch.object(server, "_MIN_PING_INTERVAL", 0.0),
                patch.object(server, "_REDIS_HB_SYNC_INTERVAL", 0.0),
                patch.object(q_stream, "put_nowait", side_effect=asyncio.QueueFull),
            ):
                yield ClientCommandDeliverScReq_pb2.ClientCommandDeliverScReq(
                    Type=CommandTypes_pb2.Ping
                )
        await asyncio.sleep(0.05)
        await servicer.disconnect_client("test-account-00000000", "client-uid-test")

    stream = servicer.ListenCommand(request_generator(), ctx_ok)
    received = []
    async for resp in stream:
        received.append(resp)
    assert len(received) == 2
    assert received[0].Type == CommandTypes_pb2.RestartApp
    assert received[1].Type == CommandTypes_pb2.Pong
    assert await stale_q.get() is None

    # 4. send_command 与 disconnect_client 在队列存在、不存在及 QueueFull 时的分支
    assert (
        await servicer.send_command("test-account-00000000", "no-client", "msg")
        is False
    )
    q = asyncio.Queue(maxsize=1)
    servicer.client_queues["test-account-00000000:c-queued"] = q
    assert (
        await servicer.send_command("test-account-00000000", "c-queued", "msg") is True
    )
    # 队列已满时 send_command 返回 False (lines 699-700)
    assert (
        await servicer.send_command("test-account-00000000", "c-queued", "msg2")
        is False
    )
    # 队列已满时 disconnect_client 自动丢弃旧项并压入 None (lines 711-715)
    assert await servicer.disconnect_client("test-account-00000000", "c-queued") is True
    assert await q.get() is None
    assert (
        await servicer.disconnect_client("test-account-00000000", "no-client") is False
    )

    # 5. ListenCommand max_grpc_connections 配额限制分支
    from app.shared.services.quota import set_quota

    async with AsyncSessionLocal() as db:
        await set_quota("test-account-00000000", "max_grpc_connections", 1, db)
    servicer.tenant_clients.setdefault("test-account-00000000", set()).add("c-queued")
    sid_q = await sm.create_session("test-account-00000000", "client-uid-test")
    ctx_q = get_mock_context(metadata=[("session", sid_q)])
    async for _ in servicer.ListenCommand(_empty_req_iter(), ctx_q):
        pass
    ctx_q.abort.assert_called_with(
        grpc.StatusCode.RESOURCE_EXHAUSTED,
        "Account gRPC connection quota (max_grpc_connections) exceeded",
    )
    servicer.client_queues.pop("test-account-00000000:c-queued", None)
    servicer.tenant_clients.pop("test-account-00000000", None)


@pytest.mark.asyncio
async def test_config_upload_and_audit():
    """测试配置上报（含预创建 RequestGuidId 分支）和审计日志上报服务的接口。"""
    sm = SessionManager()
    config_servicer = server.ConfigUploadServicer(sm)
    audit_servicer = server.AuditServicer(sm)

    # 1. 未授权会话且无有效 RequestGuidId 或超大 Payload -> InvalidRequest
    ctx_fail = get_mock_context(metadata=[("session", "invalid-sid")])
    res_cfg = await config_servicer.UploadConfig(MagicMock(RequestGuidId=""), ctx_fail)
    assert res_cfg.Retcode == Retcode_pb2.InvalidRequest

    res_cfg_big = await config_servicer.UploadConfig(
        MagicMock(RequestGuidId="", Payload="x" * (2100 * 1024)), ctx_fail
    )
    assert res_cfg_big.Retcode == Retcode_pb2.InvalidRequest

    res_audit = await audit_servicer.LogEvent(MagicMock(), ctx_fail)
    assert res_audit.Retcode == Retcode_pb2.InvalidRequest

    # 2. 预创建 ConfigUploadRecord，测试更新已存在记录分支及租户/设备校验分支
    async with AsyncSessionLocal() as db:
        db.add(
            ConfigUploadRecord(
                request_guid="pre-guid-123",
                account_id="test-account-00000000",
                client_uid="client-uid-audit",
                status="pending",
                payload="",
                uploaded_at=datetime.now(timezone.utc),
            )
        )
        db.add(
            ClientRecord(
                uid="client-uid-audit",
                account_id="test-account-00000000",
                ip="127.0.0.1",
                registered_at=datetime.now(timezone.utc),
            )
        )
        db.add(
            ClientRecord(
                uid="client-uid-disabled-audit",
                account_id="test-account-00000000",
                is_disabled=True,
                registered_at=datetime.now(timezone.utc),
            )
        )
        await db.commit()

    sid = await sm.create_session("", "client-uid-audit")
    ctx_ok = get_mock_context(metadata=[("session", sid)])

    req_cfg_existing = ConfigUploadScReq_pb2.ConfigUploadScReq(
        RequestGuidId="pre-guid-123", Payload='{"updated": true}'
    )
    # 2a. 租户不匹配时拒绝更新 (line 767)
    sid_other_tid = await sm.create_session("other-tenant-id", "client-uid-audit")
    ctx_other_tid = get_mock_context(metadata=[("session", sid_other_tid)])
    assert (
        await config_servicer.UploadConfig(req_cfg_existing, ctx_other_tid)
    ).Retcode == Retcode_pb2.InvalidRequest

    # 2b. 客户端 UID 不匹配时拒绝更新 (line 776)
    sid_other_uid = await sm.create_session("test-account-00000000", "other-client-uid")
    ctx_other_uid = get_mock_context(metadata=[("session", sid_other_uid)])
    assert (
        await config_servicer.UploadConfig(req_cfg_existing, ctx_other_uid)
    ).Retcode == Retcode_pb2.InvalidRequest

    # 2b-2. 无 session 时（上游客户端模式）对端 IP 与 ClientRecord.ip 不匹配则拒绝更新，匹配则放行
    ctx_no_sid_bad_ip = get_mock_context(metadata=[], peer="ipv4:203.0.113.99:54321")
    assert (
        await config_servicer.UploadConfig(req_cfg_existing, ctx_no_sid_bad_ip)
    ).Retcode == Retcode_pb2.InvalidRequest

    # 2c. 匹配的会话成功更新
    res_cfg_ex = await config_servicer.UploadConfig(req_cfg_existing, ctx_ok)
    assert res_cfg_ex.Retcode == Retcode_pb2.Success

    # 3. 全新 RequestGuidId 上报
    req_cfg_new = ConfigUploadScReq_pb2.ConfigUploadScReq(
        RequestGuidId="new-guid-456", Payload='{"setting": "test"}'
    )
    res_cfg_ok = await config_servicer.UploadConfig(req_cfg_new, ctx_ok)
    assert res_cfg_ok.Retcode == Retcode_pb2.Success

    # 4. 审计日志上报（含无 tid 时从 ClientRecord 回查 account_id、未授权拦截、禁用/跨租户拦截及 str Payload 分支）
    req_audit = AuditScReq_pb2.AuditScReq(Event=1, Payload=b"", TimestampUtc=1700000000)
    res_audit_ok = await audit_servicer.LogEvent(req_audit, ctx_ok)
    assert res_audit_ok.Retcode == Retcode_pb2.Success

    ctx_cuid_only = get_mock_context(metadata=[("cuid", "client-uid-audit")])
    res_audit_cuid = await audit_servicer.LogEvent(req_audit, ctx_cuid_only)
    assert res_audit_cuid.Retcode == Retcode_pb2.InvalidRequest

    # 禁用设备上报审计日志被拒绝 (line 849)
    sid_dis_audit = await sm.create_session(
        "test-account-00000000", "client-uid-disabled-audit"
    )
    ctx_dis_audit = get_mock_context(metadata=[("session", sid_dis_audit)])
    assert (
        await audit_servicer.LogEvent(req_audit, ctx_dis_audit)
    ).Retcode == Retcode_pb2.InvalidRequest

    # 跨租户会话上报审计日志被拒绝 (line 855)
    assert (
        await audit_servicer.LogEvent(req_audit, ctx_other_tid)
    ).Retcode == Retcode_pb2.InvalidRequest

    mock_str_audit = MagicMock()
    mock_str_audit.Payload = "string-payload"
    mock_str_audit.Event = 1
    mock_str_audit.TimestampUtc = 1700000000
    assert (
        await audit_servicer.LogEvent(mock_str_audit, ctx_ok)
    ).Retcode == Retcode_pb2.Success

    mock_big_audit = MagicMock()
    mock_big_audit.Payload = b"x" * (2100 * 1024)
    assert (
        await audit_servicer.LogEvent(mock_big_audit, ctx_ok)
    ).Retcode == Retcode_pb2.InvalidRequest

    # 5. feature.audit 配额关闭 (0) 时拒绝上报
    from app.shared.services.quota import set_quota

    async with AsyncSessionLocal() as db:
        await set_quota("test-account-00000000", "feature.audit", 0, db)
    assert (
        await audit_servicer.LogEvent(req_audit, ctx_ok)
    ).Retcode == Retcode_pb2.InvalidRequest


@pytest.mark.asyncio
async def test_serve_grpc_bootstrap():
    """测试 gRPC 服务器的引导和安全停止动作。"""
    with patch.object(server, "GRPC_PORT", 0):
        srv, cmd_s, mgr = await server.serve_grpc()
        assert srv is not None
        assert cmd_s is not None
        assert mgr is not None
        await srv.stop(grace=None)
