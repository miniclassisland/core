"""test_session.py
"""

import os
import pytest
from unittest.mock import MagicMock
from app.grpc.session import (
    parse_grpc_peer_ip,
    GPGKeyManager,
    SessionManager,
)


def test_parse_grpc_peer_ip():
    """测试 gRPC 对端 IP 的清洗解析逻辑。"""
    assert parse_grpc_peer_ip("ipv4:127.0.0.1:12345") == "127.0.0.1"
    assert parse_grpc_peer_ip("ipv6:[::1]:12345") == "::1"
    assert parse_grpc_peer_ip("ipv6:fe80::1:12345") == "fe80::1"
    assert parse_grpc_peer_ip("192.168.1.100") == "192.168.1.100"
    assert parse_grpc_peer_ip("") == ""


def test_gpg_key_manager_lifecycle():
    """测试 GPGKeyManager 在密钥文件不存在、损坏及正常解析时的逻辑。"""
    temp_key_file = "/tmp/temp_test_key.key"
    if os.path.exists(temp_key_file):
        os.remove(temp_key_file)

    try:
        # 1. 首次创建（文件不存在，应当能自动生成）
        km = GPGKeyManager(temp_key_file)
        assert km.public_key_armor != ""
        assert km.private_key is not None

        # 2. 二次加载（文件存在，正常读取）
        km2 = GPGKeyManager(temp_key_file)
        assert km2.public_key_armor == km.public_key_armor

        # 3. 损坏重新生成（文件存在但内容非法）
        with open(temp_key_file, "w") as f:
            f.write("INVALID GPG ARMOR DATA")

        km3 = GPGKeyManager(temp_key_file)
        assert km3.public_key_armor != ""
        assert km3.private_key is not None

        # 4. 解密非法数据校验（应当记录错误并返回 None）
        res = km3.decrypt("INVALID ENCRYPTED DATA BLOB")
        assert res is None
    finally:
        if os.path.exists(temp_key_file):
            os.remove(temp_key_file)


@pytest.mark.asyncio
async def test_session_manager_flows():
    """测试 SessionManager 中握手机制、会话绑定以及 Redis 在线状态维护的完整业务。"""
    key_file = "/tmp/test_session_manager_key.key"
    if os.path.exists(key_file):
        os.remove(key_file)

    try:
        sm = SessionManager(key_file)
        tenant_id = "test-account-00000000"
        cuid = "client-uid-test-123"

        # 1. 暂存/取用握手挑战令牌
        challenge = "challenge-plain-text-12345"
        await sm.store_pending_handshake(tenant_id, cuid, challenge)

        # 验证提取挑战令牌（取后即删）
        retrieved = await sm.pop_handshake_challenge(tenant_id, cuid)
        assert retrieved == challenge

        retrieved_again = await sm.pop_handshake_challenge(tenant_id, cuid)
        assert retrieved_again is None

        # 2. 会话（Session）生命周期测试
        # 创建会话
        sid = await sm.create_session(tenant_id, cuid)
        assert sid is not None

        # 检验会话可信身份
        assert await sm.validate_session(sid) == cuid
        assert await sm.get_session_tenant(sid) == tenant_id

        # 校验不存在的会话
        assert await sm.validate_session("non-existent-sid") is None
        assert await sm.get_session_tenant("non-existent-sid") is None
        assert await sm.validate_session("") is None
        assert await sm.get_session_tenant("") is None

        # 3. 在线状态心跳机制
        assert await sm.is_client_online(tenant_id, cuid) is False
        await sm.set_client_online(tenant_id, cuid, ip="ipv4:127.0.0.1:8888")
        assert await sm.is_client_online(tenant_id, cuid) is True

        # 更新心跳
        await sm.update_heartbeat(tenant_id, cuid)

        # 获取当前所有在线设备
        status_list = await sm.get_all_clients_status(tenant_id)
        assert any(s["uid"] == cuid for s in status_list)

        # 获取在线 IP 集合
        ips = await sm.get_all_online_ips(tenant_id)
        assert "127.0.0.1" in ips

        # 下线设备
        await sm.set_client_offline(tenant_id, cuid)
        assert await sm.is_client_online(tenant_id, cuid) is False

        # 4. complete_handshake 分支覆盖
        # 4.1 握手不被接受
        await sm.store_pending_handshake(tenant_id, cuid, challenge)
        res_fail = await sm.complete_handshake(tenant_id, cuid, accepted=False)
        assert res_fail is None

        # 4.2 握手接受且挑战令牌正常
        await sm.store_pending_handshake(tenant_id, cuid, challenge)
        res_ok = await sm.complete_handshake(tenant_id, cuid, accepted=True)
        assert res_ok is not None
        assert await sm.validate_session(res_ok) == cuid

        # 4.3 挑战令牌已过期/不存在，即使接受也应当返回 None
        res_expired = await sm.complete_handshake(tenant_id, cuid, accepted=True)
        assert res_expired is None
    finally:
        if os.path.exists(key_file):
            os.remove(key_file)
