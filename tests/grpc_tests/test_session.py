"""test_session.py"""

import os
from unittest.mock import patch, MagicMock
import pytest
import pgpy
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
    """测试 GPGKeyManager 在密钥文件不存在、损坏、正常加密解密时的逻辑。"""
    temp_key_file = "/tmp/temp_test_key.key"
    if os.path.exists(temp_key_file):
        os.remove(temp_key_file)

    try:
        km = GPGKeyManager(temp_key_file)
        assert km.public_key_armor != ""
        assert km.private_key is not None

        # 测试正常加密与解密
        from typing import Any

        blob_res: Any = pgpy.PGPKey.from_blob(km.public_key_armor)
        pubkey, _ = blob_res
        msg = pgpy.PGPMessage.new("challenge-secret-123")
        enc = str(pubkey.encrypt(msg))
        dec = km.decrypt(enc)
        assert dec == "challenge-secret-123" or dec == b"challenge-secret-123"

        # 模拟 decrypt 返回 bytearray 分支
        mock_dec_msg = MagicMock()
        mock_dec_msg.message = bytearray(b"bytearray-secret")
        with (
            patch("pgpy.PGPMessage.from_blob", return_value=MagicMock()),
            patch.object(km.private_key, "decrypt", return_value=mock_dec_msg),
        ):
            assert km.decrypt("dummy") == b"bytearray-secret"

        km2 = GPGKeyManager(temp_key_file)
        assert km2.public_key_armor == km.public_key_armor

        with open(temp_key_file, "w") as f:
            f.write("INVALID GPG ARMOR DATA")

        km3 = GPGKeyManager(temp_key_file)
        assert km3.public_key_armor != ""
        assert km3.private_key is not None

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

        # decrypt_challenge 分支（正常与 _private_key=None）
        assert sm.decrypt_challenge("bad-blob") is None
        orig_pk = sm._private_key
        sm._private_key = None
        assert sm.decrypt_challenge("any") is None
        sm._private_key = orig_pk

        challenge = "challenge-plain-text-12345"
        await sm.store_pending_handshake(
            tenant_id, cuid, challenge, peer_ip="127.0.0.1"
        )

        retrieved = await sm.pop_handshake_challenge(tenant_id, cuid)
        assert retrieved == challenge
        assert await sm.pop_handshake_ip(tenant_id, cuid) == "127.0.0.1"
        assert await sm.pop_handshake_ip(tenant_id, cuid) is None

        retrieved_again = await sm.pop_handshake_challenge(tenant_id, cuid)
        assert retrieved_again is None

        sid = await sm.create_session(tenant_id, cuid)
        assert sid is not None

        assert await sm.validate_session(sid) == cuid
        assert await sm.get_session_tenant(sid) == tenant_id

        # 测试 L1 缓存未命中时回退到 Redis 读取
        from app.grpc import session as session_mod

        session_mod._LOCAL_SESSION_CACHE.clear()
        assert await sm.get_session_tenant(sid) == tenant_id
        session_mod._LOCAL_SESSION_CACHE.clear()
        assert await sm.validate_session(sid) == cuid

        assert await sm.validate_session("non-existent-sid") is None
        assert await sm.get_session_tenant("non-existent-sid") is None
        assert await sm.validate_session("") is None
        assert await sm.get_session_tenant("") is None

        # update_heartbeat 当设备尚不在线时的分支 (line 186)
        await sm.set_client_offline(tenant_id, cuid)
        assert await sm.is_client_online(tenant_id, cuid) is False
        await sm.update_heartbeat(tenant_id, cuid)
        assert await sm.is_client_online(tenant_id, cuid) is True

        # 测试 tid fallback 检查 online::{cuid} 分支 (line 176)
        await sm.set_client_offline(tenant_id, cuid)
        await sm.set_client_online("", cuid, ip="ipv4:127.0.0.1:8888")
        assert await sm.is_client_online(tenant_id, cuid) is True
        await sm.set_client_offline("", cuid)

        await sm.set_client_online(tenant_id, cuid, ip="ipv4:127.0.0.1:8888")
        assert await sm.is_client_online(tenant_id, cuid) is True
        await sm.update_heartbeat(tenant_id, cuid)

        status_list = await sm.get_all_clients_status(tenant_id)
        assert any(s["uid"] == cuid for s in status_list)

        # 测试 online_set 中存在已过期成员时的自动清理与 fallback scan 分支
        from app.shared.utils.redis import get_redis
        from app.shared.utils.config import REDIS_DB_SESSION

        rd = get_redis(REDIS_DB_SESSION)
        await rd.sadd(f"online_set:{tenant_id}", "expired-cuid")
        status_list_clean = await sm.get_all_clients_status(tenant_id)
        assert all(s["uid"] != "expired-cuid" for s in status_list_clean)

        await sm.set_client_online("", "notid-cuid", ip="127.0.0.1")
        status_empty_tid = await sm.get_all_clients_status("")
        assert any(s["uid"] == "notid-cuid" for s in status_empty_tid)
        await sm.set_client_offline("", "notid-cuid")

        await sm.set_client_offline(tenant_id, cuid)
        assert await sm.is_client_online(tenant_id, cuid) is False
        assert await sm.get_all_clients_status("never-used-tenant-id") == []
    finally:
        if os.path.exists(key_file):
            os.remove(key_file)
