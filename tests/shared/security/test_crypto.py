"""test_crypto.py
"""

import pytest
from app.shared.security import crypto


def test_password_hashing():
    """Test Argon2id password hashing and verification."""
    pwd = "MySecretPassword123!"
    h = crypto.hash_password(pwd)
    assert h != pwd
    assert crypto.verify_password(pwd, h) is True
    assert crypto.verify_password("WrongPassword", h) is False


def test_totp_lifecycle():
    """Test TOTP generation and verification."""
    secret = "BASE32SECRET3232"
    uri = crypto.get_totp_uri(secret, "user@school.com")
    assert "MINIClassIsland" in uri
    assert "user" in uri

    # Verify invalid token
    assert crypto.verify_totp(secret, "000000") is False


@pytest.mark.asyncio
async def test_recovery_codes():
    """测试一次性 2FA 恢复码机制。"""
    user_id = "test-user-uuid"
    codes = ["CODE1", "CODE2", "CODE3"]

    await crypto.store_recovery_codes(user_id, codes)

    count = await crypto.get_remaining_recovery_count(user_id)
    assert count == 3

    # 使用正确的恢复码
    res = await crypto.use_recovery_code(user_id, "code1")
    assert res is True

    count = await crypto.get_remaining_recovery_count(user_id)
    assert count == 2

    # 使用已失效的恢复码
    res = await crypto.use_recovery_code(user_id, "code1")
    assert res is False

    # 使用不正确的恢复码
    res = await crypto.use_recovery_code(user_id, "INVALID")
    assert res is False


def test_cc_protection_state():
    """测试 CC 攻击防护相关状态方法。"""
    assert crypto.get_cc_state() is False
    crypto.set_cc_state(True)
    assert crypto.get_cc_state() is True
    crypto.set_cc_state(False)

    assert isinstance(crypto.get_ip_failures_dict(), dict)
    assert hasattr(crypto.get_global_requests(), "append")
