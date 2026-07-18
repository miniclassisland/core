"""test_crypto.py
"""

import pytest
from app.shared.security import crypto


def test_password_hashing():
    """测试密码 Argon2id 散列及校验。"""
    pwd = "MySecretPassword123!"
    h = crypto.hash_password(pwd)
    assert h != pwd
    assert crypto.verify_password(h, pwd) is True
    assert crypto.verify_password(h, "WrongPassword") is False


def test_totp_lifecycle():
    """测试 TOTP 双因子令牌生成与检验。"""
    secret = "BASE32SECRET3232"
    uri = crypto.generate_totp_uri(secret, "user@school.com", "MySchool")
    assert "MySchool" in uri
    assert "user@school.com" in uri

    # 验证无效的 token
    assert crypto.verify_totp_token(secret, "000000") is False


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
