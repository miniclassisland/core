"""test_crypto.py"""

import pytest
from app.shared.security import crypto


def test_password_hashing():
    """Test Argon2id password hashing and verification."""
    pwd = "MySecretPassword123!"
    h = crypto.hash_password(pwd)
    assert h != pwd
    assert crypto.verify_password(pwd, h) is True
    assert crypto.verify_password("WrongPassword", h) is False


def test_classisland_credential_encoding():
    """Test upstream ClassIsland Base64 Credential JSON encoding and edge branches."""
    assert crypto.is_encoded_classisland_credential("") is False
    assert crypto.encode_classisland_credential("") == ""
    assert crypto.normalize_credentials_payload("not-a-dict") == "not-a-dict"

    encoded = crypto.encode_classisland_credential("Class123456")
    assert encoded != ""
    assert crypto.is_encoded_classisland_credential(encoded) is True
    assert crypto.encode_classisland_credential(encoded) == encoded


def test_totp_lifecycle():
    """Test TOTP secret generation, URI, and verification."""
    secret = crypto.generate_totp_secret()
    assert len(secret) >= 16
    uri = crypto.get_totp_uri(secret, "user@school.com")
    assert (
        "MINI%20ClassIsland" in uri
        or "MINI+ClassIsland" in uri
        or "MINI ClassIsland" in uri
    )
    assert "user" in uri
    assert crypto.verify_totp(secret, "000000") is False


@pytest.mark.asyncio
async def test_recovery_codes():
    """Test one-time 2FA recovery code generation, storage, and consumption."""
    user_id = "test-user-uuid"
    gen_codes = crypto.generate_recovery_codes()
    assert len(gen_codes) == 8

    codes = ["CODE1", "CODE2", "CODE3"]
    await crypto.store_recovery_codes(user_id, codes)
    assert await crypto.get_remaining_recovery_count(user_id) == 3

    assert await crypto.use_recovery_code(user_id, "code1") is True
    assert await crypto.get_remaining_recovery_count(user_id) == 2
    assert await crypto.use_recovery_code(user_id, "code1") is False
    assert await crypto.use_recovery_code(user_id, "INVALID") is False


def test_cc_protection_state():
    """Test CC attack protection global state helpers."""
    assert crypto.get_cc_state() is False
    crypto.set_cc_state(True)
    assert crypto.get_cc_state() is True
    crypto.set_cc_state(False)

    assert isinstance(crypto.get_ip_failures_dict(), dict)
    assert hasattr(crypto.get_global_requests(), "append")
