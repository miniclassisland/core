"""test_crypto.py"""

import pytest
from app.shared.security import crypto


@pytest.mark.asyncio
async def test_password_hashing():
    """Test Argon2id password hashing and verification (sync and async worker thread)."""
    pwd = "MySecretPassword123!"
    h = crypto.hash_password(pwd)
    assert h != pwd
    assert crypto.verify_password(pwd, h) is True
    assert crypto.verify_password("WrongPassword", h) is False
    h_async = await crypto.hash_password_async(pwd)
    assert await crypto.verify_password_async(pwd, h_async) is True
    assert await crypto.verify_password_async("WrongPassword", h_async) is False


def test_classisland_credential_encoding():
    """Test upstream ClassIsland Base64 Credential JSON encoding and edge branches."""
    assert crypto.is_encoded_classisland_credential("") is False
    assert crypto.encode_classisland_credential("") == ""
    assert crypto.normalize_credentials_payload("not-a-dict") == "not-a-dict"

    encoded = crypto.encode_classisland_credential("Class123456")
    assert encoded != ""
    assert crypto.is_encoded_classisland_credential(encoded) is True
    assert crypto.encode_classisland_credential(encoded) == encoded


def test_resource_payload_normalization():
    """Test normalize_resource_payload and ensure_guid_str for upstream ClassIsland System.Guid compatibility."""
    assert crypto.ensure_guid_str("") == "00000000-0000-0000-0000-000000000000"
    assert crypto.ensure_guid_str("", allow_empty=True) == ""
    assert crypto.ensure_guid_str("   ", allow_empty=True) == ""
    assert (
        crypto.ensure_guid_str("sub-chinese") == "97d0bf3f-137f-4f8a-87d6-ff387063bbd3"
    )
    valid_uuid = "1154d452-5ede-4194-b4dd-cb40c956c8ed"
    assert crypto.ensure_guid_str(valid_uuid) == valid_uuid
    custom_uuid = crypto.ensure_guid_str("custom-non-guid-id")
    assert len(custom_uuid) == 36 and "-" in custom_uuid

    assert crypto._normalize_hhmmss("") == ("1970-01-01T08:00:00", "08:00:00")
    assert crypto._normalize_hhmmss("1970-01-01T09:15:30.123") == (
        "1970-01-01T09:15:30",
        "09:15:30",
    )

    assert crypto.normalize_resource_payload("Subjects", "not-a-dict") == "not-a-dict"

    sub_norm = crypto.normalize_resource_payload(
        "Subjects",
        {"sub-chinese": {"Name": "语文"}, "skip_non_dict": "val"},
    )
    assert "97d0bf3f-137f-4f8a-87d6-ff387063bbd3" in sub_norm["Subjects"]

    tl_norm = crypto.normalize_resource_payload(
        "TimeLayout",
        {
            "tl-weekday": {
                "Name": "作息",
                "Layouts": [
                    {
                        "StartSecond": "1970-01-01T08:00:00",
                        "EndSecond": "1970-01-01T08:45:00",
                        "TimeType": 0,
                        "DefaultClassId": "sub-chinese",
                    },
                    "skip-non-dict",
                ],
            },
            "bad": "skip",
        },
    )
    tl_guid = "4b9c71e2-6a1f-4d8e-9b2c-3d4e5f6a7b8c"
    assert tl_guid in tl_norm["TimeLayouts"]
    assert tl_norm["TimeLayouts"][tl_guid]["Layouts"][0]["StartTime"] == "08:00:00"
    assert (
        tl_norm["TimeLayouts"][tl_guid]["Layouts"][0]["DefaultClassId"]
        == "97d0bf3f-137f-4f8a-87d6-ff387063bbd3"
    )

    cp_norm = crypto.normalize_resource_payload(
        "ClassPlan",
        {
            "cp-monday": {
                "Name": "周一",
                "TimeLayoutId": "tl-weekday",
                "OverlaySourceId": "cp-monday",
                "Classes": [
                    {"SubjectId": "sub-chinese", "IsEnabled": True},
                    "skip-non-dict",
                ],
            },
            "bad": "skip",
        },
    )
    cp_guid = "5c8d62f3-7b2a-4e9f-8c3d-4e5f6a7b8c9d"
    assert cp_guid in cp_norm["ClassPlans"]
    assert cp_norm["ClassPlans"][cp_guid]["TimeLayoutId"] == tl_guid
    assert cp_norm["ClassPlans"][cp_guid]["OverlaySourceId"] == cp_guid
    assert (
        cp_norm["ClassPlans"][cp_guid]["Classes"][0]["SubjectId"]
        == "97d0bf3f-137f-4f8a-87d6-ff387063bbd3"
    )
    assert "00000000-0000-0000-0000-000000000000" in cp_norm["ClassPlanGroups"]

    assert crypto.normalize_resource_payload(
        "Policy", {"AllowExitManagement": True}
    ) == {"AllowExitManagement": True}


@pytest.mark.asyncio
async def test_totp_lifecycle():
    """Test TOTP secret generation, URI, verification, and replay protection."""
    import pyotp

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
    assert await crypto.verify_totp_once("u-totp-1", secret, "000000") is False
    code = pyotp.TOTP(secret).now()
    assert await crypto.verify_totp_once("u-totp-1", secret, code) is True
    assert await crypto.verify_totp_once("u-totp-1", secret, code) is False


@pytest.mark.asyncio
async def test_recovery_codes():
    """Test one-time 2FA recovery code generation, storage, and consumption."""
    user_id = "test-user-uuid"
    gen_codes = crypto.generate_recovery_codes()
    assert len(gen_codes) == 8

    codes = ["CODE1", "CODE2", "CODE3"]
    await crypto.store_recovery_codes(user_id, codes)
    assert await crypto.get_remaining_recovery_count(user_id) == 3
    assert await crypto.check_recovery_code(user_id, "code1") is True
    assert await crypto.check_recovery_code(user_id, "") is False
    assert await crypto.check_recovery_code(user_id, "NONEXISTENT") is False

    assert await crypto.use_recovery_code(user_id, "code1") is True
    assert await crypto.get_remaining_recovery_count(user_id) == 2
    assert await crypto.use_recovery_code(user_id, "code1") is False
    assert await crypto.use_recovery_code(user_id, "INVALID") is False

    # Legacy unhashed entry compatibility branch
    from app.shared.utils.redis import get_redis
    from app.shared.utils.config import REDIS_DB_AUTH

    rd = get_redis(REDIS_DB_AUTH)
    await rd.sadd(f"{crypto._RECOVERY_KEY_PREFIX}:{user_id}", "LEGACYRAW")
    assert await crypto.use_recovery_code(user_id, "legacyraw") is True

    await crypto.delete_recovery_codes(user_id)
    assert await crypto.get_remaining_recovery_count(user_id) == 0


def test_cc_protection_state():
    """Test CC attack protection global state helpers."""
    assert crypto.get_cc_state() is False
    crypto.set_cc_state(True)
    assert crypto.get_cc_state() is True
    crypto.set_cc_state(False)

    assert isinstance(crypto.get_ip_failures_dict(), dict)
    assert hasattr(crypto.get_global_requests(), "append")
