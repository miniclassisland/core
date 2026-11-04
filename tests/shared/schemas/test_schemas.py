"""test_schemas.py"""

import pytest
from pydantic import ValidationError
from app.shared.schemas import schemas


def test_pydantic_schemas_instantiation():
    """验证所有 Pydantic 校验模型均能被正确实例化和序列化。"""
    u_register = schemas.UserRegisterRequest(
        username="teacher1",
        email="teacher1@school.com",
        password="PassWord123!",
        display_name="Teacher One",
    )
    assert u_register.username == "teacher1"

    with pytest.raises(ValidationError):
        schemas.UserRegisterRequest(
            username="teacher1",
            email="teacher1@school.com",
            password="lowercase123!",
            display_name="T",
        )
    with pytest.raises(ValidationError):
        schemas.UserRegisterRequest(
            username="teacher1",
            email="teacher1@school.com",
            password="UPPERCASE123!",
            display_name="T",
        )
    with pytest.raises(ValidationError):
        schemas.UserRegisterRequest(
            username="teacher1",
            email="teacher1@school.com",
            password="NoDigitsHere!",
            display_name="T",
        )
    with pytest.raises(ValidationError):
        schemas.UserRegisterRequest(
            username="bad user!",
            email="teacher1@school.com",
            password="PassWord123!",
            display_name="T",
        )

    u_login = schemas.UserLoginRequest(
        email="teacher1@school.com", password="PassWord123!"
    )
    assert u_login.email == "teacher1@school.com"

    u_resp = schemas.UserOut(
        id="user-uuid-12345",
        username="teacher1",
        email="teacher1@school.com",
        display_name="Teacher One",
        role_code="member",
        is_active=True,
        can_create_account=True,
        created_at="2026-03-25T08:00:00Z",
    )
    assert u_resp.role_code == "member"

    acc_create = schemas.AccountCreate(name="Test School", slug="test-school")
    assert acc_create.slug == "test-school"
    with pytest.raises(ValidationError):
        schemas.AccountCreate(name="Bad", slug="BAD_SLUG!")

    acc_update = schemas.AccountUpdate(slug="valid-slug")
    assert acc_update.slug == "valid-slug"
    acc_update_none = schemas.AccountUpdate(slug=None)
    assert acc_update_none.slug is None
    with pytest.raises(ValidationError):
        schemas.AccountUpdate(slug="BAD_SLUG!")

    settings_upd = schemas.SettingsUpdate(
        items={"registration_open": "true", "motd": "Welcome"}
    )
    assert settings_upd.items["registration_open"] == "true"
    with pytest.raises(ValidationError):
        schemas.SettingsUpdate(items={"illegal_key": "val"})

    totp_verify = schemas.TotpVerifyRequest(temp_token="temp-token-123", code="123456")
    assert totp_verify.code == "123456"

    bo = schemas.BatchOperation(
        action=schemas.BatchOpType.create,
        resource_type="ClassPlan",
        name="plan1",
        payload={"content": "data"},
    )
    bo_req = schemas.BatchRequest(operations=[bo])
    assert len(bo_req.operations) == 1
