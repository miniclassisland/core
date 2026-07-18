"""test_schemas.py
"""

from app.shared.schemas import schemas


def test_pydantic_schemas_instantiation():
    """验证所有 Pydantic 校验模型均能被正确实例化和序列化。"""
    # User schemas
    u_register = schemas.UserRegisterRequest(
        username="teacher1",
        email="teacher1@school.com",
        password="PassWord123!",
        display_name="Teacher One",
    )
    assert u_register.username == "teacher1"

    u_login = schemas.UserLoginRequest(email="teacher1@school.com", password="PassWord123!")
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

    # CustomRole schemas
    cr_create = schemas.RoleCreateRequest(
        role_code="editor", role_name="Editor", permissions=["edit", "view"]
    )
    assert cr_create.role_code == "editor"

    # Account schemas
    acc_create = schemas.AccountCreate(
        name="Test School", slug="test-school"
    )
    assert acc_create.slug == "test-school"

    # TOTP schemas
    totp_verify = schemas.TotpVerifyRequest(temp_token="temp-token-123", code="123456")
    assert totp_verify.code == "123456"

    # Batch operation schemas
    bo = schemas.BatchOperation(
        action="create",
        resource_type="ClassPlan",
        name="plan1",
        payload={"content": "data"},
    )
    bo_req = schemas.BatchRequest(operations=[bo])
    assert len(bo_req.operations) == 1
