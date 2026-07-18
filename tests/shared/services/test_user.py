"""test_user.py
"""

import pytest
from app.shared.services import user as user_service
from app.shared.db.session import AsyncSessionLocal
from app.shared.db.models import ReservedName, User, Account


@pytest.mark.asyncio
async def test_slug_and_name_reservations():
    """测试保留 Slug 与保留账户名拦截。"""
    assert user_service.validate_slug_format("my-school") is True
    assert user_service.validate_slug_format("INVALID_SLUG_FORMAT") is False

    assert user_service.validate_username_format("teacher_1") is True
    assert user_service.validate_username_format("INVALID USERNAME") is False

    async with AsyncSessionLocal() as db:
        # 手动插入一个预留词并测试
        db.add(ReservedName(name="reserved_word"))
        await db.commit()

        assert await user_service.is_name_reserved("reserved_word", db) is True
        assert await user_service.is_name_reserved("normal_word", db) is False


@pytest.mark.asyncio
async def test_roles_initialization():
    """测试默认系统角色的初始化。"""
    async with AsyncSessionLocal() as db:
        await user_service.ensure_system_roles(db)
        # 多次调用应当幂等安全
        await user_service.ensure_system_roles(db)


@pytest.mark.asyncio
async def test_user_and_account_services():
    """测试商户账户创建、管理员注册、登录及审批等完整服务生命周期。"""
    async with AsyncSessionLocal() as db:
        # 1. 注册主用户
        owner = await user_service.register_user(
            email="alpha@school.com",
            password="AlphaAdmin123!",
            display_name="Alpha 管理员",
            db=db,
            username="alpha_admin",
        )
        assert owner.username == "alpha_admin"
        assert owner.role_code == "pending"

        # 尝试使用重复邮箱注册应当失败
        with pytest.raises(Exception):
            await user_service.register_user(
                email="alpha@school.com",
                password="AnotherPassword1!",
                display_name="Duplicate",
                db=db,
            )

        # 2. 正常注册另一个新用户，等待审批
        new_user = await user_service.register_user(
            email="beta@school.com",
            password="BetaPassword123!",
            display_name="Beta 教师",
            db=db,
            username="beta_teacher",
        )
        assert new_user.username == "beta_teacher"
        assert new_user.is_active is False  # 待审核

        # 3. 登录测试
        # 尝试登录未审批通过的账户，应当报错（例如由于角色待审核）
        with pytest.raises(ValueError, match="该账户尚未通过审核"):
            await user_service.login_user("beta@school.com", "BetaPassword123!", db)

        # 登录一个完全不存在的用户
        with pytest.raises(ValueError, match="邮箱或密码错误"):
            await user_service.login_user("non_existent@school.com", "password", db)

        # 4. 管理端审批流测试
        # 获取待审批列表
        pending = await user_service.list_pending_users(db)
        assert any(p.username == "beta_teacher" for p in pending)

        # 进行审批通过
        approved_user = await user_service.approve_user(new_user.id, db)
        assert approved_user is not None
        assert approved_user.is_active is True

        # 对不存在的用户进行审批，应返回 None
        assert await user_service.approve_user("invalid-uuid", db) is None

        # 5. 测试拒绝/删除逻辑
        # 注册一个临时用户并拒绝
        temp_user = await user_service.register_user(
            email="temp@school.com",
            password="TempPassword123!",
            display_name="Temp User",
            db=db,
            username="temp_user",
        )
        assert await user_service.reject_user(temp_user.id, db) is True
        assert await user_service.reject_user("invalid-uuid", db) is False

        # 6. 成功登录通过审核的用户
        token, logged_in, need_2fa = await user_service.login_user("beta@school.com", "BetaPassword123!", db)
        assert logged_in.id == new_user.id
        assert token is not None

        # 7. 创建商户账户
        acc = await user_service.create_account(
            name="Alpha School",
            user_id=owner.id,
            db=db,
            slug="alpha-school",
        )
        assert acc.slug == "alpha-school"

        # 8. 查询与分页测试
        users_list, total_users = await user_service.list_users(db, offset=0, limit=10)
        assert len(users_list) >= 2

        # 9. 修改 Slug 测试
        # 以 owner 身份修改，应当成功
        await user_service.update_account_slug(acc.id, "alpha-school-new", owner.id, db)
        acc_updated = await db.get(Account, acc.id)
        assert acc_updated.slug == "alpha-school-new"

        # 使用非 owner/admin 用户修改应当抛出权限错误
        with pytest.raises(PermissionError):
            await user_service.update_account_slug(acc.id, "alpha-school-fail", new_user.id, db)
