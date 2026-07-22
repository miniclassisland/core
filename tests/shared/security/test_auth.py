"""test_auth.py
"""

import pytest
from fastapi import HTTPException, Request
from unittest.mock import MagicMock
from app.shared.security import auth
from app.shared.db.session import AsyncSessionLocal
from app.shared.db.models import CustomRole, User, AccountMember
from app.shared.services.user import ensure_system_roles
from app.shared.utils.tenant import tenant_ctx


@pytest.mark.asyncio
async def test_api_token_lifecycle():
    """测试 API 访问令牌的生成、校验与注销。"""
    tenant_id = "test-account-00000000"
    
    # 1. 生成令牌
    token = await auth.generate_token(scope="command", tenant_id=tenant_id, ttl=300)
    assert token is not None

    # 2. 校验与刷新令牌
    res = await auth.validate_and_refresh(token, tenant_id=tenant_id)
    assert res is not None
    scope, tid = res
    assert scope == "command"
    assert tid == tenant_id

    # 3. 校验不存在的令牌
    assert await auth.validate_and_refresh("invalid-token", tenant_id=tenant_id) is None

    # 4. 注销令牌
    assert await auth.revoke_token(token, tenant_id=tenant_id) is True
    # 重复注销返回 False
    assert await auth.revoke_token(token, tenant_id=tenant_id) is False

    # 5. 校验已注销的令牌（过宽限期或标记软删除）
    # 软删除标记后，validate_and_refresh 应当返回 None
    assert await auth.validate_and_refresh(token, tenant_id=tenant_id) is None


@pytest.mark.asyncio
async def test_session_token_lifecycle():
    """测试会话令牌的创建、解析与销毁。"""
    user_id = "test-user-id"
    
    # 1. 创建会话令牌
    sid = await auth.create_session_token(user_id, ttl=3600)
    assert sid is not None

    # 2. 解析会话令牌
    uid = await auth.resolve_user_from_token(sid)
    assert uid == user_id

    # 3. 解析不存在的令牌
    assert await auth.resolve_user_from_token("invalid-sid") is None


@pytest.mark.asyncio
async def test_get_current_user_dependency(test_superadmin_user):
    """测试 get_current_user 依赖注入。"""
    request = MagicMock(spec=Request)
    request.state = MagicMock()
    
    # 1. 未认证时抛出 401
    request.state.current_user_id = None
    async with AsyncSessionLocal() as db:
        with pytest.raises(HTTPException) as exc:
            await auth.get_current_user(request, db)
        assert exc.value.status_code == 401

    # 2. 已认证但用户不存在于数据库时抛出 401
    request.state.current_user_id = "non-existent-user-id"
    async with AsyncSessionLocal() as db:
        with pytest.raises(HTTPException) as exc:
            await auth.get_current_user(request, db)
        assert exc.value.status_code == 401

    # 3. 正常认证成功
    request.state.current_user_id = test_superadmin_user
    async with AsyncSessionLocal() as db:
        user = await auth.get_current_user(request, db)
        assert user is not None
        assert user.id == test_superadmin_user


@pytest.mark.asyncio
async def test_rbac_dependencies(test_superadmin_user):
    """测试 require_role 与 require_permission 权限拦截器。"""
    async with AsyncSessionLocal() as db:
        # 初始化默认系统角色
        await ensure_system_roles(db)

        # 获取超级管理员用户实体
        superadmin = await db.get(User, test_superadmin_user)
        assert superadmin is not None

        # 1. 验证 require_role 成功 (superadmin 优先级通常为 100)
        role_check = auth.require_role(50)
        res_user = await role_check(superadmin, db)
        assert res_user == superadmin

        # 2. 验证 require_role 失败
        role_check_high = auth.require_role(101)
        with pytest.raises(HTTPException) as exc:
            await role_check_high(superadmin, db)
        assert exc.value.status_code == 403

        # 3. 验证 require_permission (针对 owner 的全局权限 '*')
        request = MagicMock(spec=Request)
        request.state = MagicMock()
        request.state.current_user_id = test_superadmin_user

        # 绑定租户 ID
        tenant_id = "test-account-00000000"
        token = tenant_ctx.set(tenant_id)
        try:
            # 建立商户成员 owner 关系
            from datetime import datetime, timezone
            from sqlalchemy import select
            existing_member = (await db.execute(select(AccountMember).where(AccountMember.user_id == test_superadmin_user, AccountMember.account_id == tenant_id))).scalar_one_or_none()
            if not existing_member:
                db.add(
                    AccountMember(
                        user_id=test_superadmin_user,
                        account_id=tenant_id,
                        role_in_account="owner",
                        joined_at=datetime.now(timezone.utc),
                    )
                )
                await db.commit()

            perm_check = auth.require_permission("any_action")
            user_id_res = await perm_check(request)
            assert user_id_res == test_superadmin_user
        finally:
            tenant_ctx.reset(token)
