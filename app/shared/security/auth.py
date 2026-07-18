"""MINIClassIsland 身份认证与权限依赖项。

提供基于 Redis 会话与 API 令牌的认证与验证，以及基于角色 (RBAC) 权限制约的 FastAPI 依赖注入项。
"""

import logging
import secrets
from typing import Optional

from fastapi import Depends, Request, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.shared.utils.config import REDIS_DB_AUTH
from app.shared.utils.redis import get_redis
from app.shared.utils.tenant import get_tenant_id, set_search_path
from app.shared.db.session import get_db, AsyncSessionLocal
from app.shared.db.models import (
    User,
    CustomRole,
    AccountMember,
    RolePermission,
    MemberPermission,
)

logger = logging.getLogger(__name__)

# 安全令牌参数
_TOKEN_BYTES = 192
_DEFAULT_TTL = 300
_GRACE_TTL = 30


# ---- 认证令牌 (API Token) 生命周期管理 ----

def _token_redis_key(tenant_id: str, token: str) -> str:
    """构造租户隔离的 Redis Token 键名。"""
    return f"auth:{tenant_id}:{token}" if tenant_id else f"auth::{token}"


async def generate_token(
    scope: str, tenant_id: str = "", *, ttl: int = _DEFAULT_TTL
) -> str:
    """在 Redis 中生成一个加密安全的单次或持久 API 访问令牌。"""
    rd = get_redis(REDIS_DB_AUTH)
    token = secrets.token_urlsafe(_TOKEN_BYTES)
    key = _token_redis_key(tenant_id, token)

    await rd.hset(key, mapping={"scope": scope, "tenant_id": tenant_id})
    await rd.expire(key, ttl)

    logger.info("Token [%s] 已为租户 [%s] 生成", scope, tenant_id or "global")
    return token


async def validate_and_refresh(
    token: str, *, tenant_id: str = "", ttl: int = _DEFAULT_TTL
) -> Optional[tuple[str, str]]:
    """校验令牌的有效性，若有效则刷新其过期生存期。"""
    rd = get_redis(REDIS_DB_AUTH)
    key = _token_redis_key(tenant_id, token)
    data = await rd.hgetall(key)

    if not data or data.get("refreshed") == "1":
        return None

    # 自动续期
    await rd.expire(key, ttl)
    return data.get("scope"), data.get("tenant_id", "")


async def revoke_token(token: str, *, tenant_id: str = "") -> bool:
    """注销/注销 API 访问令牌，提供一定的安全宽限时间防刷新碰撞。"""
    if not token:
        return False

    rd = get_redis(REDIS_DB_AUTH)
    key = _token_redis_key(tenant_id, token)
    exists = await rd.exists(key)
    if not exists:
        return False

    # 标记软删除，并设置宽限期
    await rd.hset(key, "refreshed", "1")
    await rd.expire(key, _GRACE_TTL)
    return True


# ---- 会话认证依赖注入项 (HTTP Session) ----

async def resolve_user_from_token(token: str) -> Optional[str]:
    """从 Redis 用户会话会话中提取关联的 User ID。"""
    rd = get_redis(REDIS_DB_AUTH)
    data = await rd.hgetall(f"session:{token}")
    return data.get("user_id") if data else None


async def get_current_user_id(request: Request) -> str:
    """FastAPI 依赖注入：轻量获取当前已认证用户的 ID。"""
    uid = getattr(request.state, "current_user_id", None)
    if not uid:
        raise HTTPException(status_code=401, detail="未认证")
    return uid


async def get_current_user(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> User:
    """FastAPI 依赖注入：从数据库查询完整的当前登录用户信息。"""
    user_id = await get_current_user_id(request)
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=401, detail="用户不存在")
    return user


# ---- 角色与权限 RBAC 限制器 ----

def require_role(min_priority: int):
    """验证用户角色等级是否大于等于指定优先级。"""

    async def _check(
        user: User = Depends(get_current_user),
        db: AsyncSession = Depends(get_db),
    ) -> User:
        result = await db.execute(
            select(CustomRole).where(CustomRole.code == user.role_code)
        )
        role = result.scalar_one_or_none()
        priority = role.priority if role else 0
        if priority < min_priority:
            raise HTTPException(status_code=403, detail="权限不足")
        return user

    return _check


async def _get_member_permissions(user_id: str, account_id: str) -> set[str]:
    """计算用户在特定账户下的全部叶子节点原子权限标识符。"""
    async with AsyncSessionLocal() as db:
        await set_search_path(db)
        # 查询租户关系
        stmt = (
            select(AccountMember)
            .where(AccountMember.user_id == user_id)
            .where(AccountMember.account_id == account_id)
        )
        member = (await db.execute(stmt)).scalar_one_or_none()
        if not member:
            return set()

        # 所有者拥有全局权限
        if member.role_in_account == "owner":
            return {"*"}

        # 累计角色自带权限
        role_perms_stmt = select(RolePermission.permission_code).where(
            RolePermission.role_code == member.role_in_account
        )
        role_perms = set((await db.execute(role_perms_stmt)).scalars().all())

        # 覆盖具体成员特权设置
        member_overrides_stmt = select(MemberPermission).where(
            MemberPermission.member_id == member.id
        )
        overrides = (await db.execute(member_overrides_stmt)).scalars().all()
        for ov in overrides:
            if ov.granted:
                role_perms.add(ov.permission_code)
            else:
                role_perms.discard(ov.permission_code)

        return role_perms


def require_permission(*perms: str):
    """FastAPI 依赖注入：检查用户在当前租户域下是否拥有全部所需操作权限。"""

    async def _checker(request: Request):
        user_id = await get_current_user_id(request)
        account_id = get_tenant_id()
        if not account_id:
            raise HTTPException(status_code=403, detail="租户上下文缺失")

        granted = await _get_member_permissions(user_id, account_id)
        if "*" in granted:
            return user_id

        for p in perms:
            if p not in granted:
                logger.warning("权限校验失败: user=%s 缺少 perm=%s", user_id, p)
                raise HTTPException(status_code=403, detail=f"缺少权限: {p}")
        return user_id

    return _checker
