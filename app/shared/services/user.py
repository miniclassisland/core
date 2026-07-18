"""MINIClassIsland 用户、账户及角色管理共享业务逻辑服务。

本文件整合了用户注册、登录、审核审批、账户创建/修改、以及自定义角色的全部共享业务流程，避免了 legacy 中零散的 12 个小文件。
"""

import re
import secrets
import uuid
from datetime import datetime, timezone
from typing import Optional, tuple

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.shared.db.models import (
    User,
    Account,
    AccountMember,
    AccountQuota,
    CustomRole,
    ReservedName,
)
from app.shared.security.crypto import hash_password, verify_password
from app.shared.security.auth import create_session_token

# 正则表达式校验器
_USERNAME_RE = re.compile(r"^[a-z0-9_]{3,64}$")
_SLUG_RE = re.compile(r"^[a-z0-9\-]{3,64}$")

# 默认账户配额限制项
_DEFAULT_QUOTAS = [
    ("max_clients", 50),
    ("max_bandwidth_mb", 1024),
    ("feature.ota", 1),
    ("feature.audit", 1),
]

# 系统内置角色预置数据
_SYSTEM_ROLES = [
    ("banned", "已封禁", -1),
    ("pending", "待激活", 0),
    ("normal", "普通用户", 10),
    ("admin", "管理员", 90),
    ("superadmin", "超级管理员", 100),
]


# ---- 格式与保留名校验 ----

def validate_username_format(name: str) -> bool:
    """校验用户名格式是否合法 (3~64 位小写字母数字下划线)。"""
    return bool(_USERNAME_RE.match(name))


def validate_slug_format(slug: str) -> bool:
    """校验 Slug 格式是否合法 (3~64 位小写字母数字连字符)。"""
    return bool(_SLUG_RE.match(slug))


async def is_name_reserved(name: str, db: AsyncSession) -> bool:
    """检查指定的名称是否已被系统预留。"""
    result = await db.execute(
        select(ReservedName).where(func.lower(ReservedName.name) == name.lower())
    )
    return result.scalar_one_or_none() is not None


# ---- 用户注册与登录 ----

async def register_user(
    email: str,
    password: str,
    display_name: str,
    db: AsyncSession,
    username: Optional[str] = None,
) -> User:
    """用户自主注册流程：校验邮箱唯一性 -> Hashing -> 创建 Pending 状态的用户。"""
    exists = await db.execute(select(User).where(User.email == email))
    if exists.scalar_one_or_none():
        raise ValueError("该邮箱已被注册")

    if not username:
        username = f"user_{secrets.token_hex(4)}"

    user = User(
        id=str(uuid.uuid4()),
        username=username,
        email=email,
        hashed_password=hash_password(password),
        display_name=display_name or username,
        role_code="pending",
        is_active=False,
        can_create_account=False,
        created_at=datetime.now(timezone.utc),
    )
    db.add(user)
    await db.commit()
    return user


async def login_user(
    email: str, password: str, db: AsyncSession
) -> tuple[Optional[str], User, bool]:
    """验证用户凭据并签发 Session 令牌。返回 (令牌, 用户, 是否需要2FA)。"""
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()

    if not user or not verify_password(password, user.hashed_password):
        raise ValueError("邮箱或密码错误")

    if user.role_code == "banned":
        raise ValueError("该账户已被封禁")
    if user.role_code == "pending":
        raise ValueError("该账户尚未激活")
    if not user.is_active:
        raise ValueError("该账户已被停用")

    if user.totp_enabled:
        return None, user, True

    token = await create_session_token(user.id)
    return token, user, False


# ---- 用户管理与审批 ----

async def list_users(
    db: AsyncSession, *, offset: int = 0, limit: int = 20
) -> tuple[list[User], int]:
    """超级管理员分页查询系统用户列表。返回 (用户列表, 总条数)。"""
    total = await db.scalar(select(func.count(User.id)))
    result = await db.execute(select(User).offset(offset).limit(limit))
    return list(result.scalars().all()), total or 0


async def get_user_by_id(user_id: str, db: AsyncSession) -> Optional[User]:
    """通过主键 ID 查询具体用户。"""
    result = await db.execute(select(User).where(User.id == user_id))
    return result.scalar_one_or_none()


async def update_user(
    user_id: str, db: AsyncSession, **fields
) -> Optional[User]:
    """更新用户的具体信息属性。"""
    user = await get_user_by_id(user_id, db)
    if not user:
        return None
    for key, val in fields.items():
        if hasattr(user, key) and val is not None:
            setattr(user, key, val)
    await db.commit()
    return user


async def list_pending_users(
    db: AsyncSession, *, offset: int = 0, limit: int = 50
) -> list[User]:
    """获取所有待审批/待激活的用户。"""
    result = await db.execute(
        select(User).where(User.role_code == "pending").offset(offset).limit(limit)
    )
    return list(result.scalars().all())


async def reject_user(user_id: str, db: AsyncSession) -> bool:
    """拒绝用户注册请求并将其删除。"""
    result = await db.execute(
        select(User).where(User.id == user_id, User.role_code == "pending")
    )
    user = result.scalar_one_or_none()
    if not user:
        return False
    await db.delete(user)
    await db.commit()
    return True


async def _create_default_account(user: User, db: AsyncSession) -> None:
    """审批通过后自动为该用户创建默认同名账户空间及配额。"""
    now = datetime.now(timezone.utc)
    slug = user.username.replace("_", "-")
    account = Account(
        id=str(uuid.uuid4()),
        name=f"{user.display_name} 的账户",
        slug=slug,
        api_key=secrets.token_urlsafe(32),
        is_active=True,
        created_at=now,
    )
    db.add(account)

    member = AccountMember(
        id=str(uuid.uuid4()),
        user_id=user.id,
        account_id=account.id,
        role_in_account="owner",
        joined_at=now,
    )
    db.add(member)

    for key, val in _DEFAULT_QUOTAS:
        db.add(
            AccountQuota(
                id=str(uuid.uuid4()),
                account_id=account.id,
                quota_key=key,
                max_value=val,
            )
        )


async def approve_user(
    user_id: str, db: AsyncSession, *, can_create_account: bool = False
) -> Optional[User]:
    """激活待注册的用户，为其创建默认个人商户空间。"""
    result = await db.execute(
        select(User).where(User.id == user_id, User.role_code == "pending")
    )
    user = result.scalar_one_or_none()
    if not user:
        return None

    user.role_code = "normal"
    user.is_active = True
    user.can_create_account = can_create_account

    await _create_default_account(user, db)
    await db.commit()
    return user


# ---- 账户/租户创建与 Slug 管理 ----

async def create_account(
    name: str, user_id: str, db: AsyncSession, slug: Optional[str] = None
) -> Account:
    """手动创建商户账户空间，并与当前用户绑定 Owner 关系。"""
    now = datetime.now(timezone.utc)
    if not slug:
        slug = f"org-{secrets.token_hex(4)}"

    account = Account(
        id=str(uuid.uuid4()),
        name=name,
        slug=slug,
        api_key=secrets.token_urlsafe(32),
        is_active=True,
        created_at=now,
    )
    db.add(account)

    db.add(
        AccountMember(
            id=str(uuid.uuid4()),
            user_id=user_id,
            account_id=account.id,
            role_in_account="owner",
            joined_at=now,
        )
    )

    for key, val in _DEFAULT_QUOTAS:
        db.add(
            AccountQuota(
                id=str(uuid.uuid4()),
                account_id=account.id,
                quota_key=key,
                max_value=val,
            )
        )

    await db.commit()
    return account


async def update_account_slug(
    account_id: str, new_slug: str, user_id: str, db: AsyncSession
) -> Optional[Account]:
    """更新租户标识 Slug（需 owner 或 admin 权限）。"""
    if not validate_slug_format(new_slug):
        raise ValueError("Slug 格式不合法（3~64位小写字母数字连字符）")

    dup = await db.execute(
        select(Account).where(Account.slug == new_slug, Account.id != account_id)
    )
    if dup.scalar_one_or_none():
        raise ValueError("该 Slug 已被占用")

    member = await db.execute(
        select(AccountMember).where(
            AccountMember.user_id == user_id,
            AccountMember.account_id == account_id,
        )
    )
    m = member.scalar_one_or_none()
    if not m or m.role_in_account not in ("owner", "admin"):
        raise PermissionError("需要账户 owner 或 admin 角色")

    acct = await db.execute(select(Account).where(Account.id == account_id))
    account = acct.scalar_one_or_none()
    if not account:
        return None

    account.slug = new_slug
    await db.commit()
    return account


# ---- 角色权限配置 ----

async def ensure_system_roles(db: AsyncSession) -> None:
    """初始化并确保内置系统角色存在。"""
    for code, label, priority in _SYSTEM_ROLES:
        exists = await db.execute(select(CustomRole).where(CustomRole.code == code))
        if exists.scalar_one_or_none():
            continue
        db.add(
            CustomRole(
                code=code,
                label=label,
                priority=priority,
                is_system=True,
            )
        )
    await db.commit()


async def list_roles(db: AsyncSession) -> list[CustomRole]:
    """获取所有角色层级列表，按优先级降序排列。"""
    result = await db.execute(select(CustomRole).order_by(CustomRole.priority.desc()))
    return list(result.scalars().all())


async def create_role(
    code: str, label: str, priority: int, db: AsyncSession
) -> CustomRole:
    """创建自定义角色定义。"""
    role = CustomRole(code=code, label=label, priority=priority, is_system=False)
    db.add(role)
    await db.commit()
    return role


async def delete_role(code: str, db: AsyncSession) -> Optional[str]:
    """删除非内置的自定义角色定义。"""
    result = await db.execute(select(CustomRole).where(CustomRole.code == code))
    role = result.scalar_one_or_none()
    if not role:
        return "角色不存在"
    if role.is_system:
        return "系统内置角色不可删除"
    await db.delete(role)
    await db.commit()
    return None
