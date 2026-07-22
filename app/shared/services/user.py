"""MINIClassIsland shared user, account, and role management business logic service.
"""

import re
import secrets
import uuid
from datetime import datetime, timezone
from typing import Optional, Tuple

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

# Regular expression validators
_USERNAME_RE = re.compile(r"^[a-z0-9_]{3,64}$")
_SLUG_RE = re.compile(r"^[a-z0-9\-]{3,64}$")

# Default account quotas
_DEFAULT_QUOTAS = [
    ("max_clients", 50),
    ("max_bandwidth_mb", 1024),
    ("feature.ota", 1),
    ("feature.audit", 1),
]

# System roles preset data
_SYSTEM_ROLES = [
    ("banned", "Banned", -1),
    ("pending", "Pending Activation", 0),
    ("normal", "Normal User", 10),
    ("admin", "Administrator", 90),
    ("superadmin", "Super Administrator", 100),
]


# ---- Format and Reserved Name Validation ----

def validate_username_format(name: str) -> bool:
    """Validate username format (3-64 lowercase alphanumeric characters and underscores)."""
    return bool(_USERNAME_RE.match(name))


def validate_slug_format(slug: str) -> bool:
    """Validate Slug format (3-64 lowercase alphanumeric characters and hyphens)."""
    return bool(_SLUG_RE.match(slug))


async def is_name_reserved(name: str, db: AsyncSession) -> bool:
    """Check if specified name is reserved by system."""
    result = await db.execute(
        select(ReservedName).where(func.lower(ReservedName.name) == name.lower())
    )
    return result.scalar_one_or_none() is not None


# ---- User Registration and Login ----

async def register_user(
    email: str,
    password: str,
    display_name: str,
    db: AsyncSession,
    username: Optional[str] = None,
) -> User:
    """User self-registration flow: validate email uniqueness -> Hashing -> create User in Pending status."""
    exists = await db.execute(select(User).where(User.email == email))
    if exists.scalar_one_or_none():
        raise ValueError("Email is already registered")

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
    """Verify user credentials and issue session token. Returns (token, user, requires_2fa)."""
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()

    if not user or not verify_password(password, user.hashed_password):
        raise ValueError("Incorrect email or password")

    if user.role_code == "banned":
        raise ValueError("Account has been banned")
    if user.role_code == "pending":
        raise ValueError("Account is not active yet")
    if not user.is_active:
        raise ValueError("Account has been deactivated")

    if user.totp_enabled:
        return None, user, True

    token = await create_session_token(user.id)
    return token, user, False


# ---- User Management and Approval ----

async def list_users(
    db: AsyncSession, *, offset: int = 0, limit: int = 20
) -> tuple[list[User], int]:
    """Super admin query list of system users. Returns (users, total_count)."""
    total = await db.scalar(select(func.count(User.id)))
    result = await db.execute(select(User).offset(offset).limit(limit))
    return list(result.scalars().all()), total or 0


async def get_user_by_id(user_id: str, db: AsyncSession) -> Optional[User]:
    """Query user by ID."""
    result = await db.execute(select(User).where(User.id == user_id))
    return result.scalar_one_or_none()


async def update_user(
    user_id: str, db: AsyncSession, **fields
) -> Optional[User]:
    """Update user profile fields."""
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
    """Get all users awaiting approval/activation."""
    result = await db.execute(
        select(User).where(User.role_code == "pending").offset(offset).limit(limit)
    )
    return list(result.scalars().all())


async def reject_user(user_id: str, db: AsyncSession) -> bool:
    """Reject user registration request and delete record."""
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
    """Automatically create default account space and quotas for user upon approval."""
    now = datetime.now(timezone.utc)
    slug = user.username.replace("_", "-")
    account = Account(
        id=str(uuid.uuid4()),
        name=f"{user.display_name}'s Account",
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
    """Approve pending user registration and create default account space."""
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


# ---- Account Creation and Slug Management ----

async def create_account(
    name: str, user_id: str, db: AsyncSession, slug: Optional[str] = None
) -> Account:
    """Manually create tenant account space and bind current user as Owner."""
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
    """Update tenant slug (requires owner or admin role)."""
    if not validate_slug_format(new_slug):
        raise ValueError("Slug format invalid (3-64 lowercase alphanumeric characters and hyphens)")

    dup = await db.execute(
        select(Account).where(Account.slug == new_slug, Account.id != account_id)
    )
    if dup.scalar_one_or_none():
        raise ValueError("Slug is already taken")

    member = await db.execute(
        select(AccountMember).where(
            AccountMember.user_id == user_id,
            AccountMember.account_id == account_id,
        )
    )
    m = member.scalar_one_or_none()
    if not m or m.role_in_account not in ("owner", "admin"):
        raise PermissionError("Account owner or admin role required")

    acct = await db.execute(select(Account).where(Account.id == account_id))
    account = acct.scalar_one_or_none()
    if not account:
        return None

    account.slug = new_slug
    await db.commit()
    return account


# ---- Role and Permission Configuration ----

async def ensure_system_roles(db: AsyncSession) -> None:
    """Initialize and ensure built-in system roles exist."""
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
    """Get list of all roles sorted by priority descending."""
    result = await db.execute(select(CustomRole).order_by(CustomRole.priority.desc()))
    return list(result.scalars().all())


async def create_role(
    code: str, label: str, priority: int, db: AsyncSession
) -> CustomRole:
    """Create custom role definition."""
    role = CustomRole(code=code, label=label, priority=priority, is_system=False)
    db.add(role)
    await db.commit()
    return role


async def delete_role(code: str, db: AsyncSession) -> Optional[str]:
    """Delete non-system custom role definition."""
    result = await db.execute(select(CustomRole).where(CustomRole.code == code))
    role = result.scalar_one_or_none()
    if not role:
        return "Role not found"
    if role.is_system:
        return "System role cannot be deleted"
    await db.delete(role)
    await db.commit()
    return None
