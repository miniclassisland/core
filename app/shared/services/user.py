"""MINI ClassIsland shared user, account, and role management business logic service."""

import re
import secrets
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select, func, or_, update, delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.shared.db.models import (
    User,
    Account,
    AccountMember,
    AccountQuota,
    CustomRole,
    ReservedName,
    PreRegisteredClient,
    PairingCode,
    Invitation,
    ClientRecord,
    ClientProfile,
    ConfigUploadRecord,
    AuditLog,
    ResourceHistory,
    MODEL_MAP,
)
from app.shared.db.schema_init import seed_account_defaults
from app.shared.security.crypto import hash_password_async, verify_password_async
from app.shared.security.auth import create_session_token
from app.shared.literals import DEFAULT_QUOTAS, SLUG_RE, SYSTEM_ROLES, USERNAME_RE

# Regular expression validators
_USERNAME_RE = USERNAME_RE
_SLUG_RE = SLUG_RE
_ACCOUNT_ID_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_\-]{1,62}[a-zA-Z0-9]$")
_ACCOUNT_ID_RESERVED = {
    "list",
    "search",
    "apply",
    "availability",
    "create",
    "invitation",
    "bulk",
}

# Default account quotas
_DEFAULT_QUOTAS = DEFAULT_QUOTAS

# System roles preset data
_SYSTEM_ROLES = SYSTEM_ROLES


# ---- Format and Reserved Name Validation ----


def validate_username_format(name: str) -> bool:
    """Validate username format (3-64 lowercase alphanumeric characters and underscores)."""
    return bool(_USERNAME_RE.match(name))


def validate_slug_format(slug: str) -> bool:
    """Validate Slug format (3-64 lowercase alphanumeric characters and hyphens)."""
    return bool(_SLUG_RE.match(slug))


def validate_account_id_format(account_id: str) -> bool:
    """Validate Account ID format (3-64 alphanumeric characters, hyphens, and underscores)."""
    return (
        bool(_ACCOUNT_ID_RE.match(account_id))
        and account_id.lower() not in _ACCOUNT_ID_RESERVED
    )


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
    *,
    role_code: str = "pending",
    is_active: bool = False,
    can_create_account: bool = False,
    create_default_account: bool = False,
) -> User:
    """User registration flow: validate uniqueness -> Argon2id hash -> create User."""
    exists = await db.execute(select(User).where(User.email == email))
    if exists.scalar_one_or_none():
        raise ValueError("Email is already registered")

    if not username:
        username = f"user_{secrets.token_hex(4)}"
    else:
        username = username.strip().lower()
        if not validate_username_format(username):
            raise ValueError(
                "Username must be 3-64 lowercase alphanumeric characters and underscores"
            )
        if await is_name_reserved(username, db):
            raise ValueError("Username is reserved by system")
        dup_u = await db.execute(select(User).where(User.username == username))
        if dup_u.scalar_one_or_none():
            raise ValueError("Username already exists")

    user = User(
        id=str(uuid.uuid4()),
        username=username,
        email=email,
        hashed_password=await hash_password_async(password),
        display_name=display_name or username,
        role_code=role_code,
        is_active=is_active,
        can_create_account=can_create_account,
        created_at=datetime.now(timezone.utc),
    )
    db.add(user)
    if create_default_account:
        await _create_default_account(user, db)
    await db.commit()
    return user


async def login_user(
    email: str, password: str, db: AsyncSession
) -> tuple[Optional[str], User, bool]:
    """Verify user credentials and issue session token. Returns (token, user, requires_2fa)."""
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()

    if not user or not await verify_password_async(password, user.hashed_password):
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
    db: AsyncSession, *, offset: int = 0, limit: int = 20, search: str = ""
) -> tuple[list[User], int]:
    """Super admin query list of system users. Returns (users, total_count)."""
    stmt = select(User)
    count_stmt = select(func.count(User.id))
    if search:
        escaped = search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        pattern = f"%{escaped}%"
        cond = or_(
            User.username.ilike(pattern, escape="\\"),
            User.email.ilike(pattern, escape="\\"),
            User.display_name.ilike(pattern, escape="\\"),
        )
        stmt = stmt.where(cond)
        count_stmt = count_stmt.where(cond)

    total = await db.scalar(count_stmt)
    result = await db.execute(
        stmt.order_by(User.created_at.desc()).offset(offset).limit(limit)
    )
    return list(result.scalars().all()), total or 0


async def get_user_by_id(user_id: str, db: AsyncSession) -> Optional[User]:
    """Query user by ID."""
    result = await db.execute(select(User).where(User.id == user_id))
    return result.scalar_one_or_none()


async def update_user(user_id: str, db: AsyncSession, **fields) -> Optional[User]:
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


async def _create_default_account(user: User, db: AsyncSession) -> Account:
    """Automatically create default account space, quotas, and default resources for user."""
    now = datetime.now(timezone.utc)
    base_slug = user.username.replace("_", "-").lower()
    slug = base_slug if len(base_slug) >= 3 else f"org-{base_slug}"
    dup = (
        await db.execute(select(Account).where(Account.slug == slug))
    ).scalar_one_or_none()
    if dup:
        slug = f"{slug}-{secrets.token_hex(2)}"

    account = Account(
        id=str(uuid.uuid4()),
        name=f"{user.display_name or user.username}'s Account",
        slug=slug,
        api_key=secrets.token_urlsafe(32),
        is_active=True,
        registration_mode="open",
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

    await seed_account_defaults(account.id, db)
    return account


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
    else:
        slug = slug.strip().lower()
        if not validate_slug_format(slug):
            raise ValueError(
                "Slug format invalid (3-64 lowercase alphanumeric characters and hyphens)"
            )
        if await is_name_reserved(slug, db):
            raise ValueError("Slug is reserved by system")
        dup = await db.execute(select(Account).where(Account.slug == slug))
        if dup.scalar_one_or_none():
            raise ValueError("Slug is already taken")

    account = Account(
        id=str(uuid.uuid4()),
        name=name,
        slug=slug,
        api_key=secrets.token_urlsafe(32),
        is_active=True,
        registration_mode="open",
        created_at=now,
    )
    db.add(account)

    if user_id:
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

    await seed_account_defaults(account.id, db)
    await db.commit()
    return account


async def update_account_info(
    account_id: str,
    user_id: str,
    db: AsyncSession,
    *,
    new_id: Optional[str] = None,
    name: Optional[str] = None,
    slug: Optional[str] = None,
    is_active: Optional[bool] = None,
    registration_mode: Optional[str] = None,
) -> Optional[Account]:
    """Update account basic info (ID, name, slug, active state, registration mode)."""
    member = await db.execute(
        select(AccountMember).where(
            AccountMember.user_id == user_id,
            AccountMember.account_id == account_id,
        )
    )
    m = member.scalar_one_or_none()
    u = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    is_superadmin = bool(u and u.role_code == "superadmin")
    is_owner = is_superadmin or bool(m and m.role_in_account == "owner")
    if not is_owner and (not m or m.role_in_account != "admin"):
        raise PermissionError("Account owner or admin role required")

    acct = await db.execute(select(Account).where(Account.id == account_id))
    account = acct.scalar_one_or_none()
    if not account:
        return None

    old_id = account.id
    old_slug = account.slug

    if name is not None:
        cleaned_name = name.strip()
        if not cleaned_name:
            raise ValueError("Account name cannot be empty")
        account.name = cleaned_name

    if slug is not None and slug != account.slug:
        if not validate_slug_format(slug):
            raise ValueError(
                "Slug format invalid (3-64 lowercase alphanumeric characters and hyphens)"
            )
        if await is_name_reserved(slug, db):
            raise ValueError("Slug is reserved by system")
        dup = await db.execute(
            select(Account).where(Account.slug == slug, Account.id != old_id)
        )
        if dup.scalar_one_or_none():
            raise ValueError("Slug is already taken")
        account.slug = slug

    id_changed = False
    if new_id is not None:
        cleaned_id = new_id.strip()
        if cleaned_id != old_id:
            if not is_owner:
                raise PermissionError(
                    "Only account owner or Super Admin can change Account ID"
                )
            if not validate_account_id_format(cleaned_id):
                raise ValueError(
                    "Account ID format invalid (3-64 alphanumeric characters, hyphens, and underscores)"
                )
            if await is_name_reserved(cleaned_id, db):
                raise ValueError("Account ID is reserved by system")
            dup_id = await db.execute(select(Account).where(Account.id == cleaned_id))
            if dup_id.scalar_one_or_none():
                raise ValueError("Account ID is already taken")

            account.id = cleaned_id
            id_changed = True
            for tbl in (
                AccountMember,
                AccountQuota,
                PreRegisteredClient,
                Invitation,
                ClientRecord,
                ClientProfile,
                ConfigUploadRecord,
                AuditLog,
                ResourceHistory,
                *MODEL_MAP.values(),
            ):
                await db.execute(
                    update(tbl)
                    .where(tbl.account_id == old_id)
                    .values(account_id=cleaned_id)
                )
            await db.execute(
                update(PairingCode)
                .where(PairingCode.tenant_id == old_id)
                .values(tenant_id=cleaned_id)
            )

    if is_active is not None:
        if is_active is False and not is_owner:
            raise PermissionError(
                "Only account owner or Super Admin can deactivate account"
            )
        account.is_active = is_active

    if registration_mode is not None:
        if registration_mode not in ("open", "pairing", "pre_reg"):
            raise ValueError("Invalid registration mode")
        account.registration_mode = registration_mode

    await db.commit()
    from app.shared.utils.tenant import invalidate_cached_account

    await invalidate_cached_account(old_slug)
    await invalidate_cached_account(account.slug)
    if id_changed or is_active is False:
        await disconnect_account_clients(old_id, db)
    return account


async def disconnect_account_clients(account_id: str, db: AsyncSession) -> None:
    """Disconnect all active gRPC streams and clear Redis online state for an account."""
    from app.shared.runtime import get_command_servicer, get_session_manager

    servicer = get_command_servicer()
    sm = get_session_manager()
    uids: set[str] = set()
    rows = (
        (
            await db.execute(
                select(ClientRecord.uid).where(ClientRecord.account_id == account_id)
            )
        )
        .scalars()
        .all()
    )
    uids.update(rows)
    if sm:
        online = await sm.get_all_clients_status(account_id)
        for item in online:
            uids.add(item["uid"])
    for uid in uids:
        if servicer:
            await servicer.disconnect_client(account_id, uid)
        if sm:
            await sm.set_client_offline(account_id, uid)


async def cleanup_account_data(account_id: str, slug: str, db: AsyncSession) -> None:
    """Delete all associated tenant records, disconnect active clients, and invalidate cache."""
    from app.shared.utils.tenant import invalidate_cached_account

    await disconnect_account_clients(account_id, db)
    await invalidate_cached_account(slug)
    for tbl in (
        AccountMember,
        AccountQuota,
        PreRegisteredClient,
        Invitation,
        ClientRecord,
        ClientProfile,
        ConfigUploadRecord,
        AuditLog,
        ResourceHistory,
        *MODEL_MAP.values(),
    ):
        await db.execute(delete(tbl).where(tbl.account_id == account_id))
    await db.execute(delete(PairingCode).where(PairingCode.tenant_id == account_id))


async def update_account_slug(
    account_id: str, new_slug: str, user_id: str, db: AsyncSession
) -> Optional[Account]:
    """Update tenant slug (requires owner or admin role)."""
    return await update_account_info(account_id, user_id, db, slug=new_slug)


# ---- Role Configuration ----


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
