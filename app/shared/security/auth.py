"""MINIClassIsland authentication and security dependencies.

Provides authentication and authorization via Redis sessions and API tokens, as well as RBAC-based FastAPI dependencies.
"""

import logging
import secrets
from typing import Optional

from fastapi import Depends, Request, HTTPException, status
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
from app.shared.literals import (
    DEFAULT_TTL,
    GRACE_TTL,
    MSG_PERMISSION_DENIED,
    MSG_UNAUTHORIZED_ACCESS,
    MSG_USER_NOT_FOUND,
    REDIS_AUTH_PREFIX,
    TOKEN_BYTES,
)

logger = logging.getLogger(__name__)

# Security token parameters
_TOKEN_BYTES = TOKEN_BYTES
_DEFAULT_TTL = DEFAULT_TTL
_GRACE_TTL = GRACE_TTL


# ---- API Token Lifecycle Management ----

def _token_redis_key(tenant_id: str, token: str) -> str:
    """Construct tenant-isolated Redis token key."""
    return f"{REDIS_AUTH_PREFIX}{tenant_id}:{token}" if tenant_id else f"{REDIS_AUTH_PREFIX}:{token}"


async def generate_token(
    scope: str, tenant_id: str = "", *, ttl: int = _DEFAULT_TTL
) -> str:
    """Generate a cryptographically secure single-use or persistent API access token in Redis."""
    rd = get_redis(REDIS_DB_AUTH)
    token = secrets.token_urlsafe(_TOKEN_BYTES)
    key = _token_redis_key(tenant_id, token)

    await rd.hset(key, mapping={"scope": scope, "tenant_id": tenant_id})
    await rd.expire(key, ttl)

    logger.info("Token [%s] generated for tenant [%s]", scope, tenant_id or "global")
    return token


async def validate_and_refresh(
    token: str, *, tenant_id: str = "", ttl: int = _DEFAULT_TTL
) -> Optional[tuple[str, str]]:
    """Validate token validity and refresh its TTL if valid."""
    rd = get_redis(REDIS_DB_AUTH)
    key = _token_redis_key(tenant_id, token)
    data = await rd.hgetall(key)

    if not data or data.get("refreshed") == "1":
        return None

    # Automatic renewal
    await rd.expire(key, ttl)
    return data.get("scope"), data.get("tenant_id", "")


async def revoke_token(token: str, *, tenant_id: str = "") -> bool:
    """Revoke API access token with grace period to avoid refresh collisions."""
    if not token:
        return False

    rd = get_redis(REDIS_DB_AUTH)
    key = _token_redis_key(tenant_id, token)
    data = await rd.hgetall(key)
    if not data or data.get("refreshed") == "1":
        return False

    # Mark soft deletion and set grace TTL
    await rd.hset(key, "refreshed", "1")
    await rd.expire(key, _GRACE_TTL)
    return True


# ---- Session Token (HTTP Session) Management ----

_SESSION_TOKEN_BYTES = 32
_SESSION_DEFAULT_TTL = 3600


async def create_session_token(user_id: str, *, ttl: int = _SESSION_DEFAULT_TTL) -> str:
    """Create session token bound to user ID."""
    rd = get_redis(REDIS_DB_AUTH)
    token = secrets.token_urlsafe(_SESSION_TOKEN_BYTES)
    key = f"session:{token}"
    await rd.hset(key, mapping={"user_id": user_id})
    await rd.expire(key, ttl)
    logger.info("Session token created: user=%s", user_id)
    return token


async def resolve_user_from_token(token: str) -> Optional[str]:
    """Retrieve user ID from Redis session token."""
    rd = get_redis(REDIS_DB_AUTH)
    data = await rd.hgetall(f"session:{token}")
    return data.get("user_id") if data else None


async def get_current_user_id(request: Request) -> str:
    """FastAPI dependency: retrieve current authenticated user ID from request state."""
    uid = getattr(request.state, "current_user_id", None)
    if not uid:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthenticated")
    return uid


async def get_current_user(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> User:
    """FastAPI dependency: query full user entity from database."""
    user_id = await get_current_user_id(request)
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user


# ---- Role and RBAC Limiters ----

def require_role(min_priority: int):
    """Enforce user role priority level."""

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
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permission denied")
        return user

    return _check


async def _get_member_permissions(user_id: str, account_id: str) -> set[str]:
    """Compute all granular permission codes for user within account scope."""
    async with AsyncSessionLocal() as db:
        await set_search_path(db)
        # Query account member record
        stmt = (
            select(AccountMember)
            .where(AccountMember.user_id == user_id)
            .where(AccountMember.account_id == account_id)
        )
        member = (await db.execute(stmt)).scalar_one_or_none()
        if not member:
            return set()

        # Account owner has global permission
        if member.role_in_account == "owner":
            return {"*"}

        # Role-based permissions
        role_perms_stmt = select(RolePermission.permission_code).where(
            RolePermission.role_code == member.role_in_account
        )
        role_perms = set((await db.execute(role_perms_stmt)).scalars().all())

        # Member specific overrides
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
    """FastAPI dependency: check if user possesses required permissions within current tenant."""

    async def _checker(request: Request):
        user_id = await get_current_user_id(request)
        account_id = get_tenant_id()
        if not account_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Tenant context missing")

        granted = await _get_member_permissions(user_id, account_id)
        if "*" in granted:
            return user_id

        for p in perms:
            if p not in granted:
                logger.warning("Permission check failed: user=%s missing perm=%s", user_id, p)
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Permission missing: {p}")
        return user_id

    return _checker


# ---- Resource Access Token Management ----

_RES_TOKEN_LENGTH = 64
_RES_DEFAULT_TTL = 300
_RES_DEFAULT_MAX_USES = 1


async def create_token(
    tenant_id: str,
    resource_type: str,
    name: str,
    *,
    ttl: int = _RES_DEFAULT_TTL,
    max_uses: int = _RES_DEFAULT_MAX_USES,
    client_ip: str = "",
) -> str:
    """Store resource access token and metadata."""
    rd = get_redis()
    token = secrets.token_urlsafe(_RES_TOKEN_LENGTH)
    key = f"token:{token}"

    await rd.hset(
        key,
        mapping={
            "tenant_id": tenant_id,
            "resource_type": resource_type,
            "name": name,
            "remaining_uses": str(max_uses),
            "client_ip": client_ip,
        },
    )
    await rd.expire(key, ttl)
    return token


async def resolve_token(token: str) -> Optional[tuple[str, str, str, str]]:
    """Resolve token string to metadata and decrement remaining uses."""
    rd = get_redis()
    key = f"token:{token}"
    data = await rd.hgetall(key)

    if not data:
        return None

    remaining = int(data["remaining_uses"]) - 1
    if remaining <= 0:
        await rd.delete(key)
    else:
        await rd.hset(key, "remaining_uses", str(remaining))

    return (
        data["tenant_id"],
        data["resource_type"],
        data["name"],
        data.get("client_ip", ""),
    )


# ---- OOBE Initialization Security Guard ----

OOBE_PASSCODE: str = ""
OOBE_TOKEN: str = ""


def generate_oobe_codes() -> None:
    """Generate and log OOBE pairing passcode, and issue setup token."""
    import random
    import string
    import uuid
    global OOBE_PASSCODE, OOBE_TOKEN
    pool = string.ascii_uppercase + string.digits
    OOBE_PASSCODE = "".join(random.choices(pool, k=8))
    OOBE_TOKEN = str(uuid.uuid4())
    logger.critical("========== [NOTICE] First-time Launch ==========")
    logger.critical("System not initialized, entering OOBE setup state.")
    logger.critical("OOBE Passcode: %s", OOBE_PASSCODE)
    logger.critical("=================================================")


def verify_oobe_passcode(code: str) -> bool:
    """Verify 8-character alphanumeric passcode."""
    global OOBE_PASSCODE
    code = code.strip().upper()
    return bool(OOBE_PASSCODE) and code == OOBE_PASSCODE


def verify_oobe_token(token: str) -> bool:
    """Check UUID setup token for /configure endpoint."""
    global OOBE_TOKEN
    token = token.strip()
    return bool(OOBE_TOKEN) and token == OOBE_TOKEN


# ---- 2FA Temp Token Management ----

_TEMP_2FA_PREFIX = "2fa_pending"
_TEMP_2FA_TTL = 300


async def create_2fa_temp_token(user_id: str) -> str:
    """Create temporary token for 2FA verification flow."""
    rd = get_redis(REDIS_DB_AUTH)
    token = secrets.token_urlsafe(32)
    await rd.setex(f"{_TEMP_2FA_PREFIX}:{token}", _TEMP_2FA_TTL, user_id)
    return token


async def pop_2fa_temp_token(token: str) -> str:
    """Pop temporary 2FA token and return user_id."""
    rd = get_redis(REDIS_DB_AUTH)
    key = f"{_TEMP_2FA_PREFIX}:{token}"
    uid = await rd.get(key)
    if not uid:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Temporary token invalid or expired")
    await rd.delete(key)
    return uid



