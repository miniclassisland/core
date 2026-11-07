"""MINI ClassIsland authentication and security dependencies.

Provides authentication and authorization via Redis sessions, resource access tokens, and RBAC-based FastAPI dependencies.
"""

import asyncio
import logging
import secrets
import string
import time
import uuid
from typing import Optional

from fastapi import Depends, Request, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.shared.utils.config import REDIS_DB_AUTH
from app.shared.utils.redis import get_redis
from app.shared.db.session import get_db
from app.shared.db.models import User, CustomRole

logger = logging.getLogger(__name__)


# ---- Session Token (HTTP Session) Management ----

_SESSION_TOKEN_BYTES = 96
_SESSION_DEFAULT_TTL = 3600
_USER_SESSIONS_PREFIX = "user_sessions"


async def create_session_token(user_id: str, *, ttl: int = _SESSION_DEFAULT_TTL) -> str:
    """Create session token bound to user ID and index it under user_sessions."""
    rd = get_redis(REDIS_DB_AUTH)
    token = secrets.token_urlsafe(_SESSION_TOKEN_BYTES)
    key = f"session:{token}"
    await rd.hset(key, mapping={"user_id": user_id})
    await rd.expire(key, ttl)
    user_set_key = f"{_USER_SESSIONS_PREFIX}:{user_id}"
    await rd.sadd(user_set_key, token)
    await rd.expire(user_set_key, max(ttl, _SESSION_DEFAULT_TTL * 24))
    logger.info("Session token created: user=%s", user_id)
    return token


async def resolve_user_from_token(token: str) -> Optional[str]:
    """Retrieve user ID from Redis session token."""
    rd = get_redis(REDIS_DB_AUTH)
    data = await rd.hgetall(f"session:{token}")
    return data.get("user_id") if data else None


async def revoke_session_token(token: str) -> None:
    """Revoke a single session token and remove it from user_sessions index."""
    if not token:
        return
    rd = get_redis(REDIS_DB_AUTH)
    key = f"session:{token}"
    data = await rd.hgetall(key)
    uid = data.get("user_id") if data else None
    await rd.delete(key)
    if uid:
        await rd.srem(f"{_USER_SESSIONS_PREFIX}:{uid}", token)


async def revoke_all_user_sessions(
    user_id: str, *, except_token: Optional[str] = None
) -> None:
    """Revoke all active session tokens for a user (optionally keeping except_token)."""
    rd = get_redis(REDIS_DB_AUTH)
    user_set_key = f"{_USER_SESSIONS_PREFIX}:{user_id}"
    tokens = await rd.smembers(user_set_key)
    pipe = rd.pipeline(transaction=False)
    for tok in tokens or ():
        if except_token and tok == except_token:
            continue
        pipe.delete(f"session:{tok}")
        pipe.srem(user_set_key, tok)
    if not except_token:
        pipe.delete(user_set_key)
    await pipe.execute()


# ---- Short-Lived SSO Exchange Code Management ----

_EXCHANGE_CODE_PREFIX = "sso_exchange"
_EXCHANGE_CODE_TTL = 30
_LOOPBACK_IPS = {"127.0.0.1", "::1", "localhost", "testclient"}
_exchange_code_lock = asyncio.Lock()


async def create_exchange_code(session_token: str, *, client_ip: str = "") -> str:
    """Issue a 30-second single-use exchange code for cross-origin SSO jump, bound to client IP."""
    rd = get_redis(REDIS_DB_AUTH)
    code = secrets.token_urlsafe(32)
    key = f"{_EXCHANGE_CODE_PREFIX}:{code}"
    await rd.hset(
        key,
        mapping={"session_token": session_token, "client_ip": client_ip},
    )
    await rd.expire(key, _EXCHANGE_CODE_TTL)
    return code


async def redeem_exchange_code(code: str, *, client_ip: str = "") -> Optional[str]:
    """Atomically consume a single-use SSO exchange code and verify client IP binding."""
    if not code:
        return None
    rd = get_redis(REDIS_DB_AUTH)
    key = f"{_EXCHANGE_CODE_PREFIX}:{code.strip()}"
    async with _exchange_code_lock:
        if await rd.hincrby(key, "used", 1) != 1:
            await rd.delete(key)
            return None
        data = await rd.hgetall(key)
        await rd.delete(key)
    if not data or "session_token" not in data:
        return None
    stored_ip = data.get("client_ip", "")
    if (
        stored_ip
        and client_ip
        and stored_ip not in _LOOPBACK_IPS
        and client_ip not in _LOOPBACK_IPS
        and stored_ip != client_ip
    ):
        return None
    return data["session_token"] or None


async def get_current_user_id(request: Request) -> str:
    """FastAPI dependency: retrieve current authenticated user ID from request state."""
    uid = getattr(request.state, "current_user_id", None)
    if not uid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthenticated"
        )
    return uid


async def get_current_user(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> User:
    """FastAPI dependency: query full user entity from database."""
    user_id = await get_current_user_id(request)
    cached_user = getattr(request.state, "current_user", None)
    if isinstance(cached_user, User) and cached_user.id == user_id:
        user = cached_user
    else:
        result = await db.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()
    if not user or not user.is_active or user.role_code in ("banned", "pending"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )
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
        priority = (
            role.priority
            if role
            else (
                100
                if user.role_code == "superadmin"
                else 80 if user.role_code == "admin" else 0
            )
        )
        if priority < min_priority:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="Permission denied"
            )
        return user

    return _check


# ---- Resource Access Token Management ----

_RES_TOKEN_LENGTH = 144
_RES_DEFAULT_TTL = 300
_RES_DEFAULT_MAX_USES = 1
_res_token_lock = asyncio.Lock()


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
    pipe = rd.pipeline(transaction=False)
    pipe.hset(
        key,
        mapping={
            "tenant_id": tenant_id,
            "resource_type": resource_type,
            "name": name,
            "remaining_uses": str(max_uses),
            "client_ip": client_ip,
        },
    )
    pipe.expire(key, ttl)
    await pipe.execute()
    return token


async def resolve_token(
    token: str, *, req_ip: str = ""
) -> Optional[tuple[str, str, str, str]]:
    """Atomically resolve token string to metadata and decrement remaining uses."""
    async with _res_token_lock:
        rd = get_redis()
        key = f"token:{token}"
        data = await rd.hgetall(key)

        if not data or "tenant_id" not in data:
            return None

        token_ip = data.get("client_ip", "")
        if (
            token_ip
            and req_ip
            and token_ip not in _LOOPBACK_IPS
            and req_ip not in _LOOPBACK_IPS
            and token_ip != req_ip
        ):
            # Return metadata without consuming remaining_uses so caller raises 403
            return (
                data["tenant_id"],
                data["resource_type"],
                data["name"],
                token_ip,
            )

        new_remaining = await rd.hincrby(key, "remaining_uses", -1)
        if new_remaining <= 0:
            await rd.delete(key)
        if new_remaining < 0:
            return None

        return (
            data["tenant_id"],
            data["resource_type"],
            data["name"],
            token_ip,
        )


# ---- OOBE Initialization Security Guard ----

OOBE_PASSCODE: str = ""
OOBE_TOKEN: str = ""
OOBE_FAIL_COUNT: int = 0
OOBE_MAX_FAILURES: int = 5
OOBE_LOCKOUT_UNTIL: float = 0.0
OOBE_LOCKOUT_SECONDS: int = 60
_OOBE_IP_FAILS: dict[str, tuple[int, float]] = {}


def generate_oobe_codes() -> None:
    """Generate and log OOBE pairing passcode, and issue setup token."""
    global OOBE_PASSCODE, OOBE_TOKEN, OOBE_FAIL_COUNT, OOBE_LOCKOUT_UNTIL
    pool = string.ascii_uppercase + string.digits
    OOBE_PASSCODE = "".join(secrets.choice(pool) for _ in range(8))
    OOBE_TOKEN = str(uuid.uuid4())
    OOBE_FAIL_COUNT = 0
    OOBE_LOCKOUT_UNTIL = 0.0
    _OOBE_IP_FAILS.clear()
    logger.critical("========== [NOTICE] First-time Launch ==========")
    logger.critical("System not initialized, entering OOBE setup state.")
    logger.critical("OOBE Passcode: %s", OOBE_PASSCODE)
    logger.critical("=================================================")


def clear_oobe_codes() -> None:
    """Clear in-memory OOBE passcode and token immediately after configuration."""
    global OOBE_PASSCODE, OOBE_TOKEN, OOBE_FAIL_COUNT, OOBE_LOCKOUT_UNTIL
    OOBE_PASSCODE = ""
    OOBE_TOKEN = ""
    OOBE_FAIL_COUNT = 0
    OOBE_LOCKOUT_UNTIL = 0.0
    _OOBE_IP_FAILS.clear()


def get_oobe_token() -> str:
    """Get currently issued OOBE setup token dynamically."""
    global OOBE_TOKEN
    return OOBE_TOKEN


def is_oobe_locked_out(client_ip: str = "") -> bool:
    """Return whether OOBE passcode verification is currently in cooldown lockout (global or per-IP)."""
    global OOBE_LOCKOUT_UNTIL, OOBE_FAIL_COUNT
    now = time.monotonic()
    if OOBE_LOCKOUT_UNTIL > 0:
        if now < OOBE_LOCKOUT_UNTIL:
            return True
        OOBE_LOCKOUT_UNTIL = 0.0
        OOBE_FAIL_COUNT = 0
    if client_ip and client_ip in _OOBE_IP_FAILS:
        _, lock_until = _OOBE_IP_FAILS[client_ip]
        if lock_until > 0:
            if now < lock_until:
                return True
            _OOBE_IP_FAILS.pop(client_ip, None)
    return False


def verify_oobe_passcode(code: str, *, client_ip: str = "") -> bool:
    """Verify 8-character alphanumeric passcode in constant time with per-IP 60s cooldown lockout."""
    global OOBE_PASSCODE, OOBE_FAIL_COUNT, OOBE_LOCKOUT_UNTIL
    if not OOBE_PASSCODE or is_oobe_locked_out(client_ip):
        return False
    cleaned = code.strip().upper()
    if secrets.compare_digest(cleaned, OOBE_PASSCODE):
        OOBE_FAIL_COUNT = 0
        OOBE_LOCKOUT_UNTIL = 0.0
        if client_ip:
            _OOBE_IP_FAILS.pop(client_ip, None)
        return True
    if client_ip:
        now = time.monotonic()
        if len(_OOBE_IP_FAILS) > 1024 and client_ip not in _OOBE_IP_FAILS:
            expired_ips = [
                ip for ip, (_, lu) in _OOBE_IP_FAILS.items() if lu > 0 and now >= lu
            ]
            for ip in expired_ips:
                _OOBE_IP_FAILS.pop(ip, None)
            if len(_OOBE_IP_FAILS) > 1024:
                unlocked_ip = next(
                    (ip for ip, (_, lu) in _OOBE_IP_FAILS.items() if lu <= now), None
                )
                if unlocked_ip is not None:
                    _OOBE_IP_FAILS.pop(unlocked_ip, None)
        cnt, lock_until = _OOBE_IP_FAILS.get(client_ip, (0, 0.0))
        cnt += 1
        if cnt >= OOBE_MAX_FAILURES:
            lock_until = now + OOBE_LOCKOUT_SECONDS
            logger.warning(
                "OOBE passcode failed %d times from IP %s, entering %ds cooldown lockout",
                cnt,
                client_ip,
                OOBE_LOCKOUT_SECONDS,
            )
        _OOBE_IP_FAILS[client_ip] = (cnt, lock_until)
        return False
    OOBE_FAIL_COUNT += 1
    if OOBE_FAIL_COUNT >= OOBE_MAX_FAILURES:
        OOBE_LOCKOUT_UNTIL = time.monotonic() + OOBE_LOCKOUT_SECONDS
        logger.warning(
            "OOBE passcode failed %d times, entering %ds cooldown lockout",
            OOBE_FAIL_COUNT,
            OOBE_LOCKOUT_SECONDS,
        )
    return False


def verify_oobe_token(token: str) -> bool:
    """Check UUID setup token for /configure endpoint in constant time."""
    global OOBE_TOKEN
    cleaned = token.strip()
    return bool(OOBE_TOKEN) and secrets.compare_digest(cleaned, OOBE_TOKEN)


# ---- 2FA Temp Token Management ----

_TEMP_2FA_PREFIX = "2fa_pending"
_TEMP_2FA_TOKEN_BYTES = 96
_TEMP_2FA_TTL = 300


async def create_2fa_temp_token(user_id: str) -> str:
    """Create temporary token for 2FA verification flow."""
    rd = get_redis(REDIS_DB_AUTH)
    token = secrets.token_urlsafe(_TEMP_2FA_TOKEN_BYTES)
    await rd.set(f"{_TEMP_2FA_PREFIX}:{token}", user_id, ex=_TEMP_2FA_TTL)
    return token


async def pop_2fa_temp_token(token: str) -> str:
    """Atomically pop temporary 2FA token and return user_id."""
    rd = get_redis(REDIS_DB_AUTH)
    key = f"{_TEMP_2FA_PREFIX}:{token}"
    uid = await rd.getdel(key)
    if not uid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Temporary token invalid or expired",
        )
    return uid
