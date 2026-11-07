"""MINI ClassIsland authentication and security dependencies.

Provides authentication and authorization via Redis sessions, resource access tokens, and RBAC-based FastAPI dependencies.
"""

import asyncio
from collections import deque
import hashlib
import hmac
import logging
import os
import re
import secrets
import string
import time
import uuid
from typing import Any, Optional

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
    await revoke_all_user_certificates(user_id)


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


# ---- Login Security Certificate Management ----

_CERT_PREFIX = "login_cert"
_CERT_EXCHANGE_PREFIX = "cert_exchange"
_USER_CERTS_PREFIX = "user_certs"
_CERT_TTL = 7 * 86400  # 1 week (604800s)
_CERT_EXCHANGE_TTL = 300  # 5 minutes (300s)
_CERT_ROTATE_WINDOW = 86400  # 24 hours (86400s)
_CERT_MAX_GENERATION = 12  # At most 12 rotations
_CERT_SESSION_MAX_TTL = 3600  # At most 1 hour per session token
_CERT_DEEPLINK_PREFIX = "miniclassisland://exchange-certificate/"
_cert_lock = asyncio.Lock()

# Process-local HMAC secret and regex validators for pre-Redis stateless MAC rejection
_CERT_MAC_KEY: bytes = os.urandom(32)
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_EXCHANGE_CODE_RE = re.compile(r"^[A-Za-z0-9_-]{40,48}$")
_CERT_SECRET_RE = re.compile(r"^[A-Za-z0-9_-]{32,128}\.[0-9a-f]{64}$")

# Per-IP and Per-Certificate flood limiters (in-memory zero-I/O shield)
_CERT_IP_WINDOW_SECONDS = 60.0
_CERT_IP_MAX_REQ_PER_WINDOW = 20
_CERT_ID_MIN_SESSION_INTERVAL = 2.0  # Minimum seconds between session minting per cert
_CERT_MAX_FAILURES_BEFORE_REVOKE = 5
_cert_ip_reqs: dict[str, deque[float]] = {}
_cert_id_last_mint: dict[str, tuple[float, str, int]] = {}


def _get_cert_mac_key() -> bytes:
    """Return process-consistent HMAC key (derived from SECRET_KEY if configured, else process key)."""
    sk = os.environ.get("SECRET_KEY", "")
    if sk:
        return sk.encode("utf-8")
    return _CERT_MAC_KEY


def _make_signed_cert_secret(cert_id: str) -> str:
    """Create a certificate secret containing an embedded HMAC-SHA256 tag bound to cert_id."""
    raw = secrets.token_urlsafe(36)
    sig = hmac.new(
        _get_cert_mac_key(),
        f"{cert_id}:{raw}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"{raw}.{sig}"


def _verify_cert_secret_stateless(cert_id: str, cert_secret: str) -> bool:
    """Statelessly verify UUID format and HMAC-SHA256 signature in ~1us before touching Redis or DB."""
    if not cert_id or not cert_secret:
        return False
    cid = cert_id.strip().lower()
    sec = cert_secret.strip()
    if len(cid) != 36 or not _UUID_RE.match(cid):
        return False
    if len(sec) > 200 or not _CERT_SECRET_RE.match(sec):
        return False
    raw, sig = sec.rsplit(".", 1)
    expected_sig = hmac.new(
        _get_cert_mac_key(),
        f"{cid}:{raw}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return secrets.compare_digest(sig, expected_sig)


def check_cert_ip_rate_limit(client_ip: str) -> bool:
    """Zero-I/O in-memory rate limiter for /token/certificate/* endpoints (returns True if allowed)."""
    if not client_ip or client_ip in _LOOPBACK_IPS:
        return True
    now = time.monotonic()
    cutoff = now - _CERT_IP_WINDOW_SECONDS
    if len(_cert_ip_reqs) > 4096 and client_ip not in _cert_ip_reqs:
        stale_ips = [
            ip for ip, dq in _cert_ip_reqs.items() if not dq or dq[-1] < cutoff
        ]
        for ip in stale_ips:
            _cert_ip_reqs.pop(ip, None)
        if len(_cert_ip_reqs) > 4096:
            _cert_ip_reqs.pop(next(iter(_cert_ip_reqs)), None)
    dq = _cert_ip_reqs.get(client_ip)
    if dq is None:
        dq = deque()
        _cert_ip_reqs[client_ip] = dq
    while dq and dq[0] < cutoff:
        dq.popleft()
    if len(dq) >= _CERT_IP_MAX_REQ_PER_WINDOW:
        return False
    dq.append(now)
    return True


def _hash_cert_secret(secret: str) -> str:
    """Compute SHA-256 hex digest of a certificate secret."""
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def normalize_cert_exchange_code(code_or_uri: str) -> str:
    """Extract raw exchange code from either raw code or miniclassisland://exchange-certificate/{Code} URI."""
    cleaned = (code_or_uri or "").strip()
    if cleaned.lower().startswith(_CERT_DEEPLINK_PREFIX):
        cleaned = cleaned[len(_CERT_DEEPLINK_PREFIX) :].strip().strip("/")
    return cleaned


async def issue_login_certificate_and_exchange_code(
    user_id: str, *, device_name: str = ""
) -> dict[str, Any]:
    """Issue a 7-day root Login Security Certificate (generation 0) and a 5-minute single-use exchange code."""
    rd = get_redis(REDIS_DB_AUTH)
    now = int(time.time())
    expires_at = now + _CERT_TTL
    cert_id = str(uuid.uuid4()).lower()
    family_id = cert_id
    cert_secret = _make_signed_cert_secret(cert_id)
    secret_hash = _hash_cert_secret(cert_secret)
    code = secrets.token_urlsafe(32)

    cert_key = f"{_CERT_PREFIX}:{cert_id}"
    ex_key = f"{_CERT_EXCHANGE_PREFIX}:{code}"
    user_certs_key = f"{_USER_CERTS_PREFIX}:{user_id}"

    pipe = rd.pipeline(transaction=False)
    pipe.hset(
        cert_key,
        mapping={
            "cert_id": cert_id,
            "family_id": family_id,
            "user_id": user_id,
            "secret_hash": secret_hash,
            "generation": "0",
            "max_generation": str(_CERT_MAX_GENERATION),
            "issued_at": str(now),
            "expires_at": str(expires_at),
            "last_used_at": "0",
            "redeemed": "0",
            "fail_count": "0",
            "device_name": (device_name or "").strip()[:64],
        },
    )
    pipe.expire(cert_key, _CERT_TTL)
    pipe.sadd(user_certs_key, cert_id)
    pipe.expire(user_certs_key, _CERT_TTL * (_CERT_MAX_GENERATION + 1))

    pipe.hset(
        ex_key,
        mapping={
            "cert_id": cert_id,
            "cert_secret": cert_secret,
            "user_id": user_id,
        },
    )
    pipe.expire(ex_key, _CERT_EXCHANGE_TTL)
    await pipe.execute()

    return {
        "code": code,
        "deeplink": f"{_CERT_DEEPLINK_PREFIX}{code}",
        "expires_in": _CERT_EXCHANGE_TTL,
        "cert_id": cert_id,
        "family_id": family_id,
        "generation": 0,
        "max_generation": _CERT_MAX_GENERATION,
        "issued_at": now,
        "expires_at": expires_at,
    }


async def redeem_certificate_exchange_code(
    code_or_uri: str,
) -> Optional[dict[str, Any]]:
    """Atomically consume a 5-minute single-use exchange code and return the full Login Security Certificate."""
    code = normalize_cert_exchange_code(code_or_uri)
    if not code or not _EXCHANGE_CODE_RE.match(code):
        return None
    rd = get_redis(REDIS_DB_AUTH)
    ex_key = f"{_CERT_EXCHANGE_PREFIX}:{code}"
    async with _cert_lock:
        if await rd.hincrby(ex_key, "used", 1) != 1:
            await rd.delete(ex_key)
            return None
        ex_data = await rd.hgetall(ex_key)
        await rd.delete(ex_key)

    if not ex_data or "cert_id" not in ex_data or "cert_secret" not in ex_data:
        return None

    cert_id = ex_data["cert_id"]
    cert_secret = ex_data["cert_secret"]
    cert_key = f"{_CERT_PREFIX}:{cert_id}"
    cert_data = await rd.hgetall(cert_key)
    if not cert_data or "user_id" not in cert_data:
        return None

    now = int(time.time())
    expires_at = int(cert_data.get("expires_at") or 0)
    if expires_at <= now:
        await rd.delete(cert_key)
        return None

    await rd.hset(
        cert_key,
        mapping={"redeemed": "1", "last_used_at": str(now)},
    )
    return {
        "cert_id": cert_id,
        "family_id": cert_data.get("family_id", cert_id),
        "user_id": cert_data["user_id"],
        "cert_secret": cert_secret,
        "generation": int(cert_data.get("generation") or 0),
        "max_generation": int(cert_data.get("max_generation") or _CERT_MAX_GENERATION),
        "issued_at": int(cert_data.get("issued_at") or now),
        "expires_at": expires_at,
        "device_name": cert_data.get("device_name", ""),
    }


async def verify_login_certificate(
    cert_id: str, cert_secret: str
) -> Optional[dict[str, Any]]:
    """Verify certificate ID and secret in constant time with pre-Redis HMAC gate and O(1) Redis lookup."""
    if not _verify_cert_secret_stateless(cert_id, cert_secret):
        return None
    cid = cert_id.strip().lower()
    sec = cert_secret.strip()
    rd = get_redis(REDIS_DB_AUTH)
    cert_key = f"{_CERT_PREFIX}:{cid}"
    cert_data = await rd.hgetall(cert_key)
    if not cert_data or "secret_hash" not in cert_data or "user_id" not in cert_data:
        return None
    now = int(time.time())
    expires_at = int(cert_data.get("expires_at") or 0)
    if expires_at <= now:
        await rd.delete(cert_key)
        return None
    candidate_hash = _hash_cert_secret(sec)
    if not secrets.compare_digest(cert_data["secret_hash"], candidate_hash):
        fails = await rd.hincrby(cert_key, "fail_count", 1)
        if fails >= _CERT_MAX_FAILURES_BEFORE_REVOKE:
            await rd.delete(cert_key)
            await rd.srem(f"{_USER_CERTS_PREFIX}:{cert_data['user_id']}", cid)
        return None
    last_used = int(cert_data.get("last_used_at") or 0)
    if now - last_used >= 5 or cert_data.get("redeemed") != "1":
        await rd.hset(cert_key, mapping={"last_used_at": str(now), "redeemed": "1"})
    return {
        "cert_id": cert_data.get("cert_id", cid),
        "family_id": cert_data.get("family_id", cid),
        "user_id": cert_data["user_id"],
        "generation": int(cert_data.get("generation") or 0),
        "max_generation": int(cert_data.get("max_generation") or _CERT_MAX_GENERATION),
        "issued_at": int(cert_data.get("issued_at") or now),
        "expires_at": expires_at,
        "device_name": cert_data.get("device_name", ""),
    }


async def rotate_login_certificate(cert_id: str, cert_secret: str) -> dict[str, Any]:
    """Rotate a Login Security Certificate to the next generation when remaining validity < 24h (max 12 generations)."""
    if not _verify_cert_secret_stateless(cert_id, cert_secret):
        raise ValueError("ERR_CERT_INVALID")
    cid = cert_id.strip().lower()
    sec = cert_secret.strip()
    rd = get_redis(REDIS_DB_AUTH)
    old_key = f"{_CERT_PREFIX}:{cid}"
    async with _cert_lock:
        cert_data = await rd.hgetall(old_key)
        if (
            not cert_data
            or "secret_hash" not in cert_data
            or "user_id" not in cert_data
        ):
            raise ValueError("ERR_CERT_INVALID")
        now = int(time.time())
        expires_at = int(cert_data.get("expires_at") or 0)
        if expires_at <= now:
            await rd.delete(old_key)
            raise ValueError("ERR_CERT_INVALID")
        candidate_hash = _hash_cert_secret(sec)
        if not secrets.compare_digest(cert_data["secret_hash"], candidate_hash):
            raise ValueError("ERR_CERT_INVALID")

        generation = int(cert_data.get("generation") or 0)
        max_generation = int(cert_data.get("max_generation") or _CERT_MAX_GENERATION)
        if generation >= max_generation:
            raise PermissionError("ERR_CERT_MAX_GENERATION")

        remaining = expires_at - now
        if remaining > _CERT_ROTATE_WINDOW:
            raise RuntimeError("ERR_CERT_ROTATE_TOO_EARLY")

        user_id = cert_data["user_id"]
        family_id = cert_data.get("family_id", cid)
        device_name = cert_data.get("device_name", "")
        new_gen = generation + 1
        new_cert_id = str(uuid.uuid4()).lower()
        new_secret = _make_signed_cert_secret(new_cert_id)
        new_secret_hash = _hash_cert_secret(new_secret)
        new_expires_at = now + _CERT_TTL
        new_key = f"{_CERT_PREFIX}:{new_cert_id}"
        user_certs_key = f"{_USER_CERTS_PREFIX}:{user_id}"

        pipe = rd.pipeline(transaction=False)
        pipe.delete(old_key)
        pipe.srem(user_certs_key, cid)
        pipe.hset(
            new_key,
            mapping={
                "cert_id": new_cert_id,
                "family_id": family_id,
                "user_id": user_id,
                "secret_hash": new_secret_hash,
                "generation": str(new_gen),
                "max_generation": str(max_generation),
                "issued_at": str(now),
                "expires_at": str(new_expires_at),
                "last_used_at": str(now),
                "redeemed": "1",
                "fail_count": "0",
                "device_name": device_name,
            },
        )
        pipe.expire(new_key, _CERT_TTL)
        pipe.sadd(user_certs_key, new_cert_id)
        pipe.expire(user_certs_key, _CERT_TTL * (_CERT_MAX_GENERATION + 1))
        await pipe.execute()
        _cert_id_last_mint.pop(cid, None)

    return {
        "cert_id": new_cert_id,
        "family_id": family_id,
        "user_id": user_id,
        "cert_secret": new_secret,
        "generation": new_gen,
        "max_generation": max_generation,
        "issued_at": now,
        "expires_at": new_expires_at,
        "device_name": device_name,
    }


async def list_user_certificates(user_id: str) -> list[dict[str, Any]]:
    """List all active Login Security Certificates for a user."""
    rd = get_redis(REDIS_DB_AUTH)
    user_certs_key = f"{_USER_CERTS_PREFIX}:{user_id}"
    cert_ids = await rd.smembers(user_certs_key)
    if not cert_ids:
        return []
    now = int(time.time())
    items: list[dict[str, Any]] = []
    stale_ids: list[str] = []
    for cid in cert_ids:
        data = await rd.hgetall(f"{_CERT_PREFIX}:{cid}")
        if not data or "user_id" not in data:
            stale_ids.append(cid)
            continue
        expires_at = int(data.get("expires_at") or 0)
        if expires_at <= now:
            stale_ids.append(cid)
            await rd.delete(f"{_CERT_PREFIX}:{cid}")
            continue
        gen = int(data.get("generation") or 0)
        max_gen = int(data.get("max_generation") or _CERT_MAX_GENERATION)
        items.append(
            {
                "cert_id": data.get("cert_id", cid),
                "family_id": data.get("family_id", cid),
                "generation": gen,
                "max_generation": max_gen,
                "issued_at": int(data.get("issued_at") or 0),
                "expires_at": expires_at,
                "last_used_at": int(data.get("last_used_at") or 0),
                "redeemed": data.get("redeemed") == "1",
                "device_name": data.get("device_name", ""),
                "can_rotate": (expires_at - now <= _CERT_ROTATE_WINDOW)
                and (gen < max_gen),
            }
        )
    if stale_ids:
        await rd.srem(user_certs_key, *stale_ids)
    items.sort(key=lambda x: x["issued_at"], reverse=True)
    return items


async def revoke_user_certificate(user_id: str, cert_id: str) -> bool:
    """Revoke a specific Login Security Certificate belonging to user_id."""
    if not cert_id:
        return False
    rd = get_redis(REDIS_DB_AUTH)
    cid = cert_id.strip()
    cert_key = f"{_CERT_PREFIX}:{cid}"
    data = await rd.hgetall(cert_key)
    if not data or data.get("user_id") != user_id:
        await rd.srem(f"{_USER_CERTS_PREFIX}:{user_id}", cid)
        return False
    await rd.delete(cert_key)
    await rd.srem(f"{_USER_CERTS_PREFIX}:{user_id}", cid)
    return True


async def revoke_all_user_certificates(user_id: str) -> None:
    """Revoke all active Login Security Certificates for a user."""
    rd = get_redis(REDIS_DB_AUTH)
    user_certs_key = f"{_USER_CERTS_PREFIX}:{user_id}"
    cert_ids = await rd.smembers(user_certs_key)
    pipe = rd.pipeline(transaction=False)
    for cid in cert_ids or ():
        pipe.delete(f"{_CERT_PREFIX}:{cid}")
    pipe.delete(user_certs_key)
    await pipe.execute()


# ---- Reverse QR Code Web Login (Mobile -> Web) ----

_QR_LOGIN_PREFIX = "qr_login"
_QR_LOGIN_TTL = 300  # 5 minutes (300s)
_QR_LOGIN_DEEPLINK_PREFIX = "miniclassisland://qr-login/"
_QR_LOGIN_CODE_RE = re.compile(r"^[A-Za-z0-9_-]{32,128}\.[0-9a-f]{64}$")


def extract_qr_login_code(code_or_uri: str) -> str:
    """Extract raw QR login challenge code from plain code or miniclassisland://qr-login/{Code} URI."""
    cleaned = (code_or_uri or "").strip()
    if cleaned.lower().startswith(_QR_LOGIN_DEEPLINK_PREFIX):
        cleaned = cleaned[len(_QR_LOGIN_DEEPLINK_PREFIX) :].strip().strip("/")
    return cleaned


def _verify_qr_login_code_stateless(raw_code: str) -> bool:
    """Stateless HMAC-SHA256 verification for QR login challenge codes before touching Redis."""
    if not raw_code or not _QR_LOGIN_CODE_RE.match(raw_code):
        return False
    nonce_part, sig_part = raw_code.rsplit(".", 1)
    expected_sig = hmac.new(
        _get_cert_mac_key(),
        f"qr_login:{nonce_part}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return secrets.compare_digest(sig_part, expected_sig)


async def create_qr_login_challenge(client_ip: str = "") -> dict[str, Any]:
    """Create a 5-minute reverse QR login challenge for Web login."""
    nonce = secrets.token_urlsafe(32)
    sig = hmac.new(
        _get_cert_mac_key(),
        f"qr_login:{nonce}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    code = f"{nonce}.{sig}"
    now = int(time.time())
    expires_at = now + _QR_LOGIN_TTL
    rd = get_redis(REDIS_DB_AUTH)
    key = f"{_QR_LOGIN_PREFIX}:{code}"
    pipe = rd.pipeline(transaction=False)
    pipe.hset(
        key,
        mapping={
            "status": "pending",
            "client_ip": client_ip,
            "created_at": str(now),
            "expires_at": str(expires_at),
            "user_id": "",
        },
    )
    pipe.expire(key, _QR_LOGIN_TTL)
    await pipe.execute()
    return {
        "code": code,
        "deeplink": f"{_QR_LOGIN_DEEPLINK_PREFIX}{code}",
        "expires_in": _QR_LOGIN_TTL,
        "expires_at": expires_at,
    }


async def authorize_qr_login_challenge(code_or_uri: str, user_id: str) -> bool:
    """Authorize a pending Web QR login challenge on behalf of user_id."""
    code = extract_qr_login_code(code_or_uri)
    if not _verify_qr_login_code_stateless(code) or not user_id:
        return False
    rd = get_redis(REDIS_DB_AUTH)
    key = f"{_QR_LOGIN_PREFIX}:{code}"
    data = await rd.hgetall(key)
    if not data or data.get("status") != "pending":
        return False
    now = int(time.time())
    expires_at = int(data.get("expires_at") or 0)
    if expires_at <= now:
        await rd.delete(key)
        return False
    await rd.hset(
        key,
        mapping={
            "status": "authorized",
            "user_id": user_id,
            "authorized_at": str(now),
        },
    )
    return True


async def poll_qr_login_challenge(code_or_uri: str) -> dict[str, Any]:
    """Poll a Web QR login challenge; if authorized, atomically consume it and issue a session token."""
    code = extract_qr_login_code(code_or_uri)
    if not _verify_qr_login_code_stateless(code):
        return {"status": "expired"}
    rd = get_redis(REDIS_DB_AUTH)
    key = f"{_QR_LOGIN_PREFIX}:{code}"
    data = await rd.hgetall(key)
    if not data:
        return {"status": "expired"}
    now = int(time.time())
    expires_at = int(data.get("expires_at") or 0)
    if expires_at <= now:
        await rd.delete(key)
        return {"status": "expired"}
    st = data.get("status", "pending")
    if st == "authorized" and data.get("user_id"):
        await rd.delete(key)
        uid = data["user_id"]
        token = await create_session_token(uid)
        return {
            "status": "authorized",
            "token": token,
            "user_id": uid,
        }
    return {
        "status": "pending",
        "expires_at": expires_at,
    }
