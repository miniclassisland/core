"""Multi-tenant execution context and hostname/Redis resolver.

Manages multi-tenant state across asynchronous call chains via ContextVar, providing tenant resolution and caching based on Redis and DB.
"""

import json
import time
from contextvars import ContextVar
from typing import Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.shared.utils.config import BASE_DOMAIN, REDIS_DB_CACHE
from app.shared.utils.redis import get_redis
from app.shared.db.models import Account
from app.shared.literals import (
    PUBLIC_SCHEMA,
    TENANT_ID_KEY,
    SCHEMA_KEY,
    SAFE_IDENTIFIER_RE,
)

# Per-request tenant ID context
tenant_ctx: ContextVar[str] = ContextVar(TENANT_ID_KEY)

# Per-request database schema namespace context
schema_ctx: ContextVar[str] = ContextVar(SCHEMA_KEY, default=PUBLIC_SCHEMA)

ACCOUNT_CACHE_TTL = 600
_LOCAL_ACCOUNT_CACHE: dict[str, tuple[float, Account]] = {}
_LOCAL_ACCOUNT_TTL = 30.0
_MAX_LOCAL_ACCOUNT_CACHE = 4096


def safe_identifier(name: str) -> str:
    """Validate SQL identifier for safety to prevent SQL injection."""
    if not SAFE_IDENTIFIER_RE.match(name):
        raise ValueError(f"Unsafe SQL identifier: {name!r}")
    return name


def get_tenant_id() -> str:
    """Get tenant ID under current coroutine request context."""
    try:
        return tenant_ctx.get()
    except LookupError:
        raise RuntimeError("No tenant context set for this request")


def get_tenant_id_or_default(default: str = "default") -> str:
    """Get tenant ID under current coroutine request context, or fallback to default."""
    try:
        val = tenant_ctx.get()
        return val if val else default
    except LookupError:
        return default


def get_schema() -> str:
    """Get database schema corresponding to current request."""
    return schema_ctx.get()


async def set_search_path(session, schema: str | None = None) -> None:
    """Validate identifier and keep PostgreSQL search_path in unified public schema."""
    _ = safe_identifier(schema or get_schema())
    return None


def extract_slug_from_host(host: str) -> Optional[str]:
    """Parse tenant slug (subdomain portion) from HTTP Host header."""
    hostname = host.split(":")[0].lower()
    base = BASE_DOMAIN.lower()

    if not hostname.endswith(f".{base}"):
        return None

    slug = hostname[: -(len(base) + 1)]
    return slug if slug else None


async def get_cached_account(slug: str) -> Optional[Account]:
    """Retrieve and reconstruct lightweight Account entity from L1 memory or Redis cache."""
    now = time.monotonic()
    hit = _LOCAL_ACCOUNT_CACHE.get(slug)
    if hit is not None and now < hit[0]:
        return hit[1]
    try:
        rd = get_redis(REDIS_DB_CACHE)
        cached = await rd.get(f"account:{slug}")
        if not cached:
            return None
        data = json.loads(cached)
        acct = Account(
            id=data["id"],
            name=data["name"],
            slug=data["slug"],
            api_key=data["api_key"],
            is_active=data["is_active"],
            registration_mode=data.get("registration_mode", "pairing"),
        )
        if len(_LOCAL_ACCOUNT_CACHE) >= _MAX_LOCAL_ACCOUNT_CACHE:
            _LOCAL_ACCOUNT_CACHE.clear()
        _LOCAL_ACCOUNT_CACHE[slug] = (now + _LOCAL_ACCOUNT_TTL, acct)
        return acct
    except Exception:
        return None


async def set_cached_account(slug: str, account: Account) -> None:
    """Serialize and cache tenant account record into L1 memory and Redis."""
    if len(_LOCAL_ACCOUNT_CACHE) >= _MAX_LOCAL_ACCOUNT_CACHE:
        _LOCAL_ACCOUNT_CACHE.clear()
    _LOCAL_ACCOUNT_CACHE[slug] = (
        time.monotonic() + _LOCAL_ACCOUNT_TTL,
        Account(
            id=account.id,
            name=account.name,
            slug=account.slug,
            api_key=account.api_key,
            is_active=account.is_active,
            registration_mode=getattr(account, "registration_mode", "pairing")
            or "pairing",
        ),
    )
    try:
        rd = get_redis(REDIS_DB_CACHE)
        await rd.set(
            f"account:{slug}",
            json.dumps(
                {
                    "id": account.id,
                    "name": account.name,
                    "slug": account.slug,
                    "api_key": account.api_key,
                    "is_active": account.is_active,
                    "registration_mode": getattr(
                        account, "registration_mode", "pairing"
                    )
                    or "pairing",
                }
            ),
            ex=ACCOUNT_CACHE_TTL,
        )
    except Exception:
        pass


async def invalidate_cached_account(slug: str) -> None:
    """Invalidate cached tenant account record in L1 memory and Redis."""
    _LOCAL_ACCOUNT_CACHE.pop(slug, None)
    try:
        rd = get_redis(REDIS_DB_CACHE)
        await rd.delete(f"account:{slug}")
    except Exception:
        pass


async def resolve_account(
    slug: str, db: Optional[AsyncSession] = None
) -> Optional[Account]:
    """Resolve active tenant entity via cache or database (acquiring DB session only on cache miss)."""
    account = await get_cached_account(slug)
    if account is not None:
        return account if account.is_active else None

    stmt = select(Account).where(Account.slug == slug)
    if db is not None:
        result = await db.execute(stmt)
        account = result.scalar_one_or_none()
    else:
        from app.shared.db.session import AsyncSessionLocal

        async with AsyncSessionLocal() as session:
            result = await session.execute(stmt)
            account = result.scalar_one_or_none()

    if account and account.is_active:
        await set_cached_account(slug, account)
        return account
    return None
