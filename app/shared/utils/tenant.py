"""Multi-tenant execution context and hostname/Redis resolver.

Manages multi-tenant state across asynchronous call chains via ContextVar, providing tenant resolution and caching based on Redis and DB.
"""

import re
import json
from contextvars import ContextVar
from typing import Optional
from sqlalchemy import text, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.shared.utils.config import BASE_DOMAIN, REDIS_DB_CACHE
from app.shared.utils.redis import get_redis
from app.shared.db.models import Account

# Per-request tenant ID context
tenant_ctx: ContextVar[str] = ContextVar("tenant_id")

# Per-request database schema namespace context
schema_ctx: ContextVar[str] = ContextVar("schema", default="public")

_SAFE_ID = re.compile(r"^[a-z0-9_\-]+$")
ACCOUNT_CACHE_TTL = 600


def safe_identifier(name: str) -> str:
    """Validate SQL identifier for safety to prevent SQL injection."""
    if not _SAFE_ID.match(name):
        raise ValueError(f"Unsafe SQL identifier: {name!r}")
    return name


def get_tenant_id() -> str:
    """Get tenant ID under current coroutine request context."""
    try:
        return tenant_ctx.get()
    except LookupError:
        raise RuntimeError("No tenant context set for this request")


def get_schema() -> str:
    """Get database schema corresponding to current request."""
    return schema_ctx.get()


async def set_search_path(session, schema: str | None = None) -> None:
    """Set PostgreSQL search_path on current Session."""
    s = safe_identifier(schema or get_schema())
    if s != "public":
        await session.execute(text(f'SET search_path TO "{s}", public'))


def extract_slug_from_host(host: str) -> Optional[str]:
    """Parse tenant slug (subdomain portion) from HTTP Host header."""
    hostname = host.split(":")[0].lower()
    base = BASE_DOMAIN.lower()

    if not hostname.endswith(f".{base}"):
        return None

    slug = hostname[: -(len(base) + 1)]
    return slug if slug else None


async def get_cached_account(slug: str) -> Optional[Account]:
    """Retrieve and reconstruct lightweight Account entity from Redis cache."""
    try:
        rd = get_redis(REDIS_DB_CACHE)
        cached = await rd.get(f"account:{slug}")
        if not cached:
            return None
        data = json.loads(cached)
        return Account(
            id=data["id"],
            name=data["name"],
            slug=data["slug"],
            api_key=data["api_key"],
            is_active=data["is_active"],
        )
    except Exception:
        return None


async def set_cached_account(slug: str, account: Account) -> None:
    """Serialize and cache tenant account record into Redis."""
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
                }
            ),
            ex=ACCOUNT_CACHE_TTL,
        )
    except Exception:
        pass


async def resolve_account(slug: str, db: AsyncSession) -> Optional[Account]:
    """Resolve active tenant entity via cache or database."""
    account = await get_cached_account(slug)
    if account is not None:
        return account if account.is_active else None

    stmt = select(Account).where(Account.slug == slug)
    result = await db.execute(stmt)
    account = result.scalar_one_or_none()

    if account and account.is_active:
        await set_cached_account(slug, account)
        return account
    return None
