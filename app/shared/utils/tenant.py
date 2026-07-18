"""多租户执行上下文与主机名/Redis 解析器。

使用 ContextVar 管理异步调用链中的多租户状态，并提供基于 Redis 及 DB 的租户解析与缓存逻辑。
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

# 每个请求范围内的租户 ID 上下文
tenant_ctx: ContextVar[str] = ContextVar("tenant_id")

# 每个请求的数据库 Schema 命名空间上下文
schema_ctx: ContextVar[str] = ContextVar("schema", default="public")

_SAFE_ID = re.compile(r"^[a-z0-9_\-]+$")
ACCOUNT_CACHE_TTL = 600


def safe_identifier(name: str) -> str:
    """安全性校验 SQL 标识符，防止 SQL 注入风险。"""
    if not _SAFE_ID.match(name):
        raise ValueError(f"Unsafe SQL identifier: {name!r}")
    return name


def get_tenant_id() -> str:
    """获取当前协程请求链路下的租户 ID。"""
    try:
        return tenant_ctx.get()
    except LookupError:
        raise RuntimeError("No tenant context set for this request")


def get_schema() -> str:
    """获取当前协程请求对应的数据库 Schema。"""
    return schema_ctx.get()


async def set_search_path(session, schema: str | None = None) -> None:
    """在当前 PostgreSQL 数据库 Session 会话上设置 search_path。"""
    s = safe_identifier(schema or get_schema())
    if s != "public":
        await session.execute(text(f'SET search_path TO "{s}", public'))


def extract_slug_from_host(host: str) -> Optional[str]:
    """从 HTTP Host 请求头中解析租户标识 slug（子域名部分）。"""
    hostname = host.split(":")[0].lower()
    base = BASE_DOMAIN.lower()

    if not hostname.endswith(f".{base}"):
        return None

    slug = hostname[: -(len(base) + 1)]
    return slug if slug else None


async def get_cached_account(slug: str) -> Optional[Account]:
    """从 Redis 缓存中读取并重构轻量账户实体。"""
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


async def set_cached_account(slug: str, account: Account) -> None:
    """将租户账户记录序列化并缓存入 Redis。"""
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


async def resolve_account(slug: str, db: AsyncSession) -> Optional[Account]:
    """通过缓存或数据库解析活跃的租户实体。"""
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
