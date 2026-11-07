"""Redis multi-database connection pool manager and accessor."""

import asyncio
import os
import logging
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit
import redis.asyncio as aioredis
from app.shared.utils.config import REDIS_URL

logger = logging.getLogger(__name__)

_pools: dict[int, Any] = {}
_lock = asyncio.Lock()
_max_conn = int(os.environ.get("REDIS_MAX_CONNECTIONS", "2000"))


def _build_url(db: int) -> str:
    """Replace logical database ID in connection URL."""
    # Unix domain socket: unix:///run/redis/redis-server.sock?db=0
    if REDIS_URL.startswith("unix://"):  # pragma: no cover
        parts = urlsplit(REDIS_URL)
        query = dict(parse_qsl(parts.query))
        query["db"] = str(db)
        return f"{parts.scheme}://{parts.netloc}{parts.path}?{urlencode(query)}"
    # e.g., redis://localhost:6379/0 -> redis://localhost:6379/{db}
    if "/" in REDIS_URL:
        base = REDIS_URL.rsplit("/", 1)[0]
        return f"{base}/{db}"
    return f"{REDIS_URL}/{db}"


async def init_redis(*, dbs: tuple[int, ...] = (0, 1, 2)) -> None:
    """Initialize independent connection pool for specified logical DBs."""
    async with _lock:
        for db in dbs:
            if db in _pools:
                try:
                    await _pools[db].ping()
                    continue
                except Exception:
                    try:
                        await _pools[db].aclose()
                    except Exception:
                        pass
            pool: Any = aioredis.from_url(
                _build_url(db), decode_responses=True, max_connections=_max_conn
            )
            await pool.ping()
            _pools[db] = pool
        logger.info("Redis connected successfully DB: %s", list(_pools.keys()))


def get_redis(db: int = 0) -> Any:
    """Get Redis instance for specified logical DB, recreating if event loop changed."""
    try:
        current_loop = asyncio.get_running_loop()
    except RuntimeError:
        current_loop = None

    pool = _pools.get(db)
    pool_loop = getattr(pool, "_active_loop", None) if pool else None

    if pool is None or (current_loop is not None and pool_loop is not current_loop):
        pool = aioredis.from_url(
            _build_url(db), decode_responses=True, max_connections=_max_conn
        )
        setattr(pool, "_active_loop", current_loop)
        _pools[db] = pool
    return pool


async def close_redis() -> None:
    """Safely close all Redis connection pools."""
    for db in list(_pools.keys()):
        await _pools[db].aclose()
    _pools.clear()
    logger.info("All Redis connection pools safely closed")
