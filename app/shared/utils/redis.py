"""Redis 多逻辑 DB 连接池管理与统一访问器。
"""

import asyncio
import os
import sys
import logging
from typing import Optional
import redis.asyncio as aioredis
from app.shared.utils.config import REDIS_URL

logger = logging.getLogger(__name__)

_pools: dict[int, aioredis.Redis] = {}
_lock = asyncio.Lock()
_max_conn = int(os.environ.get("REDIS_MAX_CONNECTIONS", "20"))


def _build_url(db: int) -> str:
    """替换连接 URL 中的逻辑库编号。"""
    # 比如 redis://localhost:6379/0 -> redis://localhost:6379/{db}
    if "/" in REDIS_URL:
        base = REDIS_URL.rsplit("/", 1)[0]
        return f"{base}/{db}"
    return f"{REDIS_URL}/{db}"


async def init_redis(*, dbs: tuple[int, ...] = (0, 1, 2)) -> None:
    """初始化指定逻辑 DB 的独立连接池。"""
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
            pool = aioredis.from_url(
                _build_url(db), decode_responses=True, max_connections=_max_conn
            )
            await pool.ping()
            _pools[db] = pool
        logger.info("Redis 连通成功 DB: %s", list(_pools.keys()))


def get_redis(db: int = 0) -> aioredis.Redis:
    """获取指定逻辑 DB 的 Redis 实例。"""
    pool = _pools.get(db)
    if pool is None:
        raise RuntimeError(f"Redis DB {db} 未初始化 — 请先调用 init_redis()")
    return pool


async def close_redis() -> None:
    """释放并关闭所有逻辑库的 Redis 连接池。"""
    for db in list(_pools.keys()):
        await _pools[db].aclose()
    _pools.clear()
    logger.info("Redis 所有连接池已安全关闭")
