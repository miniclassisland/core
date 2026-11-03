"""test_redis.py"""

from unittest.mock import patch, AsyncMock
import pytest
from app.shared.utils import redis


def test_get_redis_no_running_loop():
    """测试同步无事件循环上下文下调用 get_redis 及 _build_url 分支。"""
    orig_url = redis.REDIS_URL
    try:
        redis.REDIS_URL = "localhost:6379"
        assert redis._build_url(2) == "localhost:6379/2"
        redis.REDIS_URL = "redis://localhost:6379/0"
        assert redis._build_url(3) == "redis://localhost:6379/3"
    finally:
        redis.REDIS_URL = orig_url

    redis._pools.clear()
    r = redis.get_redis(0)
    assert r is not None
    redis._pools.clear()


@pytest.mark.asyncio
async def test_redis_init_and_get():
    """测试 Redis 初始化、多库连接池分配及清理。"""
    await redis.init_redis()
    # 再次调用验证复用连接池与 ping 分支
    await redis.init_redis()

    rd0 = redis.get_redis(0)
    assert rd0 is not None

    await rd0.set("test_key", "test_val")
    val = await rd0.get("test_key")
    assert val == "test_val"
    await rd0.delete("test_key")

    rd1 = redis.get_redis(1)
    assert rd1 is not None

    # 模拟 ping 异常以及 aclose 异常分支触发重连
    with (
        patch.object(
            redis._pools[0], "ping", AsyncMock(side_effect=RuntimeError("ping err"))
        ),
        patch.object(
            redis._pools[0], "aclose", AsyncMock(side_effect=RuntimeError("close err"))
        ),
    ):
        await redis.init_redis()

    await redis.close_redis()
    await redis.init_redis()
