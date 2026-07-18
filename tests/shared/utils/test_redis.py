"""test_redis.py
"""

import pytest
from app.shared.utils import redis


@pytest.mark.asyncio
async def test_redis_init_and_get():
    """测试 Redis 初始化、多库连接池分配及清理。"""
    await redis.init_redis()

    # 获取默认库连接
    rd0 = redis.get_redis(0)
    assert rd0 is not None

    # 尝试写入和读取
    await rd0.set("test_key", "test_val")
    val = await rd0.get("test_key")
    assert val == "test_val"
    await rd0.delete("test_key")

    # 获取其他 DB 的连接
    rd1 = redis.get_redis(1)
    assert rd1 is not None

    # 关闭连接池
    await redis.close_redis()
