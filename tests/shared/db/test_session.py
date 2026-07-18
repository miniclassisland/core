"""test_session.py
"""

import pytest
from app.shared.db import session


@pytest.mark.asyncio
async def test_session_init():
    """测试数据库初始化。"""
    # 应当能够幂等初始化数据库表而没有异常
    await session.init_db()


@pytest.mark.asyncio
async def test_get_db_dependency():
    """测试 get_db 依赖项产生器。"""
    # 模拟 get_db 在上下文管理器中获取连接
    async for db in session.get_db():
        assert db is not None
        # 验证 search_path 设置正常
        res = await db.execute(session.Base.metadata.tables["accounts"].select())
        assert res is not None
