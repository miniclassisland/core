"""数据库连接引擎与异步 Session 会话管理。
"""

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from app.shared.utils.config import DATABASE_URL
from app.shared.utils.tenant import set_search_path
from app.shared.db.models import Base

# 配置异步数据库引擎
engine = create_async_engine(DATABASE_URL, echo=False, pool_size=10, max_overflow=20)

# 创建异步 Session 连接池实例
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def init_db() -> None:
    """执行全局 DDL，在数据库中创建公有表。"""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_db():
    """FastAPI 依赖注入项：自动开启异步会话并在结束时释放，同时依上下文设置租户隔离的 search_path。"""
    async with AsyncSessionLocal() as session:
        await set_search_path(session)
        yield session
