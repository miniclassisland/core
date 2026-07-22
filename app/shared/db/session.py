"""Database engine and async Session manager.
"""

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from app.shared.utils.config import DATABASE_URL
from app.shared.utils.tenant import set_search_path
from app.shared.db.models import Base

# Configure async database engine
engine = create_async_engine(DATABASE_URL, echo=False, pool_size=10, max_overflow=20)

# Create async Session factory
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def init_db() -> None:
    """Execute DDL to create public tables in the database."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_db():
    """FastAPI dependency: acquire async session, apply tenant search_path context, and release on exit."""
    async with AsyncSessionLocal() as session:
        await set_search_path(session)
        yield session
