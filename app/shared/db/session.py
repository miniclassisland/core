"""Database engine and async Session manager."""

from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from app.shared.utils.config import DATABASE_URL
from app.shared.utils.tenant import set_search_path
from app.shared.db.models import Base

# Configure async database engine for 10,000+ active devices high concurrency
engine = create_async_engine(
    DATABASE_URL,
    echo=False,
    pool_size=60,
    max_overflow=140,
    pool_pre_ping=True,
    pool_recycle=1800,
)

# Create async Session factory
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def init_db() -> None:
    """Execute DDL to create public tables and ensure schema columns in the database."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        if engine.dialect.name == "postgresql":
            await conn.execute(
                text(
                    "ALTER TABLE community_bindings ADD COLUMN IF NOT EXISTS is_manual BOOLEAN NOT NULL DEFAULT FALSE"
                )
            )
            await conn.execute(
                text(
                    "ALTER TABLE community_bindings ADD COLUMN IF NOT EXISTS is_joined BOOLEAN NOT NULL DEFAULT TRUE"
                )
            )
            await conn.execute(
                text(
                    "ALTER TABLE clients ADD COLUMN IF NOT EXISTS extend_management_enabled BOOLEAN NOT NULL DEFAULT FALSE"
                )
            )
            await conn.execute(
                text(
                    "ALTER TABLE clients ADD COLUMN IF NOT EXISTS extend_management_version VARCHAR(64)"
                )
            )
            await conn.execute(
                text(
                    "ALTER TABLE clients ADD COLUMN IF NOT EXISTS is_app_locked BOOLEAN NOT NULL DEFAULT FALSE"
                )
            )
            await conn.execute(
                text(
                    "ALTER TABLE clients ADD COLUMN IF NOT EXISTS plugin_settings_json TEXT"
                )
            )
            await conn.execute(
                text(
                    "ALTER TABLE clients ADD COLUMN IF NOT EXISTS plugin_components_json TEXT"
                )
            )
            await conn.execute(
                text(
                    "ALTER TABLE clients ADD COLUMN IF NOT EXISTS hardware_info_json TEXT"
                )
            )


async def get_db():
    """FastAPI dependency: acquire async session, apply tenant search_path context, and release on exit."""
    async with AsyncSessionLocal() as session:
        await set_search_path(session)
        yield session
