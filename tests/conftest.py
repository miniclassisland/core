import sys
import os
import pytest
import pytest_asyncio

# Force tests to use dedicated test database miniclassisland_test to protect runtime database
TEST_DB_URL = os.getenv("TEST_DATABASE_URL", "postgresql+psycopg://postgres:password@localhost:5432/miniclassisland_test")
os.environ["DATABASE_URL"] = TEST_DB_URL

import app.shared.utils.config as cfg
from app.shared.db import session as db_session
cfg.DATABASE_URL = TEST_DB_URL
from sqlalchemy.ext.asyncio import create_async_engine
test_engine = create_async_engine(TEST_DB_URL, echo=False)
db_session.engine = test_engine
db_session.AsyncSessionLocal.configure(bind=test_engine)

# Remove tests directory from sys.path to avoid shadowing third-party modules like grpc
paths_to_remove = []
for path in sys.path:
    normalized = os.path.normpath(path)
    parts = normalized.split(os.sep)
    if parts and parts[-1] == "tests":
        paths_to_remove.append(path)

for path in paths_to_remove:
    try:
        sys.path.remove(path)
    except ValueError:
        pass


@pytest_asyncio.fixture(autouse=True)
async def db_cleaner():
    """Clean all database tables in test database before each test to ensure test isolation."""
    from app.shared.db.models import Base
    from sqlalchemy import text

    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        for table in reversed(Base.metadata.sorted_tables):
            await conn.execute(text(f'TRUNCATE TABLE "{table.name}" CASCADE;'))


@pytest_asyncio.fixture
async def test_superadmin_user():
    """Fixture to create and return a superadmin user ID for testing."""
    from datetime import datetime, timezone
    from app.shared.db.session import AsyncSessionLocal
    from app.shared.db.models import User
    from app.shared.security.crypto import hash_password
    from sqlalchemy import select

    async with AsyncSessionLocal() as db:
        existing = (await db.execute(select(User).where(User.username == "superadmin_test"))).scalar_one_or_none()
        if existing:
            return existing.id

        user = User(
            username="superadmin_test",
            email="superadmin@school.com",
            hashed_password=hash_password("SuperAdmin123!"),
            display_name="Super Admin Test",
            role_code="superadmin",
            is_active=True,
            can_create_account=True,
            created_at=datetime.now(timezone.utc),
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)
        return user.id


