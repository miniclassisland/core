"""test_schema_init.py"""

import pytest
from app.shared.db.session import AsyncSessionLocal
from app.shared.db.schema_init import seed_account_defaults


@pytest.mark.asyncio
async def test_seed_account_defaults_reentrant():
    """Test idempotent default profile resource seeding for a tenant account."""
    async with AsyncSessionLocal() as db:
        await seed_account_defaults("test-seed-acct-1", db)
        await seed_account_defaults("test-seed-acct-1", db)
