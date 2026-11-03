"""test_quota.py"""

import pytest
from app.shared.services import quota
from app.shared.db.session import AsyncSessionLocal
from app.shared.db.models import AccountQuota


@pytest.mark.asyncio
async def test_quota_service_fallback():
    """Test quota checks when unset, unlimited (-1), under limit, and at limit, plus get_quotas and set_quota."""
    account_id = "test-account-00000000"
    async with AsyncSessionLocal() as db:
        assert await quota.check_quota(account_id, "clients_limit", db) is True

        # Create quota via set_quota
        q = await quota.set_quota(account_id, "clients_limit", 5, db)
        assert q.max_value == 5

        # Update existing quota via set_quota to -1 (unlimited)
        q_unlim = await quota.set_quota(account_id, "clients_limit", -1, db)
        assert q_unlim.max_value == -1
        assert await quota.check_quota(account_id, "clients_limit", db) is True

        # Update back to 5 and test under/over limit
        q = await quota.set_quota(account_id, "clients_limit", 5, db)
        q.current_value = 4
        await db.commit()
        assert await quota.check_quota(account_id, "clients_limit", db) is True

        q.current_value = 5
        await db.commit()
        assert await quota.check_quota(account_id, "clients_limit", db) is False

        all_q = await quota.get_quotas(account_id, db)
        assert len(all_q) == 1


@pytest.mark.asyncio
async def test_quota_increment():
    """Test increment_quota under limit, over limit, and unset."""
    account_id = "test-account-00000000"
    async with AsyncSessionLocal() as db:
        q = AccountQuota(
            account_id=account_id,
            quota_key="bandwidth",
            max_value=100,
            current_value=0,
        )
        db.add(q)
        await db.commit()

        assert (
            await quota.increment_quota(account_id, "bandwidth", db, amount=50) is True
        )
        await db.refresh(q)
        assert q.current_value == 50

        assert (
            await quota.increment_quota(account_id, "bandwidth", db, amount=60) is False
        )
        await db.refresh(q)
        assert q.current_value == 50

        assert (
            await quota.increment_quota(account_id, "non_existent", db, amount=10)
            is True
        )
