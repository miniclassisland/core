"""test_quota.py"""

import pytest
from app.shared.services import quota
from app.shared.db.session import AsyncSessionLocal


@pytest.mark.asyncio
async def test_quota_service_fallback():
    """Test quota checks when unset, unlimited (-1), under limit, and at limit, plus get_quotas and set_quota."""
    account_id = "test-account-00000000"
    async with AsyncSessionLocal() as db:
        assert await quota.check_quota("", "max_clients", db) is True
        assert await quota.check_quota("default", "max_clients", db) is True
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
        assert (
            await quota.check_quota(account_id, "clients_limit", db, live_current=4)
            is True
        )
        assert (
            await quota.check_quota(account_id, "clients_limit", db, live_current=5)
            is False
        )

        q.current_value = 5
        await db.commit()
        assert await quota.check_quota(account_id, "clients_limit", db) is False

        # Test feature.*, max_clients, and max_bandwidth_mb branches
        await quota.set_quota(account_id, "feature.audit", 1, db)
        assert await quota.check_quota(account_id, "feature.audit", db) is True
        await quota.set_quota(account_id, "feature.audit", 0, db)
        assert await quota.check_quota(account_id, "feature.audit", db) is False

        await quota.set_quota(account_id, "max_clients", 1, db)
        assert await quota.check_quota(account_id, "max_clients", db) is True

        assert quota.record_bandwidth_bytes("", 100) == 0
        assert quota.record_bandwidth_bytes("default", 100) == 0
        assert quota.record_bandwidth_bytes(account_id, 0) == 0
        quota.reset_bandwidth_bytes(account_id)
        assert quota.get_bandwidth_mb(account_id, 0) == 0
        assert quota.record_bandwidth_bytes(account_id, 512 * 1024) == 512 * 1024
        assert quota.get_bandwidth_mb(account_id, 0) == 1
        await quota.set_quota(account_id, "max_bandwidth_mb", 2, db)
        assert await quota.check_quota(account_id, "max_bandwidth_mb", db) is True
        await quota.set_quota(account_id, "max_bandwidth_mb", 1, db)
        assert await quota.check_quota(account_id, "max_bandwidth_mb", db) is False
        quota.reset_bandwidth_bytes(account_id)

        all_q = await quota.get_quotas(account_id, db)
        assert len(all_q) >= 5
        all_q_second = await quota.get_quotas(account_id, db)
        assert len(all_q_second) == len(all_q)
