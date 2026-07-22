"""MINIClassIsland tenant resource quota metrics and limitation management service.
"""

import uuid
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.shared.db.models import AccountQuota


async def get_quota_record(
    account_id: str, key: str, db: AsyncSession
) -> AccountQuota | None:
    """Query quota record entity for specified account."""
    result = await db.execute(
        select(AccountQuota).where(
            AccountQuota.account_id == account_id,
            AccountQuota.quota_key == key,
        )
    )
    return result.scalar_one_or_none()


async def check_quota(
    account_id: str,
    quota_key: str,
    db: AsyncSession,
) -> bool:
    """Check if tenant account has not reached quota limit for a given quota key."""
    quota = await get_quota_record(account_id, quota_key, db)
    if not quota:
        return True  # Unlimited if not set
    if quota.max_value == -1:
        return True  # -1 represents no limit
    return quota.current_value < quota.max_value


async def increment_quota(
    account_id: str,
    quota_key: str,
    db: AsyncSession,
    *,
    amount: int = 1,
) -> bool:
    """Increment quota usage. Returns False if limit exceeded."""
    quota = await get_quota_record(account_id, quota_key, db)
    if not quota:
        return True
    if quota.max_value != -1:
        if quota.current_value + amount > quota.max_value:
            return False
    quota.current_value += amount
    await db.commit()
    return True


async def get_quotas(account_id: str, db: AsyncSession) -> list[AccountQuota]:
    """Get all quota records and current usage for account."""
    result = await db.execute(
        select(AccountQuota).where(AccountQuota.account_id == account_id)
    )
    return list(result.scalars().all())


async def set_quota(
    account_id: str,
    quota_key: str,
    max_value: int,
    db: AsyncSession,
) -> AccountQuota:
    """Create or update quota maximum value for account."""
    existing = await get_quota_record(account_id, quota_key, db)
    if existing:
        existing.max_value = max_value
        await db.commit()
        return existing

    quota = AccountQuota(
        id=str(uuid.uuid4()),
        account_id=account_id,
        quota_key=quota_key,
        max_value=max_value,
    )
    db.add(quota)
    await db.commit()
    return quota
