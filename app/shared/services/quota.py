"""MINI ClassIsland tenant resource quota metrics and limitation management service."""

import uuid
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.shared.db.models import AccountQuota, ClientRecord
from app.shared.literals import DEFAULT_QUOTAS


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
    *,
    live_current: int | None = None,
) -> bool:
    """Check if tenant account has not reached quota limit for a given quota key."""
    if not account_id or account_id == "default":
        return True
    quota = await get_quota_record(account_id, quota_key, db)
    if not quota:
        return True  # Unlimited if not set
    if quota.max_value == -1:
        return True  # -1 represents no limit
    if quota_key.startswith("feature."):
        return quota.max_value > 0
    if live_current is not None:
        return live_current < quota.max_value
    if quota_key == "max_clients":
        cnt = (
            await db.scalar(
                select(func.count(ClientRecord.uid)).where(
                    ClientRecord.account_id == account_id
                )
            )
            or 0
        )
        return cnt < quota.max_value
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
    """Get all quota records and current usage for account, seeding missing default keys."""
    result = await db.execute(
        select(AccountQuota).where(AccountQuota.account_id == account_id)
    )
    rows = list(result.scalars().all())
    existing_keys = {r.quota_key for r in rows}
    added = False
    for key, default_val in DEFAULT_QUOTAS:
        if key not in existing_keys:
            q = AccountQuota(
                id=str(uuid.uuid4()),
                account_id=account_id,
                quota_key=key,
                max_value=default_val,
            )
            db.add(q)
            rows.append(q)
            added = True
    if added:
        await db.commit()
    return rows


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
