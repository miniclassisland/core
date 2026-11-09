"""MINI ClassIsland tenant resource quota metrics and limitation management service."""

import uuid
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.shared.db.models import AccountQuota, ClientRecord
from app.shared.literals import DEFAULT_QUOTAS

# High-performance in-memory bandwidth byte accumulator per tenant account
_BANDWIDTH_BYTES: dict[str, int] = {}


def record_bandwidth_bytes(account_id: str, byte_count: int) -> int:
    """Record outbound/inbound payload bytes for tenant account in O(1) memory."""
    if not account_id or account_id == "default" or byte_count <= 0:
        return 0
    total = _BANDWIDTH_BYTES.get(account_id, 0) + byte_count
    _BANDWIDTH_BYTES[account_id] = total
    return total


def get_bandwidth_mb(account_id: str, db_current_mb: int = 0) -> int:
    """Calculate total bandwidth usage in MB combining DB persisted value and live byte counter."""
    raw_bytes = _BANDWIDTH_BYTES.get(account_id, 0)
    live_mb = (raw_bytes + (1024 * 1024) - 1) // (1024 * 1024) if raw_bytes > 0 else 0
    return db_current_mb + live_mb


def reset_bandwidth_bytes(account_id: str) -> None:
    """Reset in-memory bandwidth byte counter for specified account."""
    _BANDWIDTH_BYTES.pop(account_id, None)


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
    if quota_key == "max_bandwidth_mb":
        raw_bytes = _BANDWIDTH_BYTES.get(account_id, 0)
        if raw_bytes >= 1024 * 1024:
            flushed_mb = raw_bytes // (1024 * 1024)
            _BANDWIDTH_BYTES[account_id] = raw_bytes % (1024 * 1024)
            quota.current_value = (quota.current_value or 0) + flushed_mb
            await db.commit()
        return get_bandwidth_mb(account_id, quota.current_value) < quota.max_value
    return quota.current_value < quota.max_value


async def get_quotas(account_id: str, db: AsyncSession) -> list[AccountQuota]:
    """Get all quota records and current usage for account, seeding missing default keys."""
    result = await db.execute(
        select(AccountQuota).where(AccountQuota.account_id == account_id)
    )
    rows = list(result.scalars().all())
    existing_keys = {r.quota_key for r in rows}
    dirty = False
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
            dirty = True
    raw_bytes = _BANDWIDTH_BYTES.get(account_id, 0)
    if raw_bytes >= 1024 * 1024:
        flushed_mb = raw_bytes // (1024 * 1024)
        _BANDWIDTH_BYTES[account_id] = raw_bytes % (1024 * 1024)
        for r in rows:
            if r.quota_key == "max_bandwidth_mb":
                r.current_value = (r.current_value or 0) + flushed_mb
                dirty = True
                break
    if dirty:
        await db.commit()
    return rows


async def set_quota(
    account_id: str,
    quota_key: str,
    max_value: int,
    db: AsyncSession,
    *,
    base_url: str | None = None,
    token: str | None = None,
    group_id: int | None = None,
    client: object | None = None,
    onebot_caller: object | None = None,
) -> AccountQuota:
    """Create or update quota maximum value for account."""
    existing = await get_quota_record(account_id, quota_key, db)
    if existing:
        changed = existing.max_value != max_value
        existing.max_value = max_value
        await db.commit()
        quota = existing
    else:
        changed = True
        quota = AccountQuota(
            id=str(uuid.uuid4()),
            account_id=account_id,
            quota_key=quota_key,
            max_value=max_value,
        )
        db.add(quota)
        await db.commit()

    if changed and quota_key in ("max_clients", "max_grpc_connections"):
        from app.shared.utils.community import notify_account_device_quota_changed

        await notify_account_device_quota_changed(
            account_id,
            quota_key,
            db,
            group_id=group_id,
            base_url=base_url,
            token=token,
            client=client,  # type: ignore[arg-type]
            onebot_caller=onebot_caller,  # type: ignore[arg-type]
        )
    return quota
