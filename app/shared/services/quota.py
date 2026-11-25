"""MINI ClassIsland tenant resource quota metrics and limitation management service."""

import asyncio
import logging
import time
import uuid
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.shared.db.models import AccountQuota, ClientRecord
from app.shared.literals import DEFAULT_QUOTAS

logger = logging.getLogger(__name__)

_BYTES_PER_MB = 1024 * 1024
# Periodic flush interval (seconds) and idle partial-MB flush threshold
_BANDWIDTH_FLUSH_INTERVAL_SEC = 30.0
_BANDWIDTH_IDLE_FLUSH_SEC = 120.0
_BANDWIDTH_IDLE_MIN_BYTES = 256 * 1024  # 256 KB

# High-performance in-memory bandwidth byte accumulator per tenant account
_BANDWIDTH_BYTES: dict[str, int] = {}
_BANDWIDTH_LAST_TOUCH: dict[str, float] = {}
_BANDWIDTH_FLUSH_LOCK: asyncio.Lock | None = None
_BANDWIDTH_FLUSHER_TASK: asyncio.Task | None = None


def _get_flush_lock() -> asyncio.Lock:
    global _BANDWIDTH_FLUSH_LOCK
    if _BANDWIDTH_FLUSH_LOCK is None:
        _BANDWIDTH_FLUSH_LOCK = asyncio.Lock()
    return _BANDWIDTH_FLUSH_LOCK


def record_bandwidth_bytes(account_id: str, byte_count: int) -> int:
    """Record outbound/inbound payload bytes for tenant account in O(1) memory."""
    if not account_id or account_id == "default" or byte_count <= 0:
        return 0
    total = _BANDWIDTH_BYTES.get(account_id, 0) + byte_count
    _BANDWIDTH_BYTES[account_id] = total
    _BANDWIDTH_LAST_TOUCH[account_id] = time.monotonic()
    return total


def get_bandwidth_mb(account_id: str, db_current_mb: int = 0) -> int:
    """Calculate total bandwidth usage in MB combining DB persisted value and live byte counter."""
    raw_bytes = _BANDWIDTH_BYTES.get(account_id, 0)
    live_mb = (raw_bytes + _BYTES_PER_MB - 1) // _BYTES_PER_MB if raw_bytes > 0 else 0
    return db_current_mb + live_mb


def reset_bandwidth_bytes(account_id: str) -> None:
    """Reset in-memory bandwidth byte counter for specified account."""
    _BANDWIDTH_BYTES.pop(account_id, None)
    _BANDWIDTH_LAST_TOUCH.pop(account_id, None)


async def flush_bandwidth_bytes(
    db: AsyncSession,
    account_id: str | None = None,
    *,
    force: bool = False,
) -> int:
    """Flush accumulated in-memory bandwidth bytes to the database in a single batch.

    When ``force=False`` (normal periodic flush), whole megabytes (>= 1 MB) are always
    flushed, and idle accounts (>= 256 KB untouched for >= 120s) are also flushed as 1 MB
    so low-volume traffic is not lost across restarts.
    When ``force=True`` (graceful shutdown), any remaining non-zero bytes are flushed
    using ceiling-MB rounding.
    """
    now = time.monotonic()
    async with _get_flush_lock():
        if account_id is not None:
            candidate_ids = [account_id] if account_id in _BANDWIDTH_BYTES else []
        else:
            candidate_ids = list(_BANDWIDTH_BYTES.keys())

        to_flush: dict[str, tuple[int, int]] = {}  # account_id -> (flushed_mb, consumed_bytes)
        for aid in candidate_ids:
            raw = _BANDWIDTH_BYTES.get(aid, 0)
            if raw <= 0:
                _BANDWIDTH_BYTES.pop(aid, None)
                _BANDWIDTH_LAST_TOUCH.pop(aid, None)
                continue
            if force:
                flushed_mb = (raw + _BYTES_PER_MB - 1) // _BYTES_PER_MB
                to_flush[aid] = (flushed_mb, raw)
            elif raw >= _BYTES_PER_MB:
                flushed_mb = raw // _BYTES_PER_MB
                to_flush[aid] = (flushed_mb, flushed_mb * _BYTES_PER_MB)
            elif (
                raw >= _BANDWIDTH_IDLE_MIN_BYTES
                and (now - _BANDWIDTH_LAST_TOUCH.get(aid, now)) >= _BANDWIDTH_IDLE_FLUSH_SEC
            ):
                to_flush[aid] = (1, raw)

        if not to_flush:
            return 0

        result = await db.execute(
            select(AccountQuota).where(
                AccountQuota.account_id.in_(list(to_flush.keys())),
                AccountQuota.quota_key == "max_bandwidth_mb",
            )
        )
        existing_map = {q.account_id: q for q in result.scalars().all()}
        default_bw_max = dict(DEFAULT_QUOTAS).get("max_bandwidth_mb", -1)

        total_flushed_mb = 0
        for aid, (flushed_mb, consumed_bytes) in to_flush.items():
            q = existing_map.get(aid)
            if q is None:
                q = AccountQuota(
                    id=str(uuid.uuid4()),
                    account_id=aid,
                    quota_key="max_bandwidth_mb",
                    max_value=default_bw_max,
                    current_value=flushed_mb,
                )
                db.add(q)
            else:
                q.current_value = (q.current_value or 0) + flushed_mb
            total_flushed_mb += flushed_mb

        await db.commit()

        # Subtract only the bytes that were committed so concurrent increments are preserved
        for aid, (_, consumed_bytes) in to_flush.items():
            rem = _BANDWIDTH_BYTES.get(aid, 0) - consumed_bytes
            if rem > 0:
                _BANDWIDTH_BYTES[aid] = rem
            else:
                _BANDWIDTH_BYTES.pop(aid, None)
                _BANDWIDTH_LAST_TOUCH.pop(aid, None)

        return total_flushed_mb


async def _bandwidth_flush_loop() -> None:
    """Background loop that periodically persists accumulated bandwidth counters."""
    from app.shared.db.session import AsyncSessionLocal

    while True:
        try:
            await asyncio.sleep(_BANDWIDTH_FLUSH_INTERVAL_SEC)
            if not _BANDWIDTH_BYTES:
                continue
            async with AsyncSessionLocal() as db:
                await flush_bandwidth_bytes(db, force=False)
        except asyncio.CancelledError:
            break
        except Exception as exc:
            logger.warning("Periodic bandwidth flush failed: %s", exc)


def start_bandwidth_flusher() -> None:
    """Start the periodic background bandwidth flusher task."""
    global _BANDWIDTH_FLUSHER_TASK
    if _BANDWIDTH_FLUSHER_TASK is None or _BANDWIDTH_FLUSHER_TASK.done():
        _BANDWIDTH_FLUSHER_TASK = asyncio.create_task(_bandwidth_flush_loop())


async def stop_bandwidth_flusher() -> None:
    """Stop the periodic flusher and perform a final forced flush of remaining bytes."""
    global _BANDWIDTH_FLUSHER_TASK
    if _BANDWIDTH_FLUSHER_TASK is not None and not _BANDWIDTH_FLUSHER_TASK.done():
        _BANDWIDTH_FLUSHER_TASK.cancel()
        try:
            await _BANDWIDTH_FLUSHER_TASK
        except asyncio.CancelledError:
            pass
    _BANDWIDTH_FLUSHER_TASK = None

    if _BANDWIDTH_BYTES:
        try:
            from app.shared.db.session import AsyncSessionLocal

            async with AsyncSessionLocal() as db:
                await flush_bandwidth_bytes(db, force=True)
        except Exception as exc:
            logger.warning("Final shutdown bandwidth flush failed: %s", exc)


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
        # New edit/assist capability flags default to disabled even on legacy accounts without a seeded row
        if quota_key in ("feature.remote_edit", "feature.assist_another"):
            return False
        return True  # Unlimited if not set
    if quota.max_value == -1:
        if quota_key == "max_bandwidth_mb":
            raw_bytes = _BANDWIDTH_BYTES.get(account_id, 0)
            if raw_bytes >= _BYTES_PER_MB:
                flushed_mb = raw_bytes // _BYTES_PER_MB
                _BANDWIDTH_BYTES[account_id] = raw_bytes % _BYTES_PER_MB
                quota.current_value = (quota.current_value or 0) + flushed_mb
                await db.commit()
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
