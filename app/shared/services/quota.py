"""MINIClassIsland 租户资源配额度量与限制管理共享服务。

包含对指定账户资源的检查、递增扣减、以及管理员针对账户限额设定等全部功能。
"""

import uuid
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.shared.db.models import AccountQuota


async def get_quota_record(
    account_id: str, key: str, db: AsyncSession
) -> AccountQuota | None:
    """查询指定账户的配额记录实体。"""
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
    """检查账户在指定配额项上是否未达上限（允许继续消费）。"""
    quota = await get_quota_record(account_id, quota_key, db)
    if not quota:
        return True  # 未设置配额时默认为无限制
    if quota.max_value == -1:
        return True  # -1 标志无配额上限
    return quota.current_value < quota.max_value


async def increment_quota(
    account_id: str,
    quota_key: str,
    db: AsyncSession,
    *,
    amount: int = 1,
) -> bool:
    """递增配额使用量。超出上限则返回 False。"""
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
    """查询指定账户的全部限额及使用量状态列表。"""
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
    """创建或更新账户的限额上限值。"""
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
