"""test_quota.py
"""

import pytest
from app.shared.services import quota
from app.shared.db.session import AsyncSessionLocal
from app.shared.db.models import AccountQuota


@pytest.mark.asyncio
async def test_quota_service_fallback():
    """测试当无配置或有配置时的限额限制。"""
    account_id = "test-account-00000000"
    async with AsyncSessionLocal() as db:
        # 1. 未设置配额时，默认应该返回 True (无限制)
        assert await quota.check_quota(account_id, "clients_limit", db) is True

        # 2. 写入具体的配额规则
        q = AccountQuota(
            account_id=account_id,
            quota_key="clients_limit",
            max_value=5,
            current_value=4,
        )
        db.add(q)
        await db.commit()

        # 当前值是 4，最大值是 5。4 < 5，所以 check_quota 应该是 True
        assert await quota.check_quota(account_id, "clients_limit", db) is True

        # 修改当前值到 5，5 < 5 应该为 False
        q.current_value = 5
        await db.commit()
        assert await quota.check_quota(account_id, "clients_limit", db) is False


@pytest.mark.asyncio
async def test_quota_increment():
    """测试配额消耗值（如带宽使用量）的自增累计更新。"""
    account_id = "test-account-00000000"
    async with AsyncSessionLocal() as db:
        # 1. 写入一个限制为 100，当前为 0 的配额
        q = AccountQuota(
            account_id=account_id,
            quota_key="bandwidth",
            max_value=100,
            current_value=0,
        )
        db.add(q)
        await db.commit()

        # 2. 自增 50，应该成功并且 current_value 变为 50
        assert await quota.increment_quota(account_id, "bandwidth", db, amount=50) is True
        await db.refresh(q)
        assert q.current_value == 50

        # 3. 再次自增 60，由于 50 + 60 = 110 > 100，应该失败返回 False，并且值不改变
        assert await quota.increment_quota(account_id, "bandwidth", db, amount=60) is False
        await db.refresh(q)
        assert q.current_value == 50

        # 4. 自增一个不存在的配额，应该返回 True (未设置限制默认为无限制)
        assert await quota.increment_quota(account_id, "non_existent", db, amount=10) is True
