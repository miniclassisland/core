"""test_tenant.py
"""

import pytest
from app.shared.utils import tenant
from app.shared.db.session import AsyncSessionLocal


def test_context_vars():
    """测试 tenant_ctx 和 schema_ctx 的 ContextVar 获取。"""
    t1 = tenant.tenant_ctx.set("test-account-00000000")
    t2 = tenant.schema_ctx.set("tenant_test-school")
    try:
        assert tenant.get_tenant_id() == "test-account-00000000"
        assert tenant.get_schema() == "tenant_test-school"
    finally:
        tenant.tenant_ctx.reset(t1)
        tenant.schema_ctx.reset(t2)


def test_extract_slug_from_host():
    """测试主机域名到租户标识的提取解析。"""
    # 正常二级域名场景
    domain = tenant.BASE_DOMAIN
    assert tenant.extract_slug_from_host(f"school1.{domain}") == "school1"
    # 主域或 IP 时应当返回 None
    assert tenant.extract_slug_from_host(domain) is None
    assert tenant.extract_slug_from_host("127.0.0.1") is None
    # 其它空或无效输入
    assert tenant.extract_slug_from_host("") is None


from datetime import datetime, timezone
from app.shared.db.models import Account


@pytest.mark.asyncio
async def test_resolve_account():
    """测试从数据库中检索并缓存商户账户记录。"""
    async with AsyncSessionLocal() as db:
        from sqlalchemy import select
        acct = (await db.execute(select(Account).where(Account.slug == "test-school"))).scalar_one_or_none()
        if not acct:
            acct = Account(
                id="test-account-00000000",
                name="Test School",
                slug="test-school",
                api_key="test-api-key",
                is_active=True,
                created_at=datetime.now(timezone.utc),
            )
            db.add(acct)
            await db.commit()

        acc = await tenant.resolve_account("test-school", db)
        assert acc is not None
        assert acc.slug == "test-school"

        # 校验不存在的租户账户
        not_exist = await tenant.resolve_account("non-existent", db)
        assert not_exist is None


@pytest.mark.asyncio
async def test_set_search_path():
    """测试通过 Schema 上下文动态路由 PostgreSQL Search Path。"""
    async with AsyncSessionLocal() as db:
        token = tenant.schema_ctx.set("tenant_test_school")
        try:
            await tenant.set_search_path(db)
        finally:
            tenant.schema_ctx.reset(token)
