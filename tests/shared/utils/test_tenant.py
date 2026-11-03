"""test_tenant.py"""

from contextvars import copy_context
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock
import pytest
from app.shared.utils import tenant
from app.shared.db.session import AsyncSessionLocal
from app.shared.db.models import Account, _default_account_id


def test_context_vars():
    """测试 tenant_ctx 和 schema_ctx 的 ContextVar 获取。"""
    # 在全新空 Context 中验证 LookupError -> RuntimeError 及 fallback
    ctx = copy_context()

    def _check_unset():
        with pytest.raises(RuntimeError):
            tenant.get_tenant_id()
        assert tenant.get_tenant_id_or_default("def") == "def"
        assert _default_account_id() == "default"

    ctx.run(_check_unset)

    t1 = tenant.tenant_ctx.set("test-account-00000000")
    t2 = tenant.schema_ctx.set("tenant_test-school")
    try:
        assert tenant.get_tenant_id() == "test-account-00000000"
        assert tenant.get_tenant_id_or_default("def") == "test-account-00000000"
        assert _default_account_id() == "test-account-00000000"
        assert tenant.get_schema() == "tenant_test-school"
    finally:
        tenant.tenant_ctx.reset(t1)
        tenant.schema_ctx.reset(t2)

    t_empty = tenant.tenant_ctx.set("")
    try:
        assert tenant.get_tenant_id_or_default("def") == "def"
        assert _default_account_id() == "default"
    finally:
        tenant.tenant_ctx.reset(t_empty)

    with pytest.raises(ValueError):
        tenant.safe_identifier("bad-ident;DROP")


def test_extract_slug_from_host():
    """测试主机域名到租户标识的提取解析。"""
    domain = tenant.BASE_DOMAIN
    assert tenant.extract_slug_from_host(f"school1.{domain}") == "school1"
    assert tenant.extract_slug_from_host(domain) is None
    assert tenant.extract_slug_from_host("127.0.0.1") is None
    assert tenant.extract_slug_from_host("") is None


@pytest.mark.asyncio
async def test_resolve_account():
    """测试从数据库中检索并缓存商户账户记录。"""
    async with AsyncSessionLocal() as db:
        from sqlalchemy import select

        acct = (
            await db.execute(select(Account).where(Account.slug == "test-school"))
        ).scalar_one_or_none()
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

        await tenant.invalidate_cached_account("test-school")
        acc = await tenant.resolve_account("test-school", db)
        assert acc is not None
        assert acc.slug == "test-school"

        # 命中缓存
        acc_cached = await tenant.resolve_account("test-school", db)
        assert acc_cached is not None

        not_exist = await tenant.resolve_account("non-existent", db)
        assert not_exist is None

        # 测试 Redis 异常容错分支
        bad_redis = MagicMock()
        bad_redis.get.side_effect = RuntimeError("redis down")
        bad_redis.set.side_effect = RuntimeError("redis down")
        bad_redis.delete.side_effect = RuntimeError("redis down")
        with patch("app.shared.utils.tenant.get_redis", return_value=bad_redis):
            assert await tenant.get_cached_account("test-school") is None
            await tenant.set_cached_account("test-school", acct)
            await tenant.invalidate_cached_account("test-school")


@pytest.mark.asyncio
async def test_set_search_path():
    """测试通过 Schema 上下文动态路由 PostgreSQL Search Path。"""
    async with AsyncSessionLocal() as db:
        token = tenant.schema_ctx.set("tenant_test_school")
        try:
            await tenant.set_search_path(db)
        finally:
            tenant.schema_ctx.reset(token)
