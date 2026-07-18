"""test_tenant.py
"""

import pytest
from app.shared.utils import tenant
from app.shared.db.session import AsyncSessionLocal


def test_context_vars():
    """测试 tenant_ctx 和 schema_ctx 的 ContextVar 获取。"""
    # 夹具 setup_infra 已经设置了默认值
    assert tenant.get_tenant_id() == "test-account-00000000"
    assert tenant.get_schema_name() == "tenant_test-school"


def test_extract_slug_from_host():
    """测试主机域名到租户标识的提取解析。"""
    # 正常二级域名场景
    assert tenant.extract_slug_from_host("school1.localhost") == "school1"
    # 主域或 IP 时应当返回 None
    assert tenant.extract_slug_from_host("localhost") is None
    assert tenant.extract_slug_from_host("127.0.0.1") is None
    # 其它空或无效输入
    assert tenant.extract_slug_from_host("") is None


@pytest.mark.asyncio
async def test_resolve_account():
    """测试从数据库中检索并缓存商户账户记录。"""
    async with AsyncSessionLocal() as db:
        # 已在 conftest.py 中插入 "test-school" 账户记录
        acc = await tenant.resolve_account("test-school", db)
        assert acc is not None
        assert acc.id == "test-account-00000000"

        # 校验不存在的租户账户
        not_exist = await tenant.resolve_account("non-existent", db)
        assert not_exist is None


@pytest.mark.asyncio
async def test_set_search_path():
    """测试通过 Schema 上下文动态路由 PostgreSQL Search Path。"""
    async with AsyncSessionLocal() as db:
        # 当存在 schema_ctx 时，应当设置成功并无报错
        await tenant.set_search_path(db)

        # 清除 schema_ctx 尝试，应走 fallback 为 public
        token = tenant.schema_ctx.set(None)
        try:
            await tenant.set_search_path(db)
        finally:
            tenant.schema_ctx.reset(token)
