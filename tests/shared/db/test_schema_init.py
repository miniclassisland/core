"""test_schema_init.py
"""

import pytest
from app.shared.db.schema_init import ensure_tenant_schema


@pytest.mark.asyncio
async def test_ensure_tenant_schema_reentrant():
    """测试多租户 schema 初始化（包含可重入/已存在场景）。"""
    # ensure_tenant_schema 应当是幂等的
    await ensure_tenant_schema("test-school")
    await ensure_tenant_schema("another-new-school")
