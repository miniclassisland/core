"""多租户独立数据库 Schema 初始化工具。
"""

from sqlalchemy import text
from app.shared.db.session import engine
from app.shared.db.models import Base
from app.shared.utils.tenant import safe_identifier

# 属于 public Schema 的全局数据表列表（不在租户私有 Schema 内创建）
_PUBLIC_ONLY = {
    "accounts",
    "users",
    "custom_roles",
    "account_members",
    "permission_defs",
    "member_permissions",
    "role_permissions",
    "account_quotas",
    "system_config",
    "reserved_names",
    "invitations",
}


async def ensure_tenant_schema(slug: str) -> str:
    """确保多租户隔离 Schema 存在，不存在则为该租户创建专用 Schema 与表空间。"""
    schema_name = safe_identifier(f"tenant_{slug}")
    tenant_tables = [
        t for t in Base.metadata.sorted_tables if t.name not in _PUBLIC_ONLY
    ]
    async with engine.begin() as conn:
        await conn.execute(text(f'CREATE SCHEMA IF NOT EXISTS "{schema_name}"'))
        await conn.execute(text(f'SET search_path TO "{schema_name}"'))
        await conn.run_sync(
            lambda sync_conn: Base.metadata.create_all(sync_conn, tables=tenant_tables)
        )
        await conn.execute(text("SET search_path TO public"))
    return schema_name
