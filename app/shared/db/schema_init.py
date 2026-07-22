"""Multi-tenant isolated database Schema initialization utility.
"""

from sqlalchemy import text
from app.shared.db.session import engine
from app.shared.db.models import Base
from app.shared.utils.tenant import safe_identifier

# Tables belonging exclusively to public Schema (not created in tenant private Schema)
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
    """Ensure multi-tenant isolation schema exists, creating dedicated schema and tables if needed."""
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
