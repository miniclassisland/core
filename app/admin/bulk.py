import json
import logging
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.shared.db.session import get_db
from app.shared.db.models import MODEL_MAP, ResourceHistory
from app.shared.db.schema_init import record_resource_history
from app.shared.schemas.schemas import BatchRequest, BatchOpType
from app.shared.security.auth import require_role
from app.shared.security.crypto import normalize_resource_payload
from app.shared.utils.tenant import get_tenant_id_or_default

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/bulk", tags=["Bulk"])
_sa = require_role(100)


def dict_deep_merge(base: dict, merge: dict) -> dict:
    """Recursively merge two dictionaries, taking values from merge on conflict."""
    for k, v in merge.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            base[k] = dict_deep_merge(base[k], v)
        else:
            base[k] = v
    return base


async def process_batch(
    req: BatchRequest,
    db: AsyncSession,
    *,
    account_id: Optional[str] = None,
):
    """Execute a batch of resource operations sequentially and return results."""
    from app.management.account import validate_payload

    acct_id = account_id or req.target_account_id or get_tenant_id_or_default()
    res = []
    try:
        for op in req.operations:
            model = MODEL_MAP.get(op.resource_type)
            if not model:
                res.append({"action": op.action, "name": op.name, "status": "skipped"})
                continue
            record = (
                await db.execute(
                    select(model).where(
                        model.account_id == acct_id,
                        model.name == op.name,
                    )
                )
            ).scalar_one_or_none()
            payload = op.payload or {}
            if isinstance(payload, dict):
                validate_payload(payload)
                payload = normalize_resource_payload(op.resource_type, payload)
            if op.action == BatchOpType.delete and record:
                await db.delete(record)
                from sqlalchemy import delete as sql_delete

                await db.execute(
                    sql_delete(ResourceHistory).where(
                        ResourceHistory.account_id == acct_id,
                        ResourceHistory.resource_type == op.resource_type,
                        ResourceHistory.name == op.name,
                    )
                )
            elif op.action in [BatchOpType.write, BatchOpType.create]:
                now = datetime.now(timezone.utc)
                rc = record or model(account_id=acct_id, name=op.name)
                serialized = json.dumps(payload, ensure_ascii=False)
                next_ver = (getattr(rc, "version", None) or 0) + 1
                rc.content = serialized
                rc.version = next_ver
                rc.updated_at = now
                db.add(rc)
                await record_resource_history(
                    db,
                    account_id=acct_id,
                    resource_type=op.resource_type,
                    name=op.name,
                    version=next_ver,
                    content=serialized,
                    created_at=now,
                )
            elif op.action == BatchOpType.update and record:
                now = datetime.now(timezone.utc)
                cur = json.loads(record.content) if record.content else {}
                merged = normalize_resource_payload(
                    op.resource_type, dict_deep_merge(cur, payload)
                )
                validate_payload(merged)
                serialized = json.dumps(merged, ensure_ascii=False)
                next_ver = (record.version or 0) + 1
                record.content = serialized
                record.version = next_ver
                record.updated_at = now
                await record_resource_history(
                    db,
                    account_id=acct_id,
                    resource_type=op.resource_type,
                    name=op.name,
                    version=next_ver,
                    content=serialized,
                    created_at=now,
                )
            res.append({"action": op.action, "name": op.name, "status": "success"})
        await db.commit()
        return {"status": "success", "results": res}
    except HTTPException:
        await db.rollback()
        raise
    except Exception as exc:
        await db.rollback()
        logger.exception("Batch operation exception: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during batch execution",
        )


@router.post("")
async def admin_bulk(
    req: BatchRequest,
    db: AsyncSession = Depends(get_db),
    _user=Depends(_sa),
):
    """Execute batch operations as Super Admin."""
    return await process_batch(req, db)
