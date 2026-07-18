import json
import logging
from datetime import datetime, timezone
from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.shared.db.session import get_db
from app.shared.db.models import MODEL_MAP
from app.shared.schemas.schemas import BatchRequest, BatchOpType

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/bulk", tags=["Bulk"])


def dict_deep_merge(base: dict, merge: dict) -> dict:
    """递归合并两个字典，冲突时以 merge 为准。"""
    for k, v in merge.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            base[k] = dict_deep_merge(base[k], v)
        else:
            base[k] = v
    return base


async def process_batch(req: BatchRequest, db: AsyncSession):
    """顺序执行一组资源操作并返回结果。"""
    res = []
    try:
        for op in req.operations:
            model = MODEL_MAP.get(op.resource_type)
            if not model:
                res.append({"action": op.action, "name": op.name, "status": "skipped"})
                continue
            record = (
                await db.execute(select(model).where(model.name == op.name))
            ).scalar_one_or_none()
            if op.action == BatchOpType.delete and record:
                await db.delete(record)
            elif op.action in [BatchOpType.write, BatchOpType.create]:
                rc = record or model(name=op.name)
                rc.content = json.dumps(op.payload or {})
                rc.version = (getattr(rc, "version", None) or 0) + 1
                rc.updated_at = datetime.now(timezone.utc)
                db.add(rc)
            elif op.action == BatchOpType.update and record:
                cur = json.loads(record.content) if record.content else {}
                record.content = json.dumps(
                    dict_deep_merge(cur, op.payload or {})
                )
                record.version = (record.version or 0) + 1
                record.updated_at = datetime.now(timezone.utc)
            res.append({"action": op.action, "name": op.name, "status": "success"})
        await db.commit()
        return {"status": "success", "results": res}
    except Exception as exc:
        await db.rollback()
        logger.exception("批量操作异常: %s", exc)
        return {"status": "error", "message": "内部错误，请联系管理员"}


@router.post("")
async def admin_bulk(
    req: BatchRequest,
    db: AsyncSession = Depends(get_db),
):
    """以超管身份执行批量操作。"""
    return await process_batch(req, db)
