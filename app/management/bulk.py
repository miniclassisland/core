from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.shared.db.session import get_db
from app.shared.schemas.schemas import BatchRequest
from app.admin.bulk import process_batch

router = APIRouter(prefix="/bulk", tags=["Bulk"])


@router.post("")
async def bulk_operations(
    req: BatchRequest,
    db: AsyncSession = Depends(get_db),
):
    """商户租户身份执行批量资源操作。"""
    return await process_batch(req, db)
