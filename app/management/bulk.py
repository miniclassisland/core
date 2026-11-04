from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.shared.db.session import get_db
from app.shared.schemas.schemas import BatchRequest
from app.shared.security.auth import require_role
from app.admin.bulk import process_batch

router = APIRouter(tags=["Bulk"])
_sa = require_role(100)


@router.post("/bulk")
@router.post("/account/bulk")
async def bulk_operations(
    req: BatchRequest,
    db: AsyncSession = Depends(get_db),
    _user=Depends(_sa),
):
    """Execute batch resource operations under tenant scope."""
    return await process_batch(req, db)
