"""Community administration endpoints."""

from fastapi import APIRouter, Depends

from app.shared.security.auth import require_role
from app.shared.utils.community import clear_all_pending_community_codes

router = APIRouter(prefix="/community", tags=["Community"])
_sa = require_role(100)


@router.post("/refresh_code")
async def rotate_community_code(_user=Depends(_sa)):
    """Invalidate all pending per-user join codes and rotate the fallback code."""
    return {"code": await clear_all_pending_community_codes()}
