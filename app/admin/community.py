"""Community administration endpoints."""

from fastapi import APIRouter, Depends

from app.shared.security.auth import require_role
from app.shared.utils.community import refresh_community_code

router = APIRouter(prefix="/community", tags=["Community"])
_sa = require_role(100)


@router.post("/refresh_code")
async def rotate_community_code(_user=Depends(_sa)):
    """Rotate and return the in-memory community join code."""
    return {"code": refresh_community_code()}
