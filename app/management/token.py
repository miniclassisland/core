from fastapi import APIRouter, Depends, Request

from app.shared.utils.config import REDIS_DB_AUTH
from app.shared.utils.redis import get_redis
from app.shared.security.auth import get_current_user_id, create_session_token
from app.shared.schemas.schemas import MessageResponse

router = APIRouter(prefix="/token", tags=["Token"])


@router.post("/refresh")
async def refresh_token(
    user_id: str = Depends(get_current_user_id),
):
    """Refresh current session token."""
    token = await create_session_token(user_id)
    return {"token": token}


@router.post("/verify")
async def verify_token(
    user_id: str = Depends(get_current_user_id),
):
    """Verify current token validity and return user ID."""
    return {"valid": True, "user_id": user_id}


@router.post("/deactivate", response_model=MessageResponse)
async def deactivate_token(request: Request):
    """Deactivate current session token (Log out)."""
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        rd = get_redis(REDIS_DB_AUTH)
        await rd.delete(f"session:{auth[7:]}")
    return MessageResponse(message="Logged out successfully")
