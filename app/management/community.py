"""Community-related management endpoints."""

from typing import Optional

from fastapi import APIRouter, Body, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.shared.db.session import get_db
from app.shared.security.auth import get_current_user_id
from app.shared.security.turnstile import require_turnstile_verification
from app.shared.utils.community import get_community_code
from app.shared.utils.logging import get_client_ip_from_request

router = APIRouter(prefix="/community", tags=["Community"])


class CommunityCodeRequest(BaseModel):
    """Community code request payload with a Turnstile token."""

    cf_turnstile_response: Optional[str] = Field(default=None, max_length=4096)


@router.post("/code")
async def issue_community_code(
    request: Request,
    payload: CommunityCodeRequest = Body(...),
    db: AsyncSession = Depends(get_db),
    _user_id: str = Depends(get_current_user_id),
):
    """Return the community join code to a logged-in, human-verified user."""
    client_ip = (
        get_client_ip_from_request(request) if hasattr(request, "headers") else ""
    )
    await require_turnstile_verification(
        payload.cf_turnstile_response,
        remote_ip=client_ip,
        db=db,
        expected_action="community_code",
    )
    return {"code": get_community_code()}
