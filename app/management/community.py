"""Community-related management endpoints."""

from typing import Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.shared.db.session import get_db
from app.shared.security.auth import get_current_user_id
from app.shared.security.turnstile import require_turnstile_verification
from app.shared.utils.community import (
    CommunityAlreadyBoundError,
    MSG_CODE_PROMPT,
    get_user_community_status,
    issue_user_community_code,
)
from app.shared.utils.logging import get_client_ip_from_request

router = APIRouter(prefix="/community", tags=["Community"])


class CommunityCodeRequest(BaseModel):
    """Community code request payload with a Turnstile token."""

    cf_turnstile_response: Optional[str] = Field(default=None, max_length=4096)


@router.get("/status")
async def get_community_status(
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """Get the current user's QQ community binding status and prompt message."""
    return await get_user_community_status(user_id, db)


@router.post("/code")
async def issue_community_code(
    request: Request,
    payload: CommunityCodeRequest = Body(...),
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """Issue a 15-minute per-user community join code to a logged-in, human-verified user."""
    client_ip = (
        get_client_ip_from_request(request) if hasattr(request, "headers") else ""
    )
    await require_turnstile_verification(
        payload.cf_turnstile_response,
        remote_ip=client_ip,
        db=db,
        expected_action="community_code",
    )
    try:
        code, expires_in = await issue_user_community_code(user_id, db)
    except CommunityAlreadyBoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        )
    return {
        "code": code,
        "expires_in": expires_in,
        "prompt": MSG_CODE_PROMPT,
    }
