from fastapi import APIRouter, Body, Depends, HTTPException, Request, status

from app.shared.security.auth import (
    get_current_user_id,
    create_session_token,
    revoke_session_token,
    create_exchange_code,
    redeem_exchange_code,
)
from app.shared.schemas.schemas import MessageResponse
from app.shared.utils.logging import get_client_ip_from_request

router = APIRouter(prefix="/token", tags=["Token"])


@router.post("/refresh")
async def refresh_token(
    request: Request,
    user_id: str = Depends(get_current_user_id),
):
    """Refresh current session token and revoke the old session token."""
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        await revoke_session_token(auth[7:])
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
        await revoke_session_token(auth[7:])
    return MessageResponse(message="Logged out successfully")


@router.post("/exchange")
async def issue_exchange_code(
    request: Request,
    _user_id: str = Depends(get_current_user_id),
):
    """Issue a 30-second single-use SSO exchange code for cross-origin site switching."""
    auth = request.headers.get("authorization", "")
    token = auth[7:] if auth.startswith("Bearer ") else ""
    client_ip = get_client_ip_from_request(request)
    code = await create_exchange_code(token, client_ip=client_ip)
    return {"code": code}


@router.post("/redeem")
async def redeem_sso_exchange_code(
    request: Request,
    body: dict = Body(...),
):
    """Redeem a single-use SSO exchange code for the underlying session token."""
    code = str(body.get("code") or "").strip()
    client_ip = get_client_ip_from_request(request)
    token = await redeem_exchange_code(code, client_ip=client_ip)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Exchange code invalid or expired",
        )
    return {"token": token}
