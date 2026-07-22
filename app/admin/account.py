import os
import sys
import threading
from fastapi import APIRouter, Depends, Form, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.shared.db.session import get_db
from app.shared.db.models import Account
from app.shared.schemas.schemas import AccountOut, UserOut
from app.shared.security.auth import (
    require_role,
    verify_oobe_passcode,
    verify_oobe_token,
    get_oobe_token,
)
from app.shared.services.user import list_pending_users, reject_user, approve_user
from app.shared.utils.oobe import write_config_file, init_database

router = APIRouter()
_sa = require_role(100)


def _to_out(user) -> UserOut:
    """Convert User model to response schema."""
    return UserOut(
        id=user.id,
        username=user.username,
        email=user.email,
        display_name=user.display_name,
        role_code=user.role_code,
        is_active=user.is_active,
        can_create_account=user.can_create_account,
        created_at=str(user.created_at),
    )


# ---- 1. Account / Tenant Administration ----

@router.get("/account", response_model=list[AccountOut], tags=["Account"])
async def list_accounts(
    db: AsyncSession = Depends(get_db),
    _user=Depends(_sa),
):
    """List all accounts across system."""
    res = await db.execute(select(Account))
    return res.scalars().all()


# ---- 2. Pending Approvals ----

@router.get("/user/pending", response_model=list[UserOut], tags=["Pending"])
async def get_pending(
    db: AsyncSession = Depends(get_db),
    _user=Depends(_sa),
):
    """List all pending user registration applications."""
    users = await list_pending_users(db)
    return [_to_out(u) for u in users]


@router.post("/user/pending/approve/{user_id}", response_model=UserOut, tags=["Pending"])
async def approve_pending(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    _user=Depends(_sa),
):
    """Approve a pending user registration application."""
    user = await approve_user(user_id, db)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found or not in pending state")
    return _to_out(user)


@router.post("/user/pending/reject/{user_id}", status_code=status.HTTP_200_OK, tags=["Pending"])
async def reject_pending(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    _user=Depends(_sa),
):
    """Reject a pending user registration application."""
    ok = await reject_user(user_id, db)
    if not ok:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found or not in pending state")
    return {"status": "rejected"}


# ---- 3. OOBE First-Time Setup Wizard ----

@router.post("/oobe/verify", tags=["OOBE"])
async def verify_passcode(passcode: str = Form(...)):
    """Verify pairing passcode and issue elevated execution token."""
    if not verify_oobe_passcode(passcode):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid passcode or expired")
    return {"token": get_oobe_token()}


@router.post("/oobe/configure", tags=["OOBE"])
async def configure_system(
    token: str = Form(...),
    db_url: str = Form(...),
    redis_url: str = Form(...),
    domain: str = Form(...),
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
):
    """Verify token, write configuration, initialize database schema, and trigger restart."""
    if not verify_oobe_token(token):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid token or expired")

    config = {
        "db_url": db_url,
        "redis_url": redis_url,
        "domain": domain,
        "username": username,
        "email": email,
        "password": password,
    }

    try:
        write_config_file(config)
        await init_database(config)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Initialization failed: {str(e)}")

    # Trigger system restart in 1 second
    threading.Timer(
        1.0, lambda: os.execv(sys.executable, [sys.executable] + sys.argv)
    ).start()
    return {"status": "ok", "message": "Initialization complete, system restarting"}
