from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.shared.db.session import get_db
from app.shared.db.models import User
from app.shared.security.auth import require_role
from app.shared.security.crypto import generate_totp_secret

router = APIRouter(prefix="/user", tags=["2FA"])
_sa = require_role(100)


@router.post("/{user_id}/2fa/enable")
async def admin_enable_2fa(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    _user=Depends(_sa),
):
    """Enable TOTP secret for the specified user and return secret."""
    user = (
        await db.execute(select(User).where(User.id == user_id))
    ).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    secret = generate_totp_secret()
    user.totp_secret = secret
    user.totp_enabled = True
    await db.commit()
    return {"status": "enabled", "secret": secret}


@router.post("/{user_id}/2fa/disable")
async def admin_disable_2fa(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    _user=Depends(_sa),
):
    """Disable TOTP authentication for the specified user."""
    user = (
        await db.execute(select(User).where(User.id == user_id))
    ).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    user.totp_enabled = False
    user.totp_secret = None
    await db.commit()
    return {"status": "disabled", "message": "2FA disabled"}


@router.post("/{user_id}/2fa/reset")
async def admin_reset_2fa(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    _user=Depends(_sa),
):
    """Reset TOTP secret for the specified user."""
    user = (
        await db.execute(select(User).where(User.id == user_id))
    ).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    user.totp_secret = generate_totp_secret()
    user.totp_enabled = False
    await db.commit()
    return {"status": "reset", "message": "TOTP secret reset"}
