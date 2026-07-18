from fastapi import APIRouter, Depends, HTTPException
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
    """为指定用户启用 TOTP 密钥并返回秘钥。"""
    user = (
        await db.execute(select(User).where(User.id == user_id))
    ).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")
    secret = generate_totp_secret()
    user.totp_secret = secret
    user.totp_enabled = True
    await db.commit()
    return {"secret": secret}


@router.post("/{user_id}/2fa/disable")
async def admin_disable_2fa(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    _user=Depends(_sa),
):
    """禁用指定用户的 TOTP 认证。"""
    user = (
        await db.execute(select(User).where(User.id == user_id))
    ).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")
    user.totp_enabled = False
    user.totp_secret = None
    await db.commit()
    return {"message": "2FA 已禁用"}


@router.post("/{user_id}/2fa/reset")
async def admin_reset_2fa(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    _user=Depends(_sa),
):
    """重置指定用户的 TOTP 密钥。"""
    user = (
        await db.execute(select(User).where(User.id == user_id))
    ).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")
    user.totp_secret = generate_totp_secret()
    user.totp_enabled = False
    await db.commit()
    return {"message": "TOTP 已重置"}
