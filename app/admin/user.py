from fastapi import APIRouter, Body, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.shared.db.session import get_db
from app.shared.db.models import User
from app.shared.schemas.schemas import (
    UserOut,
    UserRegisterRequest,
    UserUpdateRequest,
    PasswordReset,
    PasswordChange,
)
from app.shared.security.auth import require_role
from app.shared.security.crypto import hash_password, verify_password
from app.shared.services.user import list_users, get_user_by_id, update_user, register_user

router = APIRouter(prefix="/user", tags=["User"])
_sa = require_role(100)


class RenameRequest(BaseModel):
    """Rename user request schema."""

    name: str = Field(..., min_length=1, max_length=64)


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


@router.get("/list", response_model=list[UserOut])
async def list_all_users(
    offset: int = 0,
    limit: int = 20,
    db: AsyncSession = Depends(get_db),
    _user=Depends(_sa),
):
    """Paginated query for all users."""
    users, _ = await list_users(db, offset=offset, limit=limit)
    return [_to_out(u) for u in users]


@router.get("/search", response_model=list[UserOut])
async def search_users(
    q: str = "",
    db: AsyncSession = Depends(get_db),
    _user=Depends(_sa),
):
    """Search users by keyword."""
    users, _ = await list_users(db, search=q)
    return [_to_out(u) for u in users]


@router.post("/create", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def create_user(
    payload: UserRegisterRequest = Body(...),
    db: AsyncSession = Depends(get_db),
    _user=Depends(_sa),
):
    """Create a new user (Super Admin direct creation, bypassing pending approval)."""
    try:
        user = await register_user(
            payload.email,
            payload.password,
            payload.display_name,
            db,
            username=payload.username,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    return _to_out(user)


@router.get("/{user_id}", response_model=UserOut)
async def get_user(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    _user=Depends(_sa),
):
    """Get user information by ID."""
    user = await get_user_by_id(user_id, db)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return _to_out(user)


@router.post("/{user_id}", response_model=UserOut)
async def update_user_info(
    user_id: str,
    body: UserUpdateRequest,
    db: AsyncSession = Depends(get_db),
    _user=Depends(_sa),
):
    """Update user information."""
    updated = await update_user(user_id, db, **body.model_dump(exclude_none=True))
    if not updated:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return _to_out(updated)


@router.delete("/{user_id}", status_code=status.HTTP_200_OK)
async def delete_user(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    _user=Depends(_sa),
):
    """Delete a user."""
    user = (
        await db.execute(select(User).where(User.id == user_id))
    ).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    await db.delete(user)
    await db.commit()
    return {"status": "deleted"}


@router.post("/{user_id}/rename", status_code=status.HTTP_200_OK)
async def rename_user(
    user_id: str,
    body: RenameRequest,
    db: AsyncSession = Depends(get_db),
    _user=Depends(_sa),
):
    """Rename a user's username."""
    user = (
        await db.execute(select(User).where(User.id == user_id))
    ).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    user.username = body.name
    await db.commit()
    return {"status": "renamed"}


@router.post("/{user_id}/password/reset", status_code=status.HTTP_200_OK)
async def reset_password(
    user_id: str,
    body: PasswordReset,
    db: AsyncSession = Depends(get_db),
    _user=Depends(_sa),
):
    """Reset user password directly (Super Admin without old password)."""
    user = (
        await db.execute(select(User).where(User.id == user_id))
    ).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    user.hashed_password = hash_password(body.new_password)
    await db.commit()
    return {"status": "password_reset"}


@router.post("/{user_id}/password/change", status_code=status.HTTP_200_OK)
async def change_password(
    user_id: str,
    body: PasswordChange,
    db: AsyncSession = Depends(get_db),
    _user=Depends(_sa),
):
    """Change user password with old password verification."""
    user = (
        await db.execute(select(User).where(User.id == user_id))
    ).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if not verify_password(body.old_password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Incorrect old password")
    user.hashed_password = hash_password(body.new_password)
    await db.commit()
    return {"status": "password_changed"}
