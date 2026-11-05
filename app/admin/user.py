from fastapi import APIRouter, Body, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.shared.db.session import get_db
from app.shared.db.models import User, CustomRole
from app.shared.schemas.schemas import (
    UserOut,
    UserRegisterRequest,
    UserUpdateRequest,
    PasswordReset,
    PasswordChange,
)
from app.shared.security.auth import require_role, revoke_all_user_sessions
from app.shared.security.crypto import (
    hash_password_async,
    verify_password_async,
    delete_recovery_codes,
)
from app.shared.services.user import (
    list_users,
    get_user_by_id,
    update_user,
    register_user,
    validate_username_format,
    is_name_reserved,
)
from app.shared.literals import MSG_USER_NOT_FOUND, SYSTEM_ROLES

router = APIRouter(prefix="/user", tags=["User"])
_sa = require_role(100)
_BUILTIN_ROLE_CODES = {code for code, _, _ in SYSTEM_ROLES}


class RenameRequest(BaseModel):
    """Rename user request schema."""

    name: str = Field(..., min_length=1, max_length=64)


def _to_out(user: User) -> UserOut:
    """Convert User model to response schema."""
    return UserOut(
        id=user.id,
        username=user.username,
        email=user.email,
        display_name=user.display_name,
        role_code=user.role_code,
        is_active=user.is_active,
        totp_enabled=bool(user.totp_enabled),
        can_create_account=user.can_create_account,
        created_at=(
            user.created_at.isoformat()
            if hasattr(user.created_at, "isoformat")
            else str(user.created_at)
        ),
    )


@router.get("/list", response_model=list[UserOut])
async def list_all_users(
    offset: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
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
    users, _ = await list_users(db, search=q, limit=100)
    return [_to_out(u) for u in users]


@router.post("/create", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def create_user(
    payload: UserRegisterRequest = Body(...),
    db: AsyncSession = Depends(get_db),
    _user=Depends(_sa),
):
    """Create a new user (Super Admin direct creation, active immediately with default account)."""
    try:
        role_code = payload.role_code or "normal"
        can_create = (
            bool(payload.can_create_account)
            if payload.can_create_account is not None
            else (role_code in ("admin", "superadmin"))
        )
        user = await register_user(
            payload.email,
            payload.password,
            payload.display_name,
            db,
            username=payload.username,
            role_code=role_code,
            is_active=role_code not in ("pending", "banned"),
            can_create_account=can_create,
            create_default_account=True,
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
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=MSG_USER_NOT_FOUND
        )
    return _to_out(user)


@router.post("/{user_id}", response_model=UserOut)
async def update_user_info(
    user_id: str,
    body: UserUpdateRequest,
    db: AsyncSession = Depends(get_db),
    admin_user: User = Depends(_sa),
):
    """Update user information."""
    admin_uid = getattr(admin_user, "id", "")
    if admin_uid and user_id == admin_uid:
        if body.is_active is False or (
            body.role_code is not None and body.role_code != "superadmin"
        ):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot deactivate or demote your own Super Admin account",
            )
    if body.role_code is not None and body.role_code not in _BUILTIN_ROLE_CODES:
        role_exists = (
            await db.execute(
                select(CustomRole.id).where(CustomRole.code == body.role_code)
            )
        ).scalar_one_or_none()
        if not role_exists:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid role_code"
            )
    if body.email is not None:
        dup_email = (
            await db.execute(
                select(User.id).where(User.email == body.email, User.id != user_id)
            )
        ).scalar_one_or_none()
        if dup_email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email is already registered",
            )
    if body.username is not None:
        cleaned_uname = body.username.strip().lower()
        if not validate_username_format(cleaned_uname):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username format invalid",
            )
        if await is_name_reserved(cleaned_uname, db):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Name is reserved by system",
            )
        dup_uname = (
            await db.execute(
                select(User.id).where(
                    User.username == cleaned_uname, User.id != user_id
                )
            )
        ).scalar_one_or_none()
        if dup_uname:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username is already taken",
            )
        body.username = cleaned_uname
    updated = await update_user(user_id, db, **body.model_dump(exclude_none=True))
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=MSG_USER_NOT_FOUND
        )
    if not updated.is_active or updated.role_code in ("banned", "pending"):
        await revoke_all_user_sessions(user_id)
    return _to_out(updated)


@router.delete("/{user_id}", status_code=status.HTTP_200_OK)
async def delete_user(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    admin_user: User = Depends(_sa),
):
    """Delete a user."""
    if getattr(admin_user, "id", "") == user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own Super Admin account",
        )
    user = (
        await db.execute(select(User).where(User.id == user_id))
    ).scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=MSG_USER_NOT_FOUND
        )
    await db.delete(user)
    await db.commit()
    await revoke_all_user_sessions(user_id)
    await delete_recovery_codes(user_id)
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
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=MSG_USER_NOT_FOUND
        )
    new_name = body.name.strip()
    if not validate_username_format(new_name):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Username format invalid"
        )
    if await is_name_reserved(new_name, db):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Name is reserved by system"
        )
    dup = (
        await db.execute(
            select(User.id).where(User.username == new_name, User.id != user_id)
        )
    ).scalar_one_or_none()
    if dup:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Username is already taken"
        )
    user.username = new_name
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
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=MSG_USER_NOT_FOUND
        )
    user.hashed_password = await hash_password_async(body.new_password)
    await db.commit()
    await revoke_all_user_sessions(user_id)
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
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=MSG_USER_NOT_FOUND
        )
    if not await verify_password_async(body.old_password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Incorrect old password"
        )
    user.hashed_password = await hash_password_async(body.new_password)
    await db.commit()
    await revoke_all_user_sessions(user_id)
    return {"status": "password_changed"}
