from fastapi import APIRouter, Body, Depends, HTTPException
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
    """重命名请求体。"""

    name: str = Field(..., min_length=1, max_length=64)


def _to_out(user) -> UserOut:
    """将 User 模型转换为响应模型。"""
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
    """分页查询所有用户。"""
    users, _ = await list_users(db, offset=offset, limit=limit)
    return [_to_out(u) for u in users]


@router.get("/search", response_model=list[UserOut])
async def search_users(
    q: str = "",
    db: AsyncSession = Depends(get_db),
    _user=Depends(_sa),
):
    """按关键字搜索用户。"""
    users, _ = await list_users(db, search=q)
    return [_to_out(u) for u in users]


@router.post("/create", response_model=UserOut)
async def create_user(
    payload: UserRegisterRequest = Body(...),
    db: AsyncSession = Depends(get_db),
    _user=Depends(_sa),
):
    """创建新用户（超管直接创建，跳过审核）。"""
    try:
        user = await register_user(
            payload.email,
            payload.password,
            payload.display_name,
            db,
            username=payload.username,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return _to_out(user)


@router.get("/{user_id}", response_model=UserOut)
async def get_user(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    _user=Depends(_sa),
):
    """获取用户信息。"""
    user = await get_user_by_id(user_id, db)
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")
    return _to_out(user)


@router.post("/{user_id}", response_model=UserOut)
async def update_user_info(
    user_id: str,
    body: UserUpdateRequest,
    db: AsyncSession = Depends(get_db),
    _user=Depends(_sa),
):
    """修改用户信息。"""
    updated = await update_user(user_id, db, **body.model_dump(exclude_none=True))
    if not updated:
        raise HTTPException(status_code=404, detail="用户不存在")
    return _to_out(updated)


@router.delete("/{user_id}")
async def delete_user(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    _user=Depends(_sa),
):
    """删除用户。"""
    user = (
        await db.execute(select(User).where(User.id == user_id))
    ).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")
    await db.delete(user)
    await db.commit()
    return {"message": "用户已删除"}


@router.post("/{user_id}/rename")
async def rename_user(
    user_id: str,
    body: RenameRequest,
    db: AsyncSession = Depends(get_db),
    _user=Depends(_sa),
):
    """重命名用户。"""
    user = (
        await db.execute(select(User).where(User.id == user_id))
    ).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")
    user.username = body.name
    await db.commit()
    return {"message": "已重命名"}


@router.post("/{user_id}/password/reset")
async def reset_password(
    user_id: str,
    body: PasswordReset,
    db: AsyncSession = Depends(get_db),
    _user=Depends(_sa),
):
    """重置用户密码（无需旧密码）。"""
    user = (
        await db.execute(select(User).where(User.id == user_id))
    ).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")
    user.hashed_password = hash_password(body.new_password)
    await db.commit()
    return {"message": "密码已重置"}


@router.post("/{user_id}/password/change")
async def change_password(
    user_id: str,
    body: PasswordChange,
    db: AsyncSession = Depends(get_db),
    _user=Depends(_sa),
):
    """超管修改用户密码（需验证旧密码）。"""
    user = (
        await db.execute(select(User).where(User.id == user_id))
    ).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")
    if not verify_password(body.old_password, user.hashed_password):
        raise HTTPException(status_code=400, detail="旧密码错误")
    user.hashed_password = hash_password(body.new_password)
    await db.commit()
    return {"message": "密码已修改"}
