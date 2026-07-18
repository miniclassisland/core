import asyncio
from typing import Optional
import typer
from sqlalchemy import select

from app.shared.db.session import AsyncSessionLocal
from app.shared.db.models import User
from app.shared.security.crypto import hash_password
from app.shared.services.user import register_user, list_users

user_app = typer.Typer(help="用户账户管理")


@user_app.command("list")
def list_users_cmd():
    """列出系统中所有注册的用户账号信息。"""
    async def _run():
        async with AsyncSessionLocal() as db:
            users, total = await list_users(db, limit=100)
            print(f"共 {total} 个用户:")
            for u in users:
                print(f"  {u.username} ({u.email}) [{u.role_code}]")
    asyncio.run(_run())


@user_app.command("create")
def create_user_cmd(
    username: str = typer.Argument(..., help="用户名"),
    email: str = typer.Argument(..., help="用户邮箱"),
    password: str = typer.Argument(..., help="用户密码"),
    role: str = typer.Option("normal", help="用户初始角色"),
):
    """创建新的用户账号。"""
    async def _run():
        async with AsyncSessionLocal() as db:
            try:
                user = await register_user(
                    username,
                    email,
                    password,
                    username,
                    db,
                )
                if role != "normal":
                    user.role_code = role
                    await db.commit()
                print(f"✅ 用户 {user.username} 已创建")
            except ValueError as exc:
                print(f"❌ {exc}")
    asyncio.run(_run())


@user_app.command("delete")
def delete_user_cmd(
    username: str = typer.Argument(..., help="要删除的用户名"),
):
    """删除指定的系统用户账号。"""
    async def _run():
        async with AsyncSessionLocal() as db:
            user = (
                await db.execute(select(User).where(User.username == username))
            ).scalar_one_or_none()
            if not user:
                print(f"❌ 用户 {username} 不存在")
                return
            await db.delete(user)
            await db.commit()
            print(f"✅ 用户 {username} 已删除")
    asyncio.run(_run())


@user_app.command("ban")
def ban_user_cmd(
    username: str = typer.Argument(..., help="要封禁的用户名"),
):
    """封禁指定的用户账号。"""
    async def _run():
        async with AsyncSessionLocal() as db:
            user = (
                await db.execute(select(User).where(User.username == username))
            ).scalar_one_or_none()
            if not user:
                print(f"❌ 用户 {username} 不存在")
                return
            user.role_code = "banned"
            await db.commit()
            print(f"✅ 用户 {username} 已封禁")
    asyncio.run(_run())


@user_app.command("activate")
def activate_user_cmd(
    username: str = typer.Argument(..., help="要激活的用户名"),
):
    """激活/解禁指定的用户账号。"""
    async def _run():
        async with AsyncSessionLocal() as db:
            user = (
                await db.execute(select(User).where(User.username == username))
            ).scalar_one_or_none()
            if not user:
                print(f"❌ 用户 {username} 不存在")
                return
            user.role_code = "normal"
            user.is_active = True
            await db.commit()
            print(f"✅ 用户 {username} 已激活")
    asyncio.run(_run())


@user_app.command("reset-password")
def reset_password_cmd(
    username: str = typer.Argument(..., help="用户名"),
    password: str = typer.Argument(..., help="新密码"),
):
    """重置指定用户账号的密码。"""
    async def _run():
        async with AsyncSessionLocal() as db:
            user = (
                await db.execute(select(User).where(User.username == username))
            ).scalar_one_or_none()
            if not user:
                print(f"❌ 用户 {username} 不存在")
                return
            user.hashed_password = hash_password(password)
            await db.commit()
            print(f"✅ 用户 {username} 密码已重置")
    asyncio.run(_run())


@user_app.command("set-role")
def set_role_cmd(
    username: str = typer.Argument(..., help="用户名"),
    role: str = typer.Argument(..., help="角色代号 (superadmin / admin / normal)"),
):
    """设定指定用户账户的系统角色。"""
    async def _run():
        async with AsyncSessionLocal() as db:
            user = (
                await db.execute(select(User).where(User.username == username))
            ).scalar_one_or_none()
            if not user:
                print(f"❌ 用户 {username} 不存在")
                return
            user.role_code = role
            await db.commit()
            print(f"✅ 用户 {username} 角色设置为 {role}")
    asyncio.run(_run())
