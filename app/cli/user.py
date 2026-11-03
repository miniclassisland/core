import asyncio
import typer
from sqlalchemy import select

from app.shared.db.session import AsyncSessionLocal
from app.shared.db.models import User
from app.shared.security.crypto import hash_password
from app.shared.services.user import register_user, list_users

user_app = typer.Typer(help="User account management")


@user_app.command("list")
def list_users_cmd():
    """List all registered user accounts in system."""

    async def _run():
        async with AsyncSessionLocal() as db:
            users, total = await list_users(db, limit=100)
            print(f"Total {total} users:")
            for u in users:
                print(f"  {u.username} ({u.email}) [{u.role_code}]")

    asyncio.run(_run())


@user_app.command("create")
def create_user_cmd(
    username: str = typer.Argument(..., help="Username"),
    email: str = typer.Argument(..., help="User email"),
    password: str = typer.Argument(..., help="User password"),
    role: str = typer.Option("normal", "--role", help="Initial user role"),
):
    """Create a new user account."""

    async def _run():
        async with AsyncSessionLocal() as db:
            try:
                user = await register_user(
                    email,
                    password,
                    username,
                    db,
                    username=username,
                )
                if role != "normal":
                    user.role_code = role
                    await db.commit()
                print(f"✅ User {user.username} created")
            except ValueError as exc:
                print(f"❌ {exc}")

    asyncio.run(_run())


@user_app.command("delete")
def delete_user_cmd(
    username: str = typer.Argument(..., help="Username to delete"),
):
    """Delete specified user account."""

    async def _run():
        async with AsyncSessionLocal() as db:
            user = (
                await db.execute(select(User).where(User.username == username))
            ).scalar_one_or_none()
            if not user:
                print(f"❌ User {username} does not exist")
                return
            await db.delete(user)
            await db.commit()
            print(f"✅ User {username} deleted")

    asyncio.run(_run())


@user_app.command("ban")
def ban_user_cmd(
    username: str = typer.Argument(..., help="Username to ban"),
):
    """Ban specified user account."""

    async def _run():
        async with AsyncSessionLocal() as db:
            user = (
                await db.execute(select(User).where(User.username == username))
            ).scalar_one_or_none()
            if not user:
                print(f"❌ User {username} does not exist")
                return
            user.role_code = "banned"
            await db.commit()
            print(f"✅ User {username} banned")

    asyncio.run(_run())


@user_app.command("activate")
def activate_user_cmd(
    username: str = typer.Argument(..., help="Username to activate"),
):
    """Activate/unban specified user account."""

    async def _run():
        async with AsyncSessionLocal() as db:
            user = (
                await db.execute(select(User).where(User.username == username))
            ).scalar_one_or_none()
            if not user:
                print(f"❌ User {username} does not exist")
                return
            user.role_code = "normal"
            user.is_active = True
            await db.commit()
            print(f"✅ User {username} activated")

    asyncio.run(_run())


@user_app.command("reset-password")
def reset_password_cmd(
    username: str = typer.Argument(..., help="Username"),
    password: str = typer.Argument(..., help="New password"),
):
    """Reset password for specified user account."""

    async def _run():
        async with AsyncSessionLocal() as db:
            user = (
                await db.execute(select(User).where(User.username == username))
            ).scalar_one_or_none()
            if not user:
                print(f"❌ User {username} does not exist")
                return
            user.hashed_password = hash_password(password)
            await db.commit()
            print(f"✅ User {username} password reset")

    asyncio.run(_run())


@user_app.command("set-role")
def set_role_cmd(
    username: str = typer.Argument(..., help="Username"),
    role: str = typer.Argument(..., help="Role code (superadmin / admin / normal)"),
):
    """Set system role for specified user account."""

    async def _run():
        async with AsyncSessionLocal() as db:
            user = (
                await db.execute(select(User).where(User.username == username))
            ).scalar_one_or_none()
            if not user:
                print(f"❌ User {username} does not exist")
                return
            user.role_code = role
            await db.commit()
            print(f"✅ User {username} role set to {role}")

    asyncio.run(_run())
