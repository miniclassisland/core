import asyncio
from typing import Optional
import click
import typer
from sqlalchemy import delete, select

from app.shared.db.session import AsyncSessionLocal
from app.shared.db.models import (
    Account,
    AccountMember,
    CommunityBinding,
    Ticket,
    TicketMessage,
    User,
)
from app.shared.security.auth import revoke_all_user_sessions
from app.shared.security.crypto import hash_password
from app.shared.services.user import (
    approve_user,
    list_pending_users,
    list_users,
    register_user,
    reject_user,
)
from app.shared.utils.community import (
    handle_user_banned_in_community,
    notify_user_approved,
)

user_app = typer.Typer(help="User account management", no_args_is_help=True)


def _require_args(**kwargs) -> None:
    """Display command help and exit(0) if any required parameter is omitted."""
    if any(v is None for v in kwargs.values()):
        ctx = click.get_current_context(silent=True)
        if ctx is not None:
            print(ctx.get_help())
        raise typer.Exit(code=0)


@user_app.command("list")
def list_users_cmd():
    """List all registered user accounts in system."""

    async def _run():
        async with AsyncSessionLocal() as db:
            users, total = await list_users(db, limit=100)
            print(f"Total {total} users:")
            for u in users:
                print(
                    f"  {u.username} ({u.email}) [{u.role_code}] active={u.is_active}"
                )

    asyncio.run(_run())


@user_app.command("info")
def user_info_cmd(
    username: Optional[str] = typer.Argument(None, help="Username"),
):
    """Display detailed user account profile and account memberships."""
    _require_args(username=username)

    async def _run():
        async with AsyncSessionLocal() as db:
            user = (
                await db.execute(select(User).where(User.username == username))
            ).scalar_one_or_none()
            if not user:
                print(f"❌ User {username} does not exist")
                return
            members = (
                (
                    await db.execute(
                        select(AccountMember).where(AccountMember.user_id == user.id)
                    )
                )
                .scalars()
                .all()
            )
            acct_slugs: list[str] = []
            if members:
                aids = [m.account_id for m in members]
                accts = (
                    (await db.execute(select(Account).where(Account.id.in_(aids))))
                    .scalars()
                    .all()
                )
                amap = {a.id: a.slug for a in accts}
                acct_slugs = [
                    f"{amap.get(m.account_id, m.account_id)} ({m.role_in_account})"
                    for m in members
                ]
            print(f"ID:                 {user.id}")
            print(f"Username:           {user.username}")
            print(f"Email:              {user.email}")
            print(f"Display Name:       {user.display_name}")
            print(f"Role:               {user.role_code}")
            print(f"Active:             {user.is_active}")
            print(f"2FA Enabled:        {user.totp_enabled}")
            print(f"Can Create Account: {user.can_create_account}")
            print(
                f"Accounts:           {', '.join(acct_slugs) if acct_slugs else '(none)'}"
            )

    asyncio.run(_run())


@user_app.command("pending")
def pending_users_cmd():
    """List all pending user registration applications."""

    async def _run():
        async with AsyncSessionLocal() as db:
            users = await list_pending_users(db)
            if not users:
                print("No pending user applications")
                return
            for u in users:
                print(f"  {u.username} ({u.email}) [id={u.id}]")

    asyncio.run(_run())


@user_app.command("approve")
def approve_user_cmd(
    username: Optional[str] = typer.Argument(None, help="Username to approve"),
):
    """Approve a pending user registration application."""
    _require_args(username=username)

    async def _run():
        async with AsyncSessionLocal() as db:
            user = (
                await db.execute(select(User).where(User.username == username))
            ).scalar_one_or_none()
            if not user:
                print(f"❌ User {username} does not exist")
                return
            approved = await approve_user(user.id, db)
            if not approved:
                print(f"❌ User {username} is not in pending state")
                return
            print(f"✅ User {username} approved")

    asyncio.run(_run())


@user_app.command("reject")
def reject_user_cmd(
    username: Optional[str] = typer.Argument(None, help="Username to reject"),
):
    """Reject a pending user registration application."""
    _require_args(username=username)

    async def _run():
        async with AsyncSessionLocal() as db:
            user = (
                await db.execute(select(User).where(User.username == username))
            ).scalar_one_or_none()
            if not user:
                print(f"❌ User {username} does not exist")
                return
            ok = await reject_user(user.id, db)
            if not ok:
                print(f"❌ User {username} is not in pending state")
                return
            print(f"✅ User {username} rejected")

    asyncio.run(_run())


@user_app.command("create")
def create_user_cmd(
    username: Optional[str] = typer.Argument(None, help="Username"),
    email: Optional[str] = typer.Argument(None, help="User email"),
    password: Optional[str] = typer.Argument(None, help="User password"),
    role: str = typer.Option("normal", "--role", help="Initial user role"),
):
    """Create a new user account."""
    _require_args(username=username, email=email, password=password)

    async def _run():
        async with AsyncSessionLocal() as db:
            try:
                effective_role = role or "normal"
                is_approved_role = effective_role not in ("pending", "banned")
                user = await register_user(
                    email or "",
                    password or "",
                    username or "",
                    db,
                    username=username,
                    role_code=effective_role,
                    is_active=is_approved_role,
                    can_create_account=is_approved_role,
                    create_default_account=False,
                )
                print(f"✅ User {user.username} created")
            except ValueError as exc:
                print(f"❌ {exc}")

    asyncio.run(_run())


@user_app.command("delete")
def delete_user_cmd(
    username: Optional[str] = typer.Argument(None, help="Username to delete"),
):
    """Delete specified user account."""
    _require_args(username=username)

    async def _run():
        async with AsyncSessionLocal() as db:
            user = (
                await db.execute(select(User).where(User.username == username))
            ).scalar_one_or_none()
            if not user:
                print(f"❌ User {username} does not exist")
                return
            uid = user.id
            user_ticket_ids = select(Ticket.id).where(Ticket.user_id == uid)
            await db.execute(
                delete(TicketMessage).where(
                    (TicketMessage.ticket_id.in_(user_ticket_ids))
                    | (TicketMessage.author_id == uid)
                )
            )
            await db.execute(delete(Ticket).where(Ticket.user_id == uid))
            await db.execute(
                delete(CommunityBinding).where(CommunityBinding.user_id == uid)
            )
            await db.execute(delete(AccountMember).where(AccountMember.user_id == uid))
            await db.delete(user)
            await db.commit()
            await revoke_all_user_sessions(uid)
            print(f"✅ User {username} deleted")

    asyncio.run(_run())


@user_app.command("ban")
def ban_user_cmd(
    username: Optional[str] = typer.Argument(None, help="Username to ban"),
):
    """Ban specified user account."""
    _require_args(username=username)

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
            await revoke_all_user_sessions(user.id)
            await handle_user_banned_in_community(user, db)
            print(f"✅ User {username} banned")

    asyncio.run(_run())


@user_app.command("activate")
def activate_user_cmd(
    username: Optional[str] = typer.Argument(None, help="Username to activate"),
):
    """Activate/unban specified user account."""
    _require_args(username=username)

    async def _run():
        async with AsyncSessionLocal() as db:
            user = (
                await db.execute(select(User).where(User.username == username))
            ).scalar_one_or_none()
            if not user:
                print(f"❌ User {username} does not exist")
                return
            was_pending = user.role_code == "pending"
            user.role_code = "normal"
            user.is_active = True
            await db.commit()
            if was_pending:
                await notify_user_approved(user, db)
            print(f"✅ User {username} activated")

    asyncio.run(_run())


@user_app.command("reset-password")
def reset_password_cmd(
    username: Optional[str] = typer.Argument(None, help="Username"),
    password: Optional[str] = typer.Argument(None, help="New password"),
):
    """Reset password for specified user account."""
    _require_args(username=username, password=password)

    async def _run():
        async with AsyncSessionLocal() as db:
            user = (
                await db.execute(select(User).where(User.username == username))
            ).scalar_one_or_none()
            if not user:
                print(f"❌ User {username} does not exist")
                return
            user.hashed_password = hash_password(password or "")
            await db.commit()
            await revoke_all_user_sessions(user.id)
            print(f"✅ User {username} password reset")

    asyncio.run(_run())


@user_app.command("reset-2fa")
def reset_2fa_cmd(
    username: Optional[str] = typer.Argument(None, help="Username"),
):
    """Reset and disable TOTP 2FA for specified user account."""
    _require_args(username=username)

    async def _run():
        async with AsyncSessionLocal() as db:
            user = (
                await db.execute(select(User).where(User.username == username))
            ).scalar_one_or_none()
            if not user:
                print(f"❌ User {username} does not exist")
                return
            user.totp_secret = None
            user.totp_enabled = False
            await db.commit()
            print(f"✅ User {username} 2FA reset")

    asyncio.run(_run())


@user_app.command("set-create-account")
def set_create_account_cmd(
    username: Optional[str] = typer.Argument(None, help="Username"),
    allowed: Optional[str] = typer.Argument(
        None, help="Whether user can create accounts (true / false)"
    ),
):
    """Grant or revoke permission for a user to create tenant accounts."""
    _require_args(username=username, allowed=allowed)

    async def _run():
        val = (allowed or "").strip().lower() in ("true", "1", "yes", "on")
        async with AsyncSessionLocal() as db:
            user = (
                await db.execute(select(User).where(User.username == username))
            ).scalar_one_or_none()
            if not user:
                print(f"❌ User {username} does not exist")
                return
            user.can_create_account = val
            await db.commit()
            print(f"✅ User {username} can_create_account set to {val}")

    asyncio.run(_run())


@user_app.command("set-role")
def set_role_cmd(
    username: Optional[str] = typer.Argument(None, help="Username"),
    role: Optional[str] = typer.Argument(
        None, help="Role code (superadmin / admin / normal)"
    ),
):
    """Set system role for specified user account."""
    _require_args(username=username, role=role)

    async def _run():
        async with AsyncSessionLocal() as db:
            user = (
                await db.execute(select(User).where(User.username == username))
            ).scalar_one_or_none()
            if not user:
                print(f"❌ User {username} does not exist")
                return
            user.role_code = role or "normal"
            await db.commit()
            await revoke_all_user_sessions(user.id)
            if user.role_code == "banned":  # pragma: no cover
                await handle_user_banned_in_community(user, db)
            print(f"✅ User {username} role set to {role}")

    asyncio.run(_run())
