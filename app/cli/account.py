import asyncio
import secrets
import uuid
from datetime import datetime, timezone
from typing import Optional
import click
import typer
from sqlalchemy import select

from app.shared.db.session import AsyncSessionLocal
from app.shared.db.models import Account, AccountMember, User

account_app = typer.Typer(help="Account and tenant management", no_args_is_help=True)


def _require_args(**kwargs) -> None:
    """Display command help and exit(0) if any required parameter is omitted."""
    if any(v is None for v in kwargs.values()):
        ctx = click.get_current_context(silent=True)
        if ctx is not None:
            print(ctx.get_help())
        raise typer.Exit(code=0)


@account_app.command("list")
def list_accounts():
    """List all tenant accounts."""

    async def _run():
        async with AsyncSessionLocal() as db:
            r = await db.execute(select(Account))
            rows = r.scalars().all()
            if not rows:
                print("No account records found")
                return
            for a in rows:
                print(f"  {a.slug} ({a.name}) [active={a.is_active}]")

    asyncio.run(_run())


@account_app.command("create")
def create_account_cmd(
    name: Optional[str] = typer.Argument(None, help="Account name"),
    slug: Optional[str] = typer.Argument(None, help="Tenant unique Slug"),
):
    """Create a new tenant account."""
    _require_args(name=name)
    name_str = name or ""
    actual_slug = slug or name_str.replace("_", "-")

    async def _run():
        async with AsyncSessionLocal() as db:
            db.add(
                Account(
                    id=str(uuid.uuid4()),
                    name=name,
                    slug=actual_slug,
                    api_key=secrets.token_urlsafe(32),
                    is_active=True,
                    created_at=datetime.now(timezone.utc),
                )
            )
            await db.commit()
            print(f"✅ Account {actual_slug} created")

    asyncio.run(_run())


@account_app.command("delete")
def delete_account_cmd(
    slug: Optional[str] = typer.Argument(None, help="Slug of account to delete"),
):
    """Delete specified account."""
    _require_args(slug=slug)

    async def _run():
        async with AsyncSessionLocal() as db:
            acct = (
                await db.execute(select(Account).where(Account.slug == slug))
            ).scalar_one_or_none()
            if not acct:
                print(f"❌ Account {slug} does not exist")
                return
            await db.delete(acct)
            await db.commit()
            print(f"✅ Account {slug} deleted")

    asyncio.run(_run())


@account_app.command("add-member")
def add_member_cmd(
    slug: Optional[str] = typer.Argument(None, help="Account Slug"),
    username: Optional[str] = typer.Argument(None, help="Username to add"),
    role: str = typer.Option(
        "owner", "--role", help="Member role (owner / admin / member)"
    ),
):
    """Add a member to a tenant account."""
    _require_args(slug=slug, username=username)

    async def _run():
        async with AsyncSessionLocal() as db:
            acct = (
                await db.execute(select(Account).where(Account.slug == slug))
            ).scalar_one_or_none()
            user = (
                await db.execute(select(User).where(User.username == username))
            ).scalar_one_or_none()
            if not acct or not user:
                print("❌ Account or user does not exist")
                return
            db.add(
                AccountMember(
                    id=str(uuid.uuid4()),
                    user_id=user.id,
                    account_id=acct.id,
                    role_in_account=role,
                    joined_at=datetime.now(timezone.utc),
                )
            )
            await db.commit()
            print(f"✅ {username} added to {slug}")

    asyncio.run(_run())


@account_app.command("remove-member")
def remove_member_cmd(
    slug: Optional[str] = typer.Argument(None, help="Account Slug"),
    username: Optional[str] = typer.Argument(None, help="Username to remove"),
):
    """Remove a member from a tenant account."""
    _require_args(slug=slug, username=username)

    async def _run():
        async with AsyncSessionLocal() as db:
            from sqlalchemy import and_

            acct = (
                await db.execute(select(Account).where(Account.slug == slug))
            ).scalar_one_or_none()
            user = (
                await db.execute(select(User).where(User.username == username))
            ).scalar_one_or_none()
            if not acct or not user:
                print("❌ Account or user does not exist")
                return
            m = (
                await db.execute(
                    select(AccountMember).where(
                        and_(
                            AccountMember.user_id == user.id,
                            AccountMember.account_id == acct.id,
                        )
                    )
                )
            ).scalar_one_or_none()
            if not m:
                print("❌ Membership record does not exist")
                return
            await db.delete(m)
            await db.commit()
            print(f"✅ {username} removed from {slug}")

    asyncio.run(_run())
