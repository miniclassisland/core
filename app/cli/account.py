import asyncio
import json
import secrets
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
import click
import typer
from sqlalchemy import func, select

from app.shared.db.session import AsyncSessionLocal
from app.shared.db.models import (
    Account,
    AccountMember,
    AccountQuota,
    ClientRecord,
    User,
)
from app.shared.db.schema_init import seed_account_defaults
from app.shared.literals import DEFAULT_QUOTAS
from app.shared.services.quota import get_bandwidth_mb, get_quotas, set_quota
from app.shared.services.user import cleanup_account_data
from app.shared.utils.config import BASE_DOMAIN
from app.shared.utils.tenant import invalidate_cached_account

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
            r = await db.execute(select(Account).order_by(Account.created_at.desc()))
            rows = r.scalars().all()
            if not rows:
                print("No account records found")
                return
            for a in rows:
                reg_mode = getattr(a, "registration_mode", "pairing") or "pairing"
                print(f"  {a.slug} ({a.name}) [active={a.is_active} mode={reg_mode}]")

    asyncio.run(_run())


@account_app.command("info")
def account_info_cmd(
    slug: Optional[str] = typer.Argument(None, help="Account Slug"),
):
    """Display detailed information, quotas, and member count for an account."""
    _require_args(slug=slug)

    async def _run():
        async with AsyncSessionLocal() as db:
            acct = (
                await db.execute(select(Account).where(Account.slug == slug))
            ).scalar_one_or_none()
            if not acct:
                print(f"❌ Account {slug} does not exist")
                return
            member_count = (
                await db.scalar(
                    select(func.count(AccountMember.id)).where(
                        AccountMember.account_id == acct.id
                    )
                )
                or 0
            )
            client_count = (
                await db.scalar(
                    select(func.count(ClientRecord.uid)).where(
                        ClientRecord.account_id == acct.id
                    )
                )
                or 0
            )
            quotas = await get_quotas(acct.id, db)
            print(f"ID:                {acct.id}")
            print(f"Slug:              {acct.slug}")
            print(f"Name:              {acct.name}")
            print(f"Active:            {acct.is_active}")
            print(f"Registration Mode: {acct.registration_mode}")
            print(f"API Key:           {acct.api_key}")
            print(f"Members:           {member_count}")
            print(f"Clients:           {client_count}")
            if quotas:
                q_parts = [f"{q.quota_key}={q.max_value}" for q in quotas]
                print(f"Quotas:            {', '.join(q_parts)}")

    asyncio.run(_run())


@account_app.command("create")
def create_account_cmd(
    name: Optional[str] = typer.Argument(None, help="Account name"),
    slug: Optional[str] = typer.Argument(None, help="Tenant unique Slug"),
):
    """Create a new tenant account with default quotas and resources."""
    _require_args(name=name)
    name_str = name or ""
    actual_slug = slug or name_str.replace("_", "-").replace(" ", "-").lower()

    async def _run():
        async with AsyncSessionLocal() as db:
            dup = (
                await db.execute(select(Account).where(Account.slug == actual_slug))
            ).scalar_one_or_none()
            if dup:
                print(f"❌ Account {actual_slug} already exists")
                return
            acct_id = str(uuid.uuid4())
            acct = Account(
                id=acct_id,
                name=name_str,
                slug=actual_slug,
                api_key=secrets.token_urlsafe(32),
                is_active=True,
                registration_mode="pairing",
                created_at=datetime.now(timezone.utc),
            )
            db.add(acct)
            for q_key, q_max in DEFAULT_QUOTAS:
                db.add(
                    AccountQuota(
                        id=str(uuid.uuid4()),
                        account_id=acct_id,
                        quota_key=q_key,
                        max_value=q_max,
                        current_value=0,
                    )
                )
            await seed_account_defaults(acct_id, db)
            await db.commit()
            print(f"✅ Account {actual_slug} created")

    asyncio.run(_run())


@account_app.command("delete")
def delete_account_cmd(
    slug: Optional[str] = typer.Argument(None, help="Slug of account to delete"),
):
    """Delete specified account and clean up associated records."""
    _require_args(slug=slug)

    async def _run():
        async with AsyncSessionLocal() as db:
            acct = (
                await db.execute(select(Account).where(Account.slug == slug))
            ).scalar_one_or_none()
            if not acct:
                print(f"❌ Account {slug} does not exist")
                return
            await cleanup_account_data(acct.id, acct.slug, db)
            await db.delete(acct)
            await db.commit()
            print(f"✅ Account {slug} deleted")

    asyncio.run(_run())


@account_app.command("enable")
def enable_account_cmd(
    slug: Optional[str] = typer.Argument(None, help="Account Slug to enable"),
):
    """Enable a deactivated tenant account."""
    _require_args(slug=slug)

    async def _run():
        async with AsyncSessionLocal() as db:
            acct = (
                await db.execute(select(Account).where(Account.slug == slug))
            ).scalar_one_or_none()
            if not acct:
                print(f"❌ Account {slug} does not exist")
                return
            acct.is_active = True
            await db.commit()
            await invalidate_cached_account(acct.slug)
            print(f"✅ Account {slug} enabled")

    asyncio.run(_run())


@account_app.command("disable")
def disable_account_cmd(
    slug: Optional[str] = typer.Argument(None, help="Account Slug to disable"),
):
    """Disable a tenant account."""
    _require_args(slug=slug)

    async def _run():
        async with AsyncSessionLocal() as db:
            acct = (
                await db.execute(select(Account).where(Account.slug == slug))
            ).scalar_one_or_none()
            if not acct:
                print(f"❌ Account {slug} does not exist")
                return
            acct.is_active = False
            await db.commit()
            await invalidate_cached_account(acct.slug)
            print(f"✅ Account {slug} disabled")

    asyncio.run(_run())


@account_app.command("set-reg-mode")
def set_reg_mode_cmd(
    slug: Optional[str] = typer.Argument(None, help="Account Slug"),
    mode: Optional[str] = typer.Argument(
        None, help="Registration mode (open / pairing / pre_reg)"
    ),
):
    """Set device registration mode for an account."""
    _require_args(slug=slug, mode=mode)

    async def _run():
        if mode not in ("open", "pairing", "pre_reg"):
            print("❌ Invalid mode; must be one of: open, pairing, pre_reg")
            return
        async with AsyncSessionLocal() as db:
            acct = (
                await db.execute(select(Account).where(Account.slug == slug))
            ).scalar_one_or_none()
            if not acct:
                print(f"❌ Account {slug} does not exist")
                return
            acct.registration_mode = mode or "pairing"
            await db.commit()
            await invalidate_cached_account(acct.slug)
            print(f"✅ Account {slug} registration mode set to {mode}")

    asyncio.run(_run())


@account_app.command("quotas")
def list_quotas_cmd(
    slug: Optional[str] = typer.Argument(None, help="Account Slug"),
):
    """List resource quotas and current usage for an account."""
    _require_args(slug=slug)

    async def _run():
        async with AsyncSessionLocal() as db:
            acct = (
                await db.execute(select(Account).where(Account.slug == slug))
            ).scalar_one_or_none()
            if not acct:
                print(f"❌ Account {slug} does not exist")
                return
            rows = await get_quotas(acct.id, db)
            client_count = (
                await db.scalar(
                    select(func.count(ClientRecord.uid)).where(
                        ClientRecord.account_id == acct.id
                    )
                )
                or 0
            )
            for r in rows:
                if r.quota_key == "max_clients":
                    cur = client_count
                elif r.quota_key == "max_bandwidth_mb":
                    cur = get_bandwidth_mb(acct.id, r.current_value)
                else:
                    cur = r.current_value
                print(f"  {r.quota_key}: {cur} / {r.max_value}")

    asyncio.run(_run())


@account_app.command("set-quota")
def set_quota_cmd(
    slug: Optional[str] = typer.Argument(None, help="Account Slug"),
    quota_key: Optional[str] = typer.Argument(
        None,
        help="Quota key (max_clients / max_grpc_connections / max_bandwidth_mb / feature.audit)",
    ),
    max_value: Optional[int] = typer.Argument(
        None, help="Maximum limit (-1 for unlimited)"
    ),
):
    """Set a resource quota limit for an account."""
    _require_args(slug=slug, quota_key=quota_key, max_value=max_value)

    async def _run():
        async with AsyncSessionLocal() as db:
            acct = (
                await db.execute(select(Account).where(Account.slug == slug))
            ).scalar_one_or_none()
            if not acct:
                print(f"❌ Account {slug} does not exist")
                return
            q = await set_quota(acct.id, quota_key or "", int(max_value or 0), db)
            print(f"✅ Quota {q.quota_key} for {slug} set to {q.max_value}")

    asyncio.run(_run())


@account_app.command("members")
def list_members_cmd(
    slug: Optional[str] = typer.Argument(None, help="Account Slug"),
):
    """List all member users in an account."""
    _require_args(slug=slug)

    async def _run():
        async with AsyncSessionLocal() as db:
            acct = (
                await db.execute(select(Account).where(Account.slug == slug))
            ).scalar_one_or_none()
            if not acct:
                print(f"❌ Account {slug} does not exist")
                return
            members = (
                (
                    await db.execute(
                        select(AccountMember).where(AccountMember.account_id == acct.id)
                    )
                )
                .scalars()
                .all()
            )
            if not members:
                print("No members found")
                return
            user_ids = [m.user_id for m in members]
            users = (
                (await db.execute(select(User).where(User.id.in_(user_ids))))
                .scalars()
                .all()
            )
            umap = {u.id: u for u in users}
            for m in members:
                u = umap.get(m.user_id)
                uname = u.username if u else m.user_id
                uemail = u.email if u else ""
                print(f"  {uname} ({uemail}) [role={m.role_in_account}]")

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
            existing = (
                await db.execute(
                    select(AccountMember).where(
                        AccountMember.user_id == user.id,
                        AccountMember.account_id == acct.id,
                    )
                )
            ).scalar_one_or_none()
            if existing:
                existing.role_in_account = role
                await db.commit()
                print(f"✅ Updated {username} role in {slug} to {role}")
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


@account_app.command("export-preset")
def export_preset_cmd(
    slug: Optional[str] = typer.Argument(None, help="Account Slug"),
    class_identity: str = typer.Option(
        "", "--class-identity", help="Optional ClassIdentity to embed"
    ),
    output: Optional[str] = typer.Option(
        None, "--output", "-o", help="Optional file path to save ManagementPreset.json"
    ),
):
    """Generate ManagementPreset.json for ClassIsland client onboarding."""
    _require_args(slug=slug)

    async def _run():
        async with AsyncSessionLocal() as db:
            acct = (
                await db.execute(select(Account).where(Account.slug == slug))
            ).scalar_one_or_none()
            if not acct:
                print(f"❌ Account {slug} does not exist")
                return
            preset: dict[str, Any] = {
                "IsManagementEnabled": True,
                "ManagementServerKind": 1,
                "ManagementServer": f"https://{acct.slug}.{BASE_DOMAIN}",
                "ManagementServerGrpc": f"https://{acct.slug}.{BASE_DOMAIN}",
            }
            if class_identity:
                preset["ClassIdentity"] = class_identity
            content = json.dumps(preset, ensure_ascii=False, indent=2)
            if output:
                Path(output).write_text(content, encoding="utf-8")
                print(f"✅ ManagementPreset.json written to {output}")
            else:
                print(content)

    asyncio.run(_run())
