import asyncio
import uuid
from datetime import datetime, timezone
from typing import Optional
import click
import typer
from sqlalchemy import delete, or_, select

from app.shared.db.session import AsyncSessionLocal
from app.shared.db.models import (
    Account,
    AuditLog,
    ClientProfile,
    ClientRecord,
    PairingCode,
    PreRegisteredClient,
)
from app.shared.literals import AUDIT_EVENT_NAMES
from app.grpc.session import SessionManager

client_app = typer.Typer(
    help="Client devices and state management",
    no_args_is_help=True,
)


def _require_args(**kwargs) -> None:
    """Display command help and exit(0) if any required parameter is omitted."""
    if any(v is None for v in kwargs.values()):
        ctx = click.get_current_context(silent=True)
        if ctx is not None:
            print(ctx.get_help())
        raise typer.Exit(code=0)


@client_app.command("list")
def list_clients_cmd(
    account: Optional[str] = typer.Option(
        None, "--account", "-a", help="Filter by account slug"
    ),
):
    """List registered physical client devices."""

    async def _run():
        async with AsyncSessionLocal() as db:
            stmt = select(ClientRecord).order_by(ClientRecord.registered_at.desc())
            if account:
                acct = (
                    await db.execute(select(Account).where(Account.slug == account))
                ).scalar_one_or_none()
                if not acct:
                    print(f"❌ Account {account} does not exist")
                    return
                stmt = stmt.where(ClientRecord.account_id == acct.id)

            rows = (await db.execute(stmt)).scalars().all()
            if not rows:
                print("No registered client devices found")
                return

            accts = (await db.execute(select(Account))).scalars().all()
            acct_map = {a.id: a.slug for a in accts}
            sm = SessionManager()
            for r in rows:
                online = await sm.is_client_online(r.account_id, r.uid)
                status_str = (
                    "disabled" if r.is_disabled else ("online" if online else "offline")
                )
                slug_str = acct_map.get(r.account_id, r.account_id)
                label = r.display_name or r.client_id or r.uid
                print(
                    f"  {r.uid} ({label}) [account={slug_str} id={r.client_id} ip={r.ip} status={status_str}]"
                )

    asyncio.run(_run())


@client_app.command("info")
def client_info_cmd(
    uid: Optional[str] = typer.Argument(None, help="Client device UID"),
):
    """Show detailed status and profile cluster for a client device."""
    _require_args(uid=uid)

    async def _run():
        async with AsyncSessionLocal() as db:
            rec = (
                await db.execute(select(ClientRecord).where(ClientRecord.uid == uid))
            ).scalar_one_or_none()
            if not rec:
                print(f"❌ Client device {uid} does not exist")
                return
            acct = (
                await db.execute(select(Account).where(Account.id == rec.account_id))
            ).scalar_one_or_none()
            prof = (
                await db.execute(
                    select(ClientProfile).where(
                        ClientProfile.account_id == rec.account_id,
                        ClientProfile.client_id == rec.uid,
                    )
                )
            ).scalar_one_or_none()
            if not prof:
                prof = (
                    await db.execute(
                        select(ClientProfile).where(
                            ClientProfile.account_id == rec.account_id,
                            ClientProfile.client_id == "__default__",
                        )
                    )
                ).scalar_one_or_none()

            sm = SessionManager()
            online = await sm.is_client_online(rec.account_id, rec.uid)
            slug_str = acct.slug if acct else rec.account_id
            print(f"UID:          {rec.uid}")
            print(f"Account:      {slug_str}")
            print(f"ClassID:      {rec.client_id}")
            print(f"Display Name: {rec.display_name}")
            print(f"MAC:          {rec.mac}")
            print(f"IP:           {rec.ip}")
            print(f"Online:       {online and not rec.is_disabled}")
            print(f"Disabled:     {rec.is_disabled}")
            if prof:
                print(
                    f"Profile:      ClassPlan={prof.class_plan} TimeLayout={prof.time_layout} "
                    f"Subjects={prof.subjects} Policy={prof.policy} DefaultSettings={prof.default_settings} "
                    f"Components={prof.components} Credentials={prof.credentials}"
                )

    asyncio.run(_run())


@client_app.command("enable")
def enable_client_cmd(
    uid: Optional[str] = typer.Argument(None, help="Client device UID to enable"),
):
    """Enable a disabled client device."""
    _require_args(uid=uid)

    async def _run():
        async with AsyncSessionLocal() as db:
            rec = (
                await db.execute(select(ClientRecord).where(ClientRecord.uid == uid))
            ).scalar_one_or_none()
            if not rec:
                print(f"❌ Client device {uid} does not exist")
                return
            rec.is_disabled = False
            await db.commit()
            print(f"✅ Client device {uid} enabled")

    asyncio.run(_run())


@client_app.command("disable")
def disable_client_cmd(
    uid: Optional[str] = typer.Argument(None, help="Client device UID to disable"),
):
    """Disable a client device and mark its session offline."""
    _require_args(uid=uid)

    async def _run():
        async with AsyncSessionLocal() as db:
            rec = (
                await db.execute(select(ClientRecord).where(ClientRecord.uid == uid))
            ).scalar_one_or_none()
            if not rec:
                print(f"❌ Client device {uid} does not exist")
                return
            rec.is_disabled = True
            await db.commit()
            sm = SessionManager()
            await sm.set_client_offline(rec.account_id, rec.uid)
            print(f"✅ Client device {uid} disabled")

    asyncio.run(_run())


@client_app.command("rename")
def rename_client_cmd(
    uid: Optional[str] = typer.Argument(None, help="Client device UID"),
    name: Optional[str] = typer.Argument(None, help="New display name"),
    class_id: Optional[str] = typer.Option(
        None, "--class-id", help="Optional new ClassIdentity (client_id)"
    ),
):
    """Update display name (and optionally ClassIdentity) for a client device."""
    _require_args(uid=uid, name=name)

    async def _run():
        async with AsyncSessionLocal() as db:
            rec = (
                await db.execute(select(ClientRecord).where(ClientRecord.uid == uid))
            ).scalar_one_or_none()
            if not rec:
                print(f"❌ Client device {uid} does not exist")
                return
            rec.display_name = (name or "").strip()
            if class_id is not None:
                rec.client_id = class_id.strip()
            await db.commit()
            print(f"✅ Client device {uid} renamed to {rec.display_name}")

    asyncio.run(_run())


@client_app.command("delete")
def delete_client_cmd(
    uid: Optional[str] = typer.Argument(None, help="Client device UID to delete"),
):
    """Unregister and delete a client device record."""
    _require_args(uid=uid)

    async def _run():
        async with AsyncSessionLocal() as db:
            rec = (
                await db.execute(select(ClientRecord).where(ClientRecord.uid == uid))
            ).scalar_one_or_none()
            if not rec:
                print(f"❌ Client device {uid} does not exist")
                return
            acct_id = rec.account_id
            await db.execute(
                delete(ClientProfile).where(
                    ClientProfile.account_id == acct_id,
                    ClientProfile.client_id == rec.uid,
                )
            )
            await db.delete(rec)
            await db.commit()
            sm = SessionManager()
            await sm.set_client_offline(acct_id, uid or "")
            print(f"✅ Client device {uid} deleted")

    asyncio.run(_run())


@client_app.command("pre-reg-list")
def list_pre_reg_cmd(
    slug: Optional[str] = typer.Argument(None, help="Account Slug"),
):
    """List pre-registered devices for an account."""
    _require_args(slug=slug)

    async def _run():
        async with AsyncSessionLocal() as db:
            acct = (
                await db.execute(select(Account).where(Account.slug == slug))
            ).scalar_one_or_none()
            if not acct:
                print(f"❌ Account {slug} does not exist")
                return
            rows = (
                (
                    await db.execute(
                        select(PreRegisteredClient)
                        .where(PreRegisteredClient.account_id == acct.id)
                        .order_by(PreRegisteredClient.created_at.desc())
                    )
                )
                .scalars()
                .all()
            )
            if not rows:
                print("No pre-registered devices found")
                return
            for p in rows:
                print(
                    f"  {p.id} | {p.label} [class_identity={p.class_identity} mac={p.mac_address} enabled={p.is_enabled} bound={p.bound_client_uid}]"
                )

    asyncio.run(_run())


@client_app.command("pre-reg-add")
def add_pre_reg_cmd(
    slug: Optional[str] = typer.Argument(None, help="Account Slug"),
    label: Optional[str] = typer.Argument(None, help="Device display label"),
    class_identity: Optional[str] = typer.Argument(None, help="Device ClassIdentity"),
    mac: str = typer.Option("", "--mac", help="Optional device MAC address"),
):
    """Create a pre-registered device entry for an account."""
    _require_args(slug=slug, label=label, class_identity=class_identity)

    async def _run():
        async with AsyncSessionLocal() as db:
            acct = (
                await db.execute(select(Account).where(Account.slug == slug))
            ).scalar_one_or_none()
            if not acct:
                print(f"❌ Account {slug} does not exist")
                return
            ci = (class_identity or "").strip()
            dup = (
                await db.execute(
                    select(PreRegisteredClient).where(
                        PreRegisteredClient.account_id == acct.id,
                        PreRegisteredClient.class_identity == ci,
                    )
                )
            ).scalar_one_or_none()
            if dup:
                print(f"❌ Pre-registered class_identity {ci} already exists")
                return
            p = PreRegisteredClient(
                id=str(uuid.uuid4()),
                account_id=acct.id,
                label=(label or "").strip(),
                class_identity=ci,
                mac_address=mac.strip(),
                is_enabled=True,
                preset_profile_json="{}",
                created_at=datetime.now(timezone.utc),
            )
            db.add(p)
            await db.commit()
            print(f"✅ Pre-registered device {p.id} ({ci}) created")

    asyncio.run(_run())


@client_app.command("pre-reg-delete")
def delete_pre_reg_cmd(
    pre_reg_id: Optional[str] = typer.Argument(None, help="Pre-registered record ID"),
):
    """Delete a pre-registered device entry by ID."""
    _require_args(pre_reg_id=pre_reg_id)

    async def _run():
        async with AsyncSessionLocal() as db:
            row = (
                await db.execute(
                    select(PreRegisteredClient).where(
                        PreRegisteredClient.id == pre_reg_id
                    )
                )
            ).scalar_one_or_none()
            if not row:
                print(f"❌ Pre-registered device {pre_reg_id} does not exist")
                return
            await db.delete(row)
            await db.commit()
            print(f"✅ Pre-registered device {pre_reg_id} deleted")

    asyncio.run(_run())


@client_app.command("pairing-list")
def list_pairing_cmd(
    slug: Optional[str] = typer.Argument(None, help="Account Slug"),
):
    """List device pairing code requests for an account."""
    _require_args(slug=slug)

    async def _run():
        async with AsyncSessionLocal() as db:
            acct = (
                await db.execute(select(Account).where(Account.slug == slug))
            ).scalar_one_or_none()
            if not acct:
                print(f"❌ Account {slug} does not exist")
                return
            rows = (
                (
                    await db.execute(
                        select(PairingCode)
                        .where(PairingCode.tenant_id == acct.id)
                        .order_by(PairingCode.created_at.desc())
                    )
                )
                .scalars()
                .all()
            )
            if not rows:
                print("No pairing requests found")
                return
            for r in rows:
                print(
                    f"  {r.code} [uid={r.client_uid} id={r.client_id} ip={r.client_ip} approved={r.approved} used={r.used}]"
                )

    asyncio.run(_run())


@client_app.command("pairing-approve")
def approve_pairing_cmd(
    code: Optional[str] = typer.Argument(None, help="Pairing code or ID"),
):
    """Approve a pending device pairing code."""
    _require_args(code=code)

    async def _run():
        async with AsyncSessionLocal() as db:
            row = (
                await db.execute(
                    select(PairingCode).where(
                        or_(PairingCode.code == code, PairingCode.id == code)
                    )
                )
            ).scalar_one_or_none()
            if not row:
                print(f"❌ Pairing code {code} does not exist")
                return
            row.approved = True
            row.status = "approved"
            await db.commit()
            print(f"✅ Pairing code {row.code} approved")

    asyncio.run(_run())


@client_app.command("pairing-reject")
def reject_pairing_cmd(
    code: Optional[str] = typer.Argument(None, help="Pairing code or ID"),
):
    """Reject and delete a device pairing code."""
    _require_args(code=code)

    async def _run():
        async with AsyncSessionLocal() as db:
            row = (
                await db.execute(
                    select(PairingCode).where(
                        or_(PairingCode.code == code, PairingCode.id == code)
                    )
                )
            ).scalar_one_or_none()
            if not row:
                print(f"❌ Pairing code {code} does not exist")
                return
            await db.delete(row)
            await db.commit()
            print(f"✅ Pairing code {code} rejected")

    asyncio.run(_run())


@client_app.command("audit-list")
def list_audit_cmd(
    slug: Optional[str] = typer.Argument(None, help="Account Slug"),
    limit: int = typer.Option(20, "--limit", "-n", help="Max records to display"),
):
    """List recent client audit event logs for an account."""
    _require_args(slug=slug)

    async def _run():
        async with AsyncSessionLocal() as db:
            acct = (
                await db.execute(select(Account).where(Account.slug == slug))
            ).scalar_one_or_none()
            if not acct:
                print(f"❌ Account {slug} does not exist")
                return
            rows = (
                (
                    await db.execute(
                        select(AuditLog)
                        .where(AuditLog.account_id == acct.id)
                        .order_by(AuditLog.id.desc())
                        .limit(limit)
                    )
                )
                .scalars()
                .all()
            )
            if not rows:
                print("No audit logs found")
                return
            for r in rows:
                ev_name = AUDIT_EVENT_NAMES.get(r.event, f"Event_{r.event}")
                print(
                    f"  #{r.id} [{r.received_at.isoformat()}] uid={r.client_uid} event={ev_name} ({r.event})"
                )

    asyncio.run(_run())


@client_app.command("audit-clear")
def clear_audit_cmd(
    slug: Optional[str] = typer.Argument(None, help="Account Slug"),
):
    """Clear all audit event logs for an account."""
    _require_args(slug=slug)

    async def _run():
        async with AsyncSessionLocal() as db:
            acct = (
                await db.execute(select(Account).where(Account.slug == slug))
            ).scalar_one_or_none()
            if not acct:
                print(f"❌ Account {slug} does not exist")
                return
            await db.execute(delete(AuditLog).where(AuditLog.account_id == acct.id))
            await db.commit()
            print(f"✅ Audit logs cleared for account {slug}")

    asyncio.run(_run())


@client_app.command("a", hidden=True)
def cmd_a():
    """Client management placeholder command a."""
    print("client cmd a executed")


@client_app.command("b", hidden=True)
def cmd_b():
    """Client management placeholder command b."""
    print("client cmd b executed")
