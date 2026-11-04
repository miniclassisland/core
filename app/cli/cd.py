import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
import click
import typer
from sqlalchemy import delete, select

from app.shared.db.session import AsyncSessionLocal
from app.shared.db.models import Account, ClientProfile, MODEL_MAP
from app.shared.db.schema_init import seed_account_defaults
from app.shared.literals import DEFAULT_RESOURCES
from app.shared.security.crypto import (
    encode_classisland_credential,
    normalize_resource_payload,
)

cd_app = typer.Typer(
    help="Configuration deployment and continuous delivery management",
    no_args_is_help=True,
)


def _require_args(**kwargs) -> None:
    """Display command help and exit(0) if any required parameter is omitted."""
    if any(v is None for v in kwargs.values()):
        ctx = click.get_current_context(silent=True)
        if ctx is not None:
            print(ctx.get_help())
        raise typer.Exit(code=0)


@cd_app.command("types")
def list_resource_types():
    """List all supported ClassIsland configuration resource types."""
    for rtype in MODEL_MAP:
        print(f"  {rtype}")


@cd_app.command("list")
def list_resources_cmd(
    slug: Optional[str] = typer.Argument(None, help="Account Slug"),
    resource_type: Optional[str] = typer.Option(
        None, "--type", "-t", help="Optional resource type filter"
    ),
):
    """List configuration resource files for an account."""
    _require_args(slug=slug)

    async def _run():
        async with AsyncSessionLocal() as db:
            acct = (
                await db.execute(select(Account).where(Account.slug == slug))
            ).scalar_one_or_none()
            if not acct:
                print(f"❌ Account {slug} does not exist")
                return
            await seed_account_defaults(acct.id, db)
            await db.commit()

            types_to_query = (
                [resource_type] if resource_type else list(MODEL_MAP.keys())
            )
            for rt in types_to_query:
                model = MODEL_MAP.get(rt or "")
                if not model:
                    print(f"❌ Invalid resource type: {rt}")
                    return
                rows = (
                    (
                        await db.execute(
                            select(model)
                            .where(model.account_id == acct.id)
                            .order_by(model.name.asc())
                        )
                    )
                    .scalars()
                    .all()
                )
                names = [f"{r.name} (v{r.version})" for r in rows]
                print(f"  [{rt}]: {', '.join(names) if names else '(none)'}")

    asyncio.run(_run())


@cd_app.command("show")
def show_resource_cmd(
    slug: Optional[str] = typer.Argument(None, help="Account Slug"),
    resource_type: Optional[str] = typer.Argument(
        None,
        help="Resource type (ClassPlan / TimeLayout / Subjects / Policy / DefaultSettings / Components / Credentials)",
    ),
    name: Optional[str] = typer.Argument(None, help="Resource file name"),
):
    """Display JSON content of a configuration resource file."""
    _require_args(slug=slug, resource_type=resource_type, name=name)

    async def _run():
        model = MODEL_MAP.get(resource_type or "")
        if not model:
            print(f"❌ Invalid resource type: {resource_type}")
            return
        async with AsyncSessionLocal() as db:
            acct = (
                await db.execute(select(Account).where(Account.slug == slug))
            ).scalar_one_or_none()
            if not acct:
                print(f"❌ Account {slug} does not exist")
                return
            await seed_account_defaults(acct.id, db)
            await db.commit()
            rec = (
                await db.execute(
                    select(model).where(model.account_id == acct.id, model.name == name)
                )
            ).scalar_one_or_none()
            if not rec:
                print(f"❌ Resource {resource_type}/{name} does not exist")
                return
            parsed = json.loads(rec.content) if rec.content else {}
            normalized = normalize_resource_payload(resource_type or "", parsed)
            print(json.dumps(normalized, ensure_ascii=False, indent=2))

    asyncio.run(_run())


@cd_app.command("create")
def create_resource_cmd(
    slug: Optional[str] = typer.Argument(None, help="Account Slug"),
    resource_type: Optional[str] = typer.Argument(None, help="Resource type"),
    name: Optional[str] = typer.Argument(None, help="New resource file name"),
):
    """Create a new configuration resource file seeded with default template."""
    _require_args(slug=slug, resource_type=resource_type, name=name)

    async def _run():
        model = MODEL_MAP.get(resource_type or "")
        if not model:
            print(f"❌ Invalid resource type: {resource_type}")
            return
        async with AsyncSessionLocal() as db:
            acct = (
                await db.execute(select(Account).where(Account.slug == slug))
            ).scalar_one_or_none()
            if not acct:
                print(f"❌ Account {slug} does not exist")
                return
            existing = (
                await db.execute(
                    select(model).where(model.account_id == acct.id, model.name == name)
                )
            ).scalar_one_or_none()
            if existing:
                print(f"❌ Resource {resource_type}/{name} already exists")
                return
            tpl = DEFAULT_RESOURCES.get(resource_type or "", {}).get("default", {})
            db.add(
                model(
                    account_id=acct.id,
                    name=name,
                    content=json.dumps(tpl, ensure_ascii=False),
                    version=1,
                    updated_at=datetime.now(timezone.utc),
                )
            )
            await db.commit()
            print(f"✅ Resource {resource_type}/{name} created for {slug}")

    asyncio.run(_run())


@cd_app.command("delete")
def delete_resource_cmd(
    slug: Optional[str] = typer.Argument(None, help="Account Slug"),
    resource_type: Optional[str] = typer.Argument(None, help="Resource type"),
    name: Optional[str] = typer.Argument(None, help="Resource file name"),
):
    """Delete a configuration resource file."""
    _require_args(slug=slug, resource_type=resource_type, name=name)

    async def _run():
        model = MODEL_MAP.get(resource_type or "")
        if not model:
            print(f"❌ Invalid resource type: {resource_type}")
            return
        async with AsyncSessionLocal() as db:
            acct = (
                await db.execute(select(Account).where(Account.slug == slug))
            ).scalar_one_or_none()
            if not acct:
                print(f"❌ Account {slug} does not exist")
                return
            existing = (
                await db.execute(
                    select(model).where(model.account_id == acct.id, model.name == name)
                )
            ).scalar_one_or_none()
            if not existing:
                print(f"❌ Resource {resource_type}/{name} does not exist")
                return
            await db.delete(existing)
            await db.commit()
            print(f"✅ Resource {resource_type}/{name} deleted from {slug}")

    asyncio.run(_run())


@cd_app.command("export")
def export_resource_cmd(
    slug: Optional[str] = typer.Argument(None, help="Account Slug"),
    resource_type: Optional[str] = typer.Argument(None, help="Resource type"),
    name: Optional[str] = typer.Argument(None, help="Resource file name"),
    output: Optional[str] = typer.Argument(None, help="Destination JSON file path"),
):
    """Export a configuration resource file to a local JSON file."""
    _require_args(slug=slug, resource_type=resource_type, name=name, output=output)

    async def _run():
        model = MODEL_MAP.get(resource_type or "")
        if not model:
            print(f"❌ Invalid resource type: {resource_type}")
            return
        async with AsyncSessionLocal() as db:
            acct = (
                await db.execute(select(Account).where(Account.slug == slug))
            ).scalar_one_or_none()
            if not acct:
                print(f"❌ Account {slug} does not exist")
                return
            await seed_account_defaults(acct.id, db)
            await db.commit()
            rec = (
                await db.execute(
                    select(model).where(model.account_id == acct.id, model.name == name)
                )
            ).scalar_one_or_none()
            if not rec:
                print(f"❌ Resource {resource_type}/{name} does not exist")
                return
            parsed = json.loads(rec.content) if rec.content else {}
            normalized = normalize_resource_payload(resource_type or "", parsed)
            Path(output or "").write_text(
                json.dumps(normalized, ensure_ascii=False, indent=2), encoding="utf-8"
            )
            print(f"✅ Exported {resource_type}/{name} to {output}")

    asyncio.run(_run())


@cd_app.command("import")
def import_resource_cmd(
    slug: Optional[str] = typer.Argument(None, help="Account Slug"),
    resource_type: Optional[str] = typer.Argument(None, help="Resource type"),
    name: Optional[str] = typer.Argument(None, help="Target resource file name"),
    file_path: Optional[str] = typer.Argument(None, help="Source JSON file path"),
):
    """Import and write a local JSON file into a configuration resource."""
    _require_args(
        slug=slug, resource_type=resource_type, name=name, file_path=file_path
    )

    async def _run():
        model = MODEL_MAP.get(resource_type or "")
        if not model:
            print(f"❌ Invalid resource type: {resource_type}")
            return
        src = Path(file_path or "")
        if not src.exists():
            print(f"❌ File {file_path} does not exist")
            return
        try:
            payload = json.loads(src.read_text(encoding="utf-8"))
        except Exception as exc:
            print(f"❌ Invalid JSON file: {exc}")
            return

        async with AsyncSessionLocal() as db:
            acct = (
                await db.execute(select(Account).where(Account.slug == slug))
            ).scalar_one_or_none()
            if not acct:
                print(f"❌ Account {slug} does not exist")
                return
            normalized = normalize_resource_payload(resource_type or "", payload)
            rec = (
                await db.execute(
                    select(model).where(model.account_id == acct.id, model.name == name)
                )
            ).scalar_one_or_none()
            if not rec:
                rec = model(account_id=acct.id, name=name, version=0)
            rec.content = json.dumps(normalized, ensure_ascii=False)
            rec.version = (rec.version or 0) + 1
            rec.updated_at = datetime.now(timezone.utc)
            db.add(rec)
            await db.commit()
            print(
                f"✅ Imported {file_path} into {slug}:{resource_type}/{name} (v{rec.version})"
            )

    asyncio.run(_run())


@cd_app.command("assign")
def assign_profile_cmd(
    slug: Optional[str] = typer.Argument(None, help="Account Slug"),
    target: Optional[str] = typer.Argument(
        None, help="Client UID or '__default__' for account default profile"
    ),
    class_plan: Optional[str] = typer.Option(
        None, "--class-plan", help="ClassPlan name"
    ),
    time_layout: Optional[str] = typer.Option(
        None, "--time-layout", help="TimeLayout name"
    ),
    subjects: Optional[str] = typer.Option(None, "--subjects", help="Subjects name"),
    policy: Optional[str] = typer.Option(None, "--policy", help="Policy name"),
    default_settings: Optional[str] = typer.Option(
        None, "--default-settings", help="DefaultSettings name"
    ),
    components: Optional[str] = typer.Option(
        None, "--components", help="Components name"
    ),
    credentials: Optional[str] = typer.Option(
        None, "--credentials", help="Credentials name"
    ),
    reset_default: bool = typer.Option(
        False, "--reset", help="Reset custom client profile to inherit __default__"
    ),
):
    """Assign configuration resource cluster to a client UID or '__default__'."""
    _require_args(slug=slug, target=target)

    async def _run():
        async with AsyncSessionLocal() as db:
            acct = (
                await db.execute(select(Account).where(Account.slug == slug))
            ).scalar_one_or_none()
            if not acct:
                print(f"❌ Account {slug} does not exist")
                return
            if reset_default and target != "__default__":
                await db.execute(
                    delete(ClientProfile).where(
                        ClientProfile.account_id == acct.id,
                        ClientProfile.client_id == target,
                    )
                )
                await db.commit()
                print(f"✅ Reset profile for {target} to account default")
                return

            prof = (
                await db.execute(
                    select(ClientProfile).where(
                        ClientProfile.account_id == acct.id,
                        ClientProfile.client_id == target,
                    )
                )
            ).scalar_one_or_none()
            now = datetime.now(timezone.utc)
            if not prof:
                prof = ClientProfile(
                    account_id=acct.id,
                    client_id=target or "__default__",
                    updated_at=now,
                )
            for attr, val in (
                ("class_plan", class_plan),
                ("time_layout", time_layout),
                ("subjects", subjects),
                ("policy", policy),
                ("default_settings", default_settings),
                ("components", components),
                ("credentials", credentials),
            ):
                if val is not None:
                    setattr(prof, attr, val)
            prof.updated_at = now
            db.add(prof)
            await db.commit()
            print(
                f"✅ Assigned profile for {slug}/{target}: ClassPlan={prof.class_plan} "
                f"TimeLayout={prof.time_layout} Subjects={prof.subjects} Policy={prof.policy}"
            )

    asyncio.run(_run())


@cd_app.command("encode-credential")
def encode_credential_cmd(
    password: Optional[str] = typer.Argument(
        None, help="Plaintext password to encode as ClassIsland credential string"
    ),
):
    """Encode a plaintext password into an upstream ClassIsland Credential string."""
    _require_args(password=password)
    print(encode_classisland_credential(password or ""))
