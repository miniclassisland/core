"""test_client.py"""

import asyncio
from datetime import datetime, timezone
from typer.testing import CliRunner
from sqlalchemy import select
from app.cli.main import cli
from app.shared.db.session import AsyncSessionLocal
from app.shared.db.models import (
    Account,
    AuditLog,
    ClientRecord,
    PairingCode,
    PreRegisteredClient,
)

runner = CliRunner()


def test_client_cli_commands():
    """Test client CLI commands (list, info, enable, disable, rename, delete, pre-reg-*, pairing-*, audit-*)."""
    # No-args help on group and subcommands with required arguments
    assert runner.invoke(cli, ["client"]).exit_code in (0, 2)
    for sub in (
        "info",
        "enable",
        "disable",
        "rename",
        "delete",
        "pre-reg-list",
        "pre-reg-add",
        "pre-reg-delete",
        "pairing-list",
        "pairing-approve",
        "pairing-reject",
        "audit-list",
        "audit-clear",
    ):
        res_help = runner.invoke(cli, ["client", sub])
        assert res_help.exit_code == 0
        assert "Usage" in res_help.output

    # Empty client list & missing account filter
    assert runner.invoke(cli, ["client", "list"]).exit_code == 0
    assert (
        runner.invoke(cli, ["client", "list", "--account", "no-such-org"]).exit_code
        == 0
    )

    # Operations on missing client / account / pre-reg / pairing
    for missing_cmd in (
        ["client", "info", "missing-uid"],
        ["client", "enable", "missing-uid"],
        ["client", "disable", "missing-uid"],
        ["client", "rename", "missing-uid", "NewName"],
        ["client", "delete", "missing-uid"],
        ["client", "pre-reg-list", "no-such-org"],
        ["client", "pre-reg-add", "no-such-org", "Label", "Class1"],
        ["client", "pre-reg-delete", "no-such-id"],
        ["client", "pairing-list", "no-such-org"],
        ["client", "pairing-approve", "NO-CODE"],
        ["client", "pairing-reject", "NO-CODE"],
        ["client", "audit-list", "no-such-org"],
        ["client", "audit-clear", "no-such-org"],
    ):
        assert runner.invoke(cli, missing_cmd).exit_code == 0

    # Create test account
    assert (
        runner.invoke(
            cli, ["account", "create", "Client CLI Org", "ccli-org"]
        ).exit_code
        == 0
    )

    # Empty pre-reg, pairing, audit lists for existing account
    assert runner.invoke(cli, ["client", "pre-reg-list", "ccli-org"]).exit_code == 0
    assert runner.invoke(cli, ["client", "pairing-list", "ccli-org"]).exit_code == 0
    assert runner.invoke(cli, ["client", "audit-list", "ccli-org"]).exit_code == 0

    # Pre-registration add, duplicate, list, delete
    assert (
        runner.invoke(
            cli,
            [
                "client",
                "pre-reg-add",
                "ccli-org",
                "Room 101",
                "Class-101",
                "--mac",
                "AA:BB:CC:DD:EE:01",
            ],
        ).exit_code
        == 0
    )
    assert (
        runner.invoke(
            cli,
            ["client", "pre-reg-add", "ccli-org", "Room 101", "Class-101"],
        ).exit_code
        == 0
    )
    res_prereg = runner.invoke(cli, ["client", "pre-reg-list", "ccli-org"])
    assert res_prereg.exit_code == 0
    assert "Class-101" in res_prereg.output

    # Seed a client record, pairing codes, and audit log in DB
    async def _seed_data() -> str:
        async with AsyncSessionLocal() as db:
            acct = (
                await db.execute(select(Account).where(Account.slug == "ccli-org"))
            ).scalar_one()
            pre = (
                await db.execute(
                    select(PreRegisteredClient).where(
                        PreRegisteredClient.account_id == acct.id
                    )
                )
            ).scalar_one()
            now = datetime.now(timezone.utc)
            db.add(
                ClientRecord(
                    uid="cli-dev-uid-1",
                    account_id=acct.id,
                    client_id="Class-101",
                    display_name="Room 101 PC",
                    mac="AA:BB:CC:DD:EE:01",
                    ip="10.0.0.10",
                    is_disabled=False,
                    registered_at=now,
                    last_seen_at=now,
                )
            )
            db.add(
                PairingCode(
                    id="pair-id-1",
                    code="PAIR01",
                    tenant_id=acct.id,
                    client_uid="cli-dev-uid-1",
                    client_id="Class-101",
                    client_mac="AA:BB:CC:DD:EE:01",
                    client_ip="10.0.0.10",
                    status="pending",
                    created_at=now,
                    approved=False,
                    used=False,
                )
            )
            db.add(
                AuditLog(
                    account_id=acct.id,
                    client_uid="cli-dev-uid-1",
                    event=10,
                    payload="",
                    decoded_json="{}",
                    timestamp_utc=1700000000,
                    received_at=now,
                )
            )
            await db.commit()
            return pre.id

    pre_id = asyncio.run(_seed_data())

    # Delete pre-reg
    assert runner.invoke(cli, ["client", "pre-reg-delete", pre_id]).exit_code == 0

    # List clients (all & filtered by account)
    res_list = runner.invoke(cli, ["client", "list", "--account", "ccli-org"])
    assert res_list.exit_code == 0
    assert "cli-dev-uid-1" in res_list.output

    # Client info (using __default__ profile fallback, then custom profile)
    res_info_def = runner.invoke(cli, ["client", "info", "cli-dev-uid-1"])
    assert res_info_def.exit_code == 0
    assert "cli-dev-uid-1" in res_info_def.output

    assert (
        runner.invoke(
            cli,
            [
                "cd",
                "assign",
                "ccli-org",
                "cli-dev-uid-1",
                "--class-plan",
                "default",
            ],
        ).exit_code
        == 0
    )
    res_info_cust = runner.invoke(cli, ["client", "info", "cli-dev-uid-1"])
    assert res_info_cust.exit_code == 0

    # Disable, enable, rename
    assert runner.invoke(cli, ["client", "disable", "cli-dev-uid-1"]).exit_code == 0
    assert runner.invoke(cli, ["client", "enable", "cli-dev-uid-1"]).exit_code == 0
    assert (
        runner.invoke(
            cli,
            [
                "client",
                "rename",
                "cli-dev-uid-1",
                "Updated Room 101",
                "--class-id",
                "Class-101B",
            ],
        ).exit_code
        == 0
    )

    # Pairing list, approve, reject
    res_pair = runner.invoke(cli, ["client", "pairing-list", "ccli-org"])
    assert res_pair.exit_code == 0
    assert "PAIR01" in res_pair.output
    assert runner.invoke(cli, ["client", "pairing-approve", "PAIR01"]).exit_code == 0
    assert runner.invoke(cli, ["client", "pairing-reject", "PAIR01"]).exit_code == 0

    # Audit list & clear
    res_audit = runner.invoke(cli, ["client", "audit-list", "ccli-org"])
    assert res_audit.exit_code == 0
    assert "cli-dev-uid-1" in res_audit.output
    assert runner.invoke(cli, ["client", "audit-clear", "ccli-org"]).exit_code == 0

    # Delete client & account
    assert runner.invoke(cli, ["client", "delete", "cli-dev-uid-1"]).exit_code == 0
    assert runner.invoke(cli, ["account", "delete", "ccli-org"]).exit_code == 0
