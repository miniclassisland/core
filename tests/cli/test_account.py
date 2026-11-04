"""test_account.py"""

from pathlib import Path
from typer.testing import CliRunner
from app.cli.main import cli

runner = CliRunner()


def test_account_cli_commands(tmp_path: Path):
    """Test account CLI subcommands (list, info, create, delete, enable, disable, set-reg-mode, quotas, set-quota, members, add-member, remove-member, export-preset) and no-arg help."""
    # No-args help on group and subcommands with required arguments
    assert runner.invoke(cli, ["account"]).exit_code in (0, 2)
    for sub in (
        "info",
        "create",
        "delete",
        "enable",
        "disable",
        "set-reg-mode",
        "quotas",
        "set-quota",
        "members",
        "add-member",
        "remove-member",
        "export-preset",
    ):
        res_help = runner.invoke(cli, ["account", sub])
        assert res_help.exit_code == 0
        assert "Usage" in res_help.output

    # Empty list
    res_empty = runner.invoke(cli, ["account", "list"])
    assert res_empty.exit_code == 0

    # Operations on non-existent account
    for missing_cmd in (
        ["account", "info", "missing-slug"],
        ["account", "delete", "missing-slug"],
        ["account", "enable", "missing-slug"],
        ["account", "disable", "missing-slug"],
        ["account", "set-reg-mode", "missing-slug", "open"],
        ["account", "quotas", "missing-slug"],
        ["account", "set-quota", "missing-slug", "max_clients", "10"],
        ["account", "members", "missing-slug"],
        ["account", "export-preset", "missing-slug"],
    ):
        assert runner.invoke(cli, missing_cmd).exit_code == 0

    # Invalid registration mode
    assert (
        runner.invoke(
            cli, ["account", "set-reg-mode", "missing-slug", "invalid-mode"]
        ).exit_code
        == 0
    )

    # Create account
    assert (
        runner.invoke(
            cli, ["account", "create", "Test School", "test-acc-slug"]
        ).exit_code
        == 0
    )

    # Duplicate account creation
    res_dup = runner.invoke(cli, ["account", "create", "Test School", "test-acc-slug"])
    assert res_dup.exit_code == 0
    assert "already exists" in res_dup.output

    # Non-empty list & info
    res_list = runner.invoke(cli, ["account", "list"])
    assert res_list.exit_code == 0
    assert "test-acc-slug" in res_list.output

    res_info = runner.invoke(cli, ["account", "info", "test-acc-slug"])
    assert res_info.exit_code == 0
    assert "test-acc-slug" in res_info.output

    # Enable / Disable / Set Registration Mode
    assert runner.invoke(cli, ["account", "disable", "test-acc-slug"]).exit_code == 0
    assert runner.invoke(cli, ["account", "enable", "test-acc-slug"]).exit_code == 0
    assert (
        runner.invoke(
            cli, ["account", "set-reg-mode", "test-acc-slug", "pairing"]
        ).exit_code
        == 0
    )

    # Quotas & Set-Quota
    res_quotas = runner.invoke(cli, ["account", "quotas", "test-acc-slug"])
    assert res_quotas.exit_code == 0
    assert "max_clients" in res_quotas.output

    assert (
        runner.invoke(
            cli, ["account", "set-quota", "test-acc-slug", "max_clients", "20"]
        ).exit_code
        == 0
    )

    # Export ManagementPreset.json (stdout and file)
    res_preset = runner.invoke(
        cli,
        [
            "account",
            "export-preset",
            "test-acc-slug",
            "--class-identity",
            "Class-1",
        ],
    )
    assert res_preset.exit_code == 0
    assert "Class-1" in res_preset.output

    preset_file = tmp_path / "ManagementPreset.json"
    assert (
        runner.invoke(
            cli,
            [
                "account",
                "export-preset",
                "test-acc-slug",
                "-o",
                str(preset_file),
            ],
        ).exit_code
        == 0
    )
    assert preset_file.exists()

    # Members when empty
    res_mem_empty = runner.invoke(cli, ["account", "members", "test-acc-slug"])
    assert res_mem_empty.exit_code == 0
    assert "No members found" in res_mem_empty.output

    # Add/remove member when user does not exist
    assert (
        runner.invoke(
            cli, ["account", "add-member", "test-acc-slug", "no_such_user"]
        ).exit_code
        == 0
    )
    assert (
        runner.invoke(
            cli, ["account", "remove-member", "test-acc-slug", "no_such_user"]
        ).exit_code
        == 0
    )

    # Create user via CLI and test add-member / members / remove-member
    assert (
        runner.invoke(
            cli,
            ["user", "create", "cli_mem_user", "climem@school.com", "CliMemPass123!"],
        ).exit_code
        == 0
    )

    # Remove before adding (membership record does not exist)
    assert (
        runner.invoke(
            cli, ["account", "remove-member", "test-acc-slug", "cli_mem_user"]
        ).exit_code
        == 0
    )

    # Add member & update existing member role
    assert (
        runner.invoke(
            cli, ["account", "add-member", "test-acc-slug", "cli_mem_user"]
        ).exit_code
        == 0
    )
    assert (
        runner.invoke(
            cli,
            [
                "account",
                "add-member",
                "test-acc-slug",
                "cli_mem_user",
                "--role",
                "admin",
            ],
        ).exit_code
        == 0
    )

    # List members (non-empty)
    res_mem_list = runner.invoke(cli, ["account", "members", "test-acc-slug"])
    assert res_mem_list.exit_code == 0
    assert "cli_mem_user" in res_mem_list.output

    # Remove member
    assert (
        runner.invoke(
            cli, ["account", "remove-member", "test-acc-slug", "cli_mem_user"]
        ).exit_code
        == 0
    )

    # Delete account
    assert runner.invoke(cli, ["account", "delete", "test-acc-slug"]).exit_code == 0
    assert runner.invoke(cli, ["user", "delete", "cli_mem_user"]).exit_code == 0
