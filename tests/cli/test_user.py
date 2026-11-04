"""test_user.py"""

from typer.testing import CliRunner
from app.cli.main import cli

runner = CliRunner()


def test_user_cli_commands():
    """Test user CLI subcommands (list, info, pending, approve, reject, create, ban, activate, reset-password, reset-2fa, set-create-account, set-role, delete) and no-arg help."""
    assert runner.invoke(cli, ["user"]).exit_code in (0, 2)
    for sub in (
        "info",
        "approve",
        "reject",
        "create",
        "delete",
        "ban",
        "activate",
        "reset-password",
        "reset-2fa",
        "set-create-account",
        "set-role",
    ):
        res_help = runner.invoke(cli, ["user", sub])
        assert res_help.exit_code == 0
        assert "Usage" in res_help.output

    # Pending when empty
    res_pend_empty = runner.invoke(cli, ["user", "pending"])
    assert res_pend_empty.exit_code == 0

    # Operations on non-existent user
    for cmd_args in (
        ["user", "info", "missing_u"],
        ["user", "approve", "missing_u"],
        ["user", "reject", "missing_u"],
        ["user", "delete", "missing_u"],
        ["user", "ban", "missing_u"],
        ["user", "activate", "missing_u"],
        ["user", "reset-password", "missing_u", "NewPass123456!"],
        ["user", "reset-2fa", "missing_u"],
        ["user", "set-create-account", "missing_u", "true"],
        ["user", "set-role", "missing_u", "admin"],
    ):
        assert runner.invoke(cli, cmd_args).exit_code == 0

    # Create user with custom role
    assert (
        runner.invoke(
            cli,
            [
                "user",
                "create",
                "cli_user_1",
                "cli1@school.com",
                "CliPassword123!",
                "--role",
                "admin",
            ],
        ).exit_code
        == 0
    )

    # Duplicate user creation -> prints error
    assert (
        runner.invoke(
            cli,
            [
                "user",
                "create",
                "cli_user_1",
                "cli1@school.com",
                "CliPassword123!",
            ],
        ).exit_code
        == 0
    )

    # List users (non-empty) & user info (with and without account membership)
    res_list = runner.invoke(cli, ["user", "list"])
    assert res_list.exit_code == 0
    assert "cli_user_1" in res_list.output

    res_info1 = runner.invoke(cli, ["user", "info", "cli_user_1"])
    assert res_info1.exit_code == 0
    assert "(none)" in res_info1.output

    # Add user to an account to cover membership display in user info
    assert (
        runner.invoke(
            cli, ["account", "create", "User Info Org", "uinfo-org"]
        ).exit_code
        == 0
    )
    assert (
        runner.invoke(
            cli, ["account", "add-member", "uinfo-org", "cli_user_1"]
        ).exit_code
        == 0
    )
    res_info2 = runner.invoke(cli, ["user", "info", "cli_user_1"])
    assert res_info2.exit_code == 0
    assert "uinfo-org" in res_info2.output
    assert runner.invoke(cli, ["account", "delete", "uinfo-org"]).exit_code == 0

    # Approve / Reject when user is NOT in pending state
    assert runner.invoke(cli, ["user", "approve", "cli_user_1"]).exit_code == 0
    assert runner.invoke(cli, ["user", "reject", "cli_user_1"]).exit_code == 0

    # Set role to pending, test pending list and approve
    assert (
        runner.invoke(cli, ["user", "set-role", "cli_user_1", "pending"]).exit_code == 0
    )
    res_pend = runner.invoke(cli, ["user", "pending"])
    assert res_pend.exit_code == 0
    assert "cli_user_1" in res_pend.output
    assert runner.invoke(cli, ["user", "approve", "cli_user_1"]).exit_code == 0

    # Set role to pending again and test reject
    assert (
        runner.invoke(
            cli,
            ["user", "create", "cli_user_pend2", "pend2@school.com", "CliPassword123!"],
        ).exit_code
        == 0
    )
    assert (
        runner.invoke(cli, ["user", "set-role", "cli_user_pend2", "pending"]).exit_code
        == 0
    )
    assert runner.invoke(cli, ["user", "reject", "cli_user_pend2"]).exit_code == 0

    # Ban, activate, reset-password, reset-2fa, set-create-account, set-role, delete
    assert runner.invoke(cli, ["user", "ban", "cli_user_1"]).exit_code == 0
    assert runner.invoke(cli, ["user", "activate", "cli_user_1"]).exit_code == 0
    assert (
        runner.invoke(
            cli, ["user", "reset-password", "cli_user_1", "NewPass123456!"]
        ).exit_code
        == 0
    )
    assert runner.invoke(cli, ["user", "reset-2fa", "cli_user_1"]).exit_code == 0
    assert (
        runner.invoke(
            cli, ["user", "set-create-account", "cli_user_1", "true"]
        ).exit_code
        == 0
    )
    assert (
        runner.invoke(cli, ["user", "set-role", "cli_user_1", "superadmin"]).exit_code
        == 0
    )
    assert runner.invoke(cli, ["user", "delete", "cli_user_1"]).exit_code == 0
