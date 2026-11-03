"""test_user.py"""

from typer.testing import CliRunner
from app.cli.main import cli

runner = CliRunner()


def test_user_cli_commands():
    """Test user CLI subcommands (list, create, ban, activate, reset-password, set-role, delete)."""
    # Operations on non-existent user
    for cmd_args in (
        ["user", "delete", "missing_u"],
        ["user", "ban", "missing_u"],
        ["user", "activate", "missing_u"],
        ["user", "reset-password", "missing_u", "NewPass123456!"],
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

    # List users (non-empty)
    res_list = runner.invoke(cli, ["user", "list"])
    assert res_list.exit_code == 0
    assert "cli_user_1" in res_list.output

    # Ban, activate, reset-password, set-role, delete
    assert runner.invoke(cli, ["user", "ban", "cli_user_1"]).exit_code == 0
    assert runner.invoke(cli, ["user", "activate", "cli_user_1"]).exit_code == 0
    assert (
        runner.invoke(
            cli, ["user", "reset-password", "cli_user_1", "NewPass123456!"]
        ).exit_code
        == 0
    )
    assert (
        runner.invoke(cli, ["user", "set-role", "cli_user_1", "superadmin"]).exit_code
        == 0
    )
    assert runner.invoke(cli, ["user", "delete", "cli_user_1"]).exit_code == 0
