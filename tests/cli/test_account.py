"""test_account.py"""

from typer.testing import CliRunner
from app.cli.main import cli

runner = CliRunner()


def test_account_cli_commands():
    """Test account CLI subcommands (list, create, delete, add-member, remove-member) and no-arg help."""
    # No-args help on group and subcommands with required arguments
    assert runner.invoke(cli, ["account"]).exit_code in (0, 2)
    for sub in ("create", "delete", "add-member", "remove-member"):
        res_help = runner.invoke(cli, ["account", sub])
        assert res_help.exit_code == 0
        assert "Usage" in res_help.output

    # Empty list
    res_empty = runner.invoke(cli, ["account", "list"])
    assert res_empty.exit_code == 0

    # Delete non-existent
    res_del_missing = runner.invoke(cli, ["account", "delete", "missing-slug"])
    assert res_del_missing.exit_code == 0

    # Create account
    assert (
        runner.invoke(
            cli, ["account", "create", "Test School", "test-acc-slug"]
        ).exit_code
        == 0
    )

    # Non-empty list
    res_list = runner.invoke(cli, ["account", "list"])
    assert res_list.exit_code == 0
    assert "test-acc-slug" in res_list.output

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

    # Create user via CLI and test add-member / remove-member
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

    # Add member
    assert (
        runner.invoke(
            cli, ["account", "add-member", "test-acc-slug", "cli_mem_user"]
        ).exit_code
        == 0
    )

    # Remove member
    assert (
        runner.invoke(
            cli, ["account", "remove-member", "test-acc-slug", "cli_mem_user"]
        ).exit_code
        == 0
    )

    # Delete account
    assert runner.invoke(cli, ["account", "delete", "test-acc-slug"]).exit_code == 0
