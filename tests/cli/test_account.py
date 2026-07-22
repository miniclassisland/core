"""test_account.py
"""

from typer.testing import CliRunner
from app.cli.main import cli

runner = CliRunner()


def test_account_cli_commands():
    """测试商户账户命令行入口及各种操作。"""
    runner.invoke(cli, ["account", "delete", "test-acc-id"])
    assert runner.invoke(cli, ["account", "list"]).exit_code == 0
    assert runner.invoke(cli, ["account", "create", "test-acc-id"]).exit_code == 0
    runner.invoke(cli, ["account", "delete", "test-acc-id"])
