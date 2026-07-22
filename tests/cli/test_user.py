"""test_user.py
"""

from typer.testing import CliRunner
from app.cli.main import cli

runner = CliRunner()


def test_user_cli_commands():
    """测试 user 命令行入口。"""
    assert runner.invoke(cli, ["user", "list"]).exit_code == 0
