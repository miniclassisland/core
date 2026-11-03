"""test_client.py"""

from typer.testing import CliRunner
from app.cli.main import cli

runner = CliRunner()


def test_client_cli_commands():
    """测试 client 命令行占位入口。"""
    assert runner.invoke(cli, ["client", "a"]).exit_code == 0
    assert runner.invoke(cli, ["client", "b"]).exit_code == 0
