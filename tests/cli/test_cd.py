"""test_cd.py"""

from typer.testing import CliRunner
from app.cli.main import cli

runner = CliRunner()


def test_cd_cli_commands():
    """测试 cd 命令行入口各个命令。"""
    assert runner.invoke(cli, ["cd", "a"]).exit_code == 0
    assert runner.invoke(cli, ["cd", "b"]).exit_code == 0
