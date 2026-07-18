"""test_main.py
"""

from typer.testing import CliRunner
from app.cli.main import cli

runner = CliRunner()


def test_cli_help():
    """测试根 CLI 输出。"""
    res = runner.invoke(cli, [])
    assert res.exit_code == 0
    assert "Usage" in res.stdout


def test_cli_about():
    """测试隐藏的 about 终端指令。"""
    res = runner.invoke(cli, ["about"])
    assert res.exit_code == 0
    assert "MINI ClassIsland" in res.stdout
