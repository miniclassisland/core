"""test_sys.py
"""

from unittest.mock import patch, MagicMock
from typer.testing import CliRunner
from app.cli.main import cli
from app.shared.utils.pid import PID

runner = CliRunner()


def test_sys_commands():
    """测试 sys 下的各个占位命令执行。"""
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        assert runner.invoke(cli, ["sys", "startup"]).exit_code == 0
        assert runner.invoke(cli, ["sys", "start"]).exit_code == 0
        assert runner.invoke(cli, ["sys", "stop"]).exit_code == 0
        assert runner.invoke(cli, ["sys", "monit"]).exit_code in (0, 1)


def test_sys_pid_command():
    """测试 sys pid 指令。"""
    # 场景 1: 未运行
    PID.remove()
    res1 = runner.invoke(cli, ["sys", "pid"])
    assert res1.exit_code == 0
    assert "not running" in res1.output

    # 场景 2: 正在运行
    PID.write()
    res2 = runner.invoke(cli, ["sys", "pid"])
    assert res2.exit_code == 0
    assert str(PID.read()) in res2.output
    PID.remove()
