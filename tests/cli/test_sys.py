"""test_sys.py"""

from pathlib import Path
from unittest.mock import patch, MagicMock, AsyncMock
from typer.testing import CliRunner
from app.cli import sys as sys_cli
from app.cli.main import cli
from app.shared.utils.pid import PID

runner = CliRunner()


def test_sys_validators_and_ask():
    """Test input validators and _ask helper in app/cli/sys.py."""
    assert sys_cli.validate_db_url("mysql://localhost") is not None
    assert sys_cli.validate_db_url("postgresql+psycopg://localhost/db") is None

    assert sys_cli.validate_email("bad-email") is not None
    assert sys_cli.validate_email("good@school.com") is None

    assert sys_cli.validate_password("short") is not None
    assert sys_cli.validate_password("alllowercase123!") is not None
    assert sys_cli.validate_password("ALLUPPERCASE123!") is not None
    assert sys_cli.validate_password("NoNumbersHere!!!") is not None
    assert sys_cli.validate_password("NoSpecialChar123") is not None
    assert sys_cli.validate_password("ValidPassword123!") is None

    assert sys_cli.validate_username("BAD!") is not None
    assert sys_cli.validate_username("good_user_1") is None

    with patch("builtins.input", side_effect=["invalid", "good@school.com"]):
        ans = sys_cli._ask("Email", "", sys_cli.validate_email)
        assert ans == "good@school.com"


def test_sys_commands():
    """Test sys commands (startup, start, stop, restart, status, install-service, daemon, monit, init)."""
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="enabled\n", stderr="")
        assert runner.invoke(cli, ["sys", "startup"]).exit_code == 0
        assert runner.invoke(cli, ["sys", "start"]).exit_code == 0
        assert runner.invoke(cli, ["sys", "stop"]).exit_code == 0
        assert runner.invoke(cli, ["sys", "restart"]).exit_code == 0
        assert runner.invoke(cli, ["sys", "status"]).exit_code == 0

        # systemctl failure branch
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="failed")
        assert runner.invoke(cli, ["sys", "start"]).exit_code == 1

    # install-service
    with patch("app.shared.utils.oobe.generate_systemd_service") as mock_gen:
        assert runner.invoke(cli, ["sys", "install-service"]).exit_code == 0
        mock_gen.assert_called_once()

    # daemon
    with (
        patch("app.shared.utils.config.validate_config"),
        patch("app.shared.utils.logging.setup_logging"),
        patch("app.main.start_servers", new_callable=AsyncMock),
    ):
        assert runner.invoke(cli, ["sys", "daemon"]).exit_code == 0

    # monit: journalctl KeyboardInterrupt branch
    with (
        patch("shutil.which", return_value="/usr/bin/journalctl"),
        patch(
            "subprocess.run",
            side_effect=[
                MagicMock(returncode=0),
                KeyboardInterrupt(),
            ],
        ),
    ):
        assert runner.invoke(cli, ["sys", "monit"]).exit_code == 0

    # monit: tail fallback branches (no dir, no files, tail + KeyboardInterrupt)
    with patch("shutil.which", return_value=None):
        with patch("pathlib.Path.exists", return_value=False):
            assert runner.invoke(cli, ["sys", "monit"]).exit_code == 1
        with (
            patch("pathlib.Path.exists", return_value=True),
            patch("pathlib.Path.glob", return_value=[]),
        ):
            assert runner.invoke(cli, ["sys", "monit"]).exit_code == 1
        with (
            patch("pathlib.Path.exists", return_value=True),
            patch("pathlib.Path.glob", return_value=[Path("test.log")]),
            patch("subprocess.run", side_effect=KeyboardInterrupt()),
        ):
            assert runner.invoke(cli, ["sys", "monit"]).exit_code == 0

    # init: non-interactive missing args
    assert runner.invoke(cli, ["sys", "init", "--no-interactive"]).exit_code == 1

    # init: non-interactive success & failure
    with (
        patch("app.cli.sys.write_config_file"),
        patch("app.cli.sys.init_database", new_callable=AsyncMock),
        patch("app.shared.utils.oobe.generate_systemd_service"),
    ):
        assert (
            runner.invoke(
                cli,
                [
                    "sys",
                    "init",
                    "--no-interactive",
                    "--db-url",
                    "postgresql+psycopg://u:p@localhost/db",
                    "--redis-url",
                    "redis://localhost:6379/0",
                    "--domain",
                    "miniclassisland.com",
                    "--username",
                    "admin",
                    "--email",
                    "admin@school.com",
                    "--password",
                    "ValidPassword123!",
                ],
            ).exit_code
            == 0
        )

    with patch("app.cli.sys.write_config_file", side_effect=RuntimeError("fail")):
        assert (
            runner.invoke(
                cli,
                [
                    "sys",
                    "init",
                    "--no-interactive",
                    "--db-url",
                    "postgresql+psycopg://u:p@localhost/db",
                    "--redis-url",
                    "redis://localhost:6379/0",
                    "--domain",
                    "miniclassisland.com",
                    "--username",
                    "admin",
                    "--email",
                    "admin@school.com",
                    "--password",
                    "ValidPassword123!",
                ],
            ).exit_code
            == 1
        )

    # init: interactive abort & interactive success
    mock_cfg_true = MagicMock()
    mock_cfg_true.exists.return_value = True
    with (
        patch.object(sys_cli, "CONFIG_FILE", mock_cfg_true),
        patch("typer.confirm", return_value=False),
    ):
        assert runner.invoke(cli, ["sys", "init"]).exit_code == 0

    mock_cfg_false = MagicMock()
    mock_cfg_false.exists.return_value = False
    with (
        patch.object(sys_cli, "CONFIG_FILE", mock_cfg_false),
        patch(
            "app.cli.sys._ask",
            side_effect=[
                "postgresql+psycopg://u:p@localhost/db",
                "redis://localhost:6379/0",
                "admin",
                "admin@school.com",
                "ValidPassword123!",
                "miniclassisland.com",
            ],
        ),
        patch("app.cli.sys.write_config_file"),
        patch("app.cli.sys.init_database", new_callable=AsyncMock),
        patch("app.shared.utils.oobe.generate_systemd_service"),
    ):
        assert runner.invoke(cli, ["sys", "init"]).exit_code == 0


def test_sys_pid_command():
    """Test sys pid command."""
    PID.remove()
    res1 = runner.invoke(cli, ["sys", "pid"])
    assert res1.exit_code == 0
    assert "not running" in res1.output

    PID.write()
    res2 = runner.invoke(cli, ["sys", "pid"])
    assert res2.exit_code == 0
    assert str(PID.read()) in res2.output
    PID.remove()


def test_sys_stats_and_settings_commands():
    """Test sys stats, settings, and set-setting commands (including no-arg help)."""
    res_help = runner.invoke(cli, ["sys", "set-setting"])
    assert res_help.exit_code == 0
    assert "Usage" in res_help.output

    # Stats
    res_stats = runner.invoke(cli, ["sys", "stats"])
    assert res_stats.exit_code == 0
    assert "Accounts:" in res_stats.output

    # Settings when empty or populated
    assert runner.invoke(cli, ["sys", "settings"]).exit_code == 0

    # Set-setting (insert and update)
    assert (
        runner.invoke(cli, ["sys", "set-setting", "cli_test_key", "val1"]).exit_code
        == 0
    )
    assert (
        runner.invoke(cli, ["sys", "set-setting", "cli_test_key", "val2"]).exit_code
        == 0
    )
    res_settings = runner.invoke(cli, ["sys", "settings"])
    assert res_settings.exit_code == 0
    assert "cli_test_key = val2" in res_settings.output
