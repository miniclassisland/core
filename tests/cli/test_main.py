"""test_main.py"""

from unittest.mock import patch
from typer.testing import CliRunner
from app.cli import main as cli_main
from app.cli.main import cli

runner = CliRunner()


def test_cli_help():
    """Test root CLI help and main() entrypoint."""
    res = runner.invoke(cli, [])
    # Click >= 8.2 exits with 2 when no command is given and help is printed.
    assert res.exit_code in (0, 2)
    assert "Usage" in res.stdout

    with patch.object(cli_main, "cli") as mock_cli:
        cli_main.main()
        mock_cli.assert_called_once()


def test_cli_about():
    """Test about command."""
    res = runner.invoke(cli, ["about"])
    assert res.exit_code == 0
    assert "MINI ClassIsland" in res.stdout
