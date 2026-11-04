"""test_cd.py"""

import json
from pathlib import Path
from typer.testing import CliRunner
from app.cli.main import cli

runner = CliRunner()


def test_cd_cli_commands(tmp_path: Path):
    """Test cd CLI commands (types, list, show, create, delete, export, import, assign, encode-credential, and legacy a/b)."""
    # Legacy placeholder commands
    assert runner.invoke(cli, ["cd", "a"]).exit_code == 0
    assert runner.invoke(cli, ["cd", "b"]).exit_code == 0

    # List resource types
    res_types = runner.invoke(cli, ["cd", "types"])
    assert res_types.exit_code == 0
    assert "ClassPlan" in res_types.output

    # No-args help on group and subcommands with required arguments
    assert runner.invoke(cli, ["cd"]).exit_code in (0, 2)
    for sub in (
        "list",
        "show",
        "create",
        "delete",
        "export",
        "import",
        "assign",
        "encode-credential",
    ):
        res_help = runner.invoke(cli, ["cd", sub])
        assert res_help.exit_code == 0
        assert "Usage" in res_help.output

    # Encode credential
    res_enc = runner.invoke(cli, ["cd", "encode-credential", "MyPass123!"])
    assert res_enc.exit_code == 0
    assert res_enc.output.strip() != ""

    # Create test account
    assert (
        runner.invoke(cli, ["account", "create", "CD CLI Org", "cdcli-org"]).exit_code
        == 0
    )

    # Error branches: missing account / invalid resource type / missing file
    assert runner.invoke(cli, ["cd", "list", "missing-org"]).exit_code == 0
    assert (
        runner.invoke(cli, ["cd", "list", "cdcli-org", "-t", "InvalidType"]).exit_code
        == 0
    )
    assert (
        runner.invoke(
            cli, ["cd", "show", "cdcli-org", "InvalidType", "default"]
        ).exit_code
        == 0
    )
    assert (
        runner.invoke(
            cli, ["cd", "show", "missing-org", "ClassPlan", "default"]
        ).exit_code
        == 0
    )
    assert (
        runner.invoke(
            cli, ["cd", "show", "cdcli-org", "ClassPlan", "missing-res"]
        ).exit_code
        == 0
    )
    assert (
        runner.invoke(
            cli, ["cd", "create", "cdcli-org", "InvalidType", "new1"]
        ).exit_code
        == 0
    )
    assert (
        runner.invoke(
            cli, ["cd", "create", "missing-org", "ClassPlan", "new1"]
        ).exit_code
        == 0
    )
    assert (
        runner.invoke(
            cli, ["cd", "delete", "cdcli-org", "InvalidType", "new1"]
        ).exit_code
        == 0
    )
    assert (
        runner.invoke(
            cli, ["cd", "delete", "missing-org", "ClassPlan", "new1"]
        ).exit_code
        == 0
    )
    assert (
        runner.invoke(
            cli, ["cd", "delete", "cdcli-org", "ClassPlan", "missing-res"]
        ).exit_code
        == 0
    )

    out_file = tmp_path / "exported_cp.json"
    assert (
        runner.invoke(
            cli,
            ["cd", "export", "cdcli-org", "InvalidType", "default", str(out_file)],
        ).exit_code
        == 0
    )
    assert (
        runner.invoke(
            cli,
            ["cd", "export", "missing-org", "ClassPlan", "default", str(out_file)],
        ).exit_code
        == 0
    )
    assert (
        runner.invoke(
            cli,
            [
                "cd",
                "export",
                "cdcli-org",
                "ClassPlan",
                "missing-res",
                str(out_file),
            ],
        ).exit_code
        == 0
    )

    bad_json_file = tmp_path / "bad.json"
    bad_json_file.write_text("{bad json", encoding="utf-8")
    assert (
        runner.invoke(
            cli,
            [
                "cd",
                "import",
                "cdcli-org",
                "InvalidType",
                "imp1",
                str(bad_json_file),
            ],
        ).exit_code
        == 0
    )
    assert (
        runner.invoke(
            cli,
            [
                "cd",
                "import",
                "cdcli-org",
                "ClassPlan",
                "imp1",
                str(tmp_path / "nonexistent.json"),
            ],
        ).exit_code
        == 0
    )
    assert (
        runner.invoke(
            cli,
            ["cd", "import", "cdcli-org", "ClassPlan", "imp1", str(bad_json_file)],
        ).exit_code
        == 0
    )

    # Normal resource operations: list, show, create, duplicate create, export, import, delete
    res_list = runner.invoke(cli, ["cd", "list", "cdcli-org"])
    assert res_list.exit_code == 0
    assert "ClassPlan" in res_list.output

    res_show = runner.invoke(cli, ["cd", "show", "cdcli-org", "ClassPlan", "default"])
    assert res_show.exit_code == 0
    assert "{" in res_show.output

    assert (
        runner.invoke(
            cli, ["cd", "create", "cdcli-org", "ClassPlan", "custom-cp"]
        ).exit_code
        == 0
    )
    assert (
        runner.invoke(
            cli, ["cd", "create", "cdcli-org", "ClassPlan", "custom-cp"]
        ).exit_code
        == 0
    )

    assert (
        runner.invoke(
            cli,
            ["cd", "export", "cdcli-org", "ClassPlan", "default", str(out_file)],
        ).exit_code
        == 0
    )
    assert out_file.exists()

    # Import missing account & valid import (new & overwrite)
    assert (
        runner.invoke(
            cli,
            ["cd", "import", "missing-org", "ClassPlan", "imp1", str(out_file)],
        ).exit_code
        == 0
    )
    assert (
        runner.invoke(
            cli,
            ["cd", "import", "cdcli-org", "ClassPlan", "imp1", str(out_file)],
        ).exit_code
        == 0
    )
    assert (
        runner.invoke(
            cli,
            ["cd", "import", "cdcli-org", "ClassPlan", "imp1", str(out_file)],
        ).exit_code
        == 0
    )
    assert json.loads(out_file.read_text(encoding="utf-8")) is not None

    assert (
        runner.invoke(
            cli, ["cd", "delete", "cdcli-org", "ClassPlan", "custom-cp"]
        ).exit_code
        == 0
    )

    # Assign profile (missing account, default, client custom, and reset)
    assert (
        runner.invoke(cli, ["cd", "assign", "missing-org", "__default__"]).exit_code
        == 0
    )
    assert (
        runner.invoke(
            cli,
            [
                "cd",
                "assign",
                "cdcli-org",
                "client-uid-x",
                "--class-plan",
                "imp1",
                "--time-layout",
                "default",
            ],
        ).exit_code
        == 0
    )
    assert (
        runner.invoke(
            cli,
            ["cd", "assign", "cdcli-org", "client-uid-x", "--reset"],
        ).exit_code
        == 0
    )

    # Clean up test account
    assert runner.invoke(cli, ["account", "delete", "cdcli-org"]).exit_code == 0
