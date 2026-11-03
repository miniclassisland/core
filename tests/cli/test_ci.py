"""test_ci.py"""

from pathlib import Path
from unittest.mock import MagicMock, patch
from typer.testing import CliRunner
from app.cli.main import cli

runner = CliRunner()


def test_build_success():
    """测试 cli 中的 build 命令（成功分支）。"""
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            returncode=0, stdout="Mocked build stdout", stderr=""
        )
        res = runner.invoke(cli, ["ci", "build"])
        assert res.exit_code == 0
        assert "built successfully" in res.output


def test_build_failure():
    """测试 cli 中的 build 命令（失败分支）。"""
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            returncode=1, stdout="", stderr="Mocked error message"
        )
        res = runner.invoke(cli, ["ci", "build"])
        assert res.exit_code == 1
        assert "Build failed" in res.output


def test_generate_grpc_no_protos():
    """测试无 proto 文件时的生成拦截。"""
    with patch("pathlib.Path.rglob") as mock_rglob:
        mock_rglob.return_value = []
        res = runner.invoke(cli, ["ci", "grpc", "generate"])
        assert res.exit_code == 1
        assert "No proto files found" in res.output


def test_generate_grpc_compilation_failure():
    """测试 proto 编译出错及文件系统异常容错分支。"""
    with (
        patch("pathlib.Path.rglob") as mock_rglob,
        patch("grpc_tools.protoc.main") as mock_protoc,
        patch("shutil.rmtree", side_effect=OSError("rm err")),
        patch("pathlib.Path.mkdir", side_effect=OSError("mkdir err")),
        patch("pathlib.Path.write_text", side_effect=OSError("write err")),
    ):
        mock_rglob.return_value = [Path("mock.proto")]
        mock_protoc.return_value = -1
        res = runner.invoke(cli, ["ci", "grpc", "generate"])
        assert res.exit_code == 255
        assert "Failed to compile" in res.output


def test_generate_grpc_success():
    """测试 proto 编译成功及 create_inits 各种分支。"""
    with (
        patch("pathlib.Path.rglob") as mock_rglob,
        patch("grpc_tools.protoc.main") as mock_protoc,
        patch("shutil.rmtree"),
        patch("pathlib.Path.mkdir"),
        patch("pathlib.Path.write_text"),
        patch("pathlib.Path.touch"),
    ):
        mock_rglob.return_value = [Path("Protobuf/Service/Handshake.proto")]
        mock_protoc.return_value = 0
        res = runner.invoke(cli, ["ci", "grpc", "generate"])
        assert res.exit_code == 0
        assert "Protocol buffer generated" in res.stdout

    # 测试 create_inits 在目录不存在及 iterdir 抛异常时的容错分支
    with (
        patch("pathlib.Path.rglob", return_value=[Path("Protobuf/Service/H.proto")]),
        patch("grpc_tools.protoc.main", return_value=0),
        patch("pathlib.Path.exists", return_value=False),
        patch("pathlib.Path.mkdir"),
        patch("pathlib.Path.write_text"),
    ):
        assert runner.invoke(cli, ["ci", "grpc", "generate"]).exit_code == 0

    with (
        patch("pathlib.Path.rglob", return_value=[Path("Protobuf/Service/H.proto")]),
        patch("grpc_tools.protoc.main", return_value=0),
        patch("shutil.rmtree"),
        patch("pathlib.Path.mkdir"),
        patch("pathlib.Path.write_text"),
        patch("pathlib.Path.iterdir", side_effect=OSError("iter err")),
    ):
        assert runner.invoke(cli, ["ci", "grpc", "generate"]).exit_code == 0
