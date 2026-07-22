"""test_ci.py
"""

import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
from typer.testing import CliRunner
from app.cli.main import cli

runner = CliRunner(mix_stderr=False)


def test_build_success():
    """测试 cli 中的 build 命令（成功分支）。"""
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="Mocked build stdout", stderr="")
        res = runner.invoke(cli, ["ci", "build"])
        assert res.exit_code == 0
        assert "built successfully" in res.stdout


def test_build_failure():
    """测试 cli 中的 build 命令（失败分支）。"""
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="Mocked error message")
        res = runner.invoke(cli, ["ci", "build"])
        assert res.exit_code == 1
        assert "Build failed" in res.stderr


def test_generate_grpc_no_protos():
    """测试无 proto 文件时的生成拦截。"""
    with patch("pathlib.Path.rglob") as mock_rglob:
        mock_rglob.return_value = []
        res = runner.invoke(cli, ["ci", "grpc", "generate"])
        assert res.exit_code == 1
        assert "No proto files found" in res.stderr


def test_generate_grpc_compilation_failure():
    """测试 proto 编译出错时的拦截分支。"""
    with patch("pathlib.Path.rglob") as mock_rglob, patch("grpc_tools.protoc.main") as mock_protoc:
        mock_rglob.return_value = [Path("mock.proto")]
        mock_protoc.return_value = -1  # 编译出错
        res = runner.invoke(cli, ["ci", "grpc", "generate"])
        assert res.exit_code == 255  # -1 as exit code is 255 in Typer
        assert "Failed to compile" in res.stderr


def test_generate_grpc_success():
    """测试 proto 编译成功分支。"""
    with patch("pathlib.Path.rglob") as mock_rglob, \
         patch("grpc_tools.protoc.main") as mock_protoc, \
         patch("shutil.rmtree") as mock_rmtree, \
         patch("pathlib.Path.mkdir"), \
         patch("pathlib.Path.touch"):
        
        mock_rglob.return_value = [Path("mock.proto")]
        mock_protoc.return_value = 0
        res = runner.invoke(cli, ["ci", "grpc", "generate"])
        assert res.exit_code == 0
        assert "Protocol buffer generated" in res.stdout
