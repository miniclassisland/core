"""test_pid.py"""

import os
from unittest.mock import patch
from app.shared.utils import pid


def test_pid_lifecycle():
    """测试 PID 文件写入、读取与销毁生命周期。"""
    pid.PID.write()
    read_pid = pid.PID.read()
    assert read_pid == os.getpid()

    with open(pid._PID, "w", encoding="utf-8") as f:
        f.write("not-an-int")
    assert pid.PID.read() is None

    pid.PID.remove()
    assert pid.PID.read() is None

    # 测试 remove 出现 OSError 分支
    with patch("pathlib.Path.read_text", side_effect=OSError("cannot read")):
        pid.PID.remove()
