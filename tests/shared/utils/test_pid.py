"""test_pid.py
"""

import os
from app.shared.utils import pid


def test_pid_lifecycle():
    """测试 PID 文件写入、读取与销毁生命周期。"""
    # 1. 写入 PID
    pid.PID.write()

    # 2. 读取 PID
    read_pid = pid.PID.read()
    assert read_pid == os.getpid()

    # 3. 移除 PID
    pid.PID.remove()
    assert pid.PID.read() is None
