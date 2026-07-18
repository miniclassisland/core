"""进程 PID 文件管理器。
"""

import os
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# PID 默认路径
_PID = Path(".miniclassisland") / "miniclassisland.pid"


class PID:
    @staticmethod
    def write() -> None:
        """写入当前进程的 PID 到文件。"""
        _PID.parent.mkdir(parents=True, exist_ok=True)
        _PID.write_text(str(os.getpid()))
        logger.info(f"PID 已写入: {os.getpid()}")

    @staticmethod
    def read() -> int | None:
        """读取文件中的 PID。"""
        if not _PID.exists():
            return None
        try:
            return int(_PID.read_text().strip())
        except (ValueError, OSError):
            return None

    @staticmethod
    def remove() -> None:
        """删除 PID 文件。"""
        try:
            _pid = _PID.read_text().strip()
            _PID.unlink(missing_ok=True)
            logger.info(f"PID 已清理: {_pid}")
        except OSError:
            pass
