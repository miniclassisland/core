"""Process PID file manager."""

import os
import logging

from app.shared.utils.config import CONFIG_DIR

logger = logging.getLogger(__name__)

# Default PID path
_PID = CONFIG_DIR / "miniclassisland.pid"


class PID:
    @staticmethod
    def write() -> None:
        """Write current process PID to file."""
        _PID.parent.mkdir(parents=True, exist_ok=True)
        _PID.write_text(str(os.getpid()))
        logger.info(f"PID written: {os.getpid()}")

    @staticmethod
    def read() -> int | None:
        """Read PID from file."""
        if not _PID.exists():
            return None
        try:
            return int(_PID.read_text().strip())
        except (ValueError, OSError):
            return None

    @staticmethod
    def remove() -> None:
        """Remove PID file."""
        try:
            _pid = _PID.read_text().strip()
            _PID.unlink(missing_ok=True)
            logger.info(f"PID cleaned up: {_pid}")
        except OSError:
            pass
