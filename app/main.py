"""MINI ClassIsland Backend Services Entry Point.

Concurrently starts Client API, Management API, and Admin API services.
"""

import asyncio
import logging
import os
import uvicorn

from app.shared.utils.config import (
    CLIENT_PORT,
    MANAGEMENT_PORT,
    ADMIN_PORT,
    CONFIG_FILE,
)
from app.shared.utils.pid import PID

logger = logging.getLogger(__name__)


async def start_servers():
    """Run three independent uvicorn instances concurrently in foreground mode."""
    PID.write()

    # Uvicorn configuration: disable default loggers to let unified logging take over
    uv_log_config = {
        "version": 1,
        "disable_existing_loggers": False,
        "handlers": {},
        "loggers": {},
    }

    if CONFIG_FILE.exists():
        from app.client import client_app
        from app.management import management_app
        from app.admin import admin_app

        c_app, m_app, a_app = client_app, management_app, admin_app
    else:
        from app.shared.security.auth import generate_oobe_codes
        from app.shared.oobe import oobe_stub_app, oobe_admin_app

        generate_oobe_codes()
        c_app, m_app, a_app = oobe_stub_app, oobe_stub_app, oobe_admin_app

    c_cfg = uvicorn.Config(
        c_app,
        host="0.0.0.0",
        port=CLIENT_PORT,
        log_config=uv_log_config,
        access_log=False,
    )
    m_cfg = uvicorn.Config(
        m_app,
        host="0.0.0.0",
        port=MANAGEMENT_PORT,
        log_config=uv_log_config,
        access_log=False,
    )
    a_cfg = uvicorn.Config(
        a_app,
        host="0.0.0.0",
        port=ADMIN_PORT,
        log_config=uv_log_config,
        access_log=False,
    )

    logger.info(
        "Starting services — Client:%d  Management:%d  Admin:%d  (PID: %d)",
        CLIENT_PORT,
        MANAGEMENT_PORT,
        ADMIN_PORT,
        os.getpid(),
    )

    servers = [
        uvicorn.Server(c_cfg),
        uvicorn.Server(m_cfg),
        uvicorn.Server(a_cfg),
    ]

    try:
        await asyncio.gather(*(s.serve() for s in servers))
    finally:
        PID.remove()
        logger.info("All services stopped, PID file cleaned up")


from app.cli.main import cli  # noqa: E402

__all__ = ["start_servers", "main", "cli"]


def main():
    """Main application entry point (unified CLI)."""
    from app.cli.main import main as cli_main

    cli_main()


if __name__ == "__main__":
    main()
