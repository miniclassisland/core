"""MINIClassIsland 后端服务主入口。

负责并发启动面向终端的 Client API、面向用户的 Management API 和面向超管的 Admin API。
"""

import asyncio
import logging
import os
import sys
import uvicorn
from pathlib import Path

from app.shared.utils.config import CLIENT_PORT, MANAGEMENT_PORT, ADMIN_PORT, CONFIG_FILE
from app.shared.utils.pid import PID

logger = logging.getLogger(__name__)


async def start_servers():
    """并发运行三个独立的 uvicorn 实例（前台模式）。"""
    PID.write()

    # uvicorn 配置：禁用默认日志，由统一日志系统接管
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
        "启动服务 — Client:%d  Management:%d  Admin:%d  (PID: %d)",
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
        logger.info("所有服务已停止，PID 文件已清理")


from app.cli.main import cli

__all__ = ["start_servers", "main", "cli"]


def main():
    """主程序（统一 CLI）入口。"""
    from app.cli.main import main as cli_main
    cli_main()


if __name__ == "__main__":
    main()
