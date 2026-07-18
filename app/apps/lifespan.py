"""全局应用生命周期管理 — 启动与停止。
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.shared.utils.config import (
    validate_config,
    CLIENT_PORT,
    MANAGEMENT_PORT,
    ADMIN_PORT,
    GRPC_PORT,
)
from app.shared.utils.redis import init_redis, close_redis
from app.shared.db.session import init_db
from app.shared.utils.logging import get_port_logger, PORT_TAG_GRPC

logger = logging.getLogger(__name__)
grpc_logger = get_port_logger(PORT_TAG_GRPC)


@asynccontextmanager
async def app_lifespan(app: FastAPI):
    """FastAPI 生命周期管理。"""
    validate_config()
    await _startup(app)
    yield
    await _shutdown(app)


async def _startup(app: FastAPI):
    """启动所有后端服务。"""
    logger.info("正在初始化数据库连接...")
    await init_db()
    logger.info("正在初始化 Redis 连接池...")
    await init_redis()
    
    # 动态本地导入 serve_grpc，防止未生成 grpc 代码时编译脚本/命令行导入崩溃
    try:
        from app.grpc.server import serve_grpc
        grpc_logger.info("正在启动 gRPC (%d)...", GRPC_PORT)
        grpc_s, cmd_s, sess_m = await serve_grpc()
        app.state.grpc_server = grpc_s
        app.state.command_servicer = cmd_s
        app.state.session_manager = sess_m
    except Exception as e:
        grpc_logger.error("gRPC 服务启动失败或 protobuf 未编译: %s", str(e))
        
    logger.info(
        "就绪 — C:%d M:%d A:%d G:%d",
        CLIENT_PORT,
        MANAGEMENT_PORT,
        ADMIN_PORT,
        GRPC_PORT,
    )


async def _shutdown(app: FastAPI):
    """优雅停机：停止 gRPC 和 Redis。"""
    logger.info("正在执行优雅停机...")
    grpc_s = getattr(app.state, "grpc_server", None)
    if grpc_s:
        grpc_logger.info("正在停止 gRPC 服务器...")
        await grpc_s.stop(grace=5)
        grpc_logger.info("gRPC 服务器已停止")
    logger.info("正在关闭 Redis 连接池...")
    await close_redis()
    logger.info("系统停机完成")
