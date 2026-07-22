"""Global application lifespan management — startup and shutdown.
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
    """FastAPI application lifespan manager."""
    validate_config()
    await _startup(app)
    yield
    await _shutdown(app)


async def _startup(app: FastAPI):
    """Start up backend services."""
    logger.info("Initializing database connection...")
    await init_db()
    logger.info("Initializing Redis connection pool...")
    await init_redis()
    
    # Dynamically import serve_grpc to prevent compilation issues when protobufs are missing
    try:
        from app.grpc.server import serve_grpc
        grpc_logger.info("Starting gRPC service (%d)...", GRPC_PORT)
        grpc_s, cmd_s, sess_m = await serve_grpc()
        app.state.grpc_server = grpc_s
        app.state.command_servicer = cmd_s
        app.state.session_manager = sess_m
    except Exception as e:
        grpc_logger.error("Failed to start gRPC service or protobuf not compiled: %s", str(e))
        
    logger.info(
        "Ready — C:%d M:%d A:%d G:%d",
        CLIENT_PORT,
        MANAGEMENT_PORT,
        ADMIN_PORT,
        GRPC_PORT,
    )


async def _shutdown(app: FastAPI):
    """Graceful shutdown: stop gRPC and Redis."""
    logger.info("Performing graceful shutdown...")
    grpc_s = getattr(app.state, "grpc_server", None)
    if grpc_s:
        grpc_logger.info("Stopping gRPC server...")
        await grpc_s.stop(grace=5)
        grpc_logger.info("gRPC server stopped")
    logger.info("Closing Redis connection pool...")
    await close_redis()
    logger.info("System shutdown complete")
