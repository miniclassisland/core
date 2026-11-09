"""Global application lifespan management — startup and shutdown."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
import logging
import os
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
from app.shared.security.turnstile import (
    close_turnstile_client,
    get_turnstile_client,
)
from app.shared.utils.community import (
    notify_service_shutdown,
    notify_service_startup_recovery,
    start_snowluma_poller,
    stop_snowluma_poller,
)
from app.shared.utils.logging import get_port_logger, PORT_TAG_GRPC
from app.shared.runtime import runtime_hub

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
    loop = asyncio.get_running_loop()
    max_workers = min(128, (os.cpu_count() or 4) * 16)
    executor = ThreadPoolExecutor(
        max_workers=max_workers, thread_name_prefix="minicims-worker"
    )
    loop.set_default_executor(executor)
    app.state.thread_executor = executor
    logger.info("Initializing database connection...")
    await init_db()
    logger.info("Initializing Redis connection pool...")
    await init_redis()
    logger.info("Initializing Turnstile HTTP client...")
    get_turnstile_client()
    await notify_service_startup_recovery()
    start_snowluma_poller()

    # Dynamically import serve_grpc to prevent compilation issues when protobufs are missing
    try:
        from app.grpc.server import serve_grpc

        grpc_logger.info("Starting gRPC service (%d)...", GRPC_PORT)
        grpc_s, cmd_s, sess_m = await serve_grpc()
        app.state.grpc_server = grpc_s
        app.state.command_servicer = cmd_s
        app.state.session_manager = sess_m
        runtime_hub.grpc_server = grpc_s
        runtime_hub.command_servicer = cmd_s
        runtime_hub.session_manager = sess_m
    except Exception as e:
        grpc_logger.error(
            "Failed to start gRPC service or protobuf not compiled: %s", str(e)
        )

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
    await notify_service_shutdown()
    grpc_s = getattr(app.state, "grpc_server", None) or runtime_hub.grpc_server
    if grpc_s:
        grpc_logger.info("Stopping gRPC server...")
        await grpc_s.stop(grace=5)
        grpc_logger.info("gRPC server stopped")
    runtime_hub.grpc_server = None
    runtime_hub.command_servicer = None
    logger.info("Closing Redis connection pool...")
    await close_redis()
    logger.info("Closing Turnstile HTTP client...")
    await close_turnstile_client()
    await stop_snowluma_poller()
    executor = getattr(app.state, "thread_executor", None)
    if executor:
        executor.shutdown(wait=False)
    logger.info("System shutdown complete")
