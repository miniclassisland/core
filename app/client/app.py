"""Client API Application Definition."""

import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware

from app.client import router as client_router
from app.client import token_get_router
from app.shared.fonts import router as fonts_router
from app.shared.security.middlewares import TenantMiddleware, CCProtectMiddleware
from app.shared.utils.config import ALLOWED_ORIGINS
from app.shared.utils.logging import RequestLoggingMiddleware, PORT_TAG_CLIENT
from app.shared.lifespan import app_lifespan

logger = logging.getLogger(__name__)

# Client App instance with bound lifespan hooks
client_app = FastAPI(
    title="MINI ClassIsland Client API",
    version="0.3.0",
    lifespan=app_lifespan,
)

# Multi-tenant subdomain resolution, GZip compression, logging, and security middleware
client_app.add_middleware(TenantMiddleware)
client_app.add_middleware(GZipMiddleware, minimum_size=500)
client_app.add_middleware(RequestLoggingMiddleware, port_tag=PORT_TAG_CLIENT)
client_app.add_middleware(CCProtectMiddleware)

# CORS middleware (MUST be added LAST to be the outermost middleware handling all early 401/403/429 error responses)
client_app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount Client router, token_get router, and fonts router
client_app.include_router(client_router, prefix="/api", tags=["Client"])
client_app.include_router(token_get_router, tags=["TokenGet"])
client_app.include_router(fonts_router)


@client_app.get("/")
async def root():
    """Client API health check status endpoint."""
    return {"status": "ok", "message": "MINI ClassIsland Client API is running"}
