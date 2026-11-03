"""Management API Application Definition."""

import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.management import router as mgr_router
from app.client import token_get_router
from app.shared.fonts import router as fonts_router
from app.shared.security.middlewares import (
    AdminAuthMiddleware,
    AccountContextMiddleware,
    CCProtectMiddleware,
)
from app.shared.utils.logging import RequestLoggingMiddleware, PORT_TAG_MGMT

logger = logging.getLogger(__name__)

management_app = FastAPI(
    title="MINI ClassIsland Management API",
    version="0.3.0",
    redirect_slashes=False,
)

# Account multi-tenant context middleware (verifies AccountMember membership)
management_app.add_middleware(AccountContextMiddleware, require_membership=True)

# Session token and authentication middleware
management_app.add_middleware(AdminAuthMiddleware)
management_app.add_middleware(RequestLoggingMiddleware, port_tag=PORT_TAG_MGMT)
management_app.add_middleware(CCProtectMiddleware)

# CORS middleware (MUST be added LAST to be the outermost middleware handling all early 401/403/429 error responses)
management_app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount Management router, token_get router, and fonts router
management_app.include_router(mgr_router)
management_app.include_router(token_get_router, tags=["TokenGet"])
management_app.include_router(fonts_router)


@management_app.get("/")
async def root():
    """Management API health check status endpoint."""
    return {"status": "ok", "message": "MINI ClassIsland Management API is running"}
