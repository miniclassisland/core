"""Super Admin API Application Definition."""

import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware

from app.admin import router as admin_router
from app.management.account import router as mgr_account_router
from app.management.token import router as mgr_token_router
from app.management.user import router as mgr_user_router
from app.client import token_get_router
from app.shared.fonts import router as fonts_router
from app.shared.security.middlewares import (
    AdminAuthMiddleware,
    CCProtectMiddleware,
)
from app.shared.utils.config import ALLOWED_ORIGINS
from app.shared.utils.logging import RequestLoggingMiddleware, PORT_TAG_ADMIN

logger = logging.getLogger(__name__)

admin_app = FastAPI(
    title="MINI ClassIsland Admin API",
    version="0.3.0",
    redirect_slashes=False,
)

# Authentication, GZip compression, logging, and security middleware
admin_app.add_middleware(AdminAuthMiddleware, require_superadmin=True)
admin_app.add_middleware(GZipMiddleware, minimum_size=500)
admin_app.add_middleware(RequestLoggingMiddleware, port_tag=PORT_TAG_ADMIN)
admin_app.add_middleware(CCProtectMiddleware)

# CORS middleware (MUST be added LAST to be the outermost middleware handling all early 401/403/429 error responses)
admin_app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount Admin router (first priority), nested Management routers, token_get router, and embedded fonts router
admin_app.include_router(admin_router)
admin_app.include_router(mgr_account_router)
admin_app.include_router(mgr_token_router)
admin_app.include_router(mgr_user_router)
admin_app.include_router(token_get_router, tags=["TokenGet"])
admin_app.include_router(fonts_router)


@admin_app.get("/")
async def root():
    """Admin API health check status endpoint."""
    return {"status": "ok", "message": "MINI ClassIsland Admin API is running"}
