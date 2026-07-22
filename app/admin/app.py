"""Super Admin API Application Definition.
"""

import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.admin import router as admin_router
from app.shared.security.middlewares import AdminAuthMiddleware, CCProtectMiddleware
from app.shared.utils.logging import RequestLoggingMiddleware, PORT_TAG_ADMIN

logger = logging.getLogger(__name__)

admin_app = FastAPI(
    title="MINIClassIsland Admin API",
    version="0.3.0",
    redirect_slashes=False,
)

# Authentication, logging, and security middleware
admin_app.add_middleware(AdminAuthMiddleware)
admin_app.add_middleware(RequestLoggingMiddleware, port_tag=PORT_TAG_ADMIN)
admin_app.add_middleware(CCProtectMiddleware)

# CORS middleware (MUST be added LAST to be the outermost middleware handling all early 401/403/429 error responses)
admin_app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount Admin router
admin_app.include_router(admin_router)


@admin_app.get("/")
async def root():
    """Admin API health check status endpoint."""
    return {"status": "ok", "message": "MINIClassIsland Admin API is running"}
