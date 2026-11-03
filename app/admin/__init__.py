"""Admin API route aggregation module."""

from fastapi import APIRouter

from .account import router as account_router
from .bulk import router as bulk_router
from .settings import router as settings_router
from .totp import router as totp_router
from .user import router as user_router

router = APIRouter()

router.include_router(account_router)
router.include_router(user_router)
router.include_router(totp_router)
router.include_router(settings_router)
router.include_router(bulk_router)

from .app import admin_app as admin_app  # noqa: E402
