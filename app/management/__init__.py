"""MINI ClassIsland Management API Route Aggregation Module."""

from fastapi import APIRouter

from .account import router as account_router
from .bulk import router as bulk_router
from .token import router as token_router
from .user import router as user_router

router = APIRouter()

router.include_router(account_router)
router.include_router(bulk_router)
router.include_router(token_router)
router.include_router(user_router)

from .app import management_app as management_app  # noqa: E402
