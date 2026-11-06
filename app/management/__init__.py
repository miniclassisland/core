"""MINI ClassIsland Management API Route Aggregation Module."""

from fastapi import APIRouter

from .account import router as account_router
from .bulk import router as bulk_router
from .community import router as community_router
from .site import router as site_router
from .ticket import router as ticket_router
from .token import router as token_router
from .user import router as user_router

router = APIRouter()

router.include_router(account_router)
router.include_router(bulk_router)
router.include_router(community_router)
router.include_router(site_router)
router.include_router(ticket_router)
router.include_router(token_router)
router.include_router(user_router)

from .app import management_app as management_app  # noqa: E402
