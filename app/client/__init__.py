"""Client API Route Module."""

from .api import router as router
from .get import router as token_get_router
from .app import client_app as client_app

__all__ = ["router", "token_get_router", "client_app"]
