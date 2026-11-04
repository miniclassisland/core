"""Non-intrusive OOBE fallback application layer."""

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from app.admin.account import router as oobe_router
from app.shared.fonts import router as fonts_router
from app.shared.security.middlewares import CCProtectMiddleware
from app.shared.utils.config import ALLOWED_ORIGINS, ALLOWED_ORIGIN_REGEX

ERR_SYSTEM_OOBE = "ERR_SYSTEM_OOBE"


def _create_stub() -> FastAPI:
    """Generate stub application returning 503 Service Unavailable."""
    app = FastAPI(title="MINI ClassIsland (OOBE Stub)", docs_url=None, redoc_url=None)
    app.add_middleware(CCProtectMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=ALLOWED_ORIGINS,
        allow_origin_regex=ALLOWED_ORIGIN_REGEX,
        allow_methods=["*"],
        allow_headers=["*"],
        allow_credentials=True,
    )
    app.include_router(fonts_router)

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
    async def _catch_all(request: Request, path: str):
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "code": ERR_SYSTEM_OOBE,
                "msg": "System not initialized. Please complete OOBE setup.",
            },
        )

    return app


def _create_admin() -> FastAPI:
    """Generate dedicated OOBE application for admin port."""
    app = FastAPI(
        title="MINI ClassIsland Admin (OOBE Mode)", docs_url=None, redoc_url=None
    )
    app.add_middleware(CCProtectMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=ALLOWED_ORIGINS,
        allow_origin_regex=ALLOWED_ORIGIN_REGEX,
        allow_methods=["*"],
        allow_headers=["*"],
        allow_credentials=True,
    )
    app.include_router(fonts_router)
    # Include OOBE setup and management router
    app.include_router(oobe_router)

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
    async def _catch_all(request: Request, path: str):
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "code": ERR_SYSTEM_OOBE,
                "msg": "System not initialized. Only OOBE endpoints are open.",
            },
        )

    return app


oobe_stub_app = _create_stub()
oobe_admin_app = _create_admin()
