"""Non-intrusive OOBE fallback application layer.
"""

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from app.admin.account import router as oobe_router

ERR_SYSTEM_OOBE = "ERR_SYSTEM_OOBE"


def _create_stub() -> FastAPI:
    """Generate stub application returning 503 Service Unavailable."""
    app = FastAPI(title="MINIClassIsland (OOBE Stub)", docs_url=None, redoc_url=None)

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
    app = FastAPI(title="MINIClassIsland Admin (OOBE Mode)", docs_url=None, redoc_url=None)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
        allow_credentials=True,
    )
    # Include OOBE setup and management router
    app.include_router(oobe_router)

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
    async def _catch_all(request: Request, path: str):
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"code": ERR_SYSTEM_OOBE, "msg": "System not initialized. Only OOBE endpoints are open."},
        )

    return app


oobe_stub_app = _create_stub()
oobe_admin_app = _create_admin()
