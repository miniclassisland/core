"""非浸入式 OOBE 占位接管应用层。
"""

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from app.admin.account import router as oobe_router

ERR_SYSTEM_OOBE = "ERR_SYSTEM_OOBE"


def _create_stub() -> FastAPI:
    """生成只返回 503 的占位应用。"""
    app = FastAPI(title="MINIClassIsland (OOBE Stub)", docs_url=None, redoc_url=None)

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
    async def _catch_all(request: Request, path: str):
        return JSONResponse(
            status_code=503,
            content={
                "code": ERR_SYSTEM_OOBE,
                "msg": "系统尚未初始化，请完成 OOBE 配置",
            },
        )

    return app


def _create_admin() -> FastAPI:
    """生成管理端口专用的 OOBE 应用。"""
    app = FastAPI(title="MINIClassIsland Admin (OOBE Mode)", docs_url=None, redoc_url=None)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
        allow_credentials=True,
    )
    # 挂载 OOBE 配置和管理路由器
    app.include_router(oobe_router)

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
    async def _catch_all(request: Request, path: str):
        return JSONResponse(
            status_code=503,
            content={"code": ERR_SYSTEM_OOBE, "msg": "系统未初始化，仅开放 OOBE 接口"},
        )

    return app


oobe_stub_app = _create_stub()
oobe_admin_app = _create_admin()
