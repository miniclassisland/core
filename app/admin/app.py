"""超级管理员 API 应用定义。
"""

import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.admin import router as admin_router
from app.shared.security.middlewares import AdminAuthMiddleware, CCProtectMiddleware
from app.shared.utils.logging import RequestLoggingMiddleware, PORT_TAG_ADMIN

logger = logging.getLogger(__name__)

admin_app = FastAPI(
    title="MINIClassIsland 超管 API",
    version="0.3.0",
    redirect_slashes=False,
)

# CORS 中间件
admin_app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 统一认证与安全防护中间件
admin_app.add_middleware(AdminAuthMiddleware)
admin_app.add_middleware(RequestLoggingMiddleware, port_tag=PORT_TAG_ADMIN)
admin_app.add_middleware(CCProtectMiddleware)

# 挂载超管聚合路由
admin_app.include_router(admin_router)


@admin_app.get("/")
async def root():
    """超管 API 状态检测。"""
    return {"message": "MINIClassIsland 超管 API 运行中"}
