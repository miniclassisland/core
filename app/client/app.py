"""客户端 API 应用定义。
"""

import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.client import router as client_router
from app.client import token_get_router
from app.shared.security.middlewares import TenantMiddleware, CCProtectMiddleware
from app.shared.utils.logging import RequestLoggingMiddleware, PORT_TAG_CLIENT
from app.shared.lifespan import app_lifespan

logger = logging.getLogger(__name__)

# 客户端 App 实例（绑定生命周期钩子）
client_app = FastAPI(
    title="MINIClassIsland 客户端 API",
    version="0.2.0",
    lifespan=app_lifespan,
)

# CORS 中间件（允许前端跨域获取资源）
client_app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 多租户子域名解析与请求日志安全中间件
client_app.add_middleware(TenantMiddleware)
client_app.add_middleware(RequestLoggingMiddleware, port_tag=PORT_TAG_CLIENT)
client_app.add_middleware(CCProtectMiddleware)

# 挂载客户端业务及引导向导路由
client_app.include_router(client_router, prefix="/api", tags=["Client"])
client_app.include_router(token_get_router, tags=["TokenGet"])


@client_app.get("/")
async def root():
    """终端 API 状态检测。"""
    return {"message": "MINIClassIsland Backend is running"}
