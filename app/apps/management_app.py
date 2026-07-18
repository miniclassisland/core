"""商户管理 API 应用定义。
"""

import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.management import router as mgr_router
from app.shared.security.middlewares import (
    AdminAuthMiddleware,
    AccountContextMiddleware,
    CCProtectMiddleware,
)
from app.shared.utils.logging import RequestLoggingMiddleware, PORT_TAG_MGMT

logger = logging.getLogger(__name__)

management_app = FastAPI(
    title="MINIClassIsland 商户管理 API",
    version="0.3.0",
    redirect_slashes=False,
)

# CORS 中间件
management_app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 账户多租户上下文设置中间件（校验 AccountMember 成员资格）
management_app.add_middleware(AccountContextMiddleware, require_membership=True)

# 会话令牌与凭证认证中间件
management_app.add_middleware(AdminAuthMiddleware)
management_app.add_middleware(RequestLoggingMiddleware, port_tag=PORT_TAG_MGMT)
management_app.add_middleware(CCProtectMiddleware)

# 挂载商户管理聚合路由
management_app.include_router(mgr_router)


@management_app.get("/")
async def root():
    """商户管理 API 状态检测。"""
    return {"message": "MINIClassIsland 商户管理 API 运行中"}
