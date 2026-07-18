import logging
import re
import time
from typing import Dict, Tuple

from fastapi import Request, Response
from starlette.middleware.base import (
    BaseHTTPMiddleware,
    RequestResponseEndpoint,
)
from starlette.responses import JSONResponse

from app.shared.utils.config import REDIS_DB_AUTH
from app.shared.utils.redis import get_redis
from app.shared.utils.tenant import tenant_ctx, schema_ctx, get_tenant_id
from app.shared.utils.logging import get_client_ip_from_request

logger = logging.getLogger(__name__)

# ---- 1. CC防护限流状态与检查 ----

_ip_failures: Dict[str, Tuple[int, float]] = {}  # ip -> (count, last_failure_time)
_global_requests: list[float] = []
_cc_active: bool = False

IP_FAILURE_LIMIT = 20
IP_BLOCK_DURATION = 300
GLOBAL_CC_LIMIT = 500
GLOBAL_CC_WINDOW = 1.0


def check_ip_blocked(ip: str) -> bool:
    if ip not in _ip_failures:
        return False
    count, last_time = _ip_failures[ip]
    if count >= IP_FAILURE_LIMIT:
        if time.time() - last_time < IP_BLOCK_DURATION:
            return True
        else:
            try:
                del _ip_failures[ip]
            except KeyError:
                pass
    return False


def record_ip_failure(ip: str) -> None:
    now = time.time()
    if ip not in _ip_failures:
        _ip_failures[ip] = (1, now)
    else:
        count, _ = _ip_failures[ip]
        _ip_failures[ip] = (count + 1, now)


def monitor_global_frequency() -> None:
    global _cc_active
    now = time.time()
    _global_requests.append(now)
    while _global_requests and _global_requests[0] < now - GLOBAL_CC_WINDOW:
        _global_requests.pop(0)
    if len(_global_requests) > GLOBAL_CC_LIMIT:
        _cc_active = True
    else:
        _cc_active = False


def get_cc_state() -> bool:
    return _cc_active


class CCProtectMiddleware(BaseHTTPMiddleware):
    """安全中间件：阻断封禁 IP 并全局防护 CC 并发攻击。"""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        ip = get_client_ip_from_request(request) or "unknown"
        if check_ip_blocked(ip):
            return JSONResponse(
                status_code=429, content={"code": "ERR_IP_BLOCKED", "msg": "异常封禁"}
            )

        monitor_global_frequency()

        path = request.url.path.lower()
        if get_cc_state() and any(k in path for k in ["login", "register"]):
            if "authorization" not in request.headers:
                return JSONResponse(
                    status_code=503, content={"code": "ERR_CC_ACTIVE", "msg": "通道受阻"}
                )

        resp = await call_next(request)
        if resp.status_code >= 400:
            record_ip_failure(ip)

        return resp


# ---- 2. 管理端/商户端 认证拦截中间件 ----

_EXEMPT = {"/", "/user/auth", "/user/apply"}
_EXEMPT_PREFIXES = ("/user/availability/",)


class AdminAuthMiddleware(BaseHTTPMiddleware):
    """会话令牌及接口凭证认证中间件。"""

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        if request.method == "OPTIONS":
            return await call_next(request)
        path = request.url.path
        if path in _EXEMPT or path.startswith(_EXEMPT_PREFIXES):
            return await call_next(request)

        auth = request.headers.get("authorization", "")
        if not auth.startswith("Bearer "):
            return JSONResponse(
                status_code=401, content={"code": "ERR_AUTH_MISSING", "msg": "未受权访客"}
            )
        token = auth[7:]

        from app.shared.security.auth import resolve_user_from_token
        user_id = await resolve_user_from_token(token)
        if user_id:
            request.state.current_user_id = user_id
            return await call_next(request)

        # 兼容旧式 command 域令牌（/account/{id}/... 路径）
        if path.startswith("/account/"):
            ok = await _check_legacy_token(token, path)
            if ok:
                return await call_next(request)

        client_ip = get_client_ip_from_request(request)
        logger.warning("认证失败：ip=%s path=%s", client_ip, path)
        return JSONResponse(
            status_code=401, content={"code": "ERR_AUTH_INVALID", "msg": "凭据作废"}
        )


async def _check_legacy_token(token: str, path: str = "") -> bool:
    rd = get_redis(REDIS_DB_AUTH)
    tid = None
    try:
        tid = get_tenant_id()
    except RuntimeError:
        pass
    if not tid and path:
        m = re.match(r"^/accounts?/([^/]+)/", path)
        if m:
            tid = m.group(1)
    if not tid:
        return False
    key = f"auth:{tid}:{token}"
    data = await rd.hgetall(key)
    return bool(data and data.get("scope") == "command")


# ---- 3. 多租户上下文自适应中间件 ----

_ACCOUNT_PATH_RE = re.compile(r"^/accounts?/([^/]+)(?:/|$)")


class AccountContextMiddleware(BaseHTTPMiddleware):
    """基于 URL 解析设置协程级别租户隔离上下文 (tenant_ctx/schema_ctx)。"""

    def __init__(self, app, require_membership: bool = True):
        super().__init__(app)
        self._require_membership = require_membership

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        if request.method == "OPTIONS":
            return await call_next(request)

        path = request.url.path
        match = _ACCOUNT_PATH_RE.match(path)
        if not match:
            return await call_next(request)

        account_id = match.group(1)

        from app.shared.db.session import AsyncSessionLocal
        from app.shared.db.models import Account
        from sqlalchemy import select

        async with AsyncSessionLocal() as db:
            result = await db.execute(select(Account).where(Account.id == account_id))
            account = result.scalar_one_or_none()

        if not account or not account.is_active:
            return JSONResponse(
                status_code=403,
                content={"code": "ERR_RESOURCE_LOCKED", "msg": "账户异常"},
            )

        # 成员资格校验（跳过 /command 子路径）
        remaining_path = path[match.end() - 1 :]
        needs_membership = self._require_membership and "/command" not in remaining_path
        if needs_membership:
            user_id = getattr(request.state, "current_user_id", None)
            if not user_id:
                return JSONResponse(
                    status_code=401, content={"code": "ERR_AUTH_MISSING", "msg": "未验证"}
                )
            from app.shared.db.models import AccountMember
            async with AsyncSessionLocal() as db:
                result = await db.execute(
                    select(AccountMember).where(
                        AccountMember.user_id == user_id,
                        AccountMember.account_id == account_id,
                    )
                )
                member = result.scalar_one_or_none()
            if not member:
                return JSONResponse(
                    status_code=403,
                    content={"code": "ERR_TENANT_NO_ACCESS", "msg": "越权访问"},
                )

        t_tok = tenant_ctx.set(account.id)
        s_tok = schema_ctx.set(f"tenant_{account.slug}")
        try:
            request.state.tenant_id = account.id
            request.state.account_slug = account.slug
            return await call_next(request)
        finally:
            schema_ctx.reset(s_tok)
            tenant_ctx.reset(t_tok)
