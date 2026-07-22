import logging
import re
import time
from typing import Dict, Tuple

from fastapi import Request, Response, status
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

# ---- 1. CC Attack Protection State & Rate Limiter ----

from app.shared.security.crypto import (
    get_cc_state,
    set_cc_state,
    get_ip_failures_dict,
    get_global_requests,
)

IP_FAILURE_LIMIT = 20
IP_BLOCK_DURATION = 300
GLOBAL_CC_LIMIT = 500
GLOBAL_CC_WINDOW = 1.0


def check_ip_blocked(ip: str) -> bool:
    ip_failures = get_ip_failures_dict()
    if ip not in ip_failures:
        return False
    fails = ip_failures[ip]
    if isinstance(fails, list):
        now = time.time()
        while fails and fails[0] < now - IP_BLOCK_DURATION:
            fails.pop(0)
        return len(fails) >= IP_FAILURE_LIMIT
    
    count, last_time = fails
    if count >= IP_FAILURE_LIMIT:
        if time.time() - last_time < IP_BLOCK_DURATION:
            return True
        else:
            try:
                del ip_failures[ip]
            except KeyError:
                pass
    return False


def record_ip_failure(ip: str) -> None:
    now = time.time()
    ip_failures = get_ip_failures_dict()
    if ip not in ip_failures:
        ip_failures[ip] = [now]
    else:
        fails = ip_failures[ip]
        if isinstance(fails, list):
            fails.append(now)
        else:
            count, _ = fails
            ip_failures[ip] = (count + 1, now)


def monitor_global_frequency() -> None:
    now = time.time()
    global_reqs = get_global_requests()
    global_reqs.append(now)
    while global_reqs and global_reqs[0] < now - GLOBAL_CC_WINDOW:
        global_reqs.pop(0)
    if len(global_reqs) > GLOBAL_CC_LIMIT:
        set_cc_state(True)
    else:
        set_cc_state(False)


class CCProtectMiddleware(BaseHTTPMiddleware):
    """Security middleware: block banned IPs and protect against global CC attacks."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        ip = get_client_ip_from_request(request) or "unknown"
        if check_ip_blocked(ip):
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS, content={"code": "ERR_IP_BLOCKED", "msg": "IP address temporarily blocked"}
            )

        monitor_global_frequency()

        path = request.url.path.lower()
        if get_cc_state() and any(k in path for k in ["login", "register"]):
            if "authorization" not in request.headers:
                return JSONResponse(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content={"code": "ERR_CC_ACTIVE", "msg": "Channel busy, try again later"}
                )

        resp = await call_next(request)
        if resp.status_code >= 400:
            record_ip_failure(ip)

        return resp


# ---- 2. Admin & Management Authentication Interceptor Middleware ----

_EXEMPT = {"/", "/user/auth", "/user/apply"}
_EXEMPT_PREFIXES = ("/user/availability/",)


class AdminAuthMiddleware(BaseHTTPMiddleware):
    """Session token and API credential authentication middleware."""

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
                status_code=status.HTTP_401_UNAUTHORIZED, content={"code": "ERR_AUTH_MISSING", "msg": "Unauthenticated visitor"}
            )
        token = auth[7:]

        from app.shared.security.auth import resolve_user_from_token
        user_id = await resolve_user_from_token(token)
        if user_id:
            request.state.current_user_id = user_id
            return await call_next(request)

        # Compatible with legacy command scope tokens (for /account/{id}/... paths)
        if path.startswith("/account/"):
            ok = await _check_legacy_token(token, path)
            if ok:
                return await call_next(request)

        client_ip = get_client_ip_from_request(request)
        logger.warning("Authentication failed: ip=%s path=%s", client_ip, path)
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED, content={"code": "ERR_AUTH_INVALID", "msg": "Invalid credentials"}
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


# ---- 3. Multi-Tenant Context Middleware ----

_ACCOUNT_PATH_RE = re.compile(r"^/accounts?/([^/]+)(?:/|$)")
_ACCOUNT_RESERVED_SUBPATHS = {"list", "search", "apply", "availability"}


class AccountContextMiddleware(BaseHTTPMiddleware):
    """Set coroutine-level tenant isolation context (tenant_ctx/schema_ctx) based on URL parsing."""

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
        if account_id in _ACCOUNT_RESERVED_SUBPATHS:
            return await call_next(request)

        from app.shared.db.session import AsyncSessionLocal
        from app.shared.db.models import Account
        from sqlalchemy import select

        async with AsyncSessionLocal() as db:
            result = await db.execute(select(Account).where(Account.id == account_id))
            account = result.scalar_one_or_none()

        if not account or not account.is_active:
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"code": "ERR_RESOURCE_LOCKED", "msg": "Account invalid or inactive"},
            )

        # Member validation (skip /command subpaths)
        remaining_path = path[match.end() - 1 :]
        needs_membership = self._require_membership and "/command" not in remaining_path
        if needs_membership:
            user_id = getattr(request.state, "current_user_id", None)
            if not user_id:
                return JSONResponse(
                    status_code=status.HTTP_401_UNAUTHORIZED, content={"code": "ERR_AUTH_MISSING", "msg": "Unauthenticated"}
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
                    status_code=status.HTTP_403_FORBIDDEN,
                    content={"code": "ERR_TENANT_NO_ACCESS", "msg": "Access denied for tenant"},
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


class TenantMiddleware(BaseHTTPMiddleware):
    """Client middleware to extract tenant slug from subdomain Host header."""

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        if request.method == "OPTIONS":
            return await call_next(request)
        path = request.url.path
        if path in {"/", "/get"}:
            return await call_next(request)

        from app.shared.utils.tenant import extract_slug_from_host, resolve_account
        slug = extract_slug_from_host(request.headers.get("host", ""))
        if not slug:
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"code": "ERR_TENANT_NO_ACCESS", "msg": "Tenant not recognized"},
            )

        from app.shared.db.session import AsyncSessionLocal
        async with AsyncSessionLocal() as db:
            account = await resolve_account(slug, db)
        if not account:
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"code": "ERR_RESOURCE_LOCKED", "msg": "Service unavailable"},
            )

        t_tok = tenant_ctx.set(account.id)
        s_tok = schema_ctx.set(f"tenant_{slug}")
        try:
            request.state.tenant_id = account.id
            request.state.tenant_slug = slug
            return await call_next(request)
        finally:
            schema_ctx.reset(s_tok)
            tenant_ctx.reset(t_tok)

