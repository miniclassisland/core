import logging
import re
import time

from fastapi import Request, Response, status
from starlette.middleware.base import (
    BaseHTTPMiddleware,
    RequestResponseEndpoint,
)
from starlette.responses import JSONResponse

from app.shared.utils.tenant import tenant_ctx, schema_ctx
from app.shared.utils.logging import get_client_ip_from_request
from app.shared.security.crypto import (
    get_cc_state,
    set_cc_state,
    get_ip_failures_dict,
    get_global_requests,
)

logger = logging.getLogger(__name__)

# ---- 1. CC Attack Protection State & Rate Limiter ----

IP_FAILURE_LIMIT = 20
IP_BLOCK_DURATION = 300
GLOBAL_CC_LIMIT = 25000
GLOBAL_CC_WINDOW = 1.0
MAX_TRACKED_IPS = 10000
_CC_PROTECTED_KEYWORDS = (
    "login",
    "register",
    "/user/auth",
    "/user/apply",
    "/user/2fa/",
    "/oobe/",
)


def check_ip_blocked(ip: str) -> bool:
    ip_failures = get_ip_failures_dict()
    if ip not in ip_failures:
        return False
    fails = ip_failures[ip]
    if isinstance(fails, list):
        now = time.time()
        while fails and fails[0] < now - IP_BLOCK_DURATION:
            fails.pop(0)
        if not fails:
            ip_failures.pop(ip, None)
            return False
        return len(fails) >= IP_FAILURE_LIMIT

    count, last_time = fails
    if count >= IP_FAILURE_LIMIT:
        if time.time() - last_time < IP_BLOCK_DURATION:
            return True
        else:
            ip_failures.pop(ip, None)
    return False


def record_ip_failure(ip: str) -> None:
    now = time.time()
    ip_failures = get_ip_failures_dict()
    if len(ip_failures) >= MAX_TRACKED_IPS and ip not in ip_failures:
        cutoff = now - IP_BLOCK_DURATION
        expired = [
            k
            for k, v in list(ip_failures.items())
            if (isinstance(v, list) and (not v or v[-1] < cutoff))
            or (not isinstance(v, list) and v[1] < cutoff)
        ]
        for k in expired:
            ip_failures.pop(k, None)
        if len(ip_failures) >= MAX_TRACKED_IPS:
            ip_failures.pop(next(iter(ip_failures)), None)
    if ip not in ip_failures:
        ip_failures[ip] = [now]
    else:
        fails = ip_failures[ip]
        if isinstance(fails, list):
            fails.append(now)
        else:
            count, _ = fails
            ip_failures[ip] = (count + 1, now)


async def check_ip_blocked_async(ip: str) -> bool:
    """Check IP block state across local memory and shared Redis sliding window."""
    if check_ip_blocked(ip):
        return True
    try:
        from app.shared.utils.config import REDIS_DB_AUTH, is_initialized
        from app.shared.utils.redis import get_redis

        if is_initialized():
            r = get_redis(REDIS_DB_AUTH)
            val = await r.get(f"cc:ip_fail:{ip}")
            if val is not None and int(val) >= IP_FAILURE_LIMIT:
                return True
    except Exception:  # pragma: no cover
        pass
    return False


async def record_ip_failure_async(ip: str) -> None:
    """Record IP authentication failure in local memory and shared Redis."""
    record_ip_failure(ip)
    try:
        from app.shared.utils.config import REDIS_DB_AUTH, is_initialized
        from app.shared.utils.redis import get_redis

        if is_initialized():
            r = get_redis(REDIS_DB_AUTH)
            key = f"cc:ip_fail:{ip}"
            cnt = await r.incr(key)
            if cnt == 1 or cnt == IP_FAILURE_LIMIT:  # pragma: no cover
                await r.expire(key, IP_BLOCK_DURATION)
    except Exception:  # pragma: no cover
        pass


def monitor_global_frequency() -> None:
    now = time.time()
    global_reqs = get_global_requests()
    global_reqs.append(now)
    cutoff = now - GLOBAL_CC_WINDOW
    while global_reqs and global_reqs[0] < cutoff:
        global_reqs.popleft()
    if len(global_reqs) > GLOBAL_CC_LIMIT:
        set_cc_state(True)
    else:
        set_cc_state(False)


class CCProtectMiddleware(BaseHTTPMiddleware):
    """Security middleware: block banned IPs and protect against global CC attacks."""

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        ip = get_client_ip_from_request(request) or "unknown"
        path = request.url.path.lower()
        is_client_delivery_path = path.startswith(
            ("/api/v1/client/", "/v1/client/", "/get", "/fonts/", "/api/v1/fonts/")
        )
        if not is_client_delivery_path and await check_ip_blocked_async(ip):
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "code": "ERR_IP_BLOCKED",
                    "msg": "IP address temporarily blocked",
                },
            )

        monitor_global_frequency()

        if get_cc_state() and any(k in path for k in _CC_PROTECTED_KEYWORDS):
            return JSONResponse(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content={
                    "code": "ERR_CC_ACTIVE",
                    "msg": "Channel busy, try again later",
                },
            )

        resp = await call_next(request)
        if resp.status_code in (401, 403) and not is_client_delivery_path:
            await record_ip_failure_async(ip)

        return resp


# ---- 2. Admin & Management Authentication Interceptor Middleware ----

_EXEMPT = {
    "/",
    "/get",
    "/user/auth",
    "/user/apply",
    "/user/2fa/totp/verify",
    "/user/2fa/totp/recover",
    "/token/redeem",
    "/oobe/verify",
    "/oobe/configure",
    "/api/oobe/verify",
    "/api/oobe/configure",
}
_EXEMPT_PREFIXES = ("/user/availability/", "/fonts/", "/api/v1/fonts/")


_PENDING_USER_ALLOWED_PATHS = {
    "/user/info",
    "/community/code",
    "/community/status",
    "/invitation/accept",
    "/account/invitation/accept",
    "/account/list",
    "/account/search",
    "/token/refresh",
    "/token/deactivate",
    "/site/announcement",
    "/version",
    "/ticket/unread-count",
    "/ticket/list",
}


def _is_pending_user_allowed_request(path: str, method: str) -> bool:
    """Return True if a pending user is permitted to call the given Management API endpoint."""
    if path in _PENDING_USER_ALLOWED_PATHS:
        return True
    path_lower = path.lower()
    if _ACCOUNT_PATH_RE.match(path) and method in (
        "GET",
        "HEAD",
        "OPTIONS",
    ):  # pragma: no cover
        if (
            not path_lower.endswith(("/create", "/delete", "/command/get-config"))
            and "/credentials" not in path_lower
        ):
            return True
    return False


class AdminAuthMiddleware(BaseHTTPMiddleware):
    """Session token and API credential authentication middleware."""

    def __init__(self, app, require_superadmin: bool = False):
        super().__init__(app)
        self._require_superadmin = require_superadmin

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
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"code": "ERR_AUTH_MISSING", "msg": "Unauthenticated visitor"},
            )
        token = auth[7:]

        from app.shared.security.auth import resolve_user_from_token

        user_id = await resolve_user_from_token(token)
        if user_id:
            from app.shared.db.session import AsyncSessionLocal
            from app.shared.db.models import User
            from sqlalchemy import select

            async with AsyncSessionLocal() as db:
                u = (
                    await db.execute(select(User).where(User.id == user_id))
                ).scalar_one_or_none()
                if not u or u.role_code == "banned":
                    return JSONResponse(
                        status_code=status.HTTP_403_FORBIDDEN,
                        content={
                            "code": "ERR_PERMISSION_DENIED",
                            "msg": "User account is inactive or banned",
                        },
                    )
                if u.role_code == "pending":
                    if (
                        self._require_superadmin
                        or not _is_pending_user_allowed_request(path, request.method)
                    ):
                        return JSONResponse(
                            status_code=status.HTTP_403_FORBIDDEN,
                            content={
                                "code": "ERR_PERMISSION_DENIED",
                                "msg": "Account is awaiting administrator approval",
                            },
                        )
                elif not u.is_active:  # pragma: no cover
                    return JSONResponse(
                        status_code=status.HTTP_403_FORBIDDEN,
                        content={
                            "code": "ERR_PERMISSION_DENIED",
                            "msg": "User account is inactive or banned",
                        },
                    )
                if self._require_superadmin and u.role_code != "superadmin":
                    return JSONResponse(
                        status_code=status.HTTP_403_FORBIDDEN,
                        content={
                            "code": "ERR_PERMISSION_DENIED",
                            "msg": "Super Administrator privilege required",
                        },
                    )
            request.state.current_user_id = user_id
            request.state.current_user = u
            return await call_next(request)

        client_ip = get_client_ip_from_request(request)
        logger.warning("Authentication failed: ip=%s path=%s", client_ip, path)
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"code": "ERR_AUTH_INVALID", "msg": "Invalid credentials"},
        )


# ---- 3. Multi-Tenant Context Middleware ----

_ACCOUNT_PATH_RE = re.compile(r"^/accounts?/([^/]+)(?:/|$)")
_ACCOUNT_RESERVED_SUBPATHS = {
    "default",
    "list",
    "search",
    "apply",
    "availability",
    "create",
    "invitation",
    "bulk",
}


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
                content={
                    "code": "ERR_RESOURCE_LOCKED",
                    "msg": "Account invalid or inactive",
                },
            )

        # Member validation and role assignment
        role_in_account = "owner"
        if self._require_membership:
            user_id = getattr(request.state, "current_user_id", None)
            if not user_id:
                return JSONResponse(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    content={"code": "ERR_AUTH_MISSING", "msg": "Unauthenticated"},
                )
            from app.shared.db.models import AccountMember, User

            cached_u = getattr(request.state, "current_user", None)
            async with AsyncSessionLocal() as db:
                result = await db.execute(
                    select(AccountMember).where(
                        AccountMember.user_id == user_id,
                        AccountMember.account_id == account_id,
                    )
                )
                member = result.scalar_one_or_none()
                u = (
                    cached_u
                    if isinstance(cached_u, User) and cached_u.id == user_id
                    else (
                        await db.execute(select(User).where(User.id == user_id))
                    ).scalar_one_or_none()
                )
                if member:
                    if u and u.role_code == "pending":  # pragma: no cover
                        role_in_account = "viewer"
                    else:
                        role_in_account = member.role_in_account or "member"
                else:
                    # Allow superadmin to inspect/manage accounts if needed
                    if not u or u.role_code != "superadmin":
                        return JSONResponse(
                            status_code=status.HTTP_403_FORBIDDEN,
                            content={
                                "code": "ERR_TENANT_NO_ACCESS",
                                "msg": "Access denied for tenant",
                            },
                        )
                    role_in_account = "owner"

        t_tok = tenant_ctx.set(account.id)
        s_tok = schema_ctx.set(f"tenant_{account.slug}")
        try:
            request.state.tenant_id = account.id
            request.state.account_slug = account.slug
            request.state.current_account = account
            request.state.role_in_account = role_in_account
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
        if path in {"/", "/get"} or path.startswith("/fonts/"):
            return await call_next(request)

        from app.shared.utils.tenant import extract_slug_from_host, resolve_account

        slug = (
            extract_slug_from_host(request.headers.get("host", ""))
            or request.headers.get("x-tenant-slug")
            or request.query_params.get("tenant")
        )
        if not slug:
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={
                    "code": "ERR_TENANT_NO_ACCESS",
                    "msg": "Tenant not recognized",
                },
            )

        account = await resolve_account(slug)
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
