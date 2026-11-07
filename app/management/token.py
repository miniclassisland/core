import time
from fastapi import APIRouter, Body, Depends, HTTPException, Request, status

from app.shared.security.auth import (
    get_current_user_id,
    create_session_token,
    revoke_session_token,
    create_exchange_code,
    redeem_exchange_code,
    redeem_certificate_exchange_code,
    verify_login_certificate,
    rotate_login_certificate,
    check_cert_ip_rate_limit,
    check_qr_poll_ip_rate_limit,
    create_qr_login_challenge,
    authorize_qr_login_challenge,
    poll_qr_login_challenge,
    resolve_user_from_token,
    _cert_id_last_mint,
    _CERT_ID_MIN_SESSION_INTERVAL,
    _CERT_ROTATE_WINDOW,
    _CERT_SESSION_MAX_TTL,
)
from app.shared.security.middlewares import record_ip_failure_async
from app.shared.schemas.schemas import (
    MessageResponse,
    CertificateRedeemRequest,
    CertificateSessionRequest,
    CertificateRotateRequest,
    QrLoginAuthorizeRequest,
)
from app.shared.utils.logging import get_client_ip_from_request

router = APIRouter(prefix="/token", tags=["Token"])


@router.post("/refresh")
async def refresh_token(
    request: Request,
    user_id: str = Depends(get_current_user_id),
):
    """Refresh current session token and revoke the old session token."""
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        await revoke_session_token(auth[7:])
    token = await create_session_token(user_id)
    return {"token": token}


@router.post("/verify")
async def verify_token(
    user_id: str = Depends(get_current_user_id),
):
    """Verify current token validity and return user ID."""
    return {"valid": True, "user_id": user_id}


@router.post("/deactivate", response_model=MessageResponse)
async def deactivate_token(request: Request):
    """Deactivate current session token (Log out)."""
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        await revoke_session_token(auth[7:])
    return MessageResponse(message="Logged out successfully")


@router.post("/exchange")
async def issue_exchange_code(
    request: Request,
    _user_id: str = Depends(get_current_user_id),
):
    """Issue a 30-second single-use SSO exchange code for cross-origin site switching."""
    auth = request.headers.get("authorization", "")
    token = auth[7:] if auth.startswith("Bearer ") else ""
    client_ip = get_client_ip_from_request(request)
    code = await create_exchange_code(token, client_ip=client_ip)
    return {"code": code}


@router.post("/redeem")
async def redeem_sso_exchange_code(
    request: Request,
    body: dict = Body(...),
):
    """Redeem a single-use SSO exchange code for the underlying session token."""
    code = str(body.get("code") or "").strip()
    client_ip = get_client_ip_from_request(request)
    token = await redeem_exchange_code(code, client_ip=client_ip)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Exchange code invalid or expired",
        )
    return {"token": token}


@router.post("/certificate/redeem")
async def redeem_certificate(
    request: Request,
    body: CertificateRedeemRequest,
):
    """Redeem a 5-minute single-use exchange code or DeepLink for a 7-day Login Security Certificate and initial 1h session token."""
    client_ip = get_client_ip_from_request(request) or "unknown"
    if not check_cert_ip_rate_limit(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Certificate endpoint rate limit exceeded",
        )
    cert = await redeem_certificate_exchange_code(body.resolved_code)
    if not cert:
        await record_ip_failure_async(client_ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Certificate exchange code invalid or expired",
        )
    now = int(time.time())
    session_ttl = min(_CERT_SESSION_MAX_TTL, max(60, cert["expires_at"] - now))
    token = await create_session_token(cert["user_id"], ttl=session_ttl)
    return {
        "certificate": cert,
        "token": token,
        "expires_in": session_ttl,
    }


@router.post("/certificate/session")
async def create_session_with_certificate(
    request: Request,
    body: CertificateSessionRequest,
):
    """Request a traditional session token (<= 1 hour) using a valid Login Security Certificate."""
    client_ip = get_client_ip_from_request(request) or "unknown"
    if not check_cert_ip_rate_limit(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Certificate endpoint rate limit exceeded",
        )
    cert = await verify_login_certificate(body.cert_id, body.cert_secret)
    if not cert:
        await record_ip_failure_async(client_ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Security certificate invalid or expired",
        )
    now = int(time.time())
    remaining = max(1, cert["expires_at"] - now)
    requested_ttl = min(
        max(60, int(body.ttl or _CERT_SESSION_MAX_TTL)), _CERT_SESSION_MAX_TTL
    )
    effective_ttl = min(requested_ttl, remaining)

    # Deduplicate rapid session minting for the same certificate within _CERT_ID_MIN_SESSION_INTERVAL
    mono_now = time.monotonic()
    cid = cert["cert_id"]
    cached_mint = _cert_id_last_mint.get(cid)
    if (
        cached_mint is not None
        and mono_now - cached_mint[0] < _CERT_ID_MIN_SESSION_INTERVAL
    ):
        token = cached_mint[1]
        effective_ttl = min(effective_ttl, cached_mint[2])
    else:
        if len(_cert_id_last_mint) > 4096:
            _cert_id_last_mint.clear()
        token = await create_session_token(cert["user_id"], ttl=effective_ttl)
        _cert_id_last_mint[cid] = (mono_now, token, effective_ttl)

    can_rotate = (remaining <= _CERT_ROTATE_WINDOW) and (
        cert["generation"] < cert["max_generation"]
    )
    return {
        "token": token,
        "expires_in": effective_ttl,
        "cert_id": cid,
        "generation": cert["generation"],
        "max_generation": cert["max_generation"],
        "cert_expires_at": cert["expires_at"],
        "can_rotate": can_rotate,
    }


@router.post("/certificate/rotate")
async def rotate_certificate(
    request: Request,
    body: CertificateRotateRequest,
):
    """Rotate a Login Security Certificate to the next generation when remaining validity < 24h (max 12 generations)."""
    client_ip = get_client_ip_from_request(request) or "unknown"
    if not check_cert_ip_rate_limit(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Certificate endpoint rate limit exceeded",
        )
    try:
        new_cert = await rotate_login_certificate(body.cert_id, body.cert_secret)
    except ValueError:
        await record_ip_failure_async(client_ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Security certificate invalid or expired",
        )
    except PermissionError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Security certificate has reached maximum rotation generation (12)",
        )
    except RuntimeError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Security certificate can only be rotated when remaining validity is under 24 hours",
        )

    token = await create_session_token(new_cert["user_id"], ttl=_CERT_SESSION_MAX_TTL)
    return {
        "certificate": new_cert,
        "token": token,
        "expires_in": _CERT_SESSION_MAX_TTL,
    }


@router.post("/qr-login/create")
async def create_web_qr_login(request: Request):
    """Create a 5-minute reverse QR login challenge for Web login."""
    client_ip = get_client_ip_from_request(request) or "unknown"
    if not check_cert_ip_rate_limit(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="QR login rate limit exceeded",
        )
    return await create_qr_login_challenge(client_ip=client_ip)


@router.get("/qr-login/poll")
async def poll_web_qr_login(request: Request, code: str):
    """Poll status of a reverse Web QR login challenge."""
    client_ip = get_client_ip_from_request(request) or "unknown"
    if not check_qr_poll_ip_rate_limit(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="QR login poll rate limit exceeded",
        )
    return await poll_qr_login_challenge(code)


@router.post("/qr-login/authorize")
async def authorize_web_qr_login(
    request: Request,
    body: QrLoginAuthorizeRequest,
):
    """Authorize a pending Web QR login session using either Bearer session token or Login Security Certificate."""
    client_ip = get_client_ip_from_request(request) or "unknown"
    if not check_cert_ip_rate_limit(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="QR login rate limit exceeded",
        )
    user_id = None
    auth_header = request.headers.get("authorization", "")
    if auth_header.startswith("Bearer "):
        user_id = await resolve_user_from_token(auth_header[7:].strip())

    if not user_id and body.cert_id and body.cert_secret:
        cert = await verify_login_certificate(body.cert_id, body.cert_secret)
        if cert:
            user_id = cert["user_id"]

    if not user_id:
        await record_ip_failure_async(client_ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Valid mobile session or Login Security Certificate required",
        )

    ok = await authorize_qr_login_challenge(body.code, user_id)
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="QR login code invalid, expired, or already used",
        )
    return {"authorized": True, "user_id": user_id}
