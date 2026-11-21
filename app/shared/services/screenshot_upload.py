"""Chunked RESTful screenshot upload service authenticated by short-lived random tokens."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import hmac
import json
import logging
import secrets
from typing import Any

from fastapi import HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.shared.db.models import ConfigUploadRecord
from app.shared.services.quota import check_quota, record_bandwidth_bytes
from app.shared.services.sse import publish_account_event
from app.shared.utils.config import REDIS_DB_SESSION
from app.shared.utils.redis import get_binary_redis, get_redis

logger = logging.getLogger(__name__)

SCREENSHOT_CHUNK_SIZE_BYTES = 1024 * 1024  # 1 MiB
MAX_SCREENSHOT_CHUNKS = 32
MAX_SCREENSHOT_BYTES = SCREENSHOT_CHUNK_SIZE_BYTES * MAX_SCREENSHOT_CHUNKS
SCREENSHOT_TOKEN_TTL_SECONDS = 300
SCREENSHOT_BLOB_TTL_SECONDS = 1800

_TOKEN_KEY_PREFIX = "mci:ss_tok:"
_CHUNK_KEY_PREFIX = "mci:ss_chunk:"
_CHUNKS_META_PREFIX = "mci:ss_chunks_meta:"
_BLOB_KEY_PREFIX = "mci:ss_blob:"
_META_KEY_PREFIX = "mci:ss_meta:"


def _hash_token(token: str) -> str:
    """Compute SHA-256 hex digest of an upload bearer token."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def extract_upload_token_from_request(request: Request, query_token: str = "") -> str:
    """Extract screenshot upload token from Authorization Bearer, X-Screenshot-Upload-Token, X-Upload-Token, or query."""
    auth_header = (request.headers.get("authorization") or "").strip()
    if auth_header.lower().startswith("bearer "):
        candidate = auth_header[7:].strip()
        if candidate:
            return candidate
    for hdr in ("x-screenshot-upload-token", "x-upload-token"):
        header_tok = (request.headers.get(hdr) or "").strip()
        if header_tok:
            return header_tok
    return (query_token or "").strip()


def _detect_image_mime(blob: bytes) -> str | None:
    """Inspect magic bytes and return verified image MIME type, or None if invalid."""
    if blob.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if blob.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if len(blob) >= 12 and blob[:4] == b"RIFF" and blob[8:12] == b"WEBP":
        return "image/webp"
    return None


async def issue_screenshot_upload_token(
    account_id: str,
    client_uid: str,
    request_guid: str,
    *,
    ttl_seconds: int = SCREENSHOT_TOKEN_TTL_SECONDS,
) -> str:
    """Issue a one-time cryptographically random upload token bound to request_guid and client_uid."""
    token = secrets.token_urlsafe(32)
    ttl = max(60, min(int(ttl_seconds), 900))
    meta = {
        "token_hash": _hash_token(token),
        "account_id": account_id,
        "client_uid": client_uid,
        "request_guid": request_guid,
        "chunk_size_bytes": SCREENSHOT_CHUNK_SIZE_BYTES,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    rd = get_redis(REDIS_DB_SESSION)
    await rd.set(
        f"{_TOKEN_KEY_PREFIX}{request_guid}",
        json.dumps(meta, ensure_ascii=False),
        ex=ttl,
    )
    return token


async def _verify_upload_token(
    *,
    request_guid: str,
    client_uid: str,
    token: str,
    request_account_id: str | None = None,
) -> dict[str, Any]:
    """Validate screenshot upload token binding to request_guid, client_uid, and tenant."""
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing screenshot upload token",
        )
    rd = get_redis(REDIS_DB_SESSION)
    raw = await rd.get(f"{_TOKEN_KEY_PREFIX}{request_guid}")
    if not raw:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Screenshot upload token expired or invalid",
        )
    try:
        meta = json.loads(raw)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid upload token metadata",
        ) from exc

    expected_hash = str(meta.get("token_hash") or "")
    if not expected_hash or not hmac.compare_digest(_hash_token(token), expected_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid screenshot upload token",
        )
    if str(meta.get("client_uid") or "") != client_uid:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Screenshot upload token client mismatch",
        )
    acct_id = str(meta.get("account_id") or "")
    if (
        request_account_id
        and request_account_id != "default"
        and acct_id
        and acct_id != request_account_id
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Screenshot upload token tenant mismatch",
        )
    return meta


async def _cleanup_upload_artifacts(request_guid: str, total_chunks: int) -> None:
    """Remove token and temporary chunk keys for request_guid."""
    rd = get_redis(REDIS_DB_SESSION)
    bin_rd = get_binary_redis(REDIS_DB_SESSION)
    await rd.delete(
        f"{_TOKEN_KEY_PREFIX}{request_guid}", f"{_CHUNKS_META_PREFIX}{request_guid}"
    )
    if total_chunks > 0:
        chunk_keys = [
            f"{_CHUNK_KEY_PREFIX}{request_guid}:{idx}" for idx in range(total_chunks)
        ]
        await bin_rd.delete(*chunk_keys)


async def store_screenshot_chunk(
    *,
    client_uid: str,
    request_guid: str,
    chunk_index: int,
    total_chunks: int,
    chunk_bytes: bytes,
    token: str,
    chunk_sha256: str = "",
    request_account_id: str | None = None,
) -> dict[str, Any]:
    """Validate and store a single <= 1 MiB screenshot upload chunk in binary Redis."""
    if total_chunks < 1 or total_chunks > MAX_SCREENSHOT_CHUNKS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"totalChunks must be between 1 and {MAX_SCREENSHOT_CHUNKS}",
        )
    if chunk_index < 0 or chunk_index >= total_chunks:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="chunkIndex out of bounds",
        )
    if not chunk_bytes or len(chunk_bytes) > SCREENSHOT_CHUNK_SIZE_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail=f"Chunk size must be between 1 and {SCREENSHOT_CHUNK_SIZE_BYTES} bytes",
        )

    await _verify_upload_token(
        request_guid=request_guid,
        client_uid=client_uid,
        token=token,
        request_account_id=request_account_id,
    )

    if chunk_sha256:
        actual_sha = hashlib.sha256(chunk_bytes).hexdigest()
        if not hmac.compare_digest(chunk_sha256.strip().lower(), actual_sha):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Chunk SHA-256 verification failed",
            )

    ttl = SCREENSHOT_TOKEN_TTL_SECONDS + 120
    bin_rd = get_binary_redis(REDIS_DB_SESSION)
    rd = get_redis(REDIS_DB_SESSION)
    await bin_rd.set(
        f"{_CHUNK_KEY_PREFIX}{request_guid}:{chunk_index}", chunk_bytes, ex=ttl
    )
    await rd.hset(
        f"{_CHUNKS_META_PREFIX}{request_guid}", str(chunk_index), str(len(chunk_bytes))
    )
    await rd.expire(f"{_CHUNKS_META_PREFIX}{request_guid}", ttl)

    return {
        "status": "ok",
        "requestGuid": request_guid,
        "chunkIndex": chunk_index,
        "totalChunks": total_chunks,
        "bytesReceived": len(chunk_bytes),
    }


async def finalize_screenshot_upload(
    *,
    db: AsyncSession,
    client_uid: str,
    request_guid: str,
    total_chunks: int,
    total_bytes: int,
    sha256_hex: str = "",
    mime_type: str = "image/png",
    width: int = 0,
    height: int = 0,
    original_width: int = 0,
    original_height: int = 0,
    bounds_x: int = 0,
    bounds_y: int = 0,
    display_index: int = 0,
    captured_at: str = "",
    token: str,
    request_account_id: str | None = None,
) -> dict[str, Any]:
    """Reassemble uploaded screenshot chunks, validate, persist metadata, and emit command.completed SSE."""
    if total_chunks < 1 or total_chunks > MAX_SCREENSHOT_CHUNKS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"totalChunks must be between 1 and {MAX_SCREENSHOT_CHUNKS}",
        )
    if total_bytes <= 0 or total_bytes > MAX_SCREENSHOT_BYTES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"totalBytes must be between 1 and {MAX_SCREENSHOT_BYTES}",
        )

    meta = await _verify_upload_token(
        request_guid=request_guid,
        client_uid=client_uid,
        token=token,
        request_account_id=request_account_id,
    )
    account_id = str(meta["account_id"])

    bin_rd = get_binary_redis(REDIS_DB_SESSION)
    chunks: list[bytes] = []
    for idx in range(total_chunks):
        part = await bin_rd.get(f"{_CHUNK_KEY_PREFIX}{request_guid}:{idx}")
        if part is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Missing screenshot chunk {idx}",
            )
        if not isinstance(part, (bytes, bytearray)):
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Corrupt binary chunk in Redis",
            )
        chunks.append(bytes(part))

    blob = b"".join(chunks)
    if len(blob) != total_bytes:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Reassembled byte size mismatch (expected {total_bytes}, got {len(blob)})",
        )

    actual_sha = hashlib.sha256(blob).hexdigest()
    if sha256_hex and not hmac.compare_digest(sha256_hex.strip().lower(), actual_sha):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Screenshot SHA-256 verification failed",
        )

    detected_mime = _detect_image_mime(blob)
    if not detected_mime:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid screenshot image payload (unsupported magic header)",
        )

    if not await check_quota(account_id, "max_bandwidth_mb", db):
        await _cleanup_upload_artifacts(request_guid, total_chunks)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Account monthly bandwidth quota exceeded",
        )

    record_bandwidth_bytes(account_id, len(blob))

    now = datetime.now(timezone.utc)
    blob_meta = {
        "request_guid": request_guid,
        "account_id": account_id,
        "client_uid": client_uid,
        "mime_type": detected_mime or mime_type or "image/png",
        "size_bytes": len(blob),
        "sha256": actual_sha,
        "width": int(width),
        "height": int(height),
        "original_width": int(original_width),
        "original_height": int(original_height),
        "bounds_x": int(bounds_x),
        "bounds_y": int(bounds_y),
        "display_index": int(display_index),
        "captured_at": captured_at or now.isoformat(),
        "uploaded_at": now.isoformat(),
    }

    rd = get_redis(REDIS_DB_SESSION)
    await bin_rd.set(
        f"{_BLOB_KEY_PREFIX}{account_id}:{request_guid}",
        blob,
        ex=SCREENSHOT_BLOB_TTL_SECONDS,
    )
    await rd.set(
        f"{_META_KEY_PREFIX}{account_id}:{request_guid}",
        json.dumps(blob_meta, ensure_ascii=False),
        ex=SCREENSHOT_BLOB_TTL_SECONDS,
    )

    # Burn one-time token and clean temporary chunk storage
    await _cleanup_upload_artifacts(request_guid, total_chunks)

    result_data = {
        "screenshotReady": True,
        "restFinalized": True,
        "requestGuid": request_guid,
        "mimeType": blob_meta["mime_type"],
        "sizeBytes": len(blob),
        "width": int(width),
        "height": int(height),
        "originalWidth": int(original_width),
        "originalHeight": int(original_height),
        "boundsX": int(bounds_x),
        "boundsY": int(bounds_y),
        "displayIndex": int(display_index),
        "sha256": actual_sha,
        "capturedAt": blob_meta["captured_at"],
    }
    envelope_payload = json.dumps(
        {
            "requestGuid": request_guid,
            "clientUid": client_uid,
            "action": "remote.screenshot",
            "success": True,
            "code": "OK",
            "message": "Success",
            "data": result_data,
        },
        ensure_ascii=False,
    )

    existing = (
        await db.execute(
            select(ConfigUploadRecord).where(
                ConfigUploadRecord.request_guid == request_guid
            )
        )
    ).scalar_one_or_none()
    if existing:
        existing.status = "completed"
        existing.payload = envelope_payload
        existing.uploaded_at = now
        cfg_type = existing.config_type
    else:
        cfg_type = 100
        db.add(
            ConfigUploadRecord(
                request_guid=request_guid,
                account_id=account_id,
                client_uid=client_uid,
                config_type=cfg_type,
                status="completed",
                payload=envelope_payload,
                uploaded_at=now,
            )
        )
    await db.commit()

    await publish_account_event(
        account_id,
        "command.completed",
        {
            "request_guid": request_guid,
            "client_uid": client_uid,
            "action": "remote.screenshot",
            "config_type": cfg_type,
            "status": "completed",
            "payload": envelope_payload,
            "uploaded_at": now.isoformat(),
        },
    )

    return {
        "status": "ok",
        **result_data,
    }


async def get_screenshot_blob(
    account_id: str, request_guid: str
) -> tuple[bytes, dict[str, Any]] | None:
    """Retrieve stored screenshot binary blob and metadata for a tenant account."""
    bin_rd = get_binary_redis(REDIS_DB_SESSION)
    rd = get_redis(REDIS_DB_SESSION)
    blob = await bin_rd.get(f"{_BLOB_KEY_PREFIX}{account_id}:{request_guid}")
    if blob is None or not isinstance(blob, (bytes, bytearray)):
        return None
    raw_meta = await rd.get(f"{_META_KEY_PREFIX}{account_id}:{request_guid}")
    meta: dict[str, Any] = {}
    if raw_meta:
        try:
            meta = json.loads(raw_meta)
        except Exception:
            meta = {}
    return bytes(blob), meta
