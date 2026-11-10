"""gRPC server main entrypoint and Servicer integration.

Provides an all-in-one implementation for gRPC command streaming, registration streaming,
audit streaming, handshake streaming, and tenant interceptor validation.
"""

from collections.abc import AsyncGenerator
import asyncio
import functools
import inspect
import json
import logging
import base64
import time
from datetime import datetime, timezone
from typing import Any
import grpc
from sqlalchemy import select, or_

# Database, sessions, and multi-tenancy
from app.shared.db.session import AsyncSessionLocal
from app.shared.db.models import (
    Account,
    ClientRecord,
    ClientProfile,
    PreRegisteredClient,
    ConfigUploadRecord,
    AuditLog,
    SystemConfig,
)
from app.shared.utils.tenant import (
    tenant_ctx,
    schema_ctx,
    resolve_account,
    extract_slug_from_host,
    set_search_path,
)
from app.shared.utils.logging import get_client_ip_from_grpc
from app.shared.utils.audit import decode_audit_payload_json
from app.shared.security.middlewares import get_cc_state
from app.shared.services.pairing import check_approved, create_pairing_request
from app.shared.services.quota import check_quota, record_bandwidth_bytes

# Protobuf package imports
from app.Protobuf.Service import (
    Handshake_pb2_grpc,
    ClientRegister_pb2_grpc,
    ClientCommandDeliver_pb2_grpc,
    ConfigUpload_pb2_grpc,
    Audit_pb2_grpc,
)
from app.Protobuf.Server import (
    HandshakeScRsp_pb2,
    ClientRegisterScRsp_pb2,
    ClientCommandDeliverScRsp_pb2,
    ConfigUploadScRsp_pb2,
    AuditScRsp_pb2,
)
from app.Protobuf.Enum import Retcode_pb2, CommandTypes_pb2

from app.grpc.session import SessionManager
from app.shared.utils.config import LISTEN_HOST, GRPC_PORT

logger = logging.getLogger(__name__)
_REGISTER_LOCKS: dict[str, asyncio.Lock] = {}
_MAX_REGISTER_LOCKS = 4096

# gRPC auth exempt methods (UploadConfig is exempted here because upstream ClassIsland
# calls UploadConfig without GetMetadata(); the servicer verifies RequestGuidId or session)
_AUTH_EXEMPT = {
    "Register",
    "UnRegister",
    "BeginHandshake",
    "CompleteHandshake",
    "UploadConfig",
}
_CC_BLOCK_METHODS = {"Register", "BeginHandshake", "CompleteHandshake"}
_QUEUE_MAXSIZE = 256
_MIN_PING_INTERVAL = 1.0
_REDIS_HB_SYNC_INTERVAL = 20.0
_STREAM_IDLE_TIMEOUT = 120
_PAIRING_KEY = "pairing_enabled"
_MAX_GRPC_PAYLOAD_BYTES = 2 * 1024 * 1024
_MAX_CHALLENGE_TOKEN_LEN = 512
_GRPC_SERVER_OPTIONS = [
    ("grpc.max_concurrent_streams", 2048),
    ("grpc.keepalive_time_ms", 60000),
    ("grpc.keepalive_timeout_ms", 20000),
    ("grpc.keepalive_permit_without_calls", 1),
    ("grpc.http2.max_pings_without_data", 0),
    ("grpc.http2.min_ping_interval_without_data_ms", 5000),
    ("grpc.http2.min_time_between_pings_ms", 5000),
    ("grpc.http2.max_ping_strikes", 0),
]


# ---- Helper Functions ----


def _get_metadata_dict(context: Any) -> dict[str, str]:
    """Extract gRPC context metadata dictionary."""
    raw = context.invocation_metadata() or ()
    return {
        str(k): (v.decode("utf-8", errors="ignore") if isinstance(v, bytes) else str(v))
        for k, v in raw
    }


def _get_tenant_id_safe() -> str:
    """Safely read tenant ID from context."""
    try:
        return tenant_ctx.get()
    except LookupError:
        return ""


# ---- gRPC Tenant Interceptor ----


class TenantInterceptor(grpc.aio.ServerInterceptor):
    """Server-side multi-tenant resolution and session auth interceptor."""

    def __init__(self, session_manager: SessionManager):
        self._sm = session_manager

    async def intercept_service(self, continuation, handler_call_details):
        method = handler_call_details.method or ""
        short_name = method.rsplit("/", 1)[-1]

        # Block non-authenticated new connections during CC protection mode
        if get_cc_state() and short_name in _CC_BLOCK_METHODS:
            raise grpc.aio.AbortError(
                grpc.StatusCode.UNAVAILABLE,
                "Network congestion defense enabled; registration and handshake rejected",
            )

        raw_md = handler_call_details.invocation_metadata or ()
        metadata: dict[str, str] = {
            str(k): (
                v.decode("utf-8", errors="ignore") if isinstance(v, bytes) else str(v)
            )
            for k, v in raw_md
        }
        authority = (
            metadata.get("x-forwarded-host")
            or metadata.get("host")
            or metadata.get(":authority", "")
        )

        slug = (
            extract_slug_from_host(authority)
            or metadata.get("tenant-id")
            or metadata.get("tenant_id")
            or metadata.get("tenant-slug")
        )

        tenant_id = None
        if slug:
            account = await resolve_account(slug)
            if account:
                tenant_id = account.id

        sid = metadata.get("session") or metadata.get("authorization", "")
        if sid.startswith("Bearer "):
            sid = sid[7:]

        if short_name not in _AUTH_EXEMPT:
            if not sid or not await self._sm.validate_session(sid):
                raise grpc.aio.AbortError(
                    grpc.StatusCode.UNAUTHENTICATED, "Device session invalid or missing"
                )
            if not tenant_id and sid:
                tenant_id = await self._sm.get_session_tenant(sid)

        handler = await continuation(handler_call_details)
        if handler is None:
            return None

        # Wrap context vars for coroutines and async generators
        def wrapper_unary(behavior):
            @functools.wraps(behavior)
            async def wrapped_behavior(request_or_iterator, context):
                t1, t2 = None, None
                if tenant_id:
                    t1 = tenant_ctx.set(tenant_id)
                    if slug:
                        t2 = schema_ctx.set(f"tenant_{slug}")
                try:
                    return await behavior(request_or_iterator, context)
                finally:
                    if t1:
                        tenant_ctx.reset(t1)
                    if t2:
                        schema_ctx.reset(t2)

            return wrapped_behavior

        def wrapper_stream(behavior):
            @functools.wraps(behavior)
            async def wrapped_behavior(request_or_iterator, context):
                t1, t2 = None, None
                if tenant_id:
                    t1 = tenant_ctx.set(tenant_id)
                    if slug:
                        t2 = schema_ctx.set(f"tenant_{slug}")
                try:
                    async for response in behavior(request_or_iterator, context):
                        yield response
                finally:
                    if t1:
                        tenant_ctx.reset(t1)
                    if t2:
                        schema_ctx.reset(t2)

            return wrapped_behavior

        def wrap_stream(behavior):
            if inspect.isasyncgenfunction(behavior):
                return wrapper_stream(behavior)
            return wrapper_unary(behavior)

        if handler.unary_unary:
            return grpc.unary_unary_rpc_method_handler(
                wrapper_unary(handler.unary_unary),
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )
        if handler.unary_stream:
            return grpc.unary_stream_rpc_method_handler(
                wrap_stream(handler.unary_stream),
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )
        if handler.stream_unary:
            return grpc.stream_unary_rpc_method_handler(
                wrapper_unary(handler.stream_unary),
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )
        if handler.stream_stream:
            return grpc.stream_stream_rpc_method_handler(
                wrap_stream(handler.stream_stream),
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )
        return handler


# ---- 1. Handshake Servicer ----


class HandshakeServicer(Handshake_pb2_grpc.HandshakeServicer):
    """RSA challenge-response security handshake service."""

    def __init__(self, session_manager: SessionManager):
        self._sm = session_manager

    async def BeginHandshake(self, request: Any, context):
        tid = _get_tenant_id_safe()
        cuid, mac = request.ClientUid, request.ClientMac

        async with AsyncSessionLocal() as db:
            await set_search_path(db)
            stmt = select(ClientRecord).where(ClientRecord.uid == cuid)
            client = (await db.execute(stmt)).scalar_one_or_none()

        if not client or (
            tid and client.account_id and client.account_id not in (tid, "default")
        ):
            return HandshakeScRsp_pb2.HandshakeScBeginHandShakeRsp(
                Retcode=Retcode_pb2.ClientNotFound
            )
        if getattr(client, "is_disabled", False):
            return HandshakeScRsp_pb2.HandshakeScBeginHandShakeRsp(
                Retcode=Retcode_pb2.InvalidRequest
            )
        if client.mac and client.mac != mac:
            return HandshakeScRsp_pb2.HandshakeScBeginHandShakeRsp(
                Retcode=Retcode_pb2.InvalidRequest
            )

        raw_cipher = request.ChallengeTokenEncrypted or ""
        if not raw_cipher or len(raw_cipher) > 16384:
            return HandshakeScRsp_pb2.HandshakeScBeginHandShakeRsp(
                Retcode=Retcode_pb2.ServerInternalError
            )

        decrypted = await asyncio.to_thread(self._sm.decrypt_challenge, raw_cipher)
        if (
            decrypted is None
            or not str(decrypted).strip()
            or len(str(decrypted)) > _MAX_CHALLENGE_TOKEN_LEN
            or any(ord(c) < 32 or ord(c) == 127 for c in str(decrypted))
        ):
            return HandshakeScRsp_pb2.HandshakeScBeginHandShakeRsp(
                Retcode=Retcode_pb2.ServerInternalError
            )

        effective_tid = tid or (
            client.account_id if client.account_id != "default" else ""
        )
        peer_ip = get_client_ip_from_grpc(context)
        record_bandwidth_bytes(effective_tid, 2400)
        await self._sm.store_pending_handshake(
            effective_tid, cuid, decrypted, peer_ip=peer_ip
        )
        return HandshakeScRsp_pb2.HandshakeScBeginHandShakeRsp(
            Retcode=Retcode_pb2.Success,
            ChallengeTokenDecrypted=decrypted,
            ServerPublicKey=self._sm.public_key_armor,
        )

    async def CompleteHandshake(self, request, context):
        tenant_id = _get_tenant_id_safe()
        cuid = _get_metadata_dict(context).get("cuid", "")
        peer_ip = get_client_ip_from_grpc(context)

        effective_tid = tenant_id
        async with AsyncSessionLocal() as db:
            await set_search_path(db)
            client = (
                await db.execute(select(ClientRecord).where(ClientRecord.uid == cuid))
            ).scalar_one_or_none()
            if client:
                if (
                    tenant_id
                    and client.account_id
                    and client.account_id not in (tenant_id, "default")
                ):
                    return HandshakeScRsp_pb2.HandshakeScCompleteHandshakeRsp(
                        Retcode=Retcode_pb2.InvalidRequest
                    )
                if getattr(client, "is_disabled", False):
                    return HandshakeScRsp_pb2.HandshakeScCompleteHandshakeRsp(
                        Retcode=Retcode_pb2.InvalidRequest
                    )
                if (
                    not effective_tid
                    and client.account_id
                    and client.account_id != "default"
                ):
                    effective_tid = client.account_id

            pending = await self._sm.pop_handshake_challenge(effective_tid, cuid)
            pending_ip = await self._sm.pop_handshake_ip(effective_tid, cuid)
            if not pending and effective_tid != tenant_id:
                pending = await self._sm.pop_handshake_challenge(tenant_id, cuid)
                pending_ip = await self._sm.pop_handshake_ip(tenant_id, cuid)

            if not request.Accepted:
                return HandshakeScRsp_pb2.HandshakeScCompleteHandshakeRsp(
                    Retcode=Retcode_pb2.HandshakeClientRejected
                )

            if not pending or (pending_ip and peer_ip and pending_ip != peer_ip):
                return HandshakeScRsp_pb2.HandshakeScCompleteHandshakeRsp(
                    Retcode=Retcode_pb2.InvalidRequest
                )

            if client:
                is_currently_online = await self._sm.is_client_online(
                    effective_tid, cuid
                )
                if peer_ip and (
                    not client.ip or client.ip == peer_ip or not is_currently_online
                ):
                    client.ip = peer_ip
                client.last_seen_at = datetime.now(timezone.utc)
                await db.commit()

        session_id = await self._sm.create_session(effective_tid, cuid)
        return HandshakeScRsp_pb2.HandshakeScCompleteHandshakeRsp(
            Retcode=Retcode_pb2.Success, SessionId=session_id
        )


# ---- 2. Client Register Servicer ----


class ClientRegisterServicer(ClientRegister_pb2_grpc.ClientRegisterServicer):
    """Client device registration and unregistration service."""

    def __init__(self, session_manager: SessionManager):
        self._sm = session_manager

    async def Register(self, request: Any, context):
        cuid = request.ClientUid
        tid = _get_tenant_id_safe()
        peer_ip = get_client_ip_from_grpc(context)
        now = datetime.now(timezone.utc)

        if len(_REGISTER_LOCKS) > _MAX_REGISTER_LOCKS:
            for k in [k for k, lk in _REGISTER_LOCKS.items() if not lk.locked()][:1024]:
                _REGISTER_LOCKS.pop(k, None)
        lock = _REGISTER_LOCKS.setdefault(tid or "default", asyncio.Lock())
        async with lock, AsyncSessionLocal() as db:
            await set_search_path(db)

            # Check if client already exists and is disabled or has mismatched hardware MAC
            existing_record = (
                await db.execute(select(ClientRecord).where(ClientRecord.uid == cuid))
            ).scalar_one_or_none()
            if existing_record and getattr(existing_record, "is_disabled", False):
                return ClientRegisterScRsp_pb2.ClientRegisterScRsp(
                    Retcode=Retcode_pb2.InvalidRequest,
                    Message="Device has been disabled by administrator.",
                )
            if (
                existing_record
                and existing_record.mac
                and existing_record.mac != request.ClientMac
            ):
                return ClientRegisterScRsp_pb2.ClientRegisterScRsp(
                    Retcode=Retcode_pb2.InvalidRequest,
                    Message="Hardware MAC address mismatch for registered ClientUid.",
                )

            # Check account registration mode & global pairing_enabled config
            reg_mode = "open"
            if tid:
                acct = (
                    await db.execute(select(Account).where(Account.id == tid))
                ).scalar_one_or_none()
                if acct and getattr(acct, "registration_mode", None):
                    reg_mode = acct.registration_mode

            stmt_cfg = select(SystemConfig).where(SystemConfig.key == _PAIRING_KEY)
            cfg = (await db.execute(stmt_cfg)).scalar_one_or_none()
            if cfg is not None and cfg.value == "true":
                reg_mode = "pairing"

            # Check pre-registration whitelist match (by class_identity or mac_address)
            matched_pre_reg = None
            if request.ClientId or request.ClientMac:
                conds = []
                if request.ClientId:
                    conds.append(PreRegisteredClient.class_identity == request.ClientId)
                if request.ClientMac:
                    conds.append(PreRegisteredClient.mac_address == request.ClientMac)
                pre_stmt = select(PreRegisteredClient).where(
                    PreRegisteredClient.is_enabled.is_(True),
                    PreRegisteredClient.account_id == (tid or "default"),
                    or_(*conds),
                )
                matched_pre_reg = (await db.execute(pre_stmt)).scalars().first()

            acct_id = tid or (
                matched_pre_reg.account_id if matched_pre_reg else "default"
            )
            if (
                existing_record is not None
                and existing_record.account_id
                and existing_record.account_id not in (acct_id, "default")
            ):
                return ClientRegisterScRsp_pb2.ClientRegisterScRsp(
                    Retcode=Retcode_pb2.InvalidRequest,
                    Message="ClientUid is already registered to another account.",
                )
            if existing_record is None and acct_id and acct_id != "default":
                if not await check_quota(acct_id, "max_clients", db):
                    return ClientRegisterScRsp_pb2.ClientRegisterScRsp(
                        Retcode=Retcode_pb2.InvalidRequest,
                        Message="Account registered device quota (max_clients) exceeded.",
                    )

            if existing_record is None and matched_pre_reg is None:
                if reg_mode == "pre_reg":
                    return ClientRegisterScRsp_pb2.ClientRegisterScRsp(
                        Retcode=Retcode_pb2.InvalidRequest,
                        Message="Only pre-registered devices are allowed to join this server. Please register ClassIdentity or MAC in Pre-Registration first.",
                    )
                if reg_mode == "pairing":
                    already_approved = await check_approved(cuid, tid)
                    if not already_approved:
                        code = await create_pairing_request(
                            tenant_id=tid,
                            client_uid=cuid,
                            client_id=request.ClientId,
                            client_mac=request.ClientMac,
                            client_ip=peer_ip,
                        )
                        logger.info(
                            "Pairing intercept triggered: uid=%s code=%s", cuid, code
                        )
                        return ClientRegisterScRsp_pb2.ClientRegisterScRsp(
                            Retcode=Retcode_pb2.PairingRequired,
                            Message=f"Device requires pairing code to join. Pairing Code: {code}. Please contact admin for approval.",
                        )

            # Write or update physical client record

            record = existing_record or ClientRecord(
                uid=cuid,
                account_id=acct_id,
                registered_at=now,
            )
            record.account_id = acct_id
            record.client_id = request.ClientId
            record.mac = request.ClientMac
            if peer_ip:
                record.ip = peer_ip
            record.last_seen_at = now

            if matched_pre_reg:
                if not record.display_name and matched_pre_reg.label:
                    record.display_name = matched_pre_reg.label
                matched_pre_reg.bound_client_uid = cuid
                if (
                    matched_pre_reg.preset_profile_json
                    and matched_pre_reg.preset_profile_json != "{}"
                ):
                    try:
                        preset = json.loads(matched_pre_reg.preset_profile_json)
                        if isinstance(preset, dict) and preset:
                            prof = (
                                await db.execute(
                                    select(ClientProfile).where(
                                        ClientProfile.account_id == acct_id,
                                        ClientProfile.client_id == cuid,
                                    )
                                )
                            ).scalar_one_or_none()
                            if not prof:
                                prof = ClientProfile(
                                    account_id=acct_id,
                                    client_id=cuid,
                                    updated_at=now,
                                )
                            for snake_k, pascal_k in (
                                ("class_plan", "ClassPlan"),
                                ("time_layout", "TimeLayout"),
                                ("subjects", "Subjects"),
                                ("default_settings", "DefaultSettings"),
                                ("policy", "Policy"),
                                ("components", "Components"),
                                ("credentials", "Credentials"),
                            ):
                                val = (
                                    preset.get(pascal_k)
                                    if pascal_k in preset
                                    else preset.get(snake_k)
                                )
                                if val is not None:
                                    setattr(prof, snake_k, str(val))
                            prof.updated_at = now
                            db.add(prof)
                    except Exception:
                        pass

            db.add(record)
            await db.commit()

        logger.info("Client device registered: uid=%s ip=%s", cuid, peer_ip)
        return ClientRegisterScRsp_pb2.ClientRegisterScRsp(
            Retcode=Retcode_pb2.Registered,
            ServerPublicKey=self._sm.public_key_armor,
        )

    async def UnRegister(self, request, context):
        md = _get_metadata_dict(context)
        sid = md.get("session", "")
        real_cuid = await self._sm.validate_session(sid) if sid else None
        if sid and not real_cuid:
            await context.abort(
                grpc.StatusCode.UNAUTHENTICATED,
                "Session authentication failed, unable to unregister",
            )
            return ClientRegisterScRsp_pb2.ClientRegisterScRsp()

        target_cuid = (
            request.ClientUid or md.get("cuid", "") or real_cuid or ""
        ).strip()
        if not target_cuid:
            await context.abort(
                grpc.StatusCode.INVALID_ARGUMENT,
                "ClientUid is required to unregister",
            )
            return ClientRegisterScRsp_pb2.ClientRegisterScRsp()

        tid = (
            await self._sm.get_session_tenant(sid) if sid else None
        ) or _get_tenant_id_safe()
        peer_ip = get_client_ip_from_grpc(context)
        req_mac = (request.ClientMac or md.get("x-client-mac", "")).strip()

        async with AsyncSessionLocal() as db:
            await set_search_path(db)
            rec = (
                await db.execute(
                    select(ClientRecord).where(ClientRecord.uid == target_cuid)
                )
            ).scalar_one_or_none()
            if rec:
                if tid and rec.account_id and rec.account_id not in (tid, "default"):
                    await context.abort(
                        grpc.StatusCode.PERMISSION_DENIED,
                        "Device does not belong to this tenant",
                    )
                    return ClientRegisterScRsp_pb2.ClientRegisterScRsp()

                authorized = bool(real_cuid and real_cuid == target_cuid)
                if (
                    not authorized
                    and rec.mac
                    and req_mac
                    and rec.mac.upper().replace(":", "-")
                    == req_mac.upper().replace(":", "-")
                ):
                    authorized = True
                if not authorized and rec.ip and peer_ip and rec.ip == peer_ip:
                    authorized = True
                if not authorized and peer_ip in ("127.0.0.1", "::1", "localhost"):
                    authorized = True

                if not authorized:
                    await context.abort(
                        grpc.StatusCode.UNAUTHENTICATED,
                        "Session authentication failed, unable to unregister",
                    )
                    return ClientRegisterScRsp_pb2.ClientRegisterScRsp()

                effective_tid = tid or rec.account_id or "default"
                pre_rows = (
                    (
                        await db.execute(
                            select(PreRegisteredClient).where(
                                PreRegisteredClient.account_id == effective_tid,
                                PreRegisteredClient.bound_client_uid == target_cuid,
                            )
                        )
                    )
                    .scalars()
                    .all()
                )
                for p in pre_rows:
                    p.bound_client_uid = ""
                await db.delete(rec)
                await db.commit()

        await self._sm.set_client_offline(tid, target_cuid)
        logger.info("Client device unregistered: uid=%s", target_cuid)
        return ClientRegisterScRsp_pb2.ClientRegisterScRsp(Retcode=Retcode_pb2.Success)


# ---- 3. Client Command Deliver Servicer ----


class ClientCommandDeliverServicer(
    ClientCommandDeliver_pb2_grpc.ClientCommandDeliverServicer
):
    """Long-polling command streaming and heartbeat channel service."""

    def __init__(self, session_manager: SessionManager):
        self._sm = session_manager
        self.client_queues: dict[str, asyncio.Queue] = {}
        self.tenant_clients: dict[str, set[str]] = {}

    async def ListenCommand(
        self, request_iterator, context
    ) -> AsyncGenerator[Any, None]:
        md = _get_metadata_dict(context)
        sid = md.get("session", "")

        real_cuid = await self._sm.validate_session(sid)
        if not real_cuid:
            await context.abort(
                grpc.StatusCode.UNAUTHENTICATED,
                "Session validation failed, listening rejected",
            )
            return

        tid = await self._sm.get_session_tenant(sid) or _get_tenant_id_safe()
        client_ip = get_client_ip_from_grpc(context)
        raw_ext = (
            (
                md.get("x-extend-management-enabled")
                or md.get("x-mci-extend-management")
                or ""
            )
            .strip()
            .lower()
        )
        ext_enabled = raw_ext in ("1", "true", "yes")
        ext_ver = (md.get("x-extend-management-version") or "").strip()

        # Allocate queue and migrate any pending commands from stale stream
        q_key = f"{tid}:{real_cuid}"
        queue: asyncio.Queue = asyncio.Queue(maxsize=_QUEUE_MAXSIZE)
        old_q = self.client_queues.get(q_key)
        self.client_queues[q_key] = queue
        if tid:
            self.tenant_clients.setdefault(tid, set()).add(real_cuid)
        await self._sm.set_client_online(
            tid,
            real_cuid,
            ip=client_ip,
            extend_enabled=ext_enabled,
            extend_version=ext_ver,
        )

        # Update DB record last_seen_at & ip and enforce max_grpc_connections quota in a single DB session
        try:
            async with AsyncSessionLocal() as db:
                rec = (
                    await db.execute(
                        select(ClientRecord).where(ClientRecord.uid == real_cuid)
                    )
                ).scalar_one_or_none()
                if rec:
                    if getattr(rec, "is_disabled", False):
                        self.client_queues.pop(q_key, None)
                        await context.abort(
                            grpc.StatusCode.PERMISSION_DENIED,
                            "Device is disabled by administrator",
                        )
                        return
                    if (
                        tid
                        and rec.account_id
                        and rec.account_id not in (tid, "default")
                    ):
                        self.client_queues.pop(q_key, None)
                        await context.abort(
                            grpc.StatusCode.PERMISSION_DENIED,
                            "Device does not belong to this tenant",
                        )
                        return
                    if not tid and rec.account_id and rec.account_id != "default":
                        self.client_queues.pop(q_key, None)
                        tid = rec.account_id
                        q_key = f"{tid}:{real_cuid}"
                        old_q = self.client_queues.get(q_key) or old_q
                        self.client_queues[q_key] = queue
                        self.tenant_clients.setdefault(tid, set()).add(real_cuid)
                    if client_ip:
                        rec.ip = client_ip
                    if ext_enabled:
                        rec.extend_management_enabled = True
                        if ext_ver:
                            rec.extend_management_version = ext_ver
                    rec.last_seen_at = datetime.now(timezone.utc)
                    await db.commit()

                if tid and tid != "default":
                    online_uids = set(self.tenant_clients.get(tid, ()))
                    if len(online_uids) <= 1:
                        online_items = await self._sm.get_all_clients_status(tid)
                        online_uids.update(item["uid"] for item in online_items)
                    other_active_count = len(online_uids - {real_cuid})
                    quota_ok = await check_quota(
                        tid,
                        "max_grpc_connections",
                        db,
                        live_current=other_active_count,
                    )
                    if not quota_ok:
                        self.client_queues.pop(q_key, None)
                        await context.abort(
                            grpc.StatusCode.RESOURCE_EXHAUSTED,
                            "Account gRPC connection quota (max_grpc_connections) exceeded",
                        )
                        return
        except Exception:
            pass

        if old_q is not None and old_q is not queue:
            while not old_q.empty():
                try:
                    pending_cmd = old_q.get_nowait()
                    old_q.task_done()
                    if (
                        pending_cmd is not None
                        and getattr(pending_cmd, "Type", None) != CommandTypes_pb2.Pong
                        and not queue.full()
                    ):
                        queue.put_nowait(pending_cmd)
                except Exception:
                    break
            try:
                old_q.put_nowait(None)
            except asyncio.QueueFull:
                pass

        logger.info(
            "[%s] Command streaming listener ready: tid=%s, cuid=%s",
            client_ip,
            tid,
            real_cuid,
        )

        last_ping = 0.0
        last_redis_hb = time.monotonic()

        async def read_task():
            nonlocal last_ping, last_redis_hb
            async for req in request_iterator:
                if req.Type == CommandTypes_pb2.Ping:
                    now = time.monotonic()
                    if now - last_ping < _MIN_PING_INTERVAL:
                        continue
                    last_ping = now
                    if now - last_redis_hb >= _REDIS_HB_SYNC_INTERVAL:
                        last_redis_hb = now
                        await self._sm.update_heartbeat(tid, real_cuid)
                    record_bandwidth_bytes(tid, 160)
                    pong = ClientCommandDeliverScRsp_pb2.ClientCommandDeliverScRsp(
                        RetCode=Retcode_pb2.Success, Type=CommandTypes_pb2.Pong
                    )
                    try:
                        queue.put_nowait(pong)
                    except asyncio.QueueFull:
                        pass
                else:
                    logger.info(
                        "Received client uplink command: type=%s (tid=%s)",
                        req.Type,
                        tid,
                    )

        task = asyncio.create_task(read_task())
        try:
            while True:
                msg = await asyncio.wait_for(queue.get(), timeout=_STREAM_IDLE_TIMEOUT)
                if msg is None:
                    queue.task_done()
                    break
                yield msg
                queue.task_done()
        except (asyncio.CancelledError, asyncio.TimeoutError):
            logger.warning(
                "Client device [%s] heartbeat idle timeout or connection interrupted",
                real_cuid,
            )
            task.cancel()
        finally:
            task.cancel()
            if self.client_queues.get(q_key) is queue:
                self.client_queues.pop(q_key, None)
                t_set = self.tenant_clients.get(tid)
                if t_set is not None:
                    t_set.discard(real_cuid)
                    if not t_set:
                        self.tenant_clients.pop(tid, None)
                await self._sm.set_client_offline(tid, real_cuid)

    async def send_command(self, tid: str, cuid: str, cmd) -> bool:
        """API push command to specific online client."""
        for key in (f"{tid}:{cuid}", f":{cuid}"):
            if key in self.client_queues:
                try:
                    self.client_queues[key].put_nowait(cmd)
                    return True
                except asyncio.QueueFull:
                    return False
        return False

    async def disconnect_client(self, tid: str, cuid: str) -> bool:
        """Forcefully close active gRPC command stream and mark client offline."""
        disconnected = False
        for key in (f"{tid}:{cuid}", f":{cuid}"):
            q = self.client_queues.get(key)
            if q is not None:
                try:
                    q.put_nowait(None)
                except asyncio.QueueFull:
                    try:
                        q.get_nowait()
                        q.task_done()
                        q.put_nowait(None)
                    except Exception:
                        pass
                disconnected = True
        await self._sm.set_client_offline(tid, cuid)
        return disconnected


# ---- 4. Config Upload Servicer ----


async def _sync_extend_response_to_client_record(
    db: Any,
    client_uid: str,
    payload_str: str,
    ext_enabled: bool = False,
    ext_ver: str = "",
) -> None:
    """Extract plugin hook catalogs, hardware info, and lock state from uploaded ExtendCommand payload."""
    if not client_uid:
        return
    rec = (
        await db.execute(select(ClientRecord).where(ClientRecord.uid == client_uid))
    ).scalar_one_or_none()
    if not rec:
        return
    if ext_enabled:
        rec.extend_management_enabled = True
        if ext_ver:
            rec.extend_management_version = ext_ver
    if not payload_str or not payload_str.strip().startswith("{"):
        return
    try:
        parsed = json.loads(payload_str)
    except Exception:
        return
    if not isinstance(parsed, dict):
        return

    action = str(parsed.get("action") or parsed.get("Action") or "").strip().lower()
    data = parsed.get("data") if "data" in parsed else parsed.get("Data")
    if not isinstance(data, dict):
        return

    if action:
        rec.extend_management_enabled = True
    if "version" in data and isinstance(data["version"], str) and data["version"]:
        rec.extend_management_version = data["version"].strip()
    if "isAppLocked" in data and isinstance(data["isAppLocked"], bool):
        rec.is_app_locked = data["isAppLocked"]

    if action in ("plugin.api_snapshot", "plugin.hook.snapshot"):
        if "settingsCatalog" in data and data["settingsCatalog"] is not None:
            rec.plugin_settings_json = json.dumps(
                data["settingsCatalog"], ensure_ascii=False
            )
        if "registeredComponents" in data and data["registeredComponents"] is not None:
            rec.plugin_components_json = json.dumps(
                data["registeredComponents"], ensure_ascii=False
            )
    elif action in (
        "plugin.get_settings",
        "plugin.settings.list",
        "plugin.settings.get",
    ):
        rec.plugin_settings_json = json.dumps(data, ensure_ascii=False)
    elif action in (
        "plugin.list_components",
        "plugin.components.list",
        "plugin.components.registry",
    ):
        rec.plugin_components_json = json.dumps(data, ensure_ascii=False)
    elif action.startswith("hardware."):
        rec.hardware_info_json = json.dumps(data, ensure_ascii=False)


class ConfigUploadServicer(ConfigUpload_pb2_grpc.ConfigUploadServicer):
    """Client configuration upload service."""

    def __init__(self, session_manager: SessionManager):
        self._sm = session_manager

    async def UploadConfig(self, request, context):
        md = _get_metadata_dict(context)
        sid = md.get("session", "")
        real_cuid = await self._sm.validate_session(sid) if sid else None
        tid = (
            await self._sm.get_session_tenant(sid) if sid else None
        ) or _get_tenant_id_safe()
        peer_ip = get_client_ip_from_grpc(context)
        raw_ext = (
            (
                md.get("x-extend-management-enabled")
                or md.get("x-mci-extend-management")
                or ""
            )
            .strip()
            .lower()
        )
        ext_enabled = raw_ext in ("1", "true", "yes")
        ext_ver = (md.get("x-extend-management-version") or "").strip()

        req_guid = getattr(request, "RequestGuidId", "")
        req_guid_str = req_guid if isinstance(req_guid, str) else ""
        payload_val = getattr(request, "Payload", "")
        payload_str = payload_val if isinstance(payload_val, str) else str(payload_val)
        if len(payload_str.encode("utf-8")) > _MAX_GRPC_PAYLOAD_BYTES:
            return ConfigUploadScRsp_pb2.ConfigUploadScRsp(
                Retcode=Retcode_pb2.InvalidRequest,
                Message="Payload size exceeds limit",
            )

        async with AsyncSessionLocal() as db:
            await set_search_path(db)
            existing = None
            if req_guid_str:
                existing = (
                    await db.execute(
                        select(ConfigUploadRecord).where(
                            ConfigUploadRecord.request_guid == req_guid_str
                        )
                    )
                ).scalar_one_or_none()

            if existing and getattr(existing, "status", "pending") == "pending":
                if (
                    tid
                    and existing.account_id
                    and existing.account_id not in (tid, "default")
                ):
                    return ConfigUploadScRsp_pb2.ConfigUploadScRsp(
                        Retcode=Retcode_pb2.InvalidRequest,
                        Message="Tenant mismatch for upload request",
                    )
                if existing.client_uid:
                    if real_cuid:
                        if existing.client_uid != real_cuid:
                            return ConfigUploadScRsp_pb2.ConfigUploadScRsp(
                                Retcode=Retcode_pb2.InvalidRequest,
                                Message="Client mismatch for upload request",
                            )
                    else:
                        client_rec = (
                            await db.execute(
                                select(ClientRecord).where(
                                    ClientRecord.uid == existing.client_uid
                                )
                            )
                        ).scalar_one_or_none()
                        if (
                            client_rec
                            and client_rec.ip
                            and peer_ip
                            and client_rec.ip != peer_ip
                        ):
                            return ConfigUploadScRsp_pb2.ConfigUploadScRsp(
                                Retcode=Retcode_pb2.InvalidRequest,
                                Message="Unauthorized client IP for upload request",
                            )
                existing.payload = payload_str
                existing.status = "completed"
                existing.uploaded_at = datetime.now(timezone.utc)
                if real_cuid:
                    existing.client_uid = real_cuid
                target_uid = real_cuid or existing.client_uid
                if target_uid:
                    await _sync_extend_response_to_client_record(
                        db, target_uid, payload_str, ext_enabled, ext_ver
                    )
                await db.commit()
                return ConfigUploadScRsp_pb2.ConfigUploadScRsp(
                    Retcode=Retcode_pb2.Success, Message="Upload successful"
                )

            if not real_cuid:
                return ConfigUploadScRsp_pb2.ConfigUploadScRsp(
                    Retcode=Retcode_pb2.InvalidRequest, Message="Session expired"
                )

            if existing is not None:
                existing.payload = payload_str
                existing.status = "completed"
                existing.uploaded_at = datetime.now(timezone.utc)
                existing.client_uid = real_cuid
            else:
                db.add(
                    ConfigUploadRecord(
                        request_guid=req_guid_str
                        or f"upload-{int(time.time() * 1000)}",
                        account_id=tid or "default",
                        client_uid=real_cuid,
                        status="completed",
                        payload=payload_str,
                        uploaded_at=datetime.now(timezone.utc),
                    )
                )
            await _sync_extend_response_to_client_record(
                db, real_cuid, payload_str, ext_enabled, ext_ver
            )
            await db.commit()

        return ConfigUploadScRsp_pb2.ConfigUploadScRsp(
            Retcode=Retcode_pb2.Success, Message="Upload successful"
        )


# ---- 5. Audit Log Servicer ----


class AuditServicer(Audit_pb2_grpc.AuditServicer):
    """Client device security audit service."""

    def __init__(self, session_manager: SessionManager):
        self._sm = session_manager

    async def LogEvent(self, request, context):
        md = _get_metadata_dict(context)
        sid = md.get("session", "")
        real_cuid = await self._sm.validate_session(sid) if sid else None
        tid = (
            await self._sm.get_session_tenant(sid) if sid else None
        ) or _get_tenant_id_safe()

        if not real_cuid:
            return AuditScRsp_pb2.AuditScRsp(Retcode=Retcode_pb2.InvalidRequest)

        raw_payload = getattr(request, "Payload", b"") or b""
        if isinstance(raw_payload, str):
            raw_payload = raw_payload.encode("utf-8")
        if len(raw_payload) > _MAX_GRPC_PAYLOAD_BYTES:
            return AuditScRsp_pb2.AuditScRsp(Retcode=Retcode_pb2.InvalidRequest)
        event_code = int(getattr(request, "Event", 0) or 0)
        decoded_str = decode_audit_payload_json(event_code, raw_payload)

        async with AsyncSessionLocal() as db:
            await set_search_path(db)
            rec = (
                await db.execute(
                    select(ClientRecord).where(ClientRecord.uid == real_cuid)
                )
            ).scalar_one_or_none()
            if rec:
                if getattr(rec, "is_disabled", False):
                    return AuditScRsp_pb2.AuditScRsp(Retcode=Retcode_pb2.InvalidRequest)
                if tid and rec.account_id and rec.account_id not in (tid, "default"):
                    return AuditScRsp_pb2.AuditScRsp(Retcode=Retcode_pb2.InvalidRequest)
                if not tid and rec.account_id:
                    tid = rec.account_id
            if tid and tid != "default":
                if not await check_quota(tid, "feature.audit", db):
                    return AuditScRsp_pb2.AuditScRsp(Retcode=Retcode_pb2.InvalidRequest)
            db.add(
                AuditLog(
                    account_id=tid or "default",
                    client_uid=real_cuid,
                    event=event_code,
                    payload=base64.b64encode(raw_payload).decode("ascii"),
                    decoded_json=decoded_str,
                    timestamp_utc=int(getattr(request, "TimestampUtc", 0) or 0),
                    received_at=datetime.now(timezone.utc),
                )
            )
            await db.commit()
        return AuditScRsp_pb2.AuditScRsp(Retcode=Retcode_pb2.Success)


# ---- gRPC Server Entrypoint ----


async def serve_grpc(interceptors=None):
    """Initialize GPG key, tenant interceptor, core Servicers and start listening."""
    mgr = SessionManager()

    final_interceptors = interceptors or [TenantInterceptor(mgr)]
    srv = grpc.aio.server(
        interceptors=final_interceptors,
        options=_GRPC_SERVER_OPTIONS,
    )

    # Attach all Servicers
    Handshake_pb2_grpc.add_HandshakeServicer_to_server(HandshakeServicer(mgr), srv)
    ClientRegister_pb2_grpc.add_ClientRegisterServicer_to_server(
        ClientRegisterServicer(mgr), srv
    )
    cmd_s = ClientCommandDeliverServicer(mgr)
    ClientCommandDeliver_pb2_grpc.add_ClientCommandDeliverServicer_to_server(cmd_s, srv)
    ConfigUpload_pb2_grpc.add_ConfigUploadServicer_to_server(
        ConfigUploadServicer(mgr), srv
    )
    Audit_pb2_grpc.add_AuditServicer_to_server(AuditServicer(mgr), srv)

    srv.add_insecure_port(f"{LISTEN_HOST}:{GRPC_PORT}")
    await srv.start()
    logger.info("gRPC server listening on %s:%s", LISTEN_HOST, GRPC_PORT)
    return srv, cmd_s, mgr
