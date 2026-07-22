"""gRPC server main entrypoint and Servicer integration.

Provides an all-in-one implementation for gRPC command streaming, registration streaming, audit streaming, handshake streaming, and tenant interceptor validation.
"""

import asyncio
import functools
import logging
import base64
import time
from datetime import datetime, timezone
import grpc
from sqlalchemy import select

# Database, sessions, and multi-tenancy
from app.shared.db.session import AsyncSessionLocal
from app.shared.db.models import (
    ClientRecord,
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
from app.shared.security.middlewares import get_cc_state
from app.shared.services.pairing import check_approved, create_pairing_request

# Protobuf package imports
from app.Protobuf.Service import (
    Handshake_pb2_grpc,
    ClientRegister_pb2_grpc,
    ClientCommandDeliver_pb2_grpc,
    ConfigUpload_pb2_grpc,
    Audit_pb2_grpc,
)
from app.Protobuf.Client import HandshakeScReq_pb2, ClientRegisterCsReq_pb2
from app.Protobuf.Server import (
    HandshakeScRsp_pb2,
    ClientRegisterScRsp_pb2,
    ClientCommandDeliverScRsp_pb2,
    ConfigUploadScRsp_pb2,
    AuditScRsp_pb2,
)
from app.Protobuf.Enum import Retcode_pb2, CommandTypes_pb2

from app.grpc.session import SessionManager
from app.shared.utils.config import GRPC_PORT

logger = logging.getLogger(__name__)

# gRPC auth exempt methods
_AUTH_EXEMPT = {"Register", "BeginHandshake", "CompleteHandshake"}
_QUEUE_MAXSIZE = 256
_MIN_PING_INTERVAL = 1.0
_STREAM_IDLE_TIMEOUT = 120
_PAIRING_KEY = "pairing_enabled"


# ---- Helper Functions ----

def _get_metadata_dict(context: grpc.aio.ServicerContext) -> dict:
    """Extract gRPC context metadata dictionary."""
    return dict(context.invocation_metadata())


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
        if get_cc_state() and short_name in _AUTH_EXEMPT:
            raise grpc.aio.AbortError(
                grpc.StatusCode.UNAVAILABLE, "Network congestion defense enabled; registration and handshake rejected"
            )

        metadata = dict(handler_call_details.invocation_metadata)
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
            async with AsyncSessionLocal() as db:
                account = await resolve_account(slug, db)
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

        # Wrap context vars for coroutines
        def wrapper(behavior):
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

        if handler.unary_unary:
            return grpc.unary_unary_rpc_method_handler(
                wrapper(handler.unary_unary),
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )
        if handler.unary_stream:
            return grpc.unary_stream_rpc_method_handler(
                wrapper(handler.unary_stream),
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )
        if handler.stream_unary:
            return grpc.stream_unary_rpc_method_handler(
                wrapper(handler.stream_unary),
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )
        if handler.stream_stream:
            return grpc.stream_stream_rpc_method_handler(
                wrapper(handler.stream_stream),
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )
        return handler


# ---- 1. Handshake Servicer ----

class HandshakeServicer(Handshake_pb2_grpc.HandshakeServicer):
    """RSA challenge-response security handshake service."""

    def __init__(self, session_manager: SessionManager):
        self._sm = session_manager

    async def BeginHandshake(self, request: HandshakeScReq_pb2, context):
        tid = _get_tenant_id_safe()
        cuid, mac = request.ClientUid, request.ClientMac

        async with AsyncSessionLocal() as db:
            await set_search_path(db)
            stmt = select(ClientRecord).where(ClientRecord.uid == cuid)
            client = (await db.execute(stmt)).scalar_one_or_none()

        if not client:
            return HandshakeScRsp_pb2.HandshakeScBeginHandShakeRsp(
                Retcode=Retcode_pb2.ClientNotFound
            )
        if client.mac and client.mac != mac:
            return HandshakeScRsp_pb2.HandshakeScBeginHandShakeRsp(
                Retcode=Retcode_pb2.InvalidRequest
            )

        decrypted = self._sm.decrypt_challenge(request.ChallengeTokenEncrypted)
        if decrypted is None:
            return HandshakeScRsp_pb2.HandshakeScBeginHandShakeRsp(
                Retcode=Retcode_pb2.ServerInternalError
            )

        await self._sm.store_pending_handshake(tid, cuid, decrypted)
        return HandshakeScRsp_pb2.HandshakeScBeginHandShakeRsp(
            Retcode=Retcode_pb2.Success,
            ChallengeTokenDecrypted=decrypted,
            ServerPublicKey=self._sm.public_key_armor,
        )

    async def CompleteHandshake(self, request, context):
        tenant_id = _get_tenant_id_safe()
        cuid = _get_metadata_dict(context).get("cuid", "")

        pending = await self._sm.pop_handshake_challenge(tenant_id, cuid)

        if not request.Accepted:
            return HandshakeScRsp_pb2.HandshakeScCompleteHandshakeRsp(
                Retcode=Retcode_pb2.HandshakeClientRejected
            )

        if not pending:
            return HandshakeScRsp_pb2.HandshakeScCompleteHandshakeRsp(
                Retcode=Retcode_pb2.InvalidRequest
            )

        session_id = await self._sm.create_session(tenant_id, cuid)
        return HandshakeScRsp_pb2.HandshakeScCompleteHandshakeRsp(
            Retcode=Retcode_pb2.Success, SessionId=session_id
        )


# ---- 2. Client Register Servicer ----

class ClientRegisterServicer(ClientRegister_pb2_grpc.ClientRegisterServicer):
    """Client device registration and unregistration service."""

    def __init__(self, session_manager: SessionManager):
        self._sm = session_manager

    async def Register(self, request: ClientRegisterCsReq_pb2, context):
        cuid = request.ClientUid
        tid = _get_tenant_id_safe()
        peer_ip = get_client_ip_from_grpc(context)

        async with AsyncSessionLocal() as db:
            await set_search_path(db)

            # Pairing mechanism check
            stmt_cfg = select(SystemConfig).where(SystemConfig.key == _PAIRING_KEY)
            cfg = (await db.execute(stmt_cfg)).scalar_one_or_none()
            pairing_enabled = cfg is not None and cfg.value == "true"

            if pairing_enabled:
                already_approved = await check_approved(cuid, tid)
                if not already_approved:
                    code = await create_pairing_request(
                        tenant_id=tid,
                        client_uid=cuid,
                        client_id=request.ClientId,
                        client_mac=request.ClientMac,
                        client_ip=peer_ip,
                    )
                    logger.info("Pairing intercept triggered: uid=%s code=%s", cuid, code)
                    return ClientRegisterScRsp_pb2.ClientRegisterScRsp(
                        Retcode=Retcode_pb2.PairingRequired,
                        Message=f"Device requires pairing code to join. Pairing Code: {code}. Please contact admin for approval."
                    )

            # Write or update physical client record
            stmt = select(ClientRecord).where(ClientRecord.uid == cuid)
            record = (await db.execute(stmt)).scalar_one_or_none() or ClientRecord(
                uid=cuid, registered_at=datetime.now(timezone.utc)
            )
            record.client_id = request.ClientId
            record.mac = request.ClientMac
            db.add(record)
            await db.commit()

        logger.info("Client device registered: uid=%s ip=%s", cuid, peer_ip)
        return ClientRegisterScRsp_pb2.ClientRegisterScRsp(
            Retcode=Retcode_pb2.Registered,
            ServerPublicKey=self._sm.public_key_armor,
        )

    async def UnRegister(self, request, context):
        sid = _get_metadata_dict(context).get("session", "")
        real_cuid = await self._sm.validate_session(sid)

        if not real_cuid or real_cuid != request.ClientUid:
            await context.abort(grpc.StatusCode.UNAUTHENTICATED, "Session authentication failed, unable to unregister")
            return ClientRegisterScRsp_pb2.ClientRegisterScRsp()

        tid = await self._sm.get_session_tenant(sid) or _get_tenant_id_safe()

        async with AsyncSessionLocal() as db:
            await set_search_path(db)
            rec = await db.get(ClientRecord, real_cuid)
            if rec:
                await db.delete(rec)
                await db.commit()

        await self._sm.set_client_offline(tid, real_cuid)
        logger.info("Client device unregistered: uid=%s", real_cuid)
        return ClientRegisterScRsp_pb2.ClientRegisterScRsp(Retcode=Retcode_pb2.Success)


# ---- 3. Client Command Deliver Servicer ----

class ClientCommandDeliverServicer(
    ClientCommandDeliver_pb2_grpc.ClientCommandDeliverServicer
):
    """Long-polling command streaming and heartbeat channel service."""

    def __init__(self, session_manager: SessionManager):
        self._sm = session_manager
        self.client_queues: dict[str, asyncio.Queue] = {}

    async def ListenCommand(self, request_iterator, context):
        md = _get_metadata_dict(context)
        sid = md.get("session", "")

        real_cuid = await self._sm.validate_session(sid)
        if not real_cuid:
            await context.abort(grpc.StatusCode.UNAUTHENTICATED, "Session validation failed, listening rejected")
            return

        tid = await self._sm.get_session_tenant(sid) or _get_tenant_id_safe()
        client_ip = get_client_ip_from_grpc(context)

        # Set device online and allocate queue
        await self._sm.set_client_online(tid, real_cuid, ip=client_ip)
        q_key = f"{tid}:{real_cuid}"
        queue = asyncio.Queue(maxsize=_QUEUE_MAXSIZE)
        self.client_queues[q_key] = queue

        logger.info("[%s] Command streaming listener ready: tid=%s, cuid=%s", client_ip, tid, real_cuid)

        last_ping = 0.0

        async def read_task():
            nonlocal last_ping
            async for req in request_iterator:
                if req.Type == CommandTypes_pb2.Ping:
                    now = time.monotonic()
                    if now - last_ping < _MIN_PING_INTERVAL:
                        continue
                    last_ping = now
                    await self._sm.update_heartbeat(tid, real_cuid)
                    pong = ClientCommandDeliverScRsp_pb2.ClientCommandDeliverScRsp(
                        RetCode=Retcode_pb2.Success, Type=CommandTypes_pb2.Pong
                    )
                    await queue.put(pong)
                else:
                    logger.info("Received client uplink command: type=%s (tid=%s)", req.Type, tid)

        task = asyncio.create_task(read_task())
        try:
            while True:
                msg = await asyncio.wait_for(queue.get(), timeout=_STREAM_IDLE_TIMEOUT)
                yield msg
                queue.task_done()
        except (asyncio.CancelledError, asyncio.TimeoutError):
            logger.warning("Client device [%s] heartbeat idle timeout or connection interrupted", real_cuid)
            task.cancel()
        finally:
            self.client_queues.pop(q_key, None)
            await self._sm.set_client_offline(tid, real_cuid)

    async def send_command(self, tid: str, cuid: str, cmd):
        """API push command to specific online client."""
        key = f"{tid}:{cuid}"
        if key in self.client_queues:
            await self.client_queues[key].put(cmd)


# ---- 4. Config Upload Servicer ----

class ConfigUploadServicer(ConfigUpload_pb2_grpc.ConfigUploadServicer):
    """Client configuration upload service."""

    def __init__(self, session_manager: SessionManager):
        self._sm = session_manager

    async def UploadConfig(self, request, context):
        sid = _get_metadata_dict(context).get("session", "")
        real_cuid = await self._sm.validate_session(sid)
        if not real_cuid:
            return ConfigUploadScRsp_pb2.ConfigUploadScRsp(
                Retcode=Retcode_pb2.InvalidRequest, Message="Session expired"
            )

        async with AsyncSessionLocal() as db:
            await set_search_path(db)
            db.add(
                ConfigUploadRecord(
                    request_guid=request.RequestGuidId,
                    client_uid=real_cuid,
                    payload=request.Payload,
                    uploaded_at=datetime.now(timezone.utc),
                )
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
        sid = _get_metadata_dict(context).get("session", "")
        real_cuid = await self._sm.validate_session(sid)
        if not real_cuid:
            return AuditScRsp_pb2.AuditScRsp(Retcode=Retcode_pb2.InvalidRequest)

        async with AsyncSessionLocal() as db:
            await set_search_path(db)
            db.add(
                AuditLog(
                    client_uid=real_cuid,
                    event=int(request.Event),
                    payload=base64.b64encode(request.Payload).decode("ascii"),
                    timestamp_utc=request.TimestampUtc,
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
    srv = grpc.aio.server(interceptors=final_interceptors)

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

    srv.add_insecure_port(f"[::]:{GRPC_PORT}")
    await srv.start()
    logger.info("gRPC server listening on port :%s", GRPC_PORT)
    return srv, cmd_s, mgr
