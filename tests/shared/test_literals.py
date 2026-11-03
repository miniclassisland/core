"""test_literals.py"""

from unittest.mock import AsyncMock, MagicMock, patch
import pytest
from httpx import ASGITransport, AsyncClient

from app.shared import literals, lifespan, oobe, runtime
from app.shared.utils import audit
from app.Protobuf.AuditEvent import (
    AuthorizeEvent_pb2,
    AppSettingsUpdated_pb2,
    ClassChangeCompleted_pb2,
    ProfileItemUpdated_pb2,
    AppCrashed_pb2,
    PluginInstalled_pb2,
    PluginUninstalled_pb2,
)


def test_literals_security_constants():
    """Verify security configuration constants exist."""
    assert hasattr(literals, "TOKEN_BYTES")
    assert hasattr(literals, "DEFAULT_TTL")
    assert hasattr(literals, "GRACE_TTL")
    assert hasattr(literals, "RECOVERY_KEY_PREFIX")
    assert hasattr(literals, "RECOVERY_CODE_COUNT")
    assert hasattr(literals, "RECOVERY_CODE_LENGTH")


def test_literals_sys_metadata():
    """Verify system metadata and default configurations exist."""
    assert literals.SYS_NAME == "MINI ClassIsland Core Management Backend System"
    assert literals.DEFAULT_BASE_DOMAIN == "localminiclassisland.miniopensource.com"
    assert literals.PUBLIC_SCHEMA == "public"
    assert literals.DEFAULT_CLIENT_PORT == 27041
    assert literals.DEFAULT_MGMT_PORT == 27042
    assert literals.DEFAULT_ADMIN_PORT == 27043
    assert literals.DEFAULT_GRPC_PORT == 27044


def test_literals_error_messages():
    """Verify standard API error message constants exist."""
    assert literals.MSG_USER_NOT_FOUND == "User not found"
    assert literals.MSG_ACCOUNT_NOT_FOUND == "Account not found"
    assert literals.MSG_INVALID_CREDENTIALS == "Invalid username or password"
    assert literals.MSG_UNAUTHORIZED_ACCESS == "Unauthorized access"
    assert literals.MSG_PERMISSION_DENIED == "Permission denied"


def test_runtime_hub():
    """Test get_session_manager and get_command_servicer in app/shared/runtime.py."""
    runtime.runtime_hub.session_manager = None
    runtime.runtime_hub.command_servicer = None

    # Lazy instantiate SessionManager
    sm = runtime.get_session_manager(None)
    assert sm is not None
    assert runtime.get_session_manager(None) is sm

    # From request.app.state
    req = MagicMock()
    req.app.state.session_manager = "state_sm"
    req.app.state.command_servicer = "state_cs"
    assert runtime.get_session_manager(req) == "state_sm"
    assert runtime.get_command_servicer(req) == "state_cs"

    req.app.state.session_manager = None
    req.app.state.command_servicer = None
    runtime.runtime_hub.command_servicer = "hub_cs"
    assert runtime.get_session_manager(req) is sm
    assert runtime.get_command_servicer(req) == "hub_cs"
    runtime.runtime_hub.command_servicer = None


@pytest.mark.asyncio
async def test_app_lifespan():
    """Test app_lifespan startup and shutdown branches (both gRPC success and exception)."""
    from fastapi import FastAPI

    app = FastAPI()
    mock_grpc = MagicMock()
    mock_grpc.stop = AsyncMock()

    with (
        patch("app.shared.lifespan.validate_config"),
        patch("app.shared.lifespan.init_db", new_callable=AsyncMock),
        patch("app.shared.lifespan.init_redis", new_callable=AsyncMock),
        patch("app.shared.lifespan.close_redis", new_callable=AsyncMock),
        patch(
            "app.grpc.server.serve_grpc",
            new_callable=AsyncMock,
            return_value=(mock_grpc, "cmd", "sm"),
        ),
    ):
        async with lifespan.app_lifespan(app):
            assert app.state.grpc_server is mock_grpc
        mock_grpc.stop.assert_awaited_once()

    # Exception branch when serve_grpc fails
    app2 = FastAPI()
    with (
        patch("app.shared.lifespan.validate_config"),
        patch("app.shared.lifespan.init_db", new_callable=AsyncMock),
        patch("app.shared.lifespan.init_redis", new_callable=AsyncMock),
        patch("app.shared.lifespan.close_redis", new_callable=AsyncMock),
        patch(
            "app.grpc.server.serve_grpc",
            new_callable=AsyncMock,
            side_effect=RuntimeError("gRPC port busy"),
        ),
    ):
        async with lifespan.app_lifespan(app2):
            pass


@pytest.mark.asyncio
async def test_oobe_stub_and_admin_apps():
    """Test oobe_stub_app and oobe_admin_app catch-all 503 responses."""
    async with AsyncClient(
        transport=ASGITransport(app=oobe.oobe_stub_app), base_url="http://test"
    ) as client_stub:
        r1 = await client_stub.get("/any/random/path")
        assert r1.status_code == 503
        assert r1.json()["code"] == oobe.ERR_SYSTEM_OOBE

    async with AsyncClient(
        transport=ASGITransport(app=oobe.oobe_admin_app), base_url="http://test"
    ) as client_admin:
        r2 = await client_admin.get("/any/unmatched/path")
        assert r2.status_code == 503
        assert r2.json()["code"] == oobe.ERR_SYSTEM_OOBE


def test_decode_audit_payload():
    """Test decode_audit_payload and decode_audit_payload_json for all event types and error branch."""
    assert audit.decode_audit_payload(1, b"")["event"] == 1

    samples = [
        (1, AuthorizeEvent_pb2.AuthorizeEvent(Level=1).SerializeToString()),
        (4, AppSettingsUpdated_pb2.AppSettingsUpdated().SerializeToString()),
        (5, ClassChangeCompleted_pb2.ClassChangeCompleted().SerializeToString()),
        (6, ProfileItemUpdated_pb2.ProfileItemUpdated().SerializeToString()),
        (9, AppCrashed_pb2.AppCrashed().SerializeToString()),
        (12, PluginInstalled_pb2.PluginInstalled().SerializeToString()),
        (
            13,
            PluginUninstalled_pb2.PluginUninstalled().SerializeToString(),
        ),
    ]
    for ev, raw in samples:
        res = audit.decode_audit_payload(ev, raw or b"\x00")
        assert "event" in res
        json_str = audit.decode_audit_payload_json(ev, raw or b"\x00")
        assert '"event"' in json_str

    # Corrupted bytes branch
    with patch(
        "app.shared.utils.audit.MessageToDict",
        side_effect=ValueError("decode fail"),
    ):
        err_res = audit.decode_audit_payload(
            1, AuthorizeEvent_pb2.AuthorizeEvent(Level=1).SerializeToString()
        )
        assert "decode_error" in err_res
