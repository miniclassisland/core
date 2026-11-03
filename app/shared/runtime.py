"""Shared in-process runtime hub for gRPC, SessionManager, and CommandDeliverServicer."""

from typing import Any, Optional
from fastapi import Request


class RuntimeHub:
    """Global singleton container shared across client_app, management_app, admin_app, and gRPC."""

    def __init__(self) -> None:
        self.grpc_server: Any = None
        self.command_servicer: Any = None
        self.session_manager: Any = None


runtime_hub = RuntimeHub()


def get_session_manager(request: Optional[Request] = None) -> Any:
    """Resolve active SessionManager from FastAPI app.state, runtime_hub, or lazy-instantiate."""
    if request is not None:
        sm = getattr(request.app.state, "session_manager", None)
        if sm is not None:
            return sm
    if runtime_hub.session_manager is not None:
        return runtime_hub.session_manager
    from app.grpc.session import SessionManager

    runtime_hub.session_manager = SessionManager()
    return runtime_hub.session_manager


def get_command_servicer(request: Optional[Request] = None) -> Any:
    """Resolve active ClientCommandDeliverServicer from FastAPI app.state or runtime_hub."""
    if request is not None:
        cs = getattr(request.app.state, "command_servicer", None)
        if cs is not None:
            return cs
    return runtime_hub.command_servicer
