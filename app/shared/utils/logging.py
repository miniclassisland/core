"""MINI ClassIsland unified logging and client IP extraction system.

Takes over FastAPI / uvicorn / gRPC log streams, providing unified formatting and reverse-proxy client IP parsing.
"""

from __future__ import annotations
import logging
import sys
import time
from datetime import datetime, timezone
from logging.handlers import TimedRotatingFileHandler
from typing import Any, Callable, TYPE_CHECKING

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.shared.utils.config import CONFIG_DIR

if TYPE_CHECKING:
    pass

# ---- Log Configuration Constants ----
_LOG_DIR = CONFIG_DIR / "logs"
_LOG_FORMAT = "%(asctime)s.%(msecs)03d | %(levelname)-5s | %(port_tag)s | %(name)-30s | %(message)s"
_LOG_DATE_FMT = "%Y-%m-%d %H:%M:%S"

# Keep the fixed-width level column compact: WARNING is displayed as WARN.
_LEVEL_DISPLAY_NAMES = {"WARNING": "WARN"}


def _display_level_name(levelname: str) -> str:
    """Return the compact display name for a logging level."""
    return _LEVEL_DISPLAY_NAMES.get(levelname, levelname)


PORT_TAG_CLIENT = "CLIENT"
PORT_TAG_MGMT = "MGMT"
PORT_TAG_ADMIN = "ADMIN"
PORT_TAG_GRPC = "GRPC"
PORT_TAG_SYSTEM = "SYSTEM"


# ---- Real IP Parsing Utilities ----


def _parse_forwarded_for(value: str) -> str:
    """Parse X-Forwarded-For header to retrieve first client real IP."""
    if not value:
        return ""
    return value.split(",")[0].strip()


_TRUSTED_PROXY_HOSTS = {"127.0.0.1", "::1", "localhost", "testclient"}


def get_client_ip_from_request(request: Request) -> str:
    """Extract real client IP from HTTP request (only trusting X-Real-IP / X-Forwarded-For from local reverse proxy)."""
    peer_host = (
        request.client.host
        if (request.client and isinstance(request.client.host, str))
        else ""
    )
    if peer_host in _TRUSTED_PROXY_HOSTS:
        real_ip = request.headers.get("x-real-ip", "")
        if real_ip:
            return real_ip.strip()

        forwarded = request.headers.get("x-forwarded-for", "")
        ip = _parse_forwarded_for(forwarded)
        if ip:
            return ip

    return peer_host


def get_client_ip_from_grpc(context: Any) -> str:
    """Parse real client IP from gRPC call invocation metadata."""
    peer = context.peer() or ""
    peer_ip = ""
    if peer and ":" in peer:
        parts = peer.split(":")
        if len(parts) >= 2:
            peer_ip = parts[1]

    if peer_ip in _TRUSTED_PROXY_HOSTS:
        raw_md = context.invocation_metadata() or ()
        metadata: dict[str, str] = {
            str(k): (
                v.decode("utf-8", errors="ignore") if isinstance(v, bytes) else str(v)
            )
            for k, v in raw_md
        }

        real_ip = metadata.get("x-real-ip", "")
        if real_ip:
            return real_ip.strip()

        forwarded = metadata.get("x-forwarded-for", "")
        ip = _parse_forwarded_for(forwarded)
        if ip:
            return ip

    return peer_ip


# ---- Log Formatter & Filters ----


class _PortTagFilter(logging.Filter):
    """Log filter to inject port_tag attribute."""

    def __init__(self, tag: str = PORT_TAG_SYSTEM):
        super().__init__()
        self.tag = tag

    def filter(self, record: logging.LogRecord) -> bool:
        if not hasattr(record, "port_tag"):
            record.port_tag = self.tag
        return True


class _ColorFormatter(logging.Formatter):
    """Terminal ANSI color formatter."""

    _COLORS = {
        PORT_TAG_CLIENT: "\033[36m",  # Cyan
        PORT_TAG_MGMT: "\033[33m",  # Yellow
        PORT_TAG_ADMIN: "\033[35m",  # Magenta
        PORT_TAG_GRPC: "\033[32m",  # Green
        PORT_TAG_SYSTEM: "\033[37m",  # White
    }
    _LEVEL_COLORS = {
        "DEBUG": "\033[90m",
        "INFO": "\033[97m",
        "WARNING": "\033[93m",
        "ERROR": "\033[91m",
        "CRITICAL": "\033[41m",
    }
    _RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        tag = getattr(record, "port_tag", PORT_TAG_SYSTEM)
        tag_color = self._COLORS.get(tag, self._RESET)
        level_color = self._LEVEL_COLORS.get(record.levelname, self._RESET)

        original_has_tag = hasattr(record, "port_tag")
        original_tag = getattr(record, "port_tag", None)
        original_levelname = record.levelname

        padded_tag = f"{tag:<7}"
        record.port_tag = f"{tag_color}{padded_tag}{self._RESET}"
        record.levelname = (
            f"{level_color}{_display_level_name(original_levelname)}{self._RESET}"
        )

        result = super().format(record)

        if original_has_tag:
            record.port_tag = original_tag
        else:
            delattr(record, "port_tag")
        record.levelname = original_levelname
        return result


class _ShortLevelFormatter(logging.Formatter):
    """Plain formatter that abbreviates long level names such as WARNING."""

    def format(self, record: logging.LogRecord) -> str:
        original_levelname = record.levelname
        record.levelname = _display_level_name(original_levelname)
        try:
            return super().format(record)
        finally:
            record.levelname = original_levelname


# ---- Logging Initialization ----


def setup_logging(*, level: int = logging.INFO) -> None:
    """Globally initialize logging format and file rotating handler."""
    _LOG_DIR.mkdir(parents=True, exist_ok=True)

    root = logging.getLogger()
    root.setLevel(level)
    root.handlers.clear()

    # Terminal output (Colorized)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_fmt = _ColorFormatter(_LOG_FORMAT, datefmt=_LOG_DATE_FMT)
    console_handler.setFormatter(console_fmt)
    console_handler.addFilter(_PortTagFilter(PORT_TAG_SYSTEM))
    root.addHandler(console_handler)

    # File output
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    log_file = _LOG_DIR / f"miniclassisland-{today}.log"
    file_handler = TimedRotatingFileHandler(
        filename=str(log_file),
        when="midnight",
        interval=1,
        backupCount=30,
        encoding="utf-8",
        utc=True,
    )
    file_handler.setLevel(level)
    file_fmt = _ShortLevelFormatter(_LOG_FORMAT, datefmt=_LOG_DATE_FMT)
    file_handler.setFormatter(file_fmt)
    file_handler.addFilter(_PortTagFilter(PORT_TAG_SYSTEM))
    root.addHandler(file_handler)

    # Suppress and redirect uvicorn loggers
    for uv_name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        uv_logger = logging.getLogger(uv_name)
        uv_logger.handlers.clear()
        uv_logger.propagate = True

    # Suppress noisy third-party loggers
    for noisy in ("asyncio", "aiohttp", "sqlalchemy.engine", "grpc"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    root.info(
        "Logging system initialized — Level: %s  Output: Console + %s",
        logging.getLevelName(level),
        log_file,
    )


def get_port_logger(tag: str) -> logging.Logger:
    """Get Logger with specific port tag filter."""
    name = f"miniclassisland.{tag.lower()}"
    logger = logging.getLogger(name)
    if not any(isinstance(f, _PortTagFilter) for f in logger.filters):
        logger.addFilter(_PortTagFilter(tag))
    return logger


# ---- Starlette/FastAPI Request Logging Middleware ----


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Unified HTTP request logging middleware."""

    def __init__(self, app, port_tag: str = PORT_TAG_SYSTEM):
        super().__init__(app)
        self.port_tag = port_tag
        self.logger = get_port_logger(port_tag)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        start = time.perf_counter()
        client_ip = get_client_ip_from_request(request)
        method = request.method
        path = request.url.path
        query = str(request.url.query) if request.url.query else ""

        self.logger.debug(
            "[%s] → %s %s%s",
            client_ip,
            method,
            path,
            f"?{query}" if query else "",
        )

        try:
            response = await call_next(request)
        except Exception as exc:
            elapsed = (time.perf_counter() - start) * 1000
            self.logger.error(
                "[%s] ✗ %s %s  elapsed %.1fms  exception: %s",
                client_ip,
                method,
                path,
                elapsed,
                exc,
            )
            raise

        elapsed = (time.perf_counter() - start) * 1000
        status = response.status_code

        if status >= 500:
            log_fn = self.logger.error
        elif status >= 400:
            log_fn = self.logger.warning
        else:
            log_fn = self.logger.info

        log_fn(
            "[%s] %s %s %s  elapsed %.1fms",
            client_ip,
            status,
            method,
            path,
            elapsed,
        )

        return response
