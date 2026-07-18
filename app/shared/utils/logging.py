"""MINIClassIsland 统一日志与客户端 IP 提取系统。

接管 FastAPI / uvicorn / gRPC 日志流，提供统一格式化和反代场景下的客户端 IP 解析。
"""

from __future__ import annotations
import logging
import sys
import time
from datetime import datetime, timezone
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path
from typing import Callable, TYPE_CHECKING

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

if TYPE_CHECKING:
    import grpc

# ---- 日志配置常量 ----
_LOG_DIR = Path(".miniclassisland") / "logs"
_LOG_FORMAT = "%(asctime)s.%(msecs)03d | %(levelname)-5s | %(port_tag)s | %(name)-30s | %(message)s"
_LOG_DATE_FMT = "%Y-%m-%d %H:%M:%S"

PORT_TAG_CLIENT = "CLIENT"
PORT_TAG_MGMT = "MGMT"
PORT_TAG_ADMIN = "ADMIN"
PORT_TAG_GRPC = "GRPC"
PORT_TAG_SYSTEM = "SYSTEM"


# ---- 真实 IP 解析辅助函数 ----

def _parse_forwarded_for(value: str) -> str:
    """解析 X-Forwarded-For 获取首个客户端真实 IP。"""
    if not value:
        return ""
    return value.split(",")[0].strip()


def get_client_ip_from_request(request: Request) -> str:
    """提取 HTTP 请求中的客户端真实 IP。"""
    forwarded = request.headers.get("x-forwarded-for", "")
    ip = _parse_forwarded_for(forwarded)
    if ip:
        return ip

    real_ip = request.headers.get("x-real-ip", "")
    if real_ip:
        return real_ip.strip()

    return request.client.host if request.client else ""


def get_client_ip_from_grpc(context: grpc.aio.ServicerContext) -> str:
    """从 gRPC 调用上下文元数据中解析客户端真实 IP。"""
    metadata = dict(context.invocation_metadata())

    forwarded = metadata.get("x-forwarded-for", "")
    ip = _parse_forwarded_for(forwarded)
    if ip:
        return ip

    real_ip = metadata.get("x-real-ip", "")
    if real_ip:
        return real_ip.strip()

    peer = context.peer() or ""
    if peer and ":" in peer:
        parts = peer.split(":")
        if len(parts) >= 2:
            return parts[1]
    return ""


# ---- 日志格式化与过滤器 ----

class _PortTagFilter(logging.Filter):
    """注入 port_tag 属性的日志过滤器。"""

    def __init__(self, tag: str = PORT_TAG_SYSTEM):
        super().__init__()
        self.tag = tag

    def filter(self, record: logging.LogRecord) -> bool:
        if not hasattr(record, "port_tag"):
            record.port_tag = self.tag
        return True


class _ColorFormatter(logging.Formatter):
    """终端彩色日志格式化器。"""

    _COLORS = {
        PORT_TAG_CLIENT: "\033[36m",  # 青色
        PORT_TAG_MGMT: "\033[33m",    # 黄色
        PORT_TAG_ADMIN: "\033[35m",   # 品红色
        PORT_TAG_GRPC: "\033[32m",    # 绿色
        PORT_TAG_SYSTEM: "\033[37m",  # 白色
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

        original_tag = record.port_tag
        original_levelname = record.levelname

        padded_tag = f"{tag:<7}"
        record.port_tag = f"{tag_color}{padded_tag}{self._RESET}"
        record.levelname = f"{level_color}{record.levelname}{self._RESET}"

        result = super().format(record)

        record.port_tag = original_tag
        record.levelname = original_levelname
        return result


# ---- 日志系统启动与实例获取 ----

def setup_logging(*, level: int = logging.INFO) -> None:
    """全局初始化日志格式及文件滚动处理器。"""
    _LOG_DIR.mkdir(parents=True, exist_ok=True)

    root = logging.getLogger()
    root.setLevel(level)
    root.handlers.clear()

    # 终端输出 (彩色)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_fmt = _ColorFormatter(_LOG_FORMAT, datefmt=_LOG_DATE_FMT)
    console_handler.setFormatter(console_fmt)
    console_handler.addFilter(_PortTagFilter(PORT_TAG_SYSTEM))
    root.addHandler(console_handler)

    # 文件输出
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
    file_fmt = logging.Formatter(_LOG_FORMAT, datefmt=_LOG_DATE_FMT)
    file_handler.setFormatter(file_fmt)
    file_handler.addFilter(_PortTagFilter(PORT_TAG_SYSTEM))
    root.addHandler(file_handler)

    # 抑制及重定向 uvicorn
    for uv_name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        uv_logger = logging.getLogger(uv_name)
        uv_logger.handlers.clear()
        uv_logger.propagate = True

    # 降低第三方日志干扰
    for noisy in ("asyncio", "aiohttp", "sqlalchemy.engine", "grpc"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    root.info(
        "日志系统已初始化 — 级别: %s  输出: 终端 + %s",
        logging.getLevelName(level),
        log_file,
    )


def get_port_logger(tag: str) -> logging.Logger:
    """获取打有特定端口标签的 Logger。"""
    name = f"miniclassisland.{tag.lower()}"
    logger = logging.getLogger(name)
    if not any(isinstance(f, _PortTagFilter) for f in logger.filters):
        logger.addFilter(_PortTagFilter(tag))
    return logger


# ---- Starlette/FastAPI 日志中间件 ----

class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """统一的 HTTP 请求日志记录中间件。"""

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
                "[%s] ✗ %s %s  耗时 %.1fms  异常: %s",
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
            "[%s] %s %s %s  耗时 %.1fms",
            client_ip,
            status,
            method,
            path,
            elapsed,
        )

        return response
