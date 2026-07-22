"""test_logging.py
"""

import pytest
import logging
from unittest.mock import MagicMock, AsyncMock
from fastapi import Request, Response
from app.shared.utils import logging as log_util


def test_configure_logging():
    """测试日志配置初始化。"""
    log_util.setup_logging()


def test_custom_formatter():
    """测试自定义的日志格式化器。"""
    formatter = log_util._ColorFormatter(log_util._LOG_FORMAT, datefmt=log_util._LOG_DATE_FMT)
    record = logging.LogRecord(
        name="test_log",
        level=logging.INFO,
        pathname="test.py",
        lineno=10,
        msg="Hello log",
        args=(),
        exc_info=None,
    )
    formatted = formatter.format(record)
    assert "Hello log" in formatted


def test_get_client_ip_from_request():
    """测试从 HTTP 请求中提取对端 IP（含反向代理头分支）。"""
    # 场景 1: 从 x-forwarded-for 头中解析第一个 IP
    req1 = MagicMock(spec=Request)
    req1.headers = {"x-forwarded-for": "1.2.3.4, 5.6.7.8"}
    assert log_util.get_client_ip_from_request(req1) == "1.2.3.4"

    # 场景 2: 从 x-real-ip 头中提取
    req2 = MagicMock(spec=Request)
    req2.headers = {"x-real-ip": "1.2.3.4"}
    assert log_util.get_client_ip_from_request(req2) == "1.2.3.4"

    # 场景 3: 直接从 request.client.host 读取
    req3 = MagicMock(spec=Request)
    req3.headers = {}
    req3.client = MagicMock()
    req3.client.host = "1.2.3.4"
    assert log_util.get_client_ip_from_request(req3) == "1.2.3.4"

    # 场景 4: 缺少所有信息时 fallback
    req4 = MagicMock(spec=Request)
    req4.headers = {}
    req4.client = None
    assert log_util.get_client_ip_from_request(req4) == ""


def test_get_client_ip_from_grpc():
    """测试从 gRPC 上下文中提取 peer IP。"""
    context = MagicMock()
    context.invocation_metadata.return_value = []
    context.peer.return_value = "ipv4:127.0.0.1:54321"
    assert log_util.get_client_ip_from_grpc(context) == "127.0.0.1"


@pytest.mark.asyncio
async def test_log_middleware():
    """测试 FastAPI 日志中间件逻辑。"""
    request = MagicMock(spec=Request)
    request.method = "GET"
    request.url = MagicMock()
    request.url.path = "/test-route"
    request.url.query = ""
    request.headers = {}
    request.client = None

    response = MagicMock(spec=Response)
    response.status_code = 200

    async def call_next(req):
        return response

    middleware = log_util.RequestLoggingMiddleware(app=None)
    res = await middleware.dispatch(request, call_next)
    assert res == response
