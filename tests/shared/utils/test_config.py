"""test_config.py
"""

from app.shared.utils import config


def test_config_values():
    """验证全局配置正确从环境变量中解析。"""
    assert config.KEY_FILE == "/tmp/test_cims_server.key"
    assert "cims" in config.DATABASE_URL
    assert "redis" in config.REDIS_URL
    assert config.CIMS_BASE_DOMAIN == "localhost"
    assert config.GRPC_PORT > 0
    assert config.CLIENT_PORT > 0
    assert config.MANAGEMENT_PORT > 0
    assert config.ADMIN_PORT > 0
