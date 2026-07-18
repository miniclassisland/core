"""test_settings.py
"""

from app.admin import settings


def test_import():
    """验证模块正常导入。"""
    assert settings is not None
