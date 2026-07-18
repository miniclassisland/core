"""test_api.py
"""

from app.client import api


def test_import():
    """验证模块正常导入。"""
    assert api is not None
