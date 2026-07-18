"""test_get.py
"""

from app.client import get


def test_import():
    """验证模块正常导入。"""
    assert get is not None
