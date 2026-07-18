"""test_bulk.py
"""

from app.admin import bulk


def test_import():
    """验证模块正常导入。"""
    assert bulk is not None
