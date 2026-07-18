"""test_bulk.py
"""

from app.management import bulk


def test_import():
    """验证模块正常导入。"""
    assert bulk is not None
