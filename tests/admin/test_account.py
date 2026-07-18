"""test_account.py
"""

from app.admin import account


def test_import():
    """验证模块可正常导入。"""
    assert account is not None
