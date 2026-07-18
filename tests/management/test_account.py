"""test_account.py
"""

from app.management import account


def test_import():
    """验证模块正常导入。"""
    assert account is not None
