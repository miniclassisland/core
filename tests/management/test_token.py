"""test_token.py
"""

from app.management import token


def test_import():
    """验证模块正常导入。"""
    assert token is not None
