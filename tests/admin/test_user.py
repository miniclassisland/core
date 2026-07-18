"""test_user.py
"""

from app.admin import user


def test_import():
    """验证模块正常导入。"""
    assert user is not None
