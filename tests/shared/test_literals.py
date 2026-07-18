"""test_literals.py
"""

from app.shared import literals


def test_literals():
    """验证安全配置常量具有正确的命名。"""
    assert hasattr(literals, "_literals__TOKEN_BYTES")
    assert hasattr(literals, "_literals__TOKEN_TTL")
    assert hasattr(literals, "_literals__GRACE_TTL")
