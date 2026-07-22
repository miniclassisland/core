"""test_literals.py
"""

from app.shared import literals


def test_literals():
    """Verify security configuration constants have correct names."""
    assert hasattr(literals, "TOKEN_BYTES")
    assert hasattr(literals, "DEFAULT_TTL")
    assert hasattr(literals, "GRACE_TTL")
