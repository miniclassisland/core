"""test_literals.py
"""

from app.shared import literals


def test_literals_security_constants():
    """Verify security configuration constants exist."""
    assert hasattr(literals, "TOKEN_BYTES")
    assert hasattr(literals, "DEFAULT_TTL")
    assert hasattr(literals, "GRACE_TTL")
    assert hasattr(literals, "RECOVERY_KEY_PREFIX")
    assert hasattr(literals, "RECOVERY_CODE_COUNT")
    assert hasattr(literals, "RECOVERY_CODE_LENGTH")


def test_literals_sys_metadata():
    """Verify system metadata and default configurations exist."""
    assert literals.SYS_NAME == "MINI ClassIsland Core Management Backend System"
    assert literals.DEFAULT_BASE_DOMAIN == "localminiclassisland.miniopensource.com"
    assert literals.PUBLIC_SCHEMA == "public"
    assert literals.DEFAULT_CLIENT_PORT == 27041
    assert literals.DEFAULT_MGMT_PORT == 27042
    assert literals.DEFAULT_ADMIN_PORT == 27043
    assert literals.DEFAULT_GRPC_PORT == 27044


def test_literals_error_messages():
    """Verify standard API error message constants exist."""
    assert literals.MSG_USER_NOT_FOUND == "User not found"
    assert literals.MSG_ACCOUNT_NOT_FOUND == "Account not found"
    assert literals.MSG_INVALID_CREDENTIALS == "Invalid username or password"
    assert literals.MSG_UNAUTHORIZED_ACCESS == "Unauthorized access"
    assert literals.MSG_PERMISSION_DENIED == "Permission denied"
