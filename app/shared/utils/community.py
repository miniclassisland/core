"""In-memory QQ community join code management.

The code is intentionally ephemeral: it is regenerated on every process start
and can be rotated manually by a super administrator. It is never persisted.
"""

import secrets
import string
import threading

CODE_LENGTH = 24
CODE_SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/|~"
CODE_CHARSET = string.ascii_letters + string.digits + CODE_SYMBOLS + " "

_lock = threading.Lock()
_code = ""


def _generate_code() -> str:
    """Generate a 24-character code with letters, digits, symbols and a space."""
    required = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
        secrets.choice(CODE_SYMBOLS),
        " ",
    ]
    chars = required + [
        secrets.choice(CODE_CHARSET) for _ in range(CODE_LENGTH - len(required))
    ]
    secrets.SystemRandom().shuffle(chars)

    # Keep spaces away from the edges so the code is easy to copy into QQ.
    while chars[0] == " " or chars[-1] == " ":
        edge = 0 if chars[0] == " " else len(chars) - 1
        interior = [i for i in range(1, len(chars) - 1) if chars[i] != " "]
        if not interior:
            break
        swap = secrets.choice(interior)
        chars[edge], chars[swap] = chars[swap], chars[edge]

    return "".join(chars)


_code = _generate_code()


def get_community_code() -> str:
    """Return the current in-memory community join code."""
    return _code


def refresh_community_code() -> str:
    """Regenerate the in-memory community join code and return it."""
    global _code
    with _lock:
        _code = _generate_code()
        return _code
