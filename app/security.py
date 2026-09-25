"""Password hashing and token generation (self-contained, stdlib only)."""
from __future__ import annotations

import hashlib
import hmac
import secrets

_PBKDF2_ITERATIONS = 120_000
_ALGO = "sha256"


def hash_password(password: str, *, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        _ALGO, password.encode("utf-8"), bytes.fromhex(salt), _PBKDF2_ITERATIONS
    )
    return f"pbkdf2_{_ALGO}${_PBKDF2_ITERATIONS}${salt}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, iterations, salt, expected = stored.split("$")
        algo = scheme.removeprefix("pbkdf2_")
        digest = hashlib.pbkdf2_hmac(
            algo, password.encode("utf-8"), bytes.fromhex(salt), int(iterations)
        )
        return hmac.compare_digest(digest.hex(), expected)
    except (ValueError, AttributeError):
        return False


def new_token(nbytes: int = 32) -> str:
    """URL-safe random token for session ids / CSRF tokens."""
    return secrets.token_urlsafe(nbytes)
