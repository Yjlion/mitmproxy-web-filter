"""
Password authentication for the management interface.

Passwords are stored as a salted PBKDF2-SHA256 hash (never plaintext). The
session cookie holds a token derived from the password hash + a server secret,
so it survives restarts but is invalidated when the password changes. This is
lightweight gating for a single-admin tool — put the UI behind HTTPS/VPN if it
is exposed beyond a trusted network.
"""
from __future__ import annotations
import hashlib
import hmac
import secrets

COOKIE_NAME = "wf_session"
_ITERATIONS = 200_000


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _ITERATIONS)
    return f"pbkdf2_sha256${_ITERATIONS}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iters, salt_hex, hash_hex = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(iters))
        return hmac.compare_digest(dk.hex(), hash_hex)
    except (ValueError, AttributeError):
        return False


def new_secret() -> str:
    return secrets.token_hex(32)


def session_token(password_hash: str, secret_key: str) -> str:
    """Deterministic cookie value; changes when the password or secret changes."""
    return hmac.new(secret_key.encode(), password_hash.encode(), hashlib.sha256).hexdigest()


def token_valid(token: str | None, password_hash: str, secret_key: str) -> bool:
    if not token or not password_hash or not secret_key:
        return False
    return hmac.compare_digest(token, session_token(password_hash, secret_key))
