"""Password hashing and session token helpers.

Deliberately stdlib-only (no bcrypt/passlib dependency) to keep
requirements.txt minimal, per the project's existing footprint.
"""
import hashlib
import hmac
import os
import secrets

PBKDF2_ITERATIONS = 260_000


def hash_password(password: str, salt: bytes | None = None) -> tuple[str, str]:
    """Returns (salt_hex, hash_hex)."""
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return salt.hex(), digest.hex()


def verify_password(password: str, salt_hex: str, hash_hex: str) -> bool:
    _, candidate = hash_password(password, bytes.fromhex(salt_hex))
    return hmac.compare_digest(candidate, hash_hex)


def new_token() -> str:
    return secrets.token_urlsafe(32)
