"""Password hashing, session token, and TOTP (RFC 6238) helpers.

Deliberately stdlib-only (no bcrypt/passlib/pyotp dependency) to keep
requirements.txt minimal, per the project's existing footprint.
"""
import base64
import hashlib
import hmac
import os
import secrets
import struct
import time

PBKDF2_ITERATIONS = 260_000
TOTP_INTERVAL_SECONDS = 30
TOTP_DIGITS = 6


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


def generate_totp_secret() -> str:
    """Base32-encoded random secret, compatible with Google Authenticator,
    Authy, 1Password, etc. - any standard RFC 6238 TOTP app."""
    return base64.b32encode(os.urandom(20)).decode("ascii").rstrip("=")


def _totp_at(secret: str, for_time: int, interval: int = TOTP_INTERVAL_SECONDS, digits: int = TOTP_DIGITS) -> str:
    padded = secret + "=" * (-len(secret) % 8)
    key = base64.b32decode(padded, casefold=True)
    counter = struct.pack(">Q", int(for_time / interval))
    digest = hmac.new(key, counter, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code_int).zfill(digits)


def verify_totp(secret: str, code: str, window: int = 1) -> bool:
    """Accepts a code from the current 30s window or one window before/after,
    to tolerate normal clock drift between the Pi and the phone."""
    if not code or not code.isdigit() or len(code) != TOTP_DIGITS:
        return False
    now_ts = int(time.time())
    for offset in range(-window, window + 1):
        candidate = _totp_at(secret, now_ts + offset * TOTP_INTERVAL_SECONDS)
        if hmac.compare_digest(candidate, code):
            return True
    return False


def totp_provisioning_uri(secret: str, username: str, issuer: str = "GODSEYE") -> str:
    return f"otpauth://totp/{issuer}:{username}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_INTERVAL_SECONDS}"
