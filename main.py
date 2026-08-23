import csv
import datetime as dt
import hmac
import io
import ipaddress
import json
import math
import os
import re
import secrets
import socket
import sqlite3
import subprocess
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel, field_validator

from .auth import generate_totp_secret, hash_password, new_token, totp_provisioning_uri, verify_password, verify_totp

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = Path(os.environ.get("GODSEYE_DB", BASE_DIR / "data" / "godseye.db"))

# A scanner that hasn't reported a successful run in this many seconds is
# treated as unhealthy even if the systemd unit still shows "active" -
# otherwise GODSEYE can look fine on the dashboard while silently doing
# nothing (see /api/v1/health).
HEARTBEAT_STALE_AFTER = int(os.environ.get("GODSEYE_HEARTBEAT_STALE_AFTER", "180"))

# Prometheus metrics endpoint is opt-in, not on-by-default: unlike the
# dashboard, a metrics scraper can't do a cookie-based login, so this needs
# its own auth story. Leaving GODSEYE_METRICS_TOKEN unset disables the
# endpoint entirely (404) rather than exposing device inventory data on the
# LAN without any credential - matches this project's default-secure posture
# elsewhere (e.g. install.sh generating a real admin password instead of a
# known default). Set it and configure the same value as a bearer_token in
# your Prometheus scrape config to enable.
METRICS_TOKEN = os.environ.get("GODSEYE_METRICS_TOKEN", "")

VALID_CLASSIFICATIONS = {"new", "known", "ignored", "investigate"}
VALID_ROLES = {"admin", "readonly"}
VALID_RULE_TYPES = {"new_device_burst", "offline_duration"}
VALID_SEVERITIES = {"info", "warning", "critical"}

SESSION_COOKIE = "godseye_session"
CSRF_COOKIE = "godseye_csrf"
SESSION_TTL_SECONDS = int(os.environ.get("GODSEYE_SESSION_TTL", str(60 * 60 * 24 * 7)))  # 7 days absolute cap
IDLE_TIMEOUT_SECONDS = int(os.environ.get("GODSEYE_IDLE_TIMEOUT", "900"))  # 15 min inactivity
COOKIE_SECURE = os.environ.get("GODSEYE_COOKIE_SECURE", "false").lower() == "true"

# Account lockout (NIST 800-63B / DISA STIG AC-7 style: lock the account after
# repeated failures rather than let a client hammer the login endpoint).
MAX_FAILED_ATTEMPTS = int(os.environ.get("GODSEYE_MAX_FAILED_ATTEMPTS", "5"))
LOCKOUT_SECONDS = int(os.environ.get("GODSEYE_LOCKOUT_SECONDS", "900"))  # 15 min

MIN_PASSWORD_LENGTH = int(os.environ.get("GODSEYE_MIN_PASSWORD_LENGTH", "12"))
MAX_PASSWORD_LENGTH = 128  # sane upper bound; not a NIST requirement, just avoids hashing-cost abuse
WEAK_PASSWORDS = {
    "godseye", "password", "password123", "admin", "administrator", "changeme",
    "letmein", "welcome", "qwerty123456", "123456789012", "raspberry", "raspberrypi",
}

# Mandatory periodic password rotation. NIST SP 800-63B section 5.1.1.2
# recommends AGAINST forcing periodic rotation of user-chosen passwords -
# it tends to produce weaker, more predictable passwords ("Summer2024!" ->
# "Summer2025!") without a clear security benefit, and instead recommends
# rotation only on evidence of compromise. Default here is therefore 0
# (disabled). Set to 30 / 90 / 180 if your organization's policy requires
# it regardless (common in older compliance baselines still used in some
# legal and healthcare contexts).
PASSWORD_MAX_AGE_DAYS = int(os.environ.get("GODSEYE_PASSWORD_MAX_AGE_DAYS", "0"))

# When an admin sets someone's password for them (initial seed, a new user
# created by an admin, or an admin-issued reset), the account isn't locked
# out of everything until they change it - they get a grace period during
# which the app works normally with just a reminder banner, and the change
# is only truly enforced once the deadline passes. 0 means enforce
# immediately with no grace period (the old, stricter behavior).
PASSWORD_CHANGE_GRACE_DAYS = int(os.environ.get("GODSEYE_PASSWORD_CHANGE_GRACE_DAYS", "2"))
PASSWORD_HISTORY_COUNT = int(os.environ.get("GODSEYE_PASSWORD_HISTORY_COUNT", "5"))

MFA_PENDING_TTL_SECONDS = int(os.environ.get("GODSEYE_MFA_PENDING_TTL", "300"))  # 5 min to enter a code after password
MFA_BACKUP_CODE_COUNT = 10

# Optional consent/warning banner shown above the login form. Off by default -
# set this to your organization's actual approved banner text if one is required;
# GODSEYE does not ship banner text of its own since that's an organizational
# policy decision, not something a project can supply on your behalf.
LOGIN_BANNER = os.environ.get("GODSEYE_LOGIN_BANNER", "")

# Only used to seed the very first admin account on a fresh install. Change
# these via env vars before first boot if you don't want the well-known
# default - either way, first login forces a password change (see login()).
ADMIN_DEFAULT_USER = os.environ.get("GODSEYE_ADMIN_USER", "GodsEye")
ADMIN_DEFAULT_PASSWORD = os.environ.get("GODSEYE_ADMIN_PASSWORD", "GodsEye")


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


# Hostnames/IPs only: first character alphanumeric (blocks a leading '-',
# which could otherwise be interpreted as a flag by ping/etc even though
# subprocess calls here use an argument list, never a shell string), then
# alnum/dot/colon (IPv6)/hyphen/underscore. This is defense in depth on
# top of never using shell=True, not a substitute for it.
_TOOL_TARGET_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.:_-]{0,253}$")


def validate_tool_target(raw: str) -> str:
    target = (raw or "").strip()
    if not target or not _TOOL_TARGET_RE.match(target):
        raise HTTPException(400, "Invalid target - use a plain hostname or IP address")
    return target


def audit(c, actor, action, target=None, details="", ip=None):
    c.execute(
        "INSERT INTO audit_log(actor,action,target,details,ip,created_at) VALUES(?,?,?,?,?,?)",
        (actor, action, target, details, ip, now()),
    )


def check_password_strength(password: str, username: str | None = None):
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters")
    if len(password) > MAX_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at most {MAX_PASSWORD_LENGTH} characters")
    if password.lower() in WEAK_PASSWORDS:
        raise ValueError("This password is too common - choose something less guessable")
    if username and password.lower() == username.lower():
        raise ValueError("Password cannot be the same as the username")


def is_password_expired(password_changed_at: str | None) -> bool:
    if PASSWORD_MAX_AGE_DAYS <= 0 or not password_changed_at:
        return False
    age_days = (dt.datetime.now(dt.timezone.utc) - dt.datetime.fromisoformat(password_changed_at)).total_seconds() / 86400
    return age_days >= PASSWORD_MAX_AGE_DAYS


def must_change_deadline() -> str | None:
    """Returns the ISO timestamp an admin-set password must be changed by,
    or None if grace periods are disabled (enforce immediately)."""
    if PASSWORD_CHANGE_GRACE_DAYS <= 0:
        return None
    return (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=PASSWORD_CHANGE_GRACE_DAYS)).isoformat()


def must_change_now(must_change_flag, must_change_by: str | None) -> bool:
    """Whether an admin-set password change is actually enforced yet.
    A flag with no deadline (grace disabled, or a legacy row from before
    grace periods existed) enforces immediately. A flag with a future
    deadline doesn't block access until that deadline passes."""
    if not must_change_flag:
        return False
    if not must_change_by:
        return True
    return dt.datetime.now(dt.timezone.utc) >= dt.datetime.fromisoformat(must_change_by)


def days_until(deadline: str | None) -> int | None:
    if not deadline:
        return None
    remaining = dt.datetime.fromisoformat(deadline) - dt.datetime.now(dt.timezone.utc)
    return max(0, math.ceil(remaining.total_seconds() / 86400))


def check_password_reuse(c, user_id: int, new_password: str, current_salt: str, current_hash: str):
    """Rejects a new password that matches the current one or any of the last
    PASSWORD_HISTORY_COUNT passwords for this account."""
    if verify_password(new_password, current_salt, current_hash):
        raise HTTPException(400, "New password must be different from your current password")
    if PASSWORD_HISTORY_COUNT <= 0:
        return
    history = c.execute(
        "SELECT password_salt, password_hash FROM password_history WHERE user_id=? ORDER BY changed_at DESC LIMIT ?",
        (user_id, PASSWORD_HISTORY_COUNT),
    ).fetchall()
    for h in history:
        if verify_password(new_password, h["password_salt"], h["password_hash"]):
            raise HTTPException(
                400, f"That password was used recently - choose one you haven't used in your last {PASSWORD_HISTORY_COUNT} changes"
            )


def record_password_history(c, user_id: int, old_salt: str, old_hash: str):
    c.execute(
        "INSERT INTO password_history(user_id,password_hash,password_salt,changed_at) VALUES(?,?,?,?)",
        (user_id, old_hash, old_salt, now()),
    )
    if PASSWORD_HISTORY_COUNT > 0:
        c.execute(
            "DELETE FROM password_history WHERE user_id=? AND id NOT IN "
            "(SELECT id FROM password_history WHERE user_id=? ORDER BY changed_at DESC LIMIT ?)",
            (user_id, user_id, PASSWORD_HISTORY_COUNT),
        )


def db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(DB_PATH, timeout=10)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA busy_timeout=10000")
    return c


def _add_column_if_missing(c, table, column, ddl):
    cols = {row["name"] for row in c.execute(f"PRAGMA table_info({table})")}
    if column not in cols:
        c.execute(f"ALTER TABLE {table} ADD COLUMN {ddl}")


def init_db():
    # Mirrors app/scanner.py's init_db(). Both services run this on startup
    # so either one can bootstrap a fresh database; see README's privilege
    # separation note for why the schema isn't owned by a single service.
    with db() as c:
        c.executescript("""
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY,
            mac TEXT NOT NULL UNIQUE,
            ip TEXT,
            hostname TEXT,
            vendor TEXT,
            name TEXT,
            device_type TEXT,
            status TEXT NOT NULL DEFAULT 'unknown',
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            trusted INTEGER NOT NULL DEFAULT 0,
            notes TEXT DEFAULT '',
            offline_escalated_at TEXT
        );
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY,
            mac TEXT,
            event_type TEXT NOT NULL,
            ip TEXT,
            created_at TEXT NOT NULL,
            details TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS scanner_heartbeat (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            last_run_at TEXT,
            last_success_at TEXT,
            last_error TEXT,
            devices_found INTEGER,
            scan_duration_ms INTEGER
        );
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            password_salt TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'readonly',
            must_change_password INTEGER NOT NULL DEFAULT 0,
            must_change_password_by TEXT,
            created_at TEXT NOT NULL,
            last_login_at TEXT,
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            locked_until TEXT,
            password_changed_at TEXT
        );
        CREATE TABLE IF NOT EXISTS password_history (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            password_hash TEXT NOT NULL,
            password_salt TEXT NOT NULL,
            changed_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            last_seen_at TEXT
        );
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY,
            actor TEXT NOT NULL,
            action TEXT NOT NULL,
            target TEXT,
            details TEXT DEFAULT '',
            ip TEXT,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS mfa_secrets (
            user_id INTEGER PRIMARY KEY,
            secret TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            confirmed_at TEXT
        );
        CREATE TABLE IF NOT EXISTS mfa_backup_codes (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            code_hash TEXT NOT NULL,
            code_salt TEXT NOT NULL,
            used_at TEXT
        );
        CREATE TABLE IF NOT EXISTS mfa_pending (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS rules (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            rule_type TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            params TEXT NOT NULL DEFAULT '{}',
            severity TEXT NOT NULL DEFAULT 'critical',
            created_at TEXT NOT NULL,
            last_triggered_at TEXT
        );
        CREATE TABLE IF NOT EXISTS saved_filters (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            target TEXT NOT NULL,
            name TEXT NOT NULL,
            definition TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_events_created ON events(created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status);
        CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
        CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_pwhistory_user ON password_history(user_id);
        CREATE INDEX IF NOT EXISTS idx_backupcodes_user ON mfa_backup_codes(user_id);
        CREATE INDEX IF NOT EXISTS idx_savedfilters_user ON saved_filters(user_id);
        """)
        _add_column_if_missing(c, "users", "failed_attempts", "failed_attempts INTEGER NOT NULL DEFAULT 0")
        _add_column_if_missing(c, "users", "locked_until", "locked_until TEXT")
        _add_column_if_missing(c, "users", "password_changed_at", "password_changed_at TEXT")
        _add_column_if_missing(c, "users", "must_change_password_by", "must_change_password_by TEXT")
        _add_column_if_missing(c, "devices", "offline_escalated_at", "offline_escalated_at TEXT")
        _add_column_if_missing(c, "sessions", "last_seen_at", "last_seen_at TEXT")
        # Backfill so enabling GODSEYE_PASSWORD_MAX_AGE_DAYS after upgrading doesn't
        # instantly treat every existing account as already expired.
        c.execute("UPDATE users SET password_changed_at=? WHERE password_changed_at IS NULL", (now(),))
        _add_column_if_missing(c, "devices", "classification", "classification TEXT NOT NULL DEFAULT 'new'")
        _add_column_if_missing(c, "devices", "missed_scans", "missed_scans INTEGER NOT NULL DEFAULT 0")
        _add_column_if_missing(c, "events", "severity", "severity TEXT NOT NULL DEFAULT 'info'")
        c.execute("UPDATE devices SET classification='known' WHERE trusted=1 AND classification='new'")

        if c.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
            salt, hashed = hash_password(ADMIN_DEFAULT_PASSWORD)
            deadline = must_change_deadline()
            c.execute(
                "INSERT INTO users(username,password_hash,password_salt,role,must_change_password,"
                "must_change_password_by,created_at,password_changed_at) "
                "VALUES(?,?,?,'admin',1,?,?,?)",
                (ADMIN_DEFAULT_USER, hashed, salt, deadline, now(), now()),
            )
            if deadline:
                print(
                    f"[GODSEYE] No users found - created default admin account '{ADMIN_DEFAULT_USER}'. "
                    f"You have {PASSWORD_CHANGE_GRACE_DAYS} day(s) to set a new password before it's "
                    "required. Set GODSEYE_ADMIN_USER / GODSEYE_ADMIN_PASSWORD before first boot to "
                    "change the seeded credentials."
                )
            else:
                print(
                    f"[GODSEYE] No users found - created default admin account '{ADMIN_DEFAULT_USER}'. "
                    "You will be required to set a new password on first login. Set GODSEYE_ADMIN_USER / "
                    "GODSEYE_ADMIN_PASSWORD before first boot to change the seeded credentials."
                )


@asynccontextmanager
async def lifespan(app):
    init_db()
    yield


app = FastAPI(title="GODSEYE", version="0.16.0", lifespan=lifespan)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'"
    if COOKIE_SECURE:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


router_prefix = "/api/v1"


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

class LoginRequest(BaseModel):
    username: str
    password: str


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str

    @field_validator("new_password")
    @classmethod
    def check_len(cls, v):
        check_password_strength(v)
        return v


class CreateUserRequest(BaseModel):
    username: str
    password: str
    role: str = "readonly"

    @field_validator("role")
    @classmethod
    def check_role(cls, v):
        if v not in VALID_ROLES:
            raise ValueError(f"role must be one of {sorted(VALID_ROLES)}")
        return v

    @field_validator("password")
    @classmethod
    def check_pw(cls, v, info):
        check_password_strength(v, info.data.get("username"))
        return v


class ResetPasswordRequest(BaseModel):
    new_password: str

    @field_validator("new_password")
    @classmethod
    def check_len(cls, v):
        check_password_strength(v)
        return v


class MfaVerifyRequest(BaseModel):
    pending_token: str
    code: str


class MfaConfirmRequest(BaseModel):
    code: str


class MfaDisableRequest(BaseModel):
    current_password: str
    code: str


ALLOWED_WHILE_PASSWORD_RESET_REQUIRED = {
    f"{router_prefix}/auth/change-password",
    f"{router_prefix}/auth/logout",
    f"{router_prefix}/auth/me",
}


def get_current_user(request: Request):
    """Auth dependency for every /api/v1 route except /auth/login.

    Uses the double-submit cookie CSRF pattern: the session cookie is
    httponly, the CSRF cookie is not (so the dashboard JS can read it) and
    every mutating request must echo it back in an X-CSRF-Token header. A
    cross-site request can ride the session cookie automatically but can't
    read the CSRF cookie's value to put in that header.

    Also enforces an idle timeout (GODSEYE_IDLE_TIMEOUT) independent of the
    session's absolute expiry, so a forgotten-open tab doesn't stay valid
    indefinitely just because it's within the 7-day absolute window.
    """
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        raise HTTPException(401, "Not authenticated")
    with db() as c:
        row = c.execute(
            "SELECT u.id AS id, u.username, u.role, u.must_change_password, u.must_change_password_by, "
            "u.password_changed_at, s.expires_at, s.last_seen_at "
            "FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token=?",
            (token,),
        ).fetchone()
        if not row:
            raise HTTPException(401, "Session expired")
        nowdt = dt.datetime.now(dt.timezone.utc)
        if dt.datetime.fromisoformat(row["expires_at"]) < nowdt:
            c.execute("DELETE FROM sessions WHERE token=?", (token,))
            raise HTTPException(401, "Session expired")
        if row["last_seen_at"] and (nowdt - dt.datetime.fromisoformat(row["last_seen_at"])).total_seconds() > IDLE_TIMEOUT_SECONDS:
            c.execute("DELETE FROM sessions WHERE token=?", (token,))
            raise HTTPException(401, "Session timed out due to inactivity")
        c.execute("UPDATE sessions SET last_seen_at=? WHERE token=?", (now(), token))
    password_reset_needed = must_change_now(row["must_change_password"], row["must_change_password_by"]) \
        or is_password_expired(row["password_changed_at"])
    if password_reset_needed and request.url.path not in ALLOWED_WHILE_PASSWORD_RESET_REQUIRED:
        # Enforced here, not just hidden behind the dashboard's modal, so a
        # direct API call can't skip the forced (or expired) password change either.
        raise HTTPException(403, "Password change required before continuing")
    if request.method in {"POST", "PATCH", "DELETE", "PUT"}:
        header = request.headers.get("x-csrf-token")
        cookie = request.cookies.get(CSRF_COOKIE)
        if not header or not cookie or not hmac.compare_digest(header, cookie):
            raise HTTPException(403, "CSRF token missing or invalid")
    return row


def require_admin(user=Depends(get_current_user)):
    if user["role"] != "admin":
        raise HTTPException(403, "Admin access required")
    return user


def _issue_session(c, user_id: int) -> tuple[str, str]:
    """Creates a session row and returns (session_token, csrf_token). Caller
    is responsible for setting the cookies via _set_session_cookies."""
    token, csrf_token = new_token(), new_token()
    expires_at = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=SESSION_TTL_SECONDS)).isoformat()
    c.execute("DELETE FROM sessions WHERE expires_at < ?", (now(),))  # opportunistic cleanup
    c.execute(
        "INSERT INTO sessions(token,user_id,created_at,expires_at,last_seen_at) VALUES(?,?,?,?,?)",
        (token, user_id, now(), expires_at, now()),
    )
    return token, csrf_token


def _set_session_cookies(response: Response, token: str, csrf_token: str):
    response.set_cookie(SESSION_COOKIE, token, httponly=True, samesite="lax", secure=COOKIE_SECURE, max_age=SESSION_TTL_SECONDS, path="/")
    response.set_cookie(CSRF_COOKIE, csrf_token, httponly=False, samesite="lax", secure=COOKIE_SECURE, max_age=SESSION_TTL_SECONDS, path="/")


def _login_response(user) -> dict:
    hard_blocked = must_change_now(user["must_change_password"], user["must_change_password_by"]) \
        or is_password_expired(user["password_changed_at"])
    resp = {
        "ok": True,
        "username": user["username"],
        "role": user["role"],
        "must_change_password": hard_blocked,
    }
    if user["must_change_password"] and not hard_blocked:
        # Still in the grace period - not blocked, but the dashboard should
        # show a reminder rather than stay silent about it.
        resp["password_change_reminder_days"] = days_until(user["must_change_password_by"])
    return resp


@app.post(f"{router_prefix}/auth/login")
def login(payload: LoginRequest, request: Request, response: Response):
    ip = client_ip(request)
    with db() as c:
        user = c.execute("SELECT * FROM users WHERE username=?", (payload.username,)).fetchone()

        if user and user["locked_until"]:
            if dt.datetime.fromisoformat(user["locked_until"]) > dt.datetime.now(dt.timezone.utc):
                audit(c, payload.username, "login_blocked_locked", ip=ip)
                raise HTTPException(423, "Account locked due to repeated failed logins. Try again later.")
            c.execute("UPDATE users SET locked_until=NULL, failed_attempts=0 WHERE id=?", (user["id"],))

        if not user or not verify_password(payload.password, user["password_salt"], user["password_hash"]):
            if user:
                attempts = user["failed_attempts"] + 1
                if attempts >= MAX_FAILED_ATTEMPTS:
                    locked_until = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=LOCKOUT_SECONDS)).isoformat()
                    c.execute("UPDATE users SET failed_attempts=?, locked_until=? WHERE id=?", (attempts, locked_until, user["id"]))
                    audit(c, payload.username, "account_locked", details=f"{attempts} failed attempts", ip=ip)
                else:
                    c.execute("UPDATE users SET failed_attempts=? WHERE id=?", (attempts, user["id"]))
            audit(c, payload.username, "login_failed", ip=ip)
            # Same generic message whether the username exists or not, so this
            # endpoint doesn't double as a username-enumeration oracle.
            raise HTTPException(401, "Invalid username or password")

        mfa = c.execute("SELECT 1 FROM mfa_secrets WHERE user_id=? AND enabled=1", (user["id"],)).fetchone()
        if mfa:
            # Password is correct, but a second factor is still required - don't
            # issue a session yet. A short-lived pending token carries the user
            # through to /auth/mfa/verify without exposing a real session cookie.
            pending_token = new_token()
            expires_at = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=MFA_PENDING_TTL_SECONDS)).isoformat()
            c.execute("DELETE FROM mfa_pending WHERE expires_at < ?", (now(),))
            c.execute(
                "INSERT INTO mfa_pending(token,user_id,created_at,expires_at) VALUES(?,?,?,?)",
                (pending_token, user["id"], now(), expires_at),
            )
            c.execute("UPDATE users SET failed_attempts=0, locked_until=NULL WHERE id=?", (user["id"],))
            audit(c, user["username"], "login_password_ok_awaiting_mfa", ip=ip)
            return {"ok": True, "mfa_required": True, "pending_token": pending_token}

        token, csrf_token = _issue_session(c, user["id"])
        c.execute("UPDATE users SET last_login_at=?, failed_attempts=0, locked_until=NULL WHERE id=?", (now(), user["id"]))
        audit(c, user["username"], "login_success", ip=ip)
    _set_session_cookies(response, token, csrf_token)
    return _login_response(user)


@app.post(f"{router_prefix}/auth/mfa/verify")
def mfa_verify(payload: MfaVerifyRequest, request: Request, response: Response):
    ip = client_ip(request)
    with db() as c:
        pending = c.execute("SELECT * FROM mfa_pending WHERE token=?", (payload.pending_token,)).fetchone()
        if not pending:
            raise HTTPException(401, "MFA session expired - please log in again")
        if dt.datetime.fromisoformat(pending["expires_at"]) < dt.datetime.now(dt.timezone.utc):
            c.execute("DELETE FROM mfa_pending WHERE token=?", (payload.pending_token,))
            raise HTTPException(401, "MFA session expired - please log in again")

        user = c.execute("SELECT * FROM users WHERE id=?", (pending["user_id"],)).fetchone()
        mfa = c.execute("SELECT secret FROM mfa_secrets WHERE user_id=? AND enabled=1", (user["id"],)).fetchone()

        code = payload.code.strip()
        code_ok = bool(mfa) and verify_totp(mfa["secret"], code)
        backup_used = False
        if not code_ok:
            candidates = c.execute(
                "SELECT id, code_hash, code_salt FROM mfa_backup_codes WHERE user_id=? AND used_at IS NULL",
                (user["id"],),
            ).fetchall()
            for cand in candidates:
                if verify_password(code, cand["code_salt"], cand["code_hash"]):
                    c.execute("UPDATE mfa_backup_codes SET used_at=? WHERE id=?", (now(), cand["id"]))
                    code_ok, backup_used = True, True
                    break

        if not code_ok:
            audit(c, user["username"], "mfa_verify_failed", ip=ip)
            raise HTTPException(401, "Invalid authentication code")

        c.execute("DELETE FROM mfa_pending WHERE token=?", (payload.pending_token,))
        token, csrf_token = _issue_session(c, user["id"])
        c.execute("UPDATE users SET last_login_at=? WHERE id=?", (now(), user["id"]))
        remaining = None
        if backup_used:
            remaining = c.execute(
                "SELECT COUNT(*) FROM mfa_backup_codes WHERE user_id=? AND used_at IS NULL", (user["id"],)
            ).fetchone()[0]
        audit(c, user["username"], "mfa_backup_code_used" if backup_used else "login_success_mfa", ip=ip)
    _set_session_cookies(response, token, csrf_token)
    resp = _login_response(user)
    if backup_used:
        resp["backup_codes_remaining"] = remaining
    return resp


@app.post(f"{router_prefix}/auth/logout")
def logout(request: Request, response: Response):
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        with db() as c:
            row = c.execute(
                "SELECT u.username FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=?", (token,)
            ).fetchone()
            c.execute("DELETE FROM sessions WHERE token=?", (token,))
            if row:
                audit(c, row["username"], "logout", ip=client_ip(request))
    response.delete_cookie(SESSION_COOKIE, path="/")
    response.delete_cookie(CSRF_COOKIE, path="/")
    return {"ok": True}


@app.get(f"{router_prefix}/auth/me")
def me(user=Depends(get_current_user)):
    with db() as c:
        mfa = c.execute("SELECT enabled FROM mfa_secrets WHERE user_id=?", (user["id"],)).fetchone()
    hard_blocked = must_change_now(user["must_change_password"], user["must_change_password_by"]) \
        or is_password_expired(user["password_changed_at"])
    resp = {
        "username": user["username"],
        "role": user["role"],
        "must_change_password": hard_blocked,
        "mfa_enabled": bool(mfa and mfa["enabled"]),
    }
    if user["must_change_password"] and not hard_blocked:
        resp["password_change_reminder_days"] = days_until(user["must_change_password_by"])
    if PASSWORD_MAX_AGE_DAYS > 0 and user["password_changed_at"]:
        age_days = (dt.datetime.now(dt.timezone.utc) - dt.datetime.fromisoformat(user["password_changed_at"])).total_seconds() / 86400
        resp["password_expires_in_days"] = max(0, round(PASSWORD_MAX_AGE_DAYS - age_days))
    return resp


@app.post(f"{router_prefix}/auth/change-password")
def change_password(payload: ChangePasswordRequest, request: Request, user=Depends(get_current_user)):
    with db() as c:
        row = c.execute("SELECT * FROM users WHERE id=?", (user["id"],)).fetchone()
        if not verify_password(payload.current_password, row["password_salt"], row["password_hash"]):
            audit(c, user["username"], "password_change_failed", ip=client_ip(request))
            raise HTTPException(401, "Current password is incorrect")
        check_password_reuse(c, user["id"], payload.new_password, row["password_salt"], row["password_hash"])
        record_password_history(c, user["id"], row["password_salt"], row["password_hash"])
        salt, hashed = hash_password(payload.new_password)
        c.execute(
            "UPDATE users SET password_hash=?,password_salt=?,must_change_password=0,"
            "must_change_password_by=NULL,password_changed_at=? WHERE id=?",
            (hashed, salt, now(), user["id"]),
        )
        # Invalidate every session for this account, including the current one - if the
        # old password had leaked, this makes sure it can't keep a session alive.
        # The dashboard re-prompts for login with the new password right after this call.
        c.execute("DELETE FROM sessions WHERE user_id=?", (user["id"],))
        audit(c, user["username"], "password_changed", ip=client_ip(request))
    return {"ok": True}


@app.post(f"{router_prefix}/auth/mfa/setup")
def mfa_setup(request: Request, user=Depends(get_current_user)):
    with db() as c:
        existing = c.execute("SELECT enabled FROM mfa_secrets WHERE user_id=?", (user["id"],)).fetchone()
        if existing and existing["enabled"]:
            raise HTTPException(400, "MFA is already enabled on this account - disable it before setting up a new device")
        secret = generate_totp_secret()
        c.execute(
            "INSERT OR REPLACE INTO mfa_secrets(user_id,secret,enabled,created_at) VALUES(?,?,0,?)",
            (user["id"], secret, now()),
        )
        audit(c, user["username"], "mfa_setup_started", ip=client_ip(request))
    grouped_secret = " ".join(secret[i:i + 4] for i in range(0, len(secret), 4))
    return {"ok": True, "secret": grouped_secret, "otpauth_uri": totp_provisioning_uri(secret, user["username"])}


@app.post(f"{router_prefix}/auth/mfa/confirm")
def mfa_confirm(payload: MfaConfirmRequest, request: Request, user=Depends(get_current_user)):
    with db() as c:
        row = c.execute("SELECT secret FROM mfa_secrets WHERE user_id=? AND enabled=0", (user["id"],)).fetchone()
        if not row:
            raise HTTPException(400, "No pending MFA setup found - call /auth/mfa/setup first")
        if not verify_totp(row["secret"], payload.code.strip()):
            audit(c, user["username"], "mfa_confirm_failed", ip=client_ip(request))
            raise HTTPException(401, "Incorrect code - check your authenticator app and try again")
        c.execute("UPDATE mfa_secrets SET enabled=1, confirmed_at=? WHERE user_id=?", (now(), user["id"]))
        c.execute("DELETE FROM mfa_backup_codes WHERE user_id=?", (user["id"],))
        codes = []
        for _ in range(MFA_BACKUP_CODE_COUNT):
            raw = secrets.token_hex(5)
            code = f"{raw[:5]}-{raw[5:]}"
            codes.append(code)
            salt, hashed = hash_password(code)
            c.execute(
                "INSERT INTO mfa_backup_codes(user_id,code_hash,code_salt,used_at) VALUES(?,?,?,NULL)",
                (user["id"], hashed, salt),
            )
        audit(c, user["username"], "mfa_enabled", ip=client_ip(request))
    return {"ok": True, "backup_codes": codes}


@app.post(f"{router_prefix}/auth/mfa/disable")
def mfa_disable(payload: MfaDisableRequest, request: Request, user=Depends(get_current_user)):
    with db() as c:
        row = c.execute("SELECT * FROM users WHERE id=?", (user["id"],)).fetchone()
        if not verify_password(payload.current_password, row["password_salt"], row["password_hash"]):
            raise HTTPException(401, "Current password is incorrect")
        mfa = c.execute("SELECT secret FROM mfa_secrets WHERE user_id=? AND enabled=1", (user["id"],)).fetchone()
        if not mfa:
            raise HTTPException(400, "MFA is not enabled on this account")
        code = payload.code.strip()
        code_ok = verify_totp(mfa["secret"], code)
        if not code_ok:
            candidates = c.execute(
                "SELECT id, code_hash, code_salt FROM mfa_backup_codes WHERE user_id=? AND used_at IS NULL",
                (user["id"],),
            ).fetchall()
            code_ok = any(verify_password(code, cand["code_salt"], cand["code_hash"]) for cand in candidates)
        if not code_ok:
            raise HTTPException(401, "Invalid authentication code")
        c.execute("DELETE FROM mfa_secrets WHERE user_id=?", (user["id"],))
        c.execute("DELETE FROM mfa_backup_codes WHERE user_id=?", (user["id"],))
        audit(c, user["username"], "mfa_disabled", ip=client_ip(request))
    return {"ok": True}


# ---------------------------------------------------------------------------
# User management (admin only)
# ---------------------------------------------------------------------------

@app.get(f"{router_prefix}/users")
def list_users(admin=Depends(require_admin)):
    with db() as c:
        rows = c.execute(
            "SELECT u.id,u.username,u.role,u.must_change_password,u.must_change_password_by,"
            "u.created_at,u.last_login_at,u.password_changed_at, "
            "COALESCE((SELECT enabled FROM mfa_secrets m WHERE m.user_id=u.id), 0) AS mfa_enabled "
            "FROM users u ORDER BY u.id"
        ).fetchall()
    return [dict(r) for r in rows]


@app.post(f"{router_prefix}/users")
def create_user(payload: CreateUserRequest, request: Request, admin=Depends(require_admin)):
    salt, hashed = hash_password(payload.password)
    with db() as c:
        try:
            c.execute(
                "INSERT INTO users(username,password_hash,password_salt,role,must_change_password,"
                "must_change_password_by,created_at,password_changed_at) "
                "VALUES(?,?,?,?,1,?,?,?)",
                (payload.username, hashed, salt, payload.role, must_change_deadline(), now(), now()),
            )
        except sqlite3.IntegrityError:
            raise HTTPException(409, "Username already exists")
        audit(c, admin["username"], "user_created", target=payload.username, details=f"role={payload.role}", ip=client_ip(request))
    return {"ok": True}


@app.post(f"{router_prefix}/users/{{user_id}}/reset-password")
def admin_reset_password(user_id: int, payload: ResetPasswordRequest, request: Request, admin=Depends(require_admin)):
    with db() as c:
        target = c.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if not target:
            raise HTTPException(404, "User not found")
        check_password_reuse(c, user_id, payload.new_password, target["password_salt"], target["password_hash"])
        record_password_history(c, user_id, target["password_salt"], target["password_hash"])
        salt, hashed = hash_password(payload.new_password)
        c.execute(
            "UPDATE users SET password_hash=?,password_salt=?,must_change_password=1,"
            "must_change_password_by=?,failed_attempts=0,locked_until=NULL,password_changed_at=? WHERE id=?",
            (hashed, salt, must_change_deadline(), now(), user_id),
        )
        c.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
        audit(c, admin["username"], "password_reset_by_admin", target=target["username"] if target else str(user_id), ip=client_ip(request))
    return {"ok": True}


@app.delete(f"{router_prefix}/users/{{user_id}}")
def delete_user(user_id: int, request: Request, admin=Depends(require_admin)):
    if user_id == admin["id"]:
        raise HTTPException(400, "Cannot delete the account you're currently logged in as")
    with db() as c:
        target = c.execute("SELECT username, role FROM users WHERE id=?", (user_id,)).fetchone()
        if not target:
            raise HTTPException(404, "User not found")
        if target["role"] == "admin":
            remaining_admins = c.execute(
                "SELECT COUNT(*) FROM users WHERE role='admin' AND id != ?", (user_id,)
            ).fetchone()[0]
            if remaining_admins == 0:
                raise HTTPException(400, "Cannot delete the last admin account")
        c.execute("DELETE FROM users WHERE id=?", (user_id,))
        c.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
        audit(c, admin["username"], "user_deleted", target=target["username"], ip=client_ip(request))
    return {"ok": True}


@app.post(f"{router_prefix}/users/{{user_id}}/mfa/reset")
def admin_reset_mfa(user_id: int, request: Request, admin=Depends(require_admin)):
    # For lost-device recovery: an admin can turn MFA off for another account
    # (never on - enrollment requires access to that person's own authenticator
    # app), after which the user re-enrolls a new device themselves.
    with db() as c:
        target = c.execute("SELECT username FROM users WHERE id=?", (user_id,)).fetchone()
        if not target:
            raise HTTPException(404, "User not found")
        c.execute("DELETE FROM mfa_secrets WHERE user_id=?", (user_id,))
        c.execute("DELETE FROM mfa_backup_codes WHERE user_id=?", (user_id,))
        audit(c, admin["username"], "mfa_reset_by_admin", target=target["username"], ip=client_ip(request))
    return {"ok": True}


@app.get(f"{router_prefix}/audit")
def audit_log(limit: int = 200, admin=Depends(require_admin)):
    limit = min(max(limit, 1), 1000)
    with db() as c:
        return [dict(r) for r in c.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))]


# ---------------------------------------------------------------------------
# Login security - an original, GODSEYE-native analysis of its own login
# audit trail (never Windows Event Logs / AD - that's a different data
# domain entirely). Surfaces brute-force-shaped patterns (many failed
# attempts from one source, one source trying multiple usernames) and a
# simple source-IP-to-username relationship graph, similar in spirit to
# graph-based logon analysis tools but built from scratch against
# audit_log with plain SQL aggregation and hand-drawn SVG - no graph
# database, no new dependency.
# ---------------------------------------------------------------------------

LOGIN_SECURITY_SUSPICIOUS_THRESHOLD = int(os.environ.get("GODSEYE_LOGIN_SECURITY_THRESHOLD", "3"))


@app.get(f"{router_prefix}/login-security")
def login_security(hours: int = 24, admin=Depends(require_admin)):
    hours = min(max(hours, 1), 24 * 30)
    since = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=hours)).isoformat()
    with db() as c:
        success_count = c.execute(
            "SELECT COUNT(*) FROM audit_log WHERE action='login_success' AND created_at>=?", (since,)
        ).fetchone()[0]
        failed_count = c.execute(
            "SELECT COUNT(*) FROM audit_log WHERE action='login_failed' AND created_at>=?", (since,)
        ).fetchone()[0]
        locked_events = c.execute(
            "SELECT COUNT(*) FROM audit_log WHERE action='account_locked' AND created_at>=?", (since,)
        ).fetchone()[0]
        currently_locked = c.execute(
            "SELECT username FROM users WHERE locked_until IS NOT NULL AND locked_until > ?", (now(),)
        ).fetchall()
        failed_pairs = c.execute(
            "SELECT actor, ip, COUNT(*) c, MIN(created_at) first_seen, MAX(created_at) last_seen "
            "FROM audit_log WHERE action='login_failed' AND created_at>=? AND ip IS NOT NULL "
            "GROUP BY actor, ip ORDER BY c DESC",
            (since,),
        ).fetchall()

    edges = [
        {"ip": r["ip"], "actor": r["actor"], "count": r["c"], "first_seen": r["first_seen"], "last_seen": r["last_seen"]}
        for r in failed_pairs
    ]

    by_ip = {}
    for e in edges:
        agg = by_ip.setdefault(e["ip"], {"usernames": set(), "total_failed": 0, "first_seen": e["first_seen"], "last_seen": e["last_seen"]})
        agg["usernames"].add(e["actor"])
        agg["total_failed"] += e["count"]
        agg["first_seen"] = min(agg["first_seen"], e["first_seen"])
        agg["last_seen"] = max(agg["last_seen"], e["last_seen"])

    suspicious = []
    for ip, agg in by_ip.items():
        # Two independent brute-force-shaped signals: enough raw failed
        # attempts from one source, or one source trying more than one
        # username (credential stuffing / username enumeration shape).
        is_suspicious = agg["total_failed"] >= LOGIN_SECURITY_SUSPICIOUS_THRESHOLD or len(agg["usernames"]) > 1
        suspicious.append({
            "ip": ip,
            "usernames": sorted(agg["usernames"]),
            "total_failed": agg["total_failed"],
            "first_seen": agg["first_seen"],
            "last_seen": agg["last_seen"],
            "suspicious": is_suspicious,
        })
    suspicious.sort(key=lambda x: -x["total_failed"])

    return {
        "window_hours": hours,
        "threshold": LOGIN_SECURITY_SUSPICIOUS_THRESHOLD,
        "summary": {
            "success": success_count,
            "failed": failed_count,
            "locked_events": locked_events,
            "currently_locked": [r["username"] for r in currently_locked],
        },
        "edges": edges,
        "by_ip": suspicious,
    }


# ---------------------------------------------------------------------------
# Devices / events / health (any authenticated user can view; admin-only to mutate)
# ---------------------------------------------------------------------------

class DeviceUpdate(BaseModel):
    name: str | None = None
    classification: str | None = None
    notes: str | None = None
    device_type: str | None = None

    @field_validator("classification")
    @classmethod
    def check_classification(cls, v):
        if v is not None and v not in VALID_CLASSIFICATIONS:
            raise ValueError(f"classification must be one of {sorted(VALID_CLASSIFICATIONS)}")
        return v


@app.get(f"{router_prefix}/health")
def health(user=Depends(get_current_user)):
    with db() as c:
        total = c.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
        online = c.execute("SELECT COUNT(*) FROM devices WHERE status='online'").fetchone()[0]
        needs_review = c.execute(
            "SELECT COUNT(*) FROM devices WHERE classification IN ('new','investigate')"
        ).fetchone()[0]
        events = c.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        hb = c.execute("SELECT * FROM scanner_heartbeat WHERE id=1").fetchone()

    scanner_ok = False
    scanner_detail = "scanner has not reported in yet"
    if hb and hb["last_success_at"]:
        age = (dt.datetime.now(dt.timezone.utc) - dt.datetime.fromisoformat(hb["last_success_at"])).total_seconds()
        scanner_ok = age <= HEARTBEAT_STALE_AFTER
        scanner_detail = f"last successful scan {int(age)}s ago" if scanner_ok else \
            f"no successful scan in {int(age)}s (stale, threshold {HEARTBEAT_STALE_AFTER}s)"

    return {
        "ok": True,
        "total": total,
        "online": online,
        "unknown": needs_review,  # kept for backward compatibility with the existing dashboard
        "needs_review": needs_review,
        "events": events,
        "scanner": {
            "healthy": scanner_ok,
            "detail": scanner_detail,
            "last_run_at": hb["last_run_at"] if hb else None,
            "last_success_at": hb["last_success_at"] if hb else None,
            "last_error": hb["last_error"] if hb else None,
            "devices_found": hb["devices_found"] if hb else None,
            "scan_duration_ms": hb["scan_duration_ms"] if hb else None,
        },
    }


def _prom_escape(v: str) -> str:
    return v.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def render_prometheus_metrics() -> str:
    """Builds the metrics body. Pulled out as its own function (not inline
    in the route) so it can be unit tested without needing a real HTTP
    request/response cycle."""
    with db() as c:
        total = c.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
        by_status = c.execute("SELECT status, COUNT(*) c FROM devices GROUP BY status").fetchall()
        by_classification = c.execute("SELECT classification, COUNT(*) c FROM devices GROUP BY classification").fetchall()
        events_total = c.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        events_by_severity = c.execute("SELECT severity, COUNT(*) c FROM events GROUP BY severity").fetchall()
        users_total = c.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        rules_enabled = c.execute("SELECT COUNT(*) FROM rules WHERE enabled=1").fetchone()[0]
        hb = c.execute("SELECT * FROM scanner_heartbeat WHERE id=1").fetchone()

    scanner_healthy = 0
    last_success_ts = 0
    if hb and hb["last_success_at"]:
        age = (dt.datetime.now(dt.timezone.utc) - dt.datetime.fromisoformat(hb["last_success_at"])).total_seconds()
        scanner_healthy = 1 if age <= HEARTBEAT_STALE_AFTER else 0
        last_success_ts = int(dt.datetime.fromisoformat(hb["last_success_at"]).timestamp())

    lines = []
    lines += [
        "# HELP godseye_devices_total Total number of known devices",
        "# TYPE godseye_devices_total gauge",
        f"godseye_devices_total {total}",
        "# HELP godseye_devices_by_status Number of devices by network status",
        "# TYPE godseye_devices_by_status gauge",
    ]
    for row in by_status:
        lines.append(f'godseye_devices_by_status{{status="{_prom_escape(row["status"] or "unknown")}"}} {row["c"]}')
    lines += [
        "# HELP godseye_devices_by_classification Number of devices by classification",
        "# TYPE godseye_devices_by_classification gauge",
    ]
    for row in by_classification:
        lines.append(f'godseye_devices_by_classification{{classification="{_prom_escape(row["classification"] or "new")}"}} {row["c"]}')
    lines += [
        "# HELP godseye_events_total Total number of recorded events",
        "# TYPE godseye_events_total counter",
        f"godseye_events_total {events_total}",
        "# HELP godseye_events_by_severity Total recorded events by severity",
        "# TYPE godseye_events_by_severity counter",
    ]
    for row in events_by_severity:
        lines.append(f'godseye_events_by_severity{{severity="{_prom_escape(row["severity"] or "info")}"}} {row["c"]}')
    lines += [
        "# HELP godseye_users_total Total number of user accounts",
        "# TYPE godseye_users_total gauge",
        f"godseye_users_total {users_total}",
        "# HELP godseye_rules_enabled Number of enabled alert rules",
        "# TYPE godseye_rules_enabled gauge",
        f"godseye_rules_enabled {rules_enabled}",
        "# HELP godseye_scanner_healthy Whether the scanner heartbeat is within the healthy threshold",
        "# TYPE godseye_scanner_healthy gauge",
        f"godseye_scanner_healthy {scanner_healthy}",
        "# HELP godseye_scanner_last_success_timestamp_seconds Unix timestamp of the last successful scan",
        "# TYPE godseye_scanner_last_success_timestamp_seconds gauge",
        f"godseye_scanner_last_success_timestamp_seconds {last_success_ts}",
        "# HELP godseye_scanner_last_scan_duration_ms Duration of the most recent scan cycle in milliseconds",
        "# TYPE godseye_scanner_last_scan_duration_ms gauge",
        f"godseye_scanner_last_scan_duration_ms {hb['scan_duration_ms'] if hb and hb['scan_duration_ms'] is not None else 0}",
    ]
    return "\n".join(lines) + "\n"


@app.get("/metrics")
def metrics(request: Request):
    if not METRICS_TOKEN:
        raise HTTPException(404, "Not found")
    auth_header = request.headers.get("authorization", "")
    provided = auth_header[7:] if auth_header.lower().startswith("bearer ") else ""
    if not provided or not hmac.compare_digest(provided, METRICS_TOKEN):
        raise HTTPException(401, "Invalid or missing bearer token")
    return PlainTextResponse(render_prometheus_metrics(), media_type="text/plain; version=0.0.4")


@app.get(f"{router_prefix}/devices")
def devices(search: str | None = None, status: str | None = None, classification: str | None = None,
            user=Depends(get_current_user)):
    query = "SELECT * FROM devices WHERE 1=1"
    values = []
    if search:
        query += " AND (mac LIKE ? OR ip LIKE ? OR hostname LIKE ? OR vendor LIKE ? OR name LIKE ?)"
        term = f"%{search}%"
        values += [term] * 5
    if status in {"online", "suspected_offline", "offline"}:
        query += " AND status=?"
        values.append(status)
    if classification in VALID_CLASSIFICATIONS:
        query += " AND classification=?"
        values.append(classification)
    query += " ORDER BY CASE status WHEN 'online' THEN 0 WHEN 'suspected_offline' THEN 1 ELSE 2 END, " \
             "CASE classification WHEN 'new' THEN 0 WHEN 'investigate' THEN 1 ELSE 2 END, last_seen DESC"
    with db() as c:
        return [dict(r) for r in c.execute(query, values)]


@app.patch(f"{router_prefix}/devices/{{device_id}}")
def update_device(device_id: int, payload: DeviceUpdate, request: Request, admin=Depends(require_admin)):
    fields, values = [], []
    for field in ("name", "classification", "notes", "device_type"):
        value = getattr(payload, field)
        if value is not None:
            fields.append(f"{field}=?")
            values.append(value)
    if not fields:
        return {"ok": True}
    values.append(device_id)
    with db() as c:
        cur = c.execute(f"UPDATE devices SET {', '.join(fields)} WHERE id=?", values)
        if cur.rowcount == 0:
            raise HTTPException(404, "Device not found")
        device = c.execute("SELECT mac FROM devices WHERE id=?", (device_id,)).fetchone()
        audit(c, admin["username"], "device_updated", target=device["mac"] if device else str(device_id),
              details=", ".join(fields), ip=client_ip(request))
    return {"ok": True}


@app.get(f"{router_prefix}/events")
def events(limit: int = 100, severity: str | None = None, user=Depends(get_current_user)):
    limit = min(max(limit, 1), 500)
    query = "SELECT * FROM events WHERE 1=1"
    values = []
    if severity in {"info", "warning", "critical"}:
        query += " AND severity=?"
        values.append(severity)
    query += " ORDER BY id DESC LIMIT ?"
    values.append(limit)
    with db() as c:
        return [dict(r) for r in c.execute(query, values)]


@app.get(f"{router_prefix}/devices/{{device_id}}/events")
def device_events(device_id: int, limit: int = 200, user=Depends(get_current_user)):
    limit = min(max(limit, 1), 500)
    with db() as c:
        device = c.execute("SELECT mac FROM devices WHERE id=?", (device_id,)).fetchone()
        if not device:
            raise HTTPException(404, "Device not found")
        return [dict(r) for r in c.execute(
            "SELECT * FROM events WHERE mac=? ORDER BY id DESC LIMIT ?", (device["mac"], limit)
        )]


@app.post(f"{router_prefix}/scan")
def manual_scan(request: Request, admin=Depends(require_admin)):
    # Scanning is deliberately isolated into the privileged godseye-scanner service.
    # Touching this endpoint asks that service to scan on its next cycle.
    flag = BASE_DIR / "data" / "scan-now"
    flag.touch()
    with db() as c:
        audit(c, admin["username"], "manual_scan_requested", ip=client_ip(request))
    return {"ok": True, "message": "Scan requested"}


# ---------------------------------------------------------------------------
# Alert rules (admin only to manage; the scanner service evaluates them)
# ---------------------------------------------------------------------------

class RuleCreate(BaseModel):
    name: str
    rule_type: str
    params: dict
    severity: str = "critical"
    enabled: bool = True

    @field_validator("rule_type")
    @classmethod
    def check_type(cls, v):
        if v not in VALID_RULE_TYPES:
            raise ValueError(f"rule_type must be one of {sorted(VALID_RULE_TYPES)}")
        return v

    @field_validator("severity")
    @classmethod
    def check_sev(cls, v):
        if v not in VALID_SEVERITIES:
            raise ValueError(f"severity must be one of {sorted(VALID_SEVERITIES)}")
        return v

    @field_validator("params")
    @classmethod
    def check_params(cls, v, info):
        rule_type = info.data.get("rule_type")
        if rule_type == "new_device_burst":
            if "count" not in v or "window_minutes" not in v:
                raise ValueError("new_device_burst params need 'count' and 'window_minutes'")
            if not (isinstance(v["count"], (int, float)) and v["count"] > 0):
                raise ValueError("'count' must be a positive number")
            if not (isinstance(v["window_minutes"], (int, float)) and v["window_minutes"] > 0):
                raise ValueError("'window_minutes' must be a positive number")
        elif rule_type == "offline_duration":
            if "minutes" not in v:
                raise ValueError("offline_duration params need 'minutes'")
            if not (isinstance(v["minutes"], (int, float)) and v["minutes"] > 0):
                raise ValueError("'minutes' must be a positive number")
            classes = v.get("classifications")
            if classes is not None:
                if not isinstance(classes, list) or not set(classes).issubset(VALID_CLASSIFICATIONS):
                    raise ValueError(f"'classifications' must be a list drawn from {sorted(VALID_CLASSIFICATIONS)}")
        return v


class RuleUpdate(BaseModel):
    enabled: bool | None = None


@app.get(f"{router_prefix}/rules")
def list_rules(user=Depends(get_current_user)):
    with db() as c:
        rows = c.execute("SELECT * FROM rules ORDER BY id").fetchall()
    return [dict(r) for r in rows]


@app.post(f"{router_prefix}/rules")
def create_rule(payload: RuleCreate, request: Request, admin=Depends(require_admin)):
    with db() as c:
        c.execute(
            "INSERT INTO rules(name,rule_type,enabled,params,severity,created_at) VALUES(?,?,?,?,?,?)",
            (payload.name, payload.rule_type, int(payload.enabled), json.dumps(payload.params), payload.severity, now()),
        )
        audit(c, admin["username"], "rule_created", target=payload.name,
              details=f"type={payload.rule_type}", ip=client_ip(request))
    return {"ok": True}


@app.patch(f"{router_prefix}/rules/{{rule_id}}")
def update_rule(rule_id: int, payload: RuleUpdate, request: Request, admin=Depends(require_admin)):
    if payload.enabled is None:
        return {"ok": True}
    with db() as c:
        cur = c.execute("UPDATE rules SET enabled=? WHERE id=?", (int(payload.enabled), rule_id))
        if cur.rowcount == 0:
            raise HTTPException(404, "Rule not found")
        audit(c, admin["username"], "rule_toggled", target=str(rule_id),
              details=f"enabled={payload.enabled}", ip=client_ip(request))
    return {"ok": True}


@app.delete(f"{router_prefix}/rules/{{rule_id}}")
def delete_rule(rule_id: int, request: Request, admin=Depends(require_admin)):
    with db() as c:
        rule = c.execute("SELECT name FROM rules WHERE id=?", (rule_id,)).fetchone()
        if not rule:
            raise HTTPException(404, "Rule not found")
        c.execute("DELETE FROM rules WHERE id=?", (rule_id,))
        audit(c, admin["username"], "rule_deleted", target=rule["name"], ip=client_ip(request))
    return {"ok": True}


# ---------------------------------------------------------------------------
# Saved filters (EventLogExpert-style filter library) - personal to each
# user, works the same for the Activity (events) and Audit Log views.
# Filtering itself happens client-side against an already-fetched page of
# rows; these endpoints just persist/recall named filter definitions so
# they don't have to be rebuilt by hand every visit. Any authenticated
# user can save filters for their own account - no admin restriction,
# since read-only users can use this on the Activity view too (the Audit
# Log view is admin-only at the UI level regardless).
# ---------------------------------------------------------------------------

VALID_FILTER_TARGETS = {"events", "audit"}


class SavedFilterCreate(BaseModel):
    name: str
    target: str
    definition: dict

    @field_validator("target")
    @classmethod
    def check_target(cls, v):
        if v not in VALID_FILTER_TARGETS:
            raise ValueError(f"target must be one of {sorted(VALID_FILTER_TARGETS)}")
        return v


@app.get(f"{router_prefix}/saved-filters")
def list_saved_filters(target: str | None = None, user=Depends(get_current_user)):
    query = "SELECT * FROM saved_filters WHERE user_id=?"
    values = [user["id"]]
    if target in VALID_FILTER_TARGETS:
        query += " AND target=?"
        values.append(target)
    query += " ORDER BY id DESC"
    with db() as c:
        rows = c.execute(query, values).fetchall()
    return [dict(r) for r in rows]


@app.post(f"{router_prefix}/saved-filters")
def create_saved_filter(payload: SavedFilterCreate, user=Depends(get_current_user)):
    with db() as c:
        c.execute(
            "INSERT INTO saved_filters(user_id,target,name,definition,created_at) VALUES(?,?,?,?,?)",
            (user["id"], payload.target, payload.name, json.dumps(payload.definition), now()),
        )
    return {"ok": True}


@app.delete(f"{router_prefix}/saved-filters/{{filter_id}}")
def delete_saved_filter(filter_id: int, user=Depends(get_current_user)):
    with db() as c:
        cur = c.execute("DELETE FROM saved_filters WHERE id=? AND user_id=?", (filter_id, user["id"]))
        if cur.rowcount == 0:
            raise HTTPException(404, "Saved filter not found")
    return {"ok": True}


# ---------------------------------------------------------------------------
# Network tools - ad-hoc ping/DNS lookup from the dashboard. Admin only,
# since these shell out and consume system resources on demand; input is
# strictly validated (see validate_tool_target) as defense in depth on top
# of never using shell=True.
# ---------------------------------------------------------------------------

class ToolTargetRequest(BaseModel):
    target: str


@app.post(f"{router_prefix}/tools/ping")
def tool_ping(payload: ToolTargetRequest, request: Request, admin=Depends(require_admin)):
    target = validate_tool_target(payload.target)
    try:
        result = subprocess.run(
            ["ping", "-c", "4", "-W", "2", target],
            capture_output=True, text=True, timeout=12,
        )
        output = (result.stdout or result.stderr or "").strip()
        success = result.returncode == 0
    except subprocess.TimeoutExpired:
        output, success = "Timed out.", False
    except FileNotFoundError:
        raise HTTPException(500, "ping is not installed on this system")
    with db() as c:
        audit(c, admin["username"], "tool_ping", target=target, ip=client_ip(request))
    return {"ok": True, "target": target, "success": success, "output": output[-4000:]}


@app.post(f"{router_prefix}/tools/dns-lookup")
def tool_dns_lookup(payload: ToolTargetRequest, request: Request, admin=Depends(require_admin)):
    target = validate_tool_target(payload.target)
    result = {"target": target}
    try:
        ipaddress.ip_address(target)
        is_ip = True
    except ValueError:
        is_ip = False
    try:
        if is_ip:
            name, aliases, _ = socket.gethostbyaddr(target)
            result["hostname"] = name
            if aliases:
                result["aliases"] = aliases
        else:
            ip = socket.gethostbyname(target)
            result["ip"] = ip
    except Exception as exc:
        result["error"] = str(exc)
    with db() as c:
        audit(c, admin["username"], "tool_dns_lookup", target=target, ip=client_ip(request))
    return {"ok": True, **result}


# ---------------------------------------------------------------------------
# Backup / export - CSV for devices and events (any authenticated user, same
# visibility as the dashboard views they mirror), CSV for the audit log and
# the full JSON backup (admin only, matching the Audit Log view's gating).
# The JSON backup deliberately excludes users, password hashes, sessions,
# and MFA secrets - a backup file is not the right place for credential
# material, and restoring it is a manual/documented process, not an
# import endpoint, to avoid silently overwriting live data.
# ---------------------------------------------------------------------------

def _csv_response(filename: str, header: list, rows: list) -> Response:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(header)
    writer.writerows(rows)
    return Response(
        content=buf.getvalue(), media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.get(f"{router_prefix}/export/devices.csv")
def export_devices_csv(user=Depends(get_current_user)):
    header = ["mac", "ip", "hostname", "vendor", "name", "device_type", "status", "classification", "first_seen", "last_seen", "notes"]
    with db() as c:
        rows = c.execute(f"SELECT {','.join(header)} FROM devices ORDER BY id").fetchall()
    return _csv_response("godseye-devices.csv", header, [[r[k] for k in header] for r in rows])


@app.get(f"{router_prefix}/export/events.csv")
def export_events_csv(user=Depends(get_current_user)):
    header = ["created_at", "event_type", "severity", "mac", "ip", "details"]
    with db() as c:
        rows = c.execute(f"SELECT {','.join(header)} FROM events ORDER BY id DESC LIMIT 5000").fetchall()
    return _csv_response("godseye-events.csv", header, [[r[k] for k in header] for r in rows])


@app.get(f"{router_prefix}/export/audit.csv")
def export_audit_csv(admin=Depends(require_admin)):
    header = ["created_at", "actor", "action", "target", "details", "ip"]
    with db() as c:
        rows = c.execute(f"SELECT {','.join(header)} FROM audit_log ORDER BY id DESC LIMIT 5000").fetchall()
    return _csv_response("godseye-audit.csv", header, [[r[k] for k in header] for r in rows])


@app.get(f"{router_prefix}/export/backup.json")
def export_backup_json(admin=Depends(require_admin)):
    device_cols = ["mac", "ip", "hostname", "vendor", "name", "device_type", "status", "classification", "first_seen", "last_seen", "notes"]
    event_cols = ["created_at", "event_type", "severity", "mac", "ip", "details"]
    rule_cols = ["name", "rule_type", "enabled", "params", "severity"]
    with db() as c:
        devices = [dict(r) for r in c.execute(f"SELECT {','.join(device_cols)} FROM devices ORDER BY id")]
        events = [dict(r) for r in c.execute(f"SELECT {','.join(event_cols)} FROM events ORDER BY id DESC LIMIT 5000")]
        rules = [dict(r) for r in c.execute(f"SELECT {','.join(rule_cols)} FROM rules ORDER BY id")]
    payload = {"exported_at": now(), "godseye_version": "0.15", "devices": devices, "events": events, "rules": rules}
    return Response(
        content=json.dumps(payload, indent=2), media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=godseye-backup.json"},
    )


@app.get("/", response_class=HTMLResponse)
def dashboard():
    banner_html = LOGIN_BANNER.replace("<", "&lt;").replace(">", "&gt;") if LOGIN_BANNER else ""
    html = DASHBOARD.replace("__LOGIN_BANNER__", banner_html)
    html = html.replace("__LOGIN_BANNER_DISPLAY__", "" if LOGIN_BANNER else "display:none")
    html = html.replace("__MIN_PASSWORD_LENGTH__", str(MIN_PASSWORD_LENGTH))
    return HTMLResponse(html)


DASHBOARD = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>GODSEYE — Network Monitor</title>
<style>
:root{color-scheme:dark;font-family:Inter,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}*{box-sizing:border-box}body{margin:0;background:#070b12;color:#e8eef7}header{position:sticky;top:0;z-index:5;background:rgba(7,11,18,.94);backdrop-filter:blur(14px);border-bottom:1px solid #1d2838;padding:16px 4%;display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}.brand{display:flex;gap:12px;align-items:center}.eye{width:38px;height:38px;border-radius:12px;background:#182338;display:grid;place-items:center;font-size:21px}.brand b{font-size:20px;letter-spacing:.08em}.muted{color:#7f8da3;font-size:12px}button,.filter{border:1px solid #2b3a52;background:#111a28;color:#dbe7f7;border-radius:9px;padding:9px 13px;cursor:pointer}button.primary{background:#2563eb;border-color:#2563eb}button.danger{background:#3a1522;border-color:#5c2436;color:#ff8194}button.link{background:none;border:none;color:#7f9fd8;padding:4px 6px}.headerRight{display:flex;gap:10px;align-items:center}.wrap{max-width:1500px;margin:auto;padding:28px 4%}.hero{display:flex;justify-content:space-between;gap:20px;align-items:end;margin-bottom:22px}.hero h1{font-size:32px;margin:0 0 5px}.cards{display:grid;grid-template-columns:repeat(5,1fr);gap:14px}.card{background:linear-gradient(145deg,#101927,#0d141f);border:1px solid #1d2a3d;border-radius:14px;padding:18px}.label{color:#8090a7;font-size:12px;text-transform:uppercase;letter-spacing:.1em}.num{font-size:32px;font-weight:750;margin-top:7px}.green{color:#50e3a4}.yellow{color:#f7c948}.red{color:#ff6b81}.toolbar{display:flex;gap:9px;margin:22px 0;flex-wrap:wrap}.toolbar input{flex:1;min-width:220px}.input{background:#0d141f;border:1px solid #2b3a52;border-radius:9px;padding:10px;color:#e8eef7}.panel{background:#0d141f;border:1px solid #1d2a3d;border-radius:14px;overflow:hidden;margin-top:18px}.panel h2{font-size:16px;margin:0;padding:16px 18px;border-bottom:1px solid #1d2a3d;display:flex;justify-content:space-between;align-items:center}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:12px 14px;border-bottom:1px solid #182335;font-size:13px}th{color:#72819a;font-size:11px;text-transform:uppercase;letter-spacing:.08em}tr:hover{background:#111a27}.dot{font-size:10px}.online{color:#50e3a4}.offline{color:#68758a}.suspected_offline{color:#f7c948}.pill{border:1px solid #31415a;border-radius:999px;padding:3px 8px;font-size:11px;color:#9eb0c8;cursor:pointer;background:none}.known{color:#50e3a4;border-color:#245c49}.new{color:#f7c948;border-color:#6d5a24}.investigate{color:#ff8194;border-color:#6d2e3c}.ignored{color:#72819a}.admin{color:#f7c948;border-color:#6d5a24}.readonly{color:#7f9fd8;border-color:#28406d}.critical{color:#ff8194;border-color:#6d2e3c}.warning{color:#f7c948;border-color:#6d5a24}.info{color:#7f9fd8;border-color:#28406d}.name{font-weight:650}.empty{padding:35px;text-align:center;color:#72819a}.healthbar{font-size:12px;padding:8px 4%;border-bottom:1px solid #1d2838}.healthbar.ok{color:#50e3a4}.healthbar.bad{color:#ff8194}
.overlay{position:fixed;inset:0;background:#070b12;display:grid;place-items:center;z-index:50;padding:20px}.authcard{width:100%;max-width:360px;background:#101927;border:1px solid #1d2a3d;border-radius:16px;padding:28px}.authcard h2{margin:0 0 6px}.authcard form{display:flex;flex-direction:column;gap:11px;margin-top:18px}.authcard .input{width:100%}.err{color:#ff8194;font-size:13px;min-height:18px}.formRow{display:flex;gap:9px}.userForm{display:flex;gap:8px;padding:14px 18px;flex-wrap:wrap;border-bottom:1px solid #182335}.userForm .input{flex:1;min-width:120px}
.shell{display:flex;align-items:flex-start}.sidebar{width:230px;flex-shrink:0;background:#0a0f18;border-right:1px solid #1d2838;padding:18px 0;display:flex;flex-direction:column;position:sticky;top:0;height:100vh;overflow-y:auto}.sidebar .brand{padding:0 18px 16px;margin-bottom:8px;border-bottom:1px solid #1d2838}.navlist{display:flex;flex-direction:column}.navitem{display:flex;align-items:center;gap:10px;padding:11px 18px;color:#9eb0c8;background:none;border:none;border-left:3px solid transparent;text-align:left;cursor:pointer;font-size:14px;width:100%}.navitem:hover{background:#111a28;color:#e8eef7}.navitem.active{background:#111a28;color:#e8eef7;border-left-color:#2563eb}.sidebar-footer{margin-top:auto;padding:14px 18px 4px;border-top:1px solid #1d2838;display:flex;flex-direction:column;gap:8px}.content{flex:1;min-width:0}.filterRow{display:flex;gap:8px;align-items:center;margin-bottom:6px;flex-wrap:wrap}.filterRow .input{flex:1;min-width:120px}.filterRow .filter{flex-shrink:0}.savedFilterChip{cursor:pointer;user-select:none}.savedFilterChip:hover{border-color:#4b5f82}.colorInput{width:38px;height:34px;padding:2px;border-radius:6px;border:1px solid #2b3a52;background:#0d141f;flex-shrink:0}
@media(max-width:900px){.cards{grid-template-columns:repeat(2,1fr)}th:nth-child(5),td:nth-child(5),th:nth-child(6),td:nth-child(6){display:none}}@media(max-width:600px){.cards{grid-template-columns:1fr}.hero{align-items:start;flex-direction:column}th:nth-child(4),td:nth-child(4){display:none}.wrap{padding:20px 3%}}
@media(max-width:820px){.shell{flex-direction:column}.sidebar{width:100%;height:auto;position:sticky;top:0;flex-direction:column;overflow:visible;border-right:none;border-bottom:1px solid #1d2838;padding:8px 0;z-index:6}.sidebar .brand{display:none}.navlist{flex-direction:row;overflow-x:auto;padding:0 4%}.navitem{width:auto;white-space:nowrap;border-left:none;border-bottom:3px solid transparent;padding:8px 12px}.navitem.active{border-left:none;border-bottom-color:#2563eb}.sidebar-footer{margin-top:8px;flex-direction:row;border-top:1px solid #1d2838;padding:8px 4% 0;gap:10px;align-items:center;flex-wrap:wrap}.sidebar-footer #whoami{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.sidebar-footer #scanBtn{width:auto!important;margin-bottom:0!important}}
</style></head>
<body>
<div id="authOverlay" class="overlay" style="display:none">
  <div class="authcard">
    <div id="loginBanner" class="muted" style="white-space:pre-wrap;margin-bottom:14px;__LOGIN_BANNER_DISPLAY__">__LOGIN_BANNER__</div>
    <h2>GODSEYE</h2>
    <div class="muted">Sign in to continue</div>
    <form id="loginForm" onsubmit="return doLogin(event)">
      <input class="input" id="loginUser" placeholder="Username" autocomplete="username" required>
      <input class="input" id="loginPass" type="password" placeholder="Password" autocomplete="current-password" required>
      <div class="err" id="loginErr"></div>
      <button class="primary" type="submit">Sign in</button>
    </form>
  </div>
</div>
<div id="pwOverlay" class="overlay" style="display:none">
  <div class="authcard">
    <h2>Set a new password</h2>
    <div class="muted">This account is using a password that must be changed before continuing.</div>
    <form id="pwForm" onsubmit="return doChangePassword(event)">
      <input class="input" id="curPass" type="password" placeholder="Current password" autocomplete="current-password" required>
      <input class="input" id="newPass" type="password" placeholder="New password (min __MIN_PASSWORD_LENGTH__ characters)" autocomplete="new-password" required minlength="__MIN_PASSWORD_LENGTH__">
      <div class="err" id="pwErr"></div>
      <button class="primary" type="submit">Set password</button>
    </form>
  </div>
</div>
<div id="mfaLoginOverlay" class="overlay" style="display:none">
  <div class="authcard">
    <h2>Two-factor authentication</h2>
    <div class="muted">Enter the 6-digit code from your authenticator app, or a backup code.</div>
    <form id="mfaLoginForm" onsubmit="return doMfaVerify(event)">
      <input class="input" id="mfaCode" placeholder="123456 or backup code" autocomplete="one-time-code" required>
      <div class="err" id="mfaLoginErr"></div>
      <button class="primary" type="submit">Verify</button>
    </form>
  </div>
</div>
<div id="app" style="display:none">
<div class="healthbar" id="healthbar"></div>
<div class="healthbar" id="pwReminderBar" style="display:none;color:#f7c948;cursor:pointer" onclick="openChangePassword()"></div>
<div class="shell">
<nav class="sidebar">
<div class="brand"><div class="eye">◉</div><div><b>GODSEYE</b><div class="muted">LOCAL NETWORK INTELLIGENCE</div></div></div>
<div class="navlist">
<button class="navitem active" data-view="overview" onclick="showView('overview')">📡 <span>Overview</span></button>
<button class="navitem" data-view="activity" onclick="showView('activity')">🕓 <span>Activity</span></button>
<button class="navitem" data-view="security" onclick="showView('security')">🔒 <span>Security</span></button>
<button class="navitem" id="navRules" data-view="rules" onclick="showView('rules')">⚡ <span>Alert Rules</span></button>
<button class="navitem" id="navUsers" data-view="users" onclick="showView('users')">👤 <span>Users</span></button>
<button class="navitem" id="navAudit" data-view="audit" onclick="showView('audit')">📜 <span>Audit Log</span></button>
<button class="navitem" id="navTools" data-view="tools" onclick="showView('tools')">🛠️ <span>Network Tools</span></button>
<button class="navitem" id="navBackup" data-view="backup" onclick="showView('backup')">💾 <span>Backup</span></button>
<button class="navitem" id="navLoginSec" data-view="loginsec" onclick="showView('loginsec')">🕵️ <span>Login Security</span></button>
</div>
<div class="sidebar-footer">
<button id="scanBtn" class="primary" onclick="scan()">⟳ Scan Now</button>
<div class="muted" id="whoami"></div>
<button class="link" onclick="openChangePassword()">Change password</button>
<button class="link" onclick="logout()">Log out</button>
</div>
</nav>
<main class="content"><div class="wrap">

<div class="view" id="view-overview">
<div class="hero"><div><h1>Network Overview</h1><div class="muted" id="updated">Loading telemetry…</div></div></div>
<div class="cards"><div class="card"><div class="label">Known Devices</div><div class="num" id="total">—</div></div><div class="card"><div class="label">Online</div><div class="num green" id="online">—</div></div><div class="card"><div class="label">Needs Review</div><div class="num yellow" id="unknown">—</div></div><div class="card"><div class="label">Events</div><div class="num" id="eventsCount">—</div></div><div class="card"><div class="label">Last Scan</div><div class="num" id="lastScan" style="font-size:16px">—</div></div></div>
<div class="toolbar"><input id="search" class="input" placeholder="Search name, IP, MAC, hostname or vendor…" oninput="loadDevices()"><select id="status" class="filter" onchange="loadDevices()"><option value="">All statuses</option><option value="online">Online</option><option value="suspected_offline">Suspected offline</option><option value="offline">Offline</option></select><select id="classification" class="filter" onchange="loadDevices()"><option value="">All classifications</option><option value="new">New</option><option value="known">Known</option><option value="investigate">Investigate</option><option value="ignored">Ignored</option></select></div>
<section class="panel"><h2>Devices</h2><div style="overflow:auto"><table><thead><tr><th>Status</th><th>Device</th><th>IP</th><th>MAC</th><th>Vendor</th><th>Classification</th></tr></thead><tbody id="devices"></tbody></table></div></section>
</div>

<div class="view" id="view-activity" style="display:none">
<section class="panel" style="margin-bottom:14px"><h2>Filter</h2>
<div style="padding:14px 18px;display:flex;flex-direction:column;gap:10px">
<div id="conditions-events"></div>
<div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">
<button class="link" onclick="addCondition('events')">+ Add condition</button>
<select class="filter" id="join-events" onchange="setJoin('events',this.value)"><option value="AND">Match ALL (AND)</option><option value="OR">Match ANY (OR)</option></select>
<select class="filter" id="mode-events" onchange="setMode('events',this.value)"><option value="include">Include matches</option><option value="exclude">Exclude matches</option></select>
<button class="link" onclick="clearFilter('events')">Clear</button>
<span class="muted" id="eventsMatchCount" style="margin-left:auto"></span>
</div>
<div class="muted" style="font-size:11px;text-transform:uppercase;letter-spacing:.08em;margin-top:4px">Highlight rules</div>
<div id="highlights-events"></div>
<button class="link" onclick="addHighlight('events')" style="align-self:flex-start">+ Add highlight rule</button>
<div class="muted" style="font-size:11px;text-transform:uppercase;letter-spacing:.08em;margin-top:4px">Saved filters</div>
<div id="savedFilters-events" style="display:flex;gap:6px;flex-wrap:wrap;align-items:center"></div>
<button class="primary" style="align-self:flex-start" onclick="saveCurrentFilter('events')">Save current filter</button>
</div>
</section>
<section class="panel"><h2>Recent Activity</h2><div style="overflow:auto"><table><thead><tr><th>Time</th><th>Event</th><th>Device</th><th>IP</th><th>Details</th></tr></thead><tbody id="events"></tbody></table></div></section>
</div>

<div class="view" id="view-security" style="display:none">
<section class="panel"><h2>Two-Factor Authentication</h2><div id="mfaStatus" style="padding:16px 18px"></div></section>
</div>

<div class="view" id="view-rules" style="display:none">
<section class="panel" id="rulesPanel"><h2>Alert Rules</h2>
<form class="userForm" onsubmit="return createRule(event)" style="flex-wrap:wrap">
<input class="input" id="ruleName" placeholder="Rule name" required style="flex:1;min-width:160px">
<select class="filter" id="ruleType" onchange="updateRuleFields()"><option value="new_device_burst">New device burst</option><option value="offline_duration">Offline duration</option></select>
<span id="ruleFieldsBurst" style="display:flex;gap:6px;align-items:center"><input class="input" id="ruleBurstCount" type="number" min="1" value="10" style="width:80px" title="Count"><span class="muted">new devices in</span><input class="input" id="ruleBurstWindow" type="number" min="1" value="5" style="width:80px" title="Window (minutes)"><span class="muted">min</span></span>
<span id="ruleFieldsOffline" style="display:none;gap:6px;align-items:center"><span class="muted">offline</span><input class="input" id="ruleOfflineMinutes" type="number" min="1" value="30" style="width:80px" title="Minutes"><span class="muted">min, classes:</span><input class="input" id="ruleOfflineClasses" placeholder="known,investigate (blank=any)" style="width:190px"></span>
<select class="filter" id="ruleSeverity"><option value="critical">Critical</option><option value="warning">Warning</option><option value="info">Info</option></select>
<button class="primary" type="submit">Add rule</button>
</form>
<div style="overflow:auto"><table><thead><tr><th>Name</th><th>Type</th><th>Condition</th><th>Severity</th><th>Last triggered</th><th>Enabled</th><th></th></tr></thead><tbody id="rules"></tbody></table></div>
</section>
</div>

<div class="view" id="view-users" style="display:none">
<section class="panel" id="usersPanel"><h2>Users</h2>
<form class="userForm" onsubmit="return createUser(event)"><input class="input" id="newUsername" placeholder="Username" required><input class="input" id="newUserPassword" type="password" placeholder="Password (min __MIN_PASSWORD_LENGTH__ chars)" required minlength="__MIN_PASSWORD_LENGTH__"><select class="filter" id="newUserRole"><option value="readonly">Read-only</option><option value="admin">Admin</option></select><button class="primary" type="submit">Add user</button></form>
<div style="overflow:auto"><table><thead><tr><th>Username</th><th>Role</th><th>Created</th><th>Last login</th><th>Password changed</th><th>Must change PW</th><th>MFA</th><th></th></tr></thead><tbody id="users"></tbody></table></div>
</section>
</div>

<div class="view" id="view-audit" style="display:none">
<section class="panel" style="margin-bottom:14px"><h2>Filter</h2>
<div style="padding:14px 18px;display:flex;flex-direction:column;gap:10px">
<div id="conditions-audit"></div>
<div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">
<button class="link" onclick="addCondition('audit')">+ Add condition</button>
<select class="filter" id="join-audit" onchange="setJoin('audit',this.value)"><option value="AND">Match ALL (AND)</option><option value="OR">Match ANY (OR)</option></select>
<select class="filter" id="mode-audit" onchange="setMode('audit',this.value)"><option value="include">Include matches</option><option value="exclude">Exclude matches</option></select>
<button class="link" onclick="clearFilter('audit')">Clear</button>
<span class="muted" id="auditMatchCount" style="margin-left:auto"></span>
</div>
<div class="muted" style="font-size:11px;text-transform:uppercase;letter-spacing:.08em;margin-top:4px">Highlight rules</div>
<div id="highlights-audit"></div>
<button class="link" onclick="addHighlight('audit')" style="align-self:flex-start">+ Add highlight rule</button>
<div class="muted" style="font-size:11px;text-transform:uppercase;letter-spacing:.08em;margin-top:4px">Saved filters</div>
<div id="savedFilters-audit" style="display:flex;gap:6px;flex-wrap:wrap;align-items:center"></div>
<button class="primary" style="align-self:flex-start" onclick="saveCurrentFilter('audit')">Save current filter</button>
</div>
</section>
<section class="panel" id="auditPanel"><h2>Audit Log</h2>
<div style="overflow:auto"><table><thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Target</th><th>Details</th><th>IP</th></tr></thead><tbody id="auditRows"></tbody></table></div>
</section>
</div>

<div class="view" id="view-tools" style="display:none">
<section class="panel"><h2>Network Tools</h2>
<div style="padding:16px 18px;display:flex;flex-direction:column;gap:20px;max-width:600px">
<div>
<div class="muted" style="margin-bottom:8px">Ping a host</div>
<div style="display:flex;gap:8px"><input class="input" id="pingTarget" placeholder="e.g. 192.168.1.1 or a hostname"><button class="primary" onclick="runPing()">Ping</button></div>
<pre id="pingResult" style="background:#0d141f;border:1px solid #2b3a52;border-radius:8px;padding:10px;margin-top:8px;white-space:pre-wrap;font-size:12px;display:none;font-family:monospace"></pre>
</div>
<div>
<div class="muted" style="margin-bottom:8px">DNS lookup</div>
<div style="display:flex;gap:8px"><input class="input" id="dnsTarget" placeholder="hostname or IP address"><button class="primary" onclick="runDnsLookup()">Lookup</button></div>
<pre id="dnsResult" style="background:#0d141f;border:1px solid #2b3a52;border-radius:8px;padding:10px;margin-top:8px;white-space:pre-wrap;font-size:12px;display:none;font-family:monospace"></pre>
</div>
</div>
</section>
</div>

<div class="view" id="view-backup" style="display:none">
<section class="panel"><h2>Backup &amp; Export</h2>
<div style="padding:16px 18px;display:flex;flex-direction:column;gap:12px">
<div class="muted">Downloads use your current login session, so links only work while you're signed in here — they're not shareable URLs.</div>
<div style="display:flex;gap:10px;flex-wrap:wrap">
<button class="primary" onclick="downloadExport('devices.csv')">Download Devices CSV</button>
<button class="primary" onclick="downloadExport('events.csv')">Download Events CSV</button>
<button class="primary" onclick="downloadExport('audit.csv')">Download Audit Log CSV</button>
<button class="primary" onclick="downloadExport('backup.json')">Download Full Backup (JSON)</button>
</div>
<div class="muted" style="font-size:12px">The full backup includes devices, events, and alert rules. It never includes user accounts, password hashes, sessions, or MFA secrets — restoring credential material from a backup file isn't something this does automatically, on purpose.</div>
</div>
</section>
</div>

<div class="view" id="view-loginsec" style="display:none">
<div class="cards">
<div class="card"><div class="label">Failed Logins (24h)</div><div class="num yellow" id="lsFailed">—</div></div>
<div class="card"><div class="label">Successful Logins (24h)</div><div class="num green" id="lsSuccess">—</div></div>
<div class="card"><div class="label">Currently Locked</div><div class="num" id="lsLocked">—</div></div>
<div class="card"><div class="label">Suspicious Sources</div><div class="num" id="lsSuspicious">—</div></div>
</div>
<section class="panel" style="margin-top:14px"><h2>Source &rarr; Account Relationships</h2>
<div class="muted" style="padding:12px 18px 0;font-size:12px">Each line is a source IP that had at least one failed login against the account it points to, in the last 24 hours. Thicker/redder lines mean more failed attempts.</div>
<div style="padding:10px 18px;overflow:auto"><svg id="loginGraphSvg" width="100%" style="min-width:520px"></svg></div>
</section>
<section class="panel" style="margin-top:14px"><h2>Suspicious Sources</h2>
<div class="muted" style="padding:12px 18px 0;font-size:12px" id="lsThresholdNote"></div>
<div style="overflow:auto"><table><thead><tr><th>Source IP</th><th>Usernames tried</th><th>Failed attempts</th><th>First seen</th><th>Last seen</th><th>Flagged</th></tr></thead><tbody id="loginSecTable"></tbody></table></div>
</section>
</div>

</div></main>
</div>
</div>
<script>
const esc=s=>String(s??'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
const CLASS_CYCLE={new:'known',known:'ignored',ignored:'investigate',investigate:'new'};
const CLASS_LABEL={new:'New',known:'Known',ignored:'Ignored',investigate:'Investigate'};
// --- EventLogExpert-style filter engine for Activity/Audit views ---
const FILTER_FIELDS={events:[['event_type','Event type'],['severity','Severity'],['mac','MAC'],['ip','IP'],['details','Details']],audit:[['actor','Actor'],['action','Action'],['target','Target'],['details','Details'],['ip','IP']]};
let ALL_EVENTS=[],ALL_AUDIT=[];
let FILTER_STATE={events:{conditions:[],join:'AND',mode:'include',highlights:[]},audit:{conditions:[],join:'AND',mode:'include',highlights:[]}};
let SAVED_FILTERS={events:[],audit:[]};
function condMatches(row,cond){const v=(row[cond.field]??'').toString().toLowerCase();const cv=(cond.value??'').toString().toLowerCase();if(cond.op==='equals')return v===cv;if(cond.op==='not_equals')return v!==cv;if(cond.op==='not_contains')return !v.includes(cv);return v.includes(cv)}
function groupMatches(row,conditions,join){const active=conditions.filter(c=>c.value!=='');if(!active.length)return true;return join==='OR'?active.some(c=>condMatches(row,c)):active.every(c=>condMatches(row,c))}
function applyFilterRows(rows,state){if(!state.conditions.length)return rows;return rows.filter(r=>{const m=groupMatches(r,state.conditions,state.join);return state.mode==='exclude'?!m:m})}
function highlightColor(row,state){for(const h of state.highlights){if(h.value!==''&&condMatches(row,h))return h.color}return null}
function fieldOptions(target,selected){return FILTER_FIELDS[target].map(([f,label])=>`<option value="${f}" ${f===selected?'selected':''}>${label}</option>`).join('')}
function opOptions(selected){const ops=[['contains','contains'],['not_contains','does not contain'],['equals','equals'],['not_equals','not equals']];return ops.map(([o,label])=>`<option value="${o}" ${o===selected?'selected':''}>${label}</option>`).join('')}
function renderFilterBuilder(target){const state=FILTER_STATE[target];const condEl=document.getElementById('conditions-'+target);condEl.innerHTML=state.conditions.map((c,i)=>`<div class="filterRow"><select class="filter" onchange="updateCondition('${target}',${i},'field',this.value)">${fieldOptions(target,c.field)}</select><select class="filter" onchange="updateCondition('${target}',${i},'op',this.value)">${opOptions(c.op)}</select><input class="input" placeholder="value" value="${esc(c.value)}" oninput="updateCondition('${target}',${i},'value',this.value)"><button class="link" onclick="removeCondition('${target}',${i})">✕</button></div>`).join('');const hlEl=document.getElementById('highlights-'+target);hlEl.innerHTML=state.highlights.map((h,i)=>`<div class="filterRow"><select class="filter" onchange="updateHighlight('${target}',${i},'field',this.value)">${fieldOptions(target,h.field)}</select><select class="filter" onchange="updateHighlight('${target}',${i},'op',this.value)">${opOptions(h.op)}</select><input class="input" placeholder="value" value="${esc(h.value)}" oninput="updateHighlight('${target}',${i},'value',this.value)"><input type="color" class="colorInput" value="${h.color}" onchange="updateHighlight('${target}',${i},'color',this.value)"><button class="link" onclick="removeHighlight('${target}',${i})">✕</button></div>`).join('')}
function syncFilterControls(target){const j=document.getElementById('join-'+target);const m=document.getElementById('mode-'+target);if(j)j.value=FILTER_STATE[target].join;if(m)m.value=FILTER_STATE[target].mode}
function addCondition(target){FILTER_STATE[target].conditions.push({field:FILTER_FIELDS[target][0][0],op:'contains',value:''});renderFilterBuilder(target)}
function removeCondition(target,idx){FILTER_STATE[target].conditions.splice(idx,1);renderFilterBuilder(target);applyAndRender(target)}
function updateCondition(target,idx,key,val){FILTER_STATE[target].conditions[idx][key]=val;applyAndRender(target)}
function addHighlight(target){FILTER_STATE[target].highlights.push({field:FILTER_FIELDS[target][0][0],op:'contains',value:'',color:'#ff8194'});renderFilterBuilder(target)}
function removeHighlight(target,idx){FILTER_STATE[target].highlights.splice(idx,1);renderFilterBuilder(target);applyAndRender(target)}
function updateHighlight(target,idx,key,val){FILTER_STATE[target].highlights[idx][key]=val;applyAndRender(target)}
function setJoin(target,val){FILTER_STATE[target].join=val;applyAndRender(target)}
function setMode(target,val){FILTER_STATE[target].mode=val;applyAndRender(target)}
function clearFilter(target){FILTER_STATE[target]={conditions:[],join:'AND',mode:'include',highlights:[]};renderFilterBuilder(target);syncFilterControls(target);applyAndRender(target)}
function applyAndRender(target){if(target==='events')renderEvents();else renderAudit()}
function renderEvents(){const state=FILTER_STATE.events;const filtered=applyFilterRows(ALL_EVENTS,state);events.innerHTML=filtered.length?filtered.map(x=>{const hl=highlightColor(x,state);const style=hl?` style="background:${hl}22;border-left:3px solid ${hl}"`:'';return `<tr${style}><td>${esc(new Date(x.created_at).toLocaleString())}</td><td><span class="pill">${esc(x.event_type)}</span></td><td>${esc(x.mac||'—')}</td><td>${esc(x.ip||'—')}</td><td>${esc(x.details)}</td></tr>`}).join(''):'<tr><td colspan="5" class="empty">No activity matches this filter.</td></tr>';const c=document.getElementById('eventsMatchCount');if(c)c.textContent=filtered.length+' / '+ALL_EVENTS.length+' shown'}
function renderAudit(){const state=FILTER_STATE.audit;const filtered=applyFilterRows(ALL_AUDIT,state);auditRows.innerHTML=filtered.length?filtered.map(x=>{const hl=highlightColor(x,state);const style=hl?` style="background:${hl}22;border-left:3px solid ${hl}"`:'';return `<tr${style}><td>${esc(new Date(x.created_at).toLocaleString())}</td><td>${esc(x.actor)}</td><td><span class="pill">${esc(x.action)}</span></td><td>${esc(x.target||'—')}</td><td>${esc(x.details||'')}</td><td>${esc(x.ip||'—')}</td></tr>`}).join(''):'<tr><td colspan="6" class="empty">No audit entries match this filter.</td></tr>';const c=document.getElementById('auditMatchCount');if(c)c.textContent=filtered.length+' / '+ALL_AUDIT.length+' shown'}
async function loadSavedFilters(target){try{SAVED_FILTERS[target]=await json('/api/v1/saved-filters?target='+target)}catch(e){SAVED_FILTERS[target]=[]}renderSavedFilters(target)}
function renderSavedFilters(target){const el=document.getElementById('savedFilters-'+target);const list=SAVED_FILTERS[target];el.innerHTML=list.length?list.map(f=>`<span class="pill savedFilterChip"><span onclick="applySavedFilter('${target}',${f.id})">${esc(f.name)}</span> <span onclick="deleteSavedFilter('${target}',${f.id})" style="color:#ff8194">✕</span></span>`).join(' '):'<span class="muted">No saved filters yet.</span>'}
function applySavedFilter(target,id){const f=SAVED_FILTERS[target].find(x=>x.id===id);if(!f)return;let def;try{def=JSON.parse(f.definition)}catch(e){return}FILTER_STATE[target]=Object.assign({conditions:[],join:'AND',mode:'include',highlights:[]},def);renderFilterBuilder(target);syncFilterControls(target);applyAndRender(target)}
async function saveCurrentFilter(target){const name=prompt('Name this filter:');if(!name)return;try{await json('/api/v1/saved-filters',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:name,target:target,definition:FILTER_STATE[target]})});await loadSavedFilters(target)}catch(e){alert('Could not save filter: '+e.message)}}
async function deleteSavedFilter(target,id){try{await json('/api/v1/saved-filters/'+id,{method:'DELETE'});await loadSavedFilters(target)}catch(e){}}
async function runPing(){const target=document.getElementById('pingTarget').value.trim();if(!target)return;const out=document.getElementById('pingResult');out.style.display='block';out.textContent='Running…';try{const r=await json('/api/v1/tools/ping',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target:target})});out.textContent=(r.success?'✓ reachable':'✗ unreachable')+'\n\n'+r.output}catch(e){out.textContent='Error: '+e.message}}
async function runDnsLookup(){const target=document.getElementById('dnsTarget').value.trim();if(!target)return;const out=document.getElementById('dnsResult');out.style.display='block';out.textContent='Looking up…';try{const r=await json('/api/v1/tools/dns-lookup',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target:target})});out.textContent=JSON.stringify(r,null,2)}catch(e){out.textContent='Error: '+e.message}}
function downloadExport(name){window.location='/api/v1/export/'+name}
async function loadLoginSecurity(){if(!ME||ME.role!=='admin'){return}let data;try{data=await json('/api/v1/login-security?hours=24')}catch(e){return}
document.getElementById('lsFailed').textContent=data.summary.failed;
document.getElementById('lsSuccess').textContent=data.summary.success;
document.getElementById('lsLocked').textContent=data.summary.currently_locked.length;
document.getElementById('lsSuspicious').textContent=data.by_ip.filter(x=>x.suspicious).length;
document.getElementById('lsThresholdNote').textContent='A source is flagged when it has '+data.threshold+'+ failed attempts against one account, or tries more than one username (configurable via GODSEYE_LOGIN_SECURITY_THRESHOLD).';
const tbody=document.getElementById('loginSecTable');
tbody.innerHTML=data.by_ip.length?data.by_ip.map(x=>`<tr${x.suspicious?' style="background:#3a1522"':''}><td>${esc(x.ip)}</td><td>${x.usernames.map(esc).join(', ')}</td><td>${x.total_failed}</td><td>${esc(new Date(x.first_seen).toLocaleString())}</td><td>${esc(new Date(x.last_seen).toLocaleString())}</td><td>${x.suspicious?'⚠ Yes':'No'}</td></tr>`).join(''):'<tr><td colspan="6" class="empty">No failed login attempts in the last 24 hours.</td></tr>';
renderLoginGraph(data.edges)}
function renderLoginGraph(edges){const svgEl=document.getElementById('loginGraphSvg');if(!edges.length){svgEl.innerHTML='<text x="10" y="24" fill="#72819a" font-size="13">No failed login attempts to visualize in this window.</text>';svgEl.setAttribute('height','40');return}
const ips=[...new Set(edges.map(e=>e.ip))];const users=[...new Set(edges.map(e=>e.actor))];
const rowH=32,leftX=110,rightX=380,topY=24;const maxCount=Math.max(...edges.map(e=>e.count));
let svg='';
edges.forEach(e=>{const y1=topY+ips.indexOf(e.ip)*rowH;const y2=topY+users.indexOf(e.actor)*rowH;const w=1+(e.count/maxCount)*4;const op=0.35+0.45*(e.count/maxCount);svg+=`<line x1="${leftX}" y1="${y1}" x2="${rightX}" y2="${y2}" stroke="#ff8194" stroke-width="${w}" opacity="${op.toFixed(2)}"/>`});
ips.forEach((ip,i)=>{const y=topY+i*rowH;svg+=`<circle cx="${leftX}" cy="${y}" r="5" fill="#ff8194"/><text x="${leftX-10}" y="${y+4}" text-anchor="end" fill="#dbe7f7" font-size="12">${esc(ip)}</text>`});
users.forEach((u,i)=>{const y=topY+i*rowH;svg+=`<circle cx="${rightX}" cy="${y}" r="5" fill="#7f9fd8"/><text x="${rightX+10}" y="${y+4}" fill="#dbe7f7" font-size="12">${esc(u)}</text>`});
const height=Math.max(ips.length,users.length)*rowH+30;
svgEl.setAttribute('viewBox',`0 0 560 ${height}`);svgEl.setAttribute('height',height);svgEl.innerHTML=svg}

let ME=null;
let PENDING_MFA_TOKEN=null;
function getCookie(name){const m=document.cookie.match('(?:^|; )'+name+'=([^;]*)');return m?decodeURIComponent(m[1]):null}
async function json(url,opt={}){opt.headers=opt.headers||{};if(opt.method&&opt.method!=='GET'){opt.headers['X-CSRF-Token']=getCookie('godseye_csrf')||''}let r=await fetch(url,opt);if(r.status===401){showLogin();throw new Error('unauthenticated')}if(!r.ok){let t=await r.text();throw new Error(t)}return r.status===204?null:r.json()}
function showLogin(){document.getElementById('app').style.display='none';document.getElementById('pwOverlay').style.display='none';document.getElementById('mfaLoginOverlay').style.display='none';document.getElementById('authOverlay').style.display='grid'}
function showApp(){document.getElementById('authOverlay').style.display='none';document.getElementById('pwOverlay').style.display='none';document.getElementById('mfaLoginOverlay').style.display='none';document.getElementById('app').style.display='block'}
function showView(name){document.querySelectorAll('.view').forEach(v=>v.style.display='none');const target=document.getElementById('view-'+name);if(target)target.style.display='';document.querySelectorAll('.navitem').forEach(b=>b.classList.remove('active'));const btn=document.querySelector('.navitem[data-view="'+name+'"]');if(btn)btn.classList.add('active');if(name==='users'&&ME&&ME.role==='admin')loadUsers();if(name==='audit'&&ME&&ME.role==='admin')loadAudit();if(name==='rules')loadRules();if(name==='security')loadSecurity()}
async function doLogin(e){e.preventDefault();const err=document.getElementById('loginErr');err.textContent='';try{let r=await fetch('/api/v1/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:loginUser.value,password:loginPass.value})});if(r.status===423){err.textContent='Account temporarily locked due to repeated failed logins. Try again later.';return false}if(!r.ok){err.textContent='Invalid username or password';return false}let data=await r.json();if(data.mfa_required){PENDING_MFA_TOKEN=data.pending_token;document.getElementById('authOverlay').style.display='none';document.getElementById('mfaLoginOverlay').style.display='grid';return false}if(data.must_change_password){document.getElementById('authOverlay').style.display='none';document.getElementById('pwOverlay').style.display='grid';return false}await boot()}catch(e){err.textContent='Sign-in failed'}return false}
async function doMfaVerify(e){e.preventDefault();const err=document.getElementById('mfaLoginErr');err.textContent='';try{let r=await fetch('/api/v1/auth/mfa/verify',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({pending_token:PENDING_MFA_TOKEN,code:mfaCode.value.trim()})});if(!r.ok){err.textContent='Invalid code';return false}let data=await r.json();PENDING_MFA_TOKEN=null;if(data.must_change_password){document.getElementById('mfaLoginOverlay').style.display='none';document.getElementById('pwOverlay').style.display='grid';return false}await boot()}catch(e){err.textContent='Verification failed'}return false}
function openChangePassword(){document.getElementById('pwOverlay').style.display='grid'}
async function doChangePassword(e){e.preventDefault();const err=document.getElementById('pwErr');err.textContent='';try{await json('/api/v1/auth/change-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({current_password:curPass.value,new_password:newPass.value})});await boot()}catch(e){err.textContent='Could not change password — check your current password'}return false}
async function logout(){await fetch('/api/v1/auth/logout',{method:'POST',headers:{'X-CSRF-Token':getCookie('godseye_csrf')||''}});showLogin()}
async function loadDevices(){let q=new URLSearchParams();if(search.value)q.set('search',search.value);if(status.value)q.set('status',status.value);if(classification.value)q.set('classification',classification.value);let d=await json('/api/v1/devices?'+q);const canEdit=ME&&ME.role==='admin';devices.innerHTML=d.length?d.map(x=>`<tr><td class="${esc(x.status)}"><span class="dot">●</span> ${esc(x.status).replace('_',' ')}</td><td><div class="name">${esc(x.name||x.hostname||'Unknown device')}</div><div class="muted">${esc(x.device_type||'Unclassified')}</div></td><td>${esc(x.ip)}</td><td>${esc(x.mac)}</td><td>${esc(x.vendor||'—')}</td><td><button class="pill ${esc(x.classification)}" ${canEdit?`onclick="cycleClass(${x.id},'${x.classification}')"`:'disabled'}>${CLASS_LABEL[x.classification]||x.classification}</button></td></tr>`).join(''):'<tr><td colspan="6" class="empty">No devices match this filter.</td></tr>'}
async function loadUsers(){if(!ME||ME.role!=='admin'){usersPanel.style.display='none';return}usersPanel.style.display='block';let u=await json('/api/v1/users');users.innerHTML=u.map(x=>{let mustChange=x.must_change_password?(x.must_change_password_by?`yes, by ${esc(new Date(x.must_change_password_by).toLocaleDateString())}`:'yes'):'no';return `<tr><td>${esc(x.username)}</td><td><span class="pill ${esc(x.role)}">${esc(x.role)}</span></td><td>${esc(new Date(x.created_at).toLocaleDateString())}</td><td>${x.last_login_at?esc(new Date(x.last_login_at).toLocaleString()):'never'}</td><td>${x.password_changed_at?esc(new Date(x.password_changed_at).toLocaleDateString()):'—'}</td><td>${mustChange}</td><td>${x.mfa_enabled?'yes':'no'}</td><td>${x.username===ME.username?'':`<button class="link" onclick="removeUser(${x.id},'${esc(x.username)}')">Remove</button>${x.mfa_enabled?` <button class="link" onclick="resetUserMfa(${x.id},'${esc(x.username)}')">Reset MFA</button>`:''}`}</td></tr>`}).join('')}
async function loadAudit(){if(!ME||ME.role!=='admin'){auditPanel.style.display='none';return}auditPanel.style.display='block';ALL_AUDIT=await json('/api/v1/audit?limit=300');renderAudit()}
async function loadSecurity(){const el=document.getElementById('mfaStatus');if(ME.mfa_enabled){el.innerHTML=`<div class="muted">Two-factor authentication is <b style="color:#50e3a4">enabled</b> on this account.</div><button class="link" style="margin-top:10px" onclick="startMfaDisable()">Disable MFA</button>`}else{el.innerHTML=`<div class="muted">Two-factor authentication is <b style="color:#f7c948">not enabled</b>. Add it for a second layer of protection beyond your password.</div><button class="primary" style="margin-top:10px" onclick="startMfaSetup()">Set up MFA</button>`}}
function updateRuleFields(){const t=document.getElementById('ruleType').value;document.getElementById('ruleFieldsBurst').style.display=t==='new_device_burst'?'flex':'none';document.getElementById('ruleFieldsOffline').style.display=t==='offline_duration'?'flex':'none'}
async function loadRules(){if(!ME||ME.role!=='admin'){rulesPanel.style.display='none';return}rulesPanel.style.display='block';let r=await json('/api/v1/rules');rules.innerHTML=r.length?r.map(x=>{let p;try{p=JSON.parse(x.params)}catch(e){p={}}let cond=x.rule_type==='new_device_burst'?`${p.count}+ new devices in ${p.window_minutes}m`:`offline ${p.minutes}m+ (${(p.classifications&&p.classifications.length?p.classifications:['any']).join(', ')})`;return `<tr><td>${esc(x.name)}</td><td>${esc(x.rule_type)}</td><td>${esc(cond)}</td><td><span class="pill ${esc(x.severity)}">${esc(x.severity)}</span></td><td>${x.last_triggered_at?esc(new Date(x.last_triggered_at).toLocaleString()):'never'}</td><td><input type="checkbox" ${x.enabled?'checked':''} onchange="toggleRule(${x.id},this.checked)"></td><td><button class="link" onclick="removeRule(${x.id},'${esc(x.name)}')">Remove</button></td></tr>`}).join(''):'<tr><td colspan="7" class="empty">No rules configured yet.</td></tr>'}
async function createRule(e){e.preventDefault();const type=document.getElementById('ruleType').value;let params;if(type==='new_device_burst'){params={count:parseInt(ruleBurstCount.value,10),window_minutes:parseFloat(ruleBurstWindow.value)}}else{params={minutes:parseFloat(ruleOfflineMinutes.value)};const raw=ruleOfflineClasses.value.trim();if(raw)params.classifications=raw.split(',').map(s=>s.trim()).filter(Boolean)}try{await json('/api/v1/rules',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:ruleName.value,rule_type:type,params:params,severity:ruleSeverity.value})});ruleName.value='';await loadRules()}catch(e){alert('Could not create rule: '+e.message)}return false}
async function toggleRule(id,enabled){await json('/api/v1/rules/'+id,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({enabled:enabled})});await loadRules()}
async function removeRule(id,name){if(!confirm('Remove rule "'+name+'"?'))return;await json('/api/v1/rules/'+id,{method:'DELETE'});await loadRules()}
async function startMfaSetup(){let data=await json('/api/v1/auth/mfa/setup',{method:'POST'});const el=document.getElementById('mfaStatus');el.innerHTML=`<div class="muted">In Google Authenticator (or any TOTP app), choose "Enter a setup key" and type this in:</div><div style="font-family:monospace;font-size:16px;background:#0d141f;border:1px solid #2b3a52;border-radius:8px;padding:10px;margin:10px 0;word-break:break-all">${esc(data.secret)}</div><div class="muted" style="font-size:11px;word-break:break-all">${esc(data.otpauth_uri)}</div><form onsubmit="return confirmMfaSetup(event)" style="margin-top:14px;display:flex;gap:8px;flex-wrap:wrap"><input class="input" id="mfaConfirmCode" placeholder="Enter 6-digit code to confirm" required style="flex:1;min-width:180px"><button class="primary" type="submit">Confirm</button></form><div class="err" id="mfaSetupErr"></div>`}
async function confirmMfaSetup(e){e.preventDefault();const err=document.getElementById('mfaSetupErr');err.textContent='';try{let data=await json('/api/v1/auth/mfa/confirm',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({code:mfaConfirmCode.value.trim()})});const el=document.getElementById('mfaStatus');el.innerHTML=`<div class="muted" style="color:#50e3a4">MFA enabled. Save these one-time backup codes somewhere safe — each works once if you lose access to your authenticator app:</div><div style="font-family:monospace;background:#0d141f;border:1px solid #2b3a52;border-radius:8px;padding:10px;margin:10px 0">${data.backup_codes.map(esc).join('<br>')}</div><button class="primary" onclick="boot()">Done</button>`;ME=await json('/api/v1/auth/me')}catch(e){err.textContent='Incorrect code — try again'}return false}
async function startMfaDisable(){const el=document.getElementById('mfaStatus');el.innerHTML=`<form onsubmit="return confirmMfaDisable(event)" style="display:flex;flex-direction:column;gap:8px;max-width:320px"><input class="input" id="mfaDisablePw" type="password" placeholder="Current password" required><input class="input" id="mfaDisableCode" placeholder="6-digit code or backup code" required><button class="danger" type="submit">Disable MFA</button><div class="err" id="mfaDisableErr"></div></form>`}
async function confirmMfaDisable(e){e.preventDefault();const err=document.getElementById('mfaDisableErr');err.textContent='';try{await json('/api/v1/auth/mfa/disable',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({current_password:mfaDisablePw.value,code:mfaDisableCode.value.trim()})});ME=await json('/api/v1/auth/me');loadSecurity()}catch(e){err.textContent='Could not disable MFA — check password and code'}return false}
async function resetUserMfa(id,username){if(!confirm('Reset MFA for "'+username+'"? They will need to set it up again.'))return;await json('/api/v1/users/'+id+'/mfa/reset',{method:'POST'});await loadUsers()}
async function createUser(e){e.preventDefault();try{await json('/api/v1/users',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:newUsername.value,password:newUserPassword.value,role:newUserRole.value})});newUsername.value='';newUserPassword.value='';await loadUsers()}catch(e){alert('Could not create user: '+e.message)}return false}
async function removeUser(id,username){if(!confirm('Remove user "'+username+'"?'))return;await json('/api/v1/users/'+id,{method:'DELETE'});await loadUsers()}
async function load(){let h=await json('/api/v1/health');total.textContent=h.total;online.textContent=h.online;unknown.textContent=h.needs_review;eventsCount.textContent=h.events;updated.textContent='Last refreshed '+new Date().toLocaleTimeString();lastScan.textContent=h.scanner.detail;const hb=document.getElementById('healthbar');if(!h.scanner.healthy){hb.className='healthbar bad';hb.textContent='⚠ Scanner unhealthy — '+h.scanner.detail;hb.style.display='block'}else{hb.style.display='none'}await loadDevices();ALL_EVENTS=await json('/api/v1/events?limit=300');renderEvents()}
async function cycleClass(id,current){await json('/api/v1/devices/'+id,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({classification:CLASS_CYCLE[current]||'new'})});load()}
async function scan(){await json('/api/v1/scan',{method:'POST'});updated.textContent='Scan requested…';setTimeout(load,3000)}
async function boot(){try{ME=await json('/api/v1/auth/me')}catch(e){showLogin();return}whoami.textContent=ME.username+' ('+ME.role+')'+(ME.password_expires_in_days!==undefined?' · password expires in '+ME.password_expires_in_days+'d':'');scanBtn.style.display=ME.role==='admin'?'inline-block':'none';['navRules','navUsers','navAudit','navTools','navBackup','navLoginSec'].forEach(id=>{document.getElementById(id).style.display=ME.role==='admin'?'':'none'});const pwBar=document.getElementById('pwReminderBar');if(ME.password_change_reminder_days!==undefined){pwBar.textContent='⚠ Set a new password within '+ME.password_change_reminder_days+' day(s) — click here to do it now.';pwBar.style.display='block'}else{pwBar.style.display='none'}renderFilterBuilder('events');syncFilterControls('events');renderFilterBuilder('audit');syncFilterControls('audit');showApp();await load();await loadUsers();await loadAudit();await loadSecurity();await loadRules();await loadSavedFilters('events');if(ME.role==='admin'){await loadSavedFilters('audit');await loadLoginSecurity()}setInterval(load,10000)}
boot();
</script></body></html>'''
