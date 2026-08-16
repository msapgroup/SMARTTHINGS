import datetime as dt
import hmac
import os
import sqlite3
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, field_validator

from .auth import hash_password, new_token, verify_password

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = Path(os.environ.get("GODSEYE_DB", BASE_DIR / "data" / "godseye.db"))

# A scanner that hasn't reported a successful run in this many seconds is
# treated as unhealthy even if the systemd unit still shows "active" -
# otherwise GODSEYE can look fine on the dashboard while silently doing
# nothing (see /api/v1/health).
HEARTBEAT_STALE_AFTER = int(os.environ.get("GODSEYE_HEARTBEAT_STALE_AFTER", "180"))

VALID_CLASSIFICATIONS = {"new", "known", "ignored", "investigate"}
VALID_ROLES = {"admin", "readonly"}

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
PASSWORD_HISTORY_COUNT = int(os.environ.get("GODSEYE_PASSWORD_HISTORY_COUNT", "5"))

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
            notes TEXT DEFAULT ''
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
        CREATE INDEX IF NOT EXISTS idx_events_created ON events(created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status);
        CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
        CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_pwhistory_user ON password_history(user_id);
        """)
        _add_column_if_missing(c, "users", "failed_attempts", "failed_attempts INTEGER NOT NULL DEFAULT 0")
        _add_column_if_missing(c, "users", "locked_until", "locked_until TEXT")
        _add_column_if_missing(c, "users", "password_changed_at", "password_changed_at TEXT")
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
            c.execute(
                "INSERT INTO users(username,password_hash,password_salt,role,must_change_password,created_at,password_changed_at) "
                "VALUES(?,?,?,'admin',1,?,?)",
                (ADMIN_DEFAULT_USER, hashed, salt, now(), now()),
            )
            print(
                f"[GODSEYE] No users found - created default admin account '{ADMIN_DEFAULT_USER}'. "
                "You will be required to set a new password on first login. Set GODSEYE_ADMIN_USER / "
                "GODSEYE_ADMIN_PASSWORD before first boot to change the seeded credentials."
            )


@asynccontextmanager
async def lifespan(app):
    init_db()
    yield


app = FastAPI(title="GODSEYE", version="0.5.0", lifespan=lifespan)


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
            "SELECT u.id AS id, u.username, u.role, u.must_change_password, u.password_changed_at, "
            "s.expires_at, s.last_seen_at "
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
    password_reset_needed = bool(row["must_change_password"]) or is_password_expired(row["password_changed_at"])
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


@app.post(f"{router_prefix}/auth/login")
def login(payload: LoginRequest, request: Request, response: Response):
    ip = client_ip(request)
    with db() as c:
        user = c.execute("SELECT * FROM users WHERE username=?", (payload.username,)).fetchone()

        if user and user["locked_until"]:
            if dt.datetime.fromisoformat(user["locked_until"]) > dt.datetime.now(dt.timezone.utc):
                audit(c, payload.username, "login_blocked_locked", ip=ip)
                raise HTTPException(423, f"Account locked due to repeated failed logins. Try again later.")
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

        token, csrf_token = new_token(), new_token()
        expires_at = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=SESSION_TTL_SECONDS)).isoformat()
        c.execute("DELETE FROM sessions WHERE expires_at < ?", (now(),))  # opportunistic cleanup
        c.execute(
            "INSERT INTO sessions(token,user_id,created_at,expires_at,last_seen_at) VALUES(?,?,?,?,?)",
            (token, user["id"], now(), expires_at, now()),
        )
        c.execute("UPDATE users SET last_login_at=?, failed_attempts=0, locked_until=NULL WHERE id=?", (now(), user["id"]))
        audit(c, user["username"], "login_success", ip=ip)
    response.set_cookie(SESSION_COOKIE, token, httponly=True, samesite="lax", secure=COOKIE_SECURE, max_age=SESSION_TTL_SECONDS, path="/")
    response.set_cookie(CSRF_COOKIE, csrf_token, httponly=False, samesite="lax", secure=COOKIE_SECURE, max_age=SESSION_TTL_SECONDS, path="/")
    return {
        "ok": True,
        "username": user["username"],
        "role": user["role"],
        "must_change_password": bool(user["must_change_password"]) or is_password_expired(user["password_changed_at"]),
    }


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
    resp = {
        "username": user["username"],
        "role": user["role"],
        "must_change_password": bool(user["must_change_password"]) or is_password_expired(user["password_changed_at"]),
    }
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
            "UPDATE users SET password_hash=?,password_salt=?,must_change_password=0,password_changed_at=? WHERE id=?",
            (hashed, salt, now(), user["id"]),
        )
        # Invalidate every session for this account, including the current one - if the
        # old password had leaked, this makes sure it can't keep a session alive.
        # The dashboard re-prompts for login with the new password right after this call.
        c.execute("DELETE FROM sessions WHERE user_id=?", (user["id"],))
        audit(c, user["username"], "password_changed", ip=client_ip(request))
    return {"ok": True}


# ---------------------------------------------------------------------------
# User management (admin only)
# ---------------------------------------------------------------------------

@app.get(f"{router_prefix}/users")
def list_users(admin=Depends(require_admin)):
    with db() as c:
        rows = c.execute(
            "SELECT id,username,role,must_change_password,created_at,last_login_at,password_changed_at FROM users ORDER BY id"
        ).fetchall()
    return [dict(r) for r in rows]


@app.post(f"{router_prefix}/users")
def create_user(payload: CreateUserRequest, request: Request, admin=Depends(require_admin)):
    salt, hashed = hash_password(payload.password)
    with db() as c:
        try:
            c.execute(
                "INSERT INTO users(username,password_hash,password_salt,role,must_change_password,created_at,password_changed_at) "
                "VALUES(?,?,?,?,1,?,?)",
                (payload.username, hashed, salt, payload.role, now(), now()),
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
            "UPDATE users SET password_hash=?,password_salt=?,must_change_password=1,failed_attempts=0,"
            "locked_until=NULL,password_changed_at=? WHERE id=?",
            (hashed, salt, now(), user_id),
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


@app.get(f"{router_prefix}/audit")
def audit_log(limit: int = 200, admin=Depends(require_admin)):
    limit = min(max(limit, 1), 1000)
    with db() as c:
        return [dict(r) for r in c.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))]


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
:root{color-scheme:dark;font-family:Inter,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}*{box-sizing:border-box}body{margin:0;background:#070b12;color:#e8eef7}header{position:sticky;top:0;z-index:5;background:rgba(7,11,18,.94);backdrop-filter:blur(14px);border-bottom:1px solid #1d2838;padding:16px 4%;display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}.brand{display:flex;gap:12px;align-items:center}.eye{width:38px;height:38px;border-radius:12px;background:#182338;display:grid;place-items:center;font-size:21px}.brand b{font-size:20px;letter-spacing:.08em}.muted{color:#7f8da3;font-size:12px}button,.filter{border:1px solid #2b3a52;background:#111a28;color:#dbe7f7;border-radius:9px;padding:9px 13px;cursor:pointer}button.primary{background:#2563eb;border-color:#2563eb}button.danger{background:#3a1522;border-color:#5c2436;color:#ff8194}button.link{background:none;border:none;color:#7f9fd8;padding:4px 6px}.headerRight{display:flex;gap:10px;align-items:center}.wrap{max-width:1500px;margin:auto;padding:28px 4%}.hero{display:flex;justify-content:space-between;gap:20px;align-items:end;margin-bottom:22px}.hero h1{font-size:32px;margin:0 0 5px}.cards{display:grid;grid-template-columns:repeat(5,1fr);gap:14px}.card{background:linear-gradient(145deg,#101927,#0d141f);border:1px solid #1d2a3d;border-radius:14px;padding:18px}.label{color:#8090a7;font-size:12px;text-transform:uppercase;letter-spacing:.1em}.num{font-size:32px;font-weight:750;margin-top:7px}.green{color:#50e3a4}.yellow{color:#f7c948}.red{color:#ff6b81}.toolbar{display:flex;gap:9px;margin:22px 0;flex-wrap:wrap}.toolbar input{flex:1;min-width:220px}.input{background:#0d141f;border:1px solid #2b3a52;border-radius:9px;padding:10px;color:#e8eef7}.panel{background:#0d141f;border:1px solid #1d2a3d;border-radius:14px;overflow:hidden;margin-top:18px}.panel h2{font-size:16px;margin:0;padding:16px 18px;border-bottom:1px solid #1d2a3d;display:flex;justify-content:space-between;align-items:center}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:12px 14px;border-bottom:1px solid #182335;font-size:13px}th{color:#72819a;font-size:11px;text-transform:uppercase;letter-spacing:.08em}tr:hover{background:#111a27}.dot{font-size:10px}.online{color:#50e3a4}.offline{color:#68758a}.suspected_offline{color:#f7c948}.pill{border:1px solid #31415a;border-radius:999px;padding:3px 8px;font-size:11px;color:#9eb0c8;cursor:pointer;background:none}.known{color:#50e3a4;border-color:#245c49}.new{color:#f7c948;border-color:#6d5a24}.investigate{color:#ff8194;border-color:#6d2e3c}.ignored{color:#72819a}.admin{color:#f7c948;border-color:#6d5a24}.readonly{color:#7f9fd8;border-color:#28406d}.name{font-weight:650}.empty{padding:35px;text-align:center;color:#72819a}.healthbar{font-size:12px;padding:8px 4%;border-bottom:1px solid #1d2838}.healthbar.ok{color:#50e3a4}.healthbar.bad{color:#ff8194}
.overlay{position:fixed;inset:0;background:#070b12;display:grid;place-items:center;z-index:50;padding:20px}.authcard{width:100%;max-width:360px;background:#101927;border:1px solid #1d2a3d;border-radius:16px;padding:28px}.authcard h2{margin:0 0 6px}.authcard form{display:flex;flex-direction:column;gap:11px;margin-top:18px}.authcard .input{width:100%}.err{color:#ff8194;font-size:13px;min-height:18px}.formRow{display:flex;gap:9px}.userForm{display:flex;gap:8px;padding:14px 18px;flex-wrap:wrap;border-bottom:1px solid #182335}.userForm .input{flex:1;min-width:120px}
@media(max-width:900px){.cards{grid-template-columns:repeat(2,1fr)}th:nth-child(5),td:nth-child(5),th:nth-child(6),td:nth-child(6){display:none}}@media(max-width:600px){.cards{grid-template-columns:1fr}.hero{align-items:start;flex-direction:column}th:nth-child(4),td:nth-child(4){display:none}.wrap{padding:20px 3%}}
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
<div id="app" style="display:none">
<div class="healthbar" id="healthbar"></div>
<header><div class="brand"><div class="eye">◉</div><div><b>GODSEYE</b><div class="muted">LOCAL NETWORK INTELLIGENCE</div></div></div>
<div class="headerRight"><span class="muted" id="whoami"></span><button id="scanBtn" class="primary" onclick="scan()">⟳ Scan Now</button><button class="link" onclick="openChangePassword()">Change password</button><button class="link" onclick="logout()">Log out</button></div>
</header>
<div class="wrap"><div class="hero"><div><h1>Network Overview</h1><div class="muted" id="updated">Loading telemetry…</div></div></div>
<div class="cards"><div class="card"><div class="label">Known Devices</div><div class="num" id="total">—</div></div><div class="card"><div class="label">Online</div><div class="num green" id="online">—</div></div><div class="card"><div class="label">Needs Review</div><div class="num yellow" id="unknown">—</div></div><div class="card"><div class="label">Events</div><div class="num" id="eventsCount">—</div></div><div class="card"><div class="label">Last Scan</div><div class="num" id="lastScan" style="font-size:16px">—</div></div></div>
<div class="toolbar"><input id="search" class="input" placeholder="Search name, IP, MAC, hostname or vendor…" oninput="loadDevices()"><select id="status" class="filter" onchange="loadDevices()"><option value="">All statuses</option><option value="online">Online</option><option value="suspected_offline">Suspected offline</option><option value="offline">Offline</option></select><select id="classification" class="filter" onchange="loadDevices()"><option value="">All classifications</option><option value="new">New</option><option value="known">Known</option><option value="investigate">Investigate</option><option value="ignored">Ignored</option></select></div>
<section class="panel"><h2>Devices</h2><div style="overflow:auto"><table><thead><tr><th>Status</th><th>Device</th><th>IP</th><th>MAC</th><th>Vendor</th><th>Classification</th></tr></thead><tbody id="devices"></tbody></table></div></section>
<section class="panel"><h2>Recent Activity</h2><div style="overflow:auto"><table><thead><tr><th>Time</th><th>Event</th><th>Device</th><th>IP</th><th>Details</th></tr></thead><tbody id="events"></tbody></table></div></section>
<section class="panel" id="usersPanel" style="display:none"><h2>Users</h2>
<form class="userForm" onsubmit="return createUser(event)"><input class="input" id="newUsername" placeholder="Username" required><input class="input" id="newUserPassword" type="password" placeholder="Password (min __MIN_PASSWORD_LENGTH__ chars)" required minlength="__MIN_PASSWORD_LENGTH__"><select class="filter" id="newUserRole"><option value="readonly">Read-only</option><option value="admin">Admin</option></select><button class="primary" type="submit">Add user</button></form>
<div style="overflow:auto"><table><thead><tr><th>Username</th><th>Role</th><th>Created</th><th>Last login</th><th>Password changed</th><th>Must change PW</th><th></th></tr></thead><tbody id="users"></tbody></table></div>
</section>
<section class="panel" id="auditPanel" style="display:none"><h2>Audit Log</h2>
<div style="overflow:auto"><table><thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Target</th><th>Details</th><th>IP</th></tr></thead><tbody id="auditRows"></tbody></table></div>
</section>
</div></div>
<script>
const esc=s=>String(s??'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
const CLASS_CYCLE={new:'known',known:'ignored',ignored:'investigate',investigate:'new'};
const CLASS_LABEL={new:'New',known:'Known',ignored:'Ignored',investigate:'Investigate'};
let ME=null;
function getCookie(name){const m=document.cookie.match('(?:^|; )'+name+'=([^;]*)');return m?decodeURIComponent(m[1]):null}
async function json(url,opt={}){opt.headers=opt.headers||{};if(opt.method&&opt.method!=='GET'){opt.headers['X-CSRF-Token']=getCookie('godseye_csrf')||''}let r=await fetch(url,opt);if(r.status===401){showLogin();throw new Error('unauthenticated')}if(!r.ok){let t=await r.text();throw new Error(t)}return r.status===204?null:r.json()}
function showLogin(){document.getElementById('app').style.display='none';document.getElementById('pwOverlay').style.display='none';document.getElementById('authOverlay').style.display='grid'}
function showApp(){document.getElementById('authOverlay').style.display='none';document.getElementById('pwOverlay').style.display='none';document.getElementById('app').style.display='block'}
async function doLogin(e){e.preventDefault();const err=document.getElementById('loginErr');err.textContent='';try{let r=await fetch('/api/v1/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:loginUser.value,password:loginPass.value})});if(r.status===423){err.textContent='Account temporarily locked due to repeated failed logins. Try again later.';return false}if(!r.ok){err.textContent='Invalid username or password';return false}let data=await r.json();if(data.must_change_password){document.getElementById('authOverlay').style.display='none';document.getElementById('pwOverlay').style.display='grid';return false}await boot()}catch(e){err.textContent='Sign-in failed'}return false}
function openChangePassword(){document.getElementById('pwOverlay').style.display='grid'}
async function doChangePassword(e){e.preventDefault();const err=document.getElementById('pwErr');err.textContent='';try{await json('/api/v1/auth/change-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({current_password:curPass.value,new_password:newPass.value})});await boot()}catch(e){err.textContent='Could not change password — check your current password'}return false}
async function logout(){await fetch('/api/v1/auth/logout',{method:'POST',headers:{'X-CSRF-Token':getCookie('godseye_csrf')||''}});showLogin()}
async function loadDevices(){let q=new URLSearchParams();if(search.value)q.set('search',search.value);if(status.value)q.set('status',status.value);if(classification.value)q.set('classification',classification.value);let d=await json('/api/v1/devices?'+q);const canEdit=ME&&ME.role==='admin';devices.innerHTML=d.length?d.map(x=>`<tr><td class="${esc(x.status)}"><span class="dot">●</span> ${esc(x.status).replace('_',' ')}</td><td><div class="name">${esc(x.name||x.hostname||'Unknown device')}</div><div class="muted">${esc(x.device_type||'Unclassified')}</div></td><td>${esc(x.ip)}</td><td>${esc(x.mac)}</td><td>${esc(x.vendor||'—')}</td><td><button class="pill ${esc(x.classification)}" ${canEdit?`onclick="cycleClass(${x.id},'${x.classification}')"`:'disabled'}>${CLASS_LABEL[x.classification]||x.classification}</button></td></tr>`).join(''):'<tr><td colspan="6" class="empty">No devices match this filter.</td></tr>'}
async function loadUsers(){if(!ME||ME.role!=='admin'){usersPanel.style.display='none';return}usersPanel.style.display='block';let u=await json('/api/v1/users');users.innerHTML=u.map(x=>`<tr><td>${esc(x.username)}</td><td><span class="pill ${esc(x.role)}">${esc(x.role)}</span></td><td>${esc(new Date(x.created_at).toLocaleDateString())}</td><td>${x.last_login_at?esc(new Date(x.last_login_at).toLocaleString()):'never'}</td><td>${x.password_changed_at?esc(new Date(x.password_changed_at).toLocaleDateString()):'—'}</td><td>${x.must_change_password?'yes':'no'}</td><td>${x.username===ME.username?'':`<button class="link" onclick="removeUser(${x.id},'${esc(x.username)}')">Remove</button>`}</td></tr>`).join('')}
async function loadAudit(){if(!ME||ME.role!=='admin'){auditPanel.style.display='none';return}auditPanel.style.display='block';let a=await json('/api/v1/audit?limit=50');auditRows.innerHTML=a.length?a.map(x=>`<tr><td>${esc(new Date(x.created_at).toLocaleString())}</td><td>${esc(x.actor)}</td><td><span class="pill">${esc(x.action)}</span></td><td>${esc(x.target||'—')}</td><td>${esc(x.details||'')}</td><td>${esc(x.ip||'—')}</td></tr>`).join(''):'<tr><td colspan="6" class="empty">No audit entries yet.</td></tr>'}
async function createUser(e){e.preventDefault();try{await json('/api/v1/users',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:newUsername.value,password:newUserPassword.value,role:newUserRole.value})});newUsername.value='';newUserPassword.value='';await loadUsers()}catch(e){alert('Could not create user: '+e.message)}return false}
async function removeUser(id,username){if(!confirm('Remove user "'+username+'"?'))return;await json('/api/v1/users/'+id,{method:'DELETE'});await loadUsers()}
async function load(){let h=await json('/api/v1/health');total.textContent=h.total;online.textContent=h.online;unknown.textContent=h.needs_review;eventsCount.textContent=h.events;updated.textContent='Last refreshed '+new Date().toLocaleTimeString();lastScan.textContent=h.scanner.detail;const hb=document.getElementById('healthbar');if(!h.scanner.healthy){hb.className='healthbar bad';hb.textContent='⚠ Scanner unhealthy — '+h.scanner.detail;hb.style.display='block'}else{hb.style.display='none'}await loadDevices();let e=await json('/api/v1/events?limit=30');events.innerHTML=e.length?e.map(x=>`<tr><td>${esc(new Date(x.created_at).toLocaleString())}</td><td><span class="pill">${esc(x.event_type)}</span></td><td>${esc(x.mac)}</td><td>${esc(x.ip)}</td><td>${esc(x.details)}</td></tr>`).join(''):'<tr><td colspan="5" class="empty">No activity yet.</td></tr>'}
async function cycleClass(id,current){await json('/api/v1/devices/'+id,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({classification:CLASS_CYCLE[current]||'new'})});load()}
async function scan(){await json('/api/v1/scan',{method:'POST'});updated.textContent='Scan requested…';setTimeout(load,3000)}
async function boot(){try{ME=await json('/api/v1/auth/me')}catch(e){showLogin();return}whoami.textContent=ME.username+' ('+ME.role+')'+(ME.password_expires_in_days!==undefined?' · password expires in '+ME.password_expires_in_days+'d':'');scanBtn.style.display=ME.role==='admin'?'inline-block':'none';showApp();await load();await loadUsers();await loadAudit();setInterval(load,10000)}
boot();
</script></body></html>'''
