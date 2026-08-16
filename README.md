# GODSEYE

**GODSEYE** is a lightweight, local-first Raspberry Pi 4 network intelligence and monitoring appliance inspired by Pi.Alert.

## Current release: 0.6

- Automatic ARP LAN discovery with `arp-scan`
- Persistent SQLite inventory
- New-device, disconnect, reconnect and IP-change events, tagged with severity
- Three-state device lifecycle (online / suspected offline / offline) that tolerates a missed scan or two before flagging a device gone
- Device classification (new / known / ignored / investigate) instead of a blunt trusted flag
- Session-based authentication with admin and read-only roles; forced password change on first login
- Two-factor authentication (TOTP - Google Authenticator, Authy, 1Password, etc.) with one-time backup codes
- Account lockout after repeated failed logins, idle session timeout, CSRF protection, security headers
- Optional password rotation (30/90/180 days) and password history/reuse prevention
- Admin-viewable audit log of logins, password changes, and administrative actions
- Device names, type and notes
- Search, status and classification filtering
- Activity history
- Scanner health heartbeat, surfaced on the dashboard if scans go stale
- Mobile-friendly dark dashboard
- Manual scan requests (admin only)
- Privilege separation: scanner is isolated from the web application
- systemd services for automatic startup/restart

## Screenshots

<p>
  <img src="docs/screenshots/login.png" width="400" alt="Login screen"><br>
  <em>Login</em>
</p>
<p>
  <img src="docs/screenshots/mfa-setup.png" width="700" alt="Two-factor authentication setup"><br>
  <em>Two-factor setup - scan or enter the key into Google Authenticator or any TOTP app</em>
</p>
<p>
  <img src="docs/screenshots/dashboard-full.png" width="700" alt="Full dashboard"><br>
  <em>Dashboard - devices, activity, security panel, users, and audit log</em>
</p>

These are real renders of the actual dashboard HTML/CSS/JavaScript shipped
in `app/main.py`, served against realistic sample data rather than a live
Raspberry Pi deployment - useful for seeing what the UI looks like without
having hardware to hand. If you'd like to swap these for screenshots of
your own running instance, they're easy to regenerate: run GODSEYE, log
in, and capture the browser window.

## Architecture

The web application runs as the unprivileged `godseye` user. Only `godseye-scanner.service` runs as root because `arp-scan` needs elevated network privileges. Both services share the SQLite database through the `godseye` group.

## Raspberry Pi installation

```bash
sudo apt update
sudo apt install -y git
sudo git clone https://github.com/msapgroup/SMARTTHINGS.git /opt/godseye-src
cd /opt/godseye-src
sudo bash install.sh
```

The installer installs the application under `/opt/godseye` and creates two services:

```bash
sudo systemctl status godseye-web
sudo systemctl status godseye-scanner
```

Then open `http://<raspberry-pi-ip>:8080` from a device on your LAN.

## Authentication

On first boot with an empty database, GODSEYE creates a default admin
account:

- Username: `GodsEye`
- Password: `GodsEye`

**You will be forced to set a new password the first time you log in** —
this is enforced by the server, not just hidden behind the UI. To avoid
the well-known default entirely, set `GODSEYE_ADMIN_USER` and
`GODSEYE_ADMIN_PASSWORD` in `godseye-web.service` *before* the first boot
(the seed only runs once, when the `users` table is empty).

Once logged in as an admin, add additional accounts from the **Users**
panel on the dashboard, or via the API:

```bash
curl -X POST http://<pi-ip>:8080/api/v1/users \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: <value of the godseye_csrf cookie>" \
  --cookie "godseye_session=<your session cookie>" \
  -d '{"username":"family","password":"a-strong-password","role":"readonly"}'
```

Roles:
- **admin** — full access: view everything, change device classification, trigger scans, manage users
- **readonly** — can view devices, events, and health, but cannot change anything

### Two-factor authentication

Any account (admin or read-only) can enable TOTP-based two-factor
authentication from the **Two-Factor Authentication** panel on the
dashboard: scan the setup key into Google Authenticator, Authy,
1Password, or any standard TOTP app, confirm with a code, and save the
10 one-time backup codes shown afterward (each works once, for when the
device with your authenticator app isn't available). Once enabled, login
requires the password *and* a current code.

If a device with an enrolled authenticator is lost, an admin can reset
MFA for that account from the Users panel — this turns MFA off so the
user can re-enroll; nobody but the account holder can turn it back on,
since that requires access to their own authenticator app.

MFA is implemented with the standard TOTP algorithm (RFC 6238) using only
the Python standard library — no external dependency, no cloud service.

## Configuration

Set these as `Environment=` lines in the systemd unit files (or export them before running `python -m app` / `python -m app.scanner` in development). All are optional; defaults are shown.

| Variable | Default | Applies to | Purpose |
| --- | --- | --- | --- |
| `GODSEYE_DB` | `<app dir>/data/godseye.db` | both | SQLite database path |
| `GODSEYE_SCAN_INTERVAL` | `60` | scanner | Seconds between scan cycles |
| `GODSEYE_SUSPECTED_THRESHOLD` | `1` | scanner | Consecutive missed scans before a device is marked suspected offline |
| `GODSEYE_OFFLINE_THRESHOLD` | `3` | scanner | Consecutive missed scans before a device is marked offline and a disconnect event is logged |
| `GODSEYE_HEARTBEAT_STALE_AFTER` | `180` | web | Seconds since the scanner's last successful run before the dashboard reports it unhealthy |
| `GODSEYE_ADMIN_USER` | `GodsEye` | web | Username seeded for the first admin account (only used when the `users` table is empty) |
| `GODSEYE_ADMIN_PASSWORD` | `GodsEye` | web | Password seeded for the first admin account — must be changed on first login regardless |
| `GODSEYE_SESSION_TTL` | `604800` (7 days) | web | Absolute session lifetime in seconds |
| `GODSEYE_IDLE_TIMEOUT` | `900` (15 min) | web | Session is invalidated after this many seconds of inactivity, independent of the absolute TTL |
| `GODSEYE_MAX_FAILED_ATTEMPTS` | `5` | web | Failed logins before an account is temporarily locked |
| `GODSEYE_LOCKOUT_SECONDS` | `900` (15 min) | web | How long an account stays locked after too many failed attempts |
| `GODSEYE_MIN_PASSWORD_LENGTH` | `12` | web | Minimum password length (NIST 800-63B requires ≥8; longer is encouraged over composition rules) |
| `GODSEYE_PASSWORD_MAX_AGE_DAYS` | `0` (disabled) | web | Force a password change after N days — see the note below before enabling |
| `GODSEYE_PASSWORD_HISTORY_COUNT` | `5` | web | How many previous passwords are remembered and blocked from reuse |
| `GODSEYE_COOKIE_SECURE` | `false` | web | Set `true` if GODSEYE sits behind a TLS-terminating reverse proxy, to mark cookies `Secure` |
| `GODSEYE_LOGIN_BANNER` | *(empty)* | web | Optional text shown above the login form (e.g. an organizational consent/warning banner) |

## Development

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 -m app
```

## Security & compliance alignment

GODSEYE is not certified or accredited against any framework, and no
software project can self-declare that — accreditation (an ATO, a HIPAA
risk assessment sign-off, a bar association's approval) is granted by an
authorizing body after formal review, not earned by writing code. This
section is an honest map of what's actually implemented against
well-known guidance, and — just as importantly — what isn't, because
those gaps matter for anyone evaluating this for a regulated environment.

**NIST SP 800-63B (Digital Identity Guidelines) — implemented:**
- Memorized secrets hashed with a salted, iterated one-way function
  (`hashlib.pbkdf2_hmac`, 260,000 iterations — 800-63B's minimum for this
  construction is 10,000)
- Minimum password length ≥8 (default 12), no arbitrary composition rules
  (no forced "must contain a symbol" rules — length is a better predictor
  of strength, per 800-63B section 5.1.1.2)
- A basic blocklist of known-weak/default passwords is checked; 800-63B's
  fuller recommendation — checking against breach-corpus databases like
  Have I Been Pwned — needs an internet connection GODSEYE deliberately
  doesn't require for its core function, so it isn't implemented
- Rate limiting / account lockout on repeated failed authentication
  attempts
- Session timeout, both idle and absolute
- **Mandatory periodic password rotation is *disabled by default*, per
  800-63B's explicit recommendation against it** — forcing regular
  rotation tends to produce weaker, more predictable passwords without a
  demonstrated security benefit. `GODSEYE_PASSWORD_MAX_AGE_DAYS` (e.g. 30,
  90, or 180) is available for organizations whose own policy or a
  different, still-current compliance baseline requires it regardless.
- **Not implemented:** multi-factor authentication (800-63B recommends
  MFA at AAL2+; GODSEYE is currently single-factor password auth only —
  on the roadmap).

**General technical safeguards (map loosely onto NIST 800-53 control
families and HIPAA Security Rule technical safeguards, §164.312):**
- Access control / unique user identification — per-account usernames,
  role separation (admin vs. read-only)
- Audit controls — `audit_log` table records logins, lockouts, password
  changes, user management, device classification changes, and manual
  scans, viewable in an admin-only dashboard panel
- Automatic logoff — idle session timeout (configurable)
- Integrity — CSRF protection on all state-changing requests
- **Not addressed by the application, and not addressable by application
  code alone:**
  - *Encryption at rest.* SQLite has no built-in encryption. The
    database file's confidentiality depends on the Pi's disk — use full-disk
    encryption (e.g. LUKS) if this matters for your data.
  - *Encryption in transit.* GODSEYE serves plain HTTP by design (LAN-only,
    see the security note below). Put a TLS-terminating reverse proxy in
    front of it if you need encryption in transit, and set
    `GODSEYE_COOKIE_SECURE=true` when you do.
  - *Business Associate Agreements, breach notification procedures,
    workforce training, risk assessments, physical safeguards.* These are
    organizational and legal requirements, not something a codebase
    provides.

**Legal industry (e.g. ABA Model Rule 1.6 confidentiality, 1.1 competence
re: technology):** there's no single technical standard analogous to
HIPAA here — these are professional-conduct rules about safeguarding
client information, satisfied through a combination of technical controls
*and* firm policy, training, and vendor agreements. The technical controls
above (access control, audit logging, session management) support that
obligation but don't discharge it on their own.

**If you're evaluating GODSEYE for a regulated deployment:** treat this
section as a starting checklist for your own risk assessment, not a
substitute for one.

## Roadmap

Near-term, following the phased plan in `docs/roadmap.md`:

- Alert/rule engine on top of the new event severity field
- OUI/manufacturer lookup and better automatic device classification
- ntfy / Telegram / email notification plugins
- Device detail and historical timelines
- Ping and service monitoring, internet/DNS health
- Network topology map, router/AP integrations, Wake-on-LAN
- Raspberry Pi health metrics
- Backup/restore and database retention controls
- Automatic updates


