"""Outbound alert notifications: generic webhook, ntfy, and email.

Stdlib only (urllib.request, smtplib) - no new dependency, consistent with
the rest of the project. All three channels are opt-in via env vars and
independent of each other; none are required.

Design intent: GODSEYE doesn't hardcode a specific PSA/ticketing
integration (e.g. ConnectWise Manage) because those typically need
per-company OAuth credentials that can't be generically configured here,
and hardcoding one vendor's API shape means it silently breaks when that
vendor changes their API. Instead, GODSEYE_WEBHOOK_URL can point at
anything that accepts a POST - a PSA's own webhook/API endpoint if it has
one, or middleware (Power Automate, Zapier, n8n, a small serverless
function) that holds those credentials and creates the ticket. See the
README's Alerting section for worked examples.

Every send_* function is best-effort: a failure here must never interrupt
scanning, so exceptions are caught and logged, never raised further.
"""
import json
import os
import smtplib
import ssl
import urllib.error
import urllib.request
from email.message import EmailMessage

SEVERITY_ORDER = {"info": 0, "warning": 1, "critical": 2}

WEBHOOK_URL = os.environ.get("GODSEYE_WEBHOOK_URL", "")
WEBHOOK_MIN_SEVERITY = os.environ.get("GODSEYE_WEBHOOK_MIN_SEVERITY", "warning")
WEBHOOK_AUTH_HEADER = os.environ.get("GODSEYE_WEBHOOK_AUTH_HEADER", "")  # e.g. "Authorization"
WEBHOOK_AUTH_VALUE = os.environ.get("GODSEYE_WEBHOOK_AUTH_VALUE", "")   # e.g. "Bearer xyz..."

NTFY_SERVER = os.environ.get("GODSEYE_NTFY_SERVER", "https://ntfy.sh")
NTFY_TOPIC = os.environ.get("GODSEYE_NTFY_TOPIC", "")
NTFY_MIN_SEVERITY = os.environ.get("GODSEYE_NTFY_MIN_SEVERITY", "warning")

SMTP_HOST = os.environ.get("GODSEYE_SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("GODSEYE_SMTP_PORT", "587"))
SMTP_USER = os.environ.get("GODSEYE_SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("GODSEYE_SMTP_PASSWORD", "")
SMTP_FROM = os.environ.get("GODSEYE_SMTP_FROM", "")
SMTP_TO = os.environ.get("GODSEYE_SMTP_TO", "")
EMAIL_MIN_SEVERITY = os.environ.get("GODSEYE_EMAIL_MIN_SEVERITY", "critical")

# Storm protection: a subnet-detection hiccup that suddenly "discovers" a
# backlog of devices, or any other burst, should not fire 50 webhook calls /
# create 50 PSA tickets in one scan cycle.
MAX_NOTIFICATIONS_PER_SCAN = int(os.environ.get("GODSEYE_MAX_NOTIFICATIONS_PER_SCAN", "10"))


def _meets_threshold(severity: str, min_severity: str) -> bool:
    return SEVERITY_ORDER.get(severity, 0) >= SEVERITY_ORDER.get(min_severity, 1)


def send_webhook(event: dict):
    if not WEBHOOK_URL or not _meets_threshold(event["severity"], WEBHOOK_MIN_SEVERITY):
        return
    data = json.dumps(event).encode("utf-8")
    req = urllib.request.Request(WEBHOOK_URL, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    if WEBHOOK_AUTH_HEADER and WEBHOOK_AUTH_VALUE:
        req.add_header(WEBHOOK_AUTH_HEADER, WEBHOOK_AUTH_VALUE)
    urllib.request.urlopen(req, timeout=8)


def send_ntfy(event: dict):
    if not NTFY_TOPIC or not _meets_threshold(event["severity"], NTFY_MIN_SEVERITY):
        return
    url = f"{NTFY_SERVER.rstrip('/')}/{NTFY_TOPIC}"
    body = event.get("details", "") or event["event_type"]
    req = urllib.request.Request(url, data=body.encode("utf-8"), method="POST")
    req.add_header("Title", f"GODSEYE: {event['event_type']}")
    req.add_header("Priority", "urgent" if event["severity"] == "critical" else "default")
    tag = {"critical": "rotating_light", "warning": "warning"}.get(event["severity"], "information_source")
    req.add_header("Tags", tag)
    urllib.request.urlopen(req, timeout=8)


def send_email(event: dict):
    if not (SMTP_HOST and SMTP_FROM and SMTP_TO) or not _meets_threshold(event["severity"], EMAIL_MIN_SEVERITY):
        return
    msg = EmailMessage()
    msg["Subject"] = f"GODSEYE alert: {event['event_type']} ({event['severity']})"
    msg["From"] = SMTP_FROM
    msg["To"] = SMTP_TO
    msg.set_content(
        f"Event: {event['event_type']}\n"
        f"Severity: {event['severity']}\n"
        f"Device MAC: {event.get('mac', '')}\n"
        f"IP: {event.get('ip', '')}\n"
        f"Time: {event.get('created_at', '')}\n"
        f"Details: {event.get('details', '')}\n"
    )
    context = ssl.create_default_context()
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
        server.starttls(context=context)
        if SMTP_USER:
            server.login(SMTP_USER, SMTP_PASSWORD)
        server.send_message(msg)


class NotificationDispatcher:
    """Fans a scan cycle's events out to every configured channel, capping
    the total per cycle so a burst of events can't cause an alert storm."""

    def __init__(self):
        self.sent_this_scan = 0

    def reset(self):
        self.sent_this_scan = 0

    def notify(self, event: dict) -> bool:
        """Returns True if this event was dispatched (or attempted),
        False if it was suppressed by the per-scan cap."""
        if self.sent_this_scan >= MAX_NOTIFICATIONS_PER_SCAN:
            return False
        self.sent_this_scan += 1
        for fn in (send_webhook, send_ntfy, send_email):
            try:
                fn(event)
            except Exception as exc:
                print(f"[GODSEYE] notification channel failed ({fn.__name__}): {exc}")
        return True
