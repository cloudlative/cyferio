"""Slack Integration for Notifications -- best-effort fan-out to every
configured, enabled SlackWorkspace (models.py) whose per-event toggle is
on, for the notification types listed in EVENT_GROUPS below. Sibling to
ticket_notifications.py/mailer.py: same "never block or fail the
triggering action over a delivery problem" posture -- every public
function here swallows its own exceptions and (for a real send) always
writes a SlackDeliveryLog row so a silently-broken webhook is diagnosable
from the Settings page rather than just vanishing.

Deliberately queries the SlackWorkspace table fresh on every call (like
mailer.py's own db-backed EmailProvider lookup, NOT the cached
`app_settings.runtime` object almost everything else in this app reads) --
Slack config CRUD would otherwise need its own cache-invalidation path,
and a notification send is already I/O-bound, so the extra query is
negligible. This is also what keeps this module honestly "workspace-aware"
rather than silently assuming exactly one row: every call site below asks
"which enabled workspaces want this event", never "the one webhook",
even though today's Settings page only ever creates one row.

Stdlib-only (urllib), same "no new pip dependency for a small outbound
HTTP call" convention as captcha.py/email_providers.py/health.py.
"""
import json
import re
import urllib.error
import urllib.request

from sqlalchemy.orm import Session

from .models import SlackDeliveryLog, SlackWorkspace

_WEBHOOK_RE = re.compile(r"^https://hooks\.slack\.com/services/\S+$")

# group label -> [(event_type key, label), ...] -- mirrors support_tickets.
# CATEGORIES' shape so routes/settings.py/templates/settings.html can reuse
# the same "grouped checkbox list" rendering pattern. A type not present in
# a SlackWorkspace's notify_types JSON defaults to OFF (see
# EVENT_TYPES/effective_notify_types below).
EVENT_GROUPS: dict[str, list[tuple[str, str]]] = {
    "Support Center": [
        ("ticket_created", "Ticket created"),
        ("ticket_assigned", "Ticket assigned"),
        ("ticket_updated", "Ticket updated"),
        ("ticket_resolved", "Ticket resolved"),
        ("ticket_reopened", "Ticket reopened"),
    ],
    "Security Events": [
        ("mfa_disabled", "MFA disabled"),
        ("mfa_reset", "MFA reset"),
        ("failed_login_attempts", "Multiple failed login attempts"),
        ("account_lockout", "Account lockouts"),
        ("access_restriction_violation", "Access restriction violations"),
    ],
    "System Events": [
        ("release_available", "New release available"),
        ("upgrade_assigned", "Upgrade assigned"),
        ("upgrade_completed", "Upgrade completed"),
        ("upgrade_failed", "Upgrade failed"),
    ],
    "Operational Events": [
        ("quota_warning", "Quota warnings"),
        ("critical_system_alert", "Critical system alerts"),
        ("health_check_failure", "Health check failures"),
        ("database_issue", "Database issues"),
        ("vpn_service_issue", "VPN service issues"),
    ],
}

# Flattened key -> label, built once at import time (same "don't re-flatten
# per request" precedent as support_tickets._CATEGORY_BY_SLUG).
EVENT_TYPES: dict[str, str] = {key: label for group in EVENT_GROUPS.values() for key, label in group}


def is_valid_webhook_url(url: str | None) -> bool:
    """Format-only validation -- a real https://hooks.slack.com/services/...
    URL shape. Reachability is deliberately NOT checked here (the spec
    calls that optional/best-effort) -- "Send Test Notification" is the
    actual reachability check, performed explicitly by an admin action,
    not implicitly on every settings save."""
    return bool(url and _WEBHOOK_RE.match(url.strip()))


def event_groups_for_form() -> list[dict]:
    """Shape consumed by settings.html's Slack section -- one dict per
    group, same convention as support_tickets.categories_for_form()."""
    return [{"group": group, "options": [{"key": k, "label": label} for k, label in entries]}
            for group, entries in EVENT_GROUPS.items()]


def effective_notify_types(workspace: SlackWorkspace) -> dict[str, bool]:
    try:
        raw = json.loads(workspace.notify_types or "{}")
    except (TypeError, ValueError):
        raw = {}
    return {key: bool(raw.get(key, False)) for key in EVENT_TYPES}


def get_or_create_default_workspace(db: Session) -> SlackWorkspace:
    """Same "singleton row, created on first access" shape as
    app_settings.get_settings_row -- Settings currently only ever
    manages ONE SlackWorkspace row through the Settings page, even though
    the table itself (and notify()'s query below) supports several."""
    row = db.query(SlackWorkspace).order_by(SlackWorkspace.id).first()
    if row is None:
        row = SlackWorkspace(name="Default Workspace", webhook_url="", is_enabled=False, notify_types="{}")
        db.add(row)
        db.commit()
        db.refresh(row)
    return row


def _post_webhook(webhook_url: str, text: str, channel_override: str | None = None, timeout: float = 10.0) -> None:
    payload: dict = {"text": text}
    if channel_override:
        payload["channel"] = channel_override
    req = urllib.request.Request(
        webhook_url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        if resp.status >= 300:
            raise RuntimeError(f"Slack webhook returned HTTP {resp.status}")


def _log_delivery(db: Session, *, workspace_id: int | None, event_type: str, text: str, success: bool, error_detail: str | None) -> None:
    try:
        db.add(SlackDeliveryLog(
            workspace_id=workspace_id, event_type=event_type, message_preview=text[:500],
            success=success, error_detail=(error_detail or "")[:2000] or None,
        ))
        db.commit()
    except Exception:
        # Logging the delivery attempt is itself best-effort -- a DB hiccup
        # writing the log row must never raise back into the caller's
        # already-successful (or already-handled-failure) action.
        pass


def notify(db: Session, event_type: str, text: str) -> None:
    """Fan out `text` to every enabled SlackWorkspace whose notify_types[
    event_type] is on. Best-effort and non-raising -- a webhook failure (or
    even a DB error looking up workspaces) is logged where possible and
    otherwise silently swallowed; this must never turn an otherwise-
    successful ticket/security/system event into a 500, same posture as
    mailer.py's own send_* functions and ticket_notifications.py."""
    try:
        workspaces = db.query(SlackWorkspace).filter(SlackWorkspace.is_enabled.is_(True)).all()
    except Exception:
        return
    for ws in workspaces:
        if not ws.webhook_url or not effective_notify_types(ws).get(event_type):
            continue
        try:
            _post_webhook(ws.webhook_url, text, ws.channel_override)
            _log_delivery(db, workspace_id=ws.id, event_type=event_type, text=text, success=True, error_detail=None)
        except Exception as e:
            _log_delivery(db, workspace_id=ws.id, event_type=event_type, text=text, success=False, error_detail=str(e))


def send_test_notification(db: Session, webhook_url: str, channel_override: str | None = None) -> tuple[bool, str]:
    """Settings page's "Send Test Notification" button -- posts SYNCHRONOUSLY
    against the given (typically just-typed, not-yet-saved) url/channel, same
    "test what was actually passed in" convention as mailer.
    send_test_email_via_config/email_providers.py's per-profile Test button.
    Always logs the attempt (see SlackDeliveryLog), matching a real send's
    logging -- attached to the matching saved workspace row if one exists
    with this exact webhook URL, else workspace_id=None. Returns
    (success, detail) rather than raising -- the route handler turns this
    into a toast, not a 500."""
    text = "This is a test notification from Cyferio to confirm your Slack integration is configured correctly."
    ws = db.query(SlackWorkspace).filter(SlackWorkspace.webhook_url == webhook_url).first()
    try:
        _post_webhook(webhook_url, text, channel_override)
        _log_delivery(db, workspace_id=ws.id if ws else None, event_type="test", text=text, success=True, error_detail=None)
        return True, "Test notification sent successfully."
    except Exception as e:
        detail = str(e)
        _log_delivery(db, workspace_id=ws.id if ws else None, event_type="test", text=text, success=False, error_detail=detail)
        return False, detail
