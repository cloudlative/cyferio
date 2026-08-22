"""Per-event notification preferences for the two channels that never had
any (or had only one coarse, all-or-nothing) admin control before this:
outbound ticket admin EMAIL, and the in-app notification bell.

Sibling to slack_notifications.py, and deliberately styled after it --
Slack Integration's "one checkbox per event type, grouped under a
category heading" UX is exactly what this module extends to the other
two channels, at an admin's request to have the same granularity
everywhere rather than Email staying stuck on one all-or-nothing toggle
(notify_admin_on_ticket_created) while Slack already had five.

Two independent event lists, not one shared one, because the two
channels' events genuinely aren't the same shape:
  - TICKET_EMAIL_EVENTS covers only the 4 admin-facing ticket events that
    ticket_notifications.py's _notify_admins() actually sends an email
    for today (see that module) -- narrowly scoped to "subdivide the one
    existing toggle", not "invent new email-worthy events".
  - BELL_EVENT_GROUPS covers every kind already written unconditionally
    to QuotaNotification/TicketNotification/AuditNotification (see
    routes/notifications.py's three _serialize_* functions for the exact
    kind strings this mirrors) -- a genuinely new capability (the bell
    never had any per-kind toggle before), so it's scoped to "everything
    the bell can already show", not "everything Slack/Email can send".

Default semantics differ between the two for the same reason they differ
in the docstrings above: a ticket-email key missing from stored JSON
defaults to False (matches notify_admin_on_ticket_created's own historical
default-off), a bell key missing from stored JSON defaults to True (the
bell showed everything unconditionally before this shipped, so "not yet
configured" must mean "keep showing everything", not "show nothing")."""
import json

# (event_type key, label) -- shown as a single ungrouped checkbox list
# under the Ticket Email Notifications section, since every one of these
# is already "Support Center" (no other category applies to admin ticket
# email today, unlike the bell/Slack lists below which span several).
TICKET_EMAIL_EVENTS: list[tuple[str, str]] = [
    ("ticket_created", "New ticket created"),
    ("ticket_critical", "Ticket marked critical priority"),
    ("ticket_reply", "User replied to a ticket"),
    ("ticket_reopened", "Ticket reopened"),
]
TICKET_EMAIL_KEYS: set[str] = {key for key, _ in TICKET_EMAIL_EVENTS}


def ticket_email_events_for_form() -> list[dict]:
    """Shape consumed by settings.html's Ticket Email Notifications
    section -- flat list, same convention as slack_notifications.
    event_groups_for_form()'s per-group "options" shape, just with no
    group wrapper since there's only ever the one category here."""
    return [{"key": key, "label": label} for key, label in TICKET_EMAIL_EVENTS]


def effective_ticket_email_types(raw_json: str | None) -> dict[str, bool]:
    try:
        raw = json.loads(raw_json or "{}")
    except (TypeError, ValueError):
        raw = {}
    return {key: bool(raw.get(key, False)) for key in TICKET_EMAIL_KEYS}


def ticket_email_enabled(raw_json: str | None, event_type: str) -> bool:
    """Called from ticket_notifications.py at each admin-email send site.
    An unrecognized event_type (a typo, or a call site added later without
    updating TICKET_EMAIL_EVENTS) is treated as disabled, not enabled --
    fail closed on "should this send an email", same posture the rest of
    this app's notification gating already takes."""
    return effective_ticket_email_types(raw_json).get(event_type, False)


# group label -> [(event_type key, label), ...] -- same shape as
# slack_notifications.EVENT_GROUPS, grouped by which producer actually
# writes the notification row (Support Center's ticket_notifications.py,
# main.py's quota loop, system_audit/__init__.py's finding notifier).
BELL_EVENT_GROUPS: dict[str, list[tuple[str, str]]] = {
    "Support Center": [
        ("ticket_created", "New ticket created"),
        ("ticket_critical", "Ticket marked critical priority"),
        ("ticket_reply", "New reply (either direction)"),
        ("ticket_reopened", "Ticket reopened"),
        ("ticket_assigned", "Ticket assigned to you"),
        ("ticket_status_changed", "Ticket status changed"),
    ],
    "Bandwidth Quota": [
        ("quota_warning", "Quota warning threshold crossed"),
        ("quota_critical", "Quota critical threshold crossed"),
    ],
    "System Audit": [
        ("audit_new_critical", "New Critical finding"),
        ("audit_new_high", "New High finding"),
        ("audit_score_dropped", "Security score dropped"),
        ("audit_finding_regressed", "Previously resolved finding returned"),
    ],
}
BELL_EVENT_KEYS: set[str] = {key for group in BELL_EVENT_GROUPS.values() for key, _ in group}


def bell_event_groups_for_form() -> list[dict]:
    """Shape consumed by settings.html's In-App Notifications (Bell)
    section -- identical structure to slack_notifications.
    event_groups_for_form(), deliberately: same rendering code on the
    frontend handles both grids."""
    return [{"group": group, "options": [{"key": k, "label": label} for k, label in entries]}
            for group, entries in BELL_EVENT_GROUPS.items()]


def effective_bell_types(raw_json: str | None) -> dict[str, bool]:
    try:
        raw = json.loads(raw_json or "{}")
    except (TypeError, ValueError):
        raw = {}
    return {key: bool(raw.get(key, True)) for key in BELL_EVENT_KEYS}


def bell_enabled(raw_json: str | None, event_type: str) -> bool:
    """Called from every bell-notification producer (ticket_notifications.
    py, main.py's quota loop, system_audit/__init__.py) immediately before
    writing a QuotaNotification/TicketNotification/AuditNotification row.
    An unrecognized event_type is treated as enabled, not disabled -- the
    opposite fail-direction from ticket_email_enabled above, because this
    channel's whole default posture is "show it unless told not to"."""
    return effective_bell_types(raw_json).get(event_type, True)
