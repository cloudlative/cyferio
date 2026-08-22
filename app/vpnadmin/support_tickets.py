"""Support Ticketing System -- shared constants (statuses, priorities,
categories) used by routes/me_tickets.py (self-service) and routes/
tickets.py (admin console). Plain Python dicts/tuples, not a Postgres
native Enum column in models.py -- adding a new category or status here
never needs db.py's _sync_enum_values() ALTER TYPE dance, same reasoning
as email_providers.PROVIDERS/AppSettings.default_quota_enforcement_policy
already being plain strings.

Deliberately NOT admin-editable from the Settings page in this version
(see the ticketing feature's plan, "Deliberately NOT made tweakable") --
unlike rate limits/attachment sizing, the status set is load-bearing for
every permission/lifecycle check in routes/tickets.py and routes/
me_tickets.py; an ad-hoc admin-added status would silently bypass those
checks rather than just changing a threshold.
"""
from sqlalchemy import update
from sqlalchemy.orm import Session

from .models import SupportTicket

# Ordered for display (e.g. a status <select>) -- not alphabetical.
#
# Simplified 2026-08-23 (5 statuses for a regular ticket, down from 9) --
# reported live: too many statuses that never meant anything different in
# practice. "new" and "open" had no behavioral distinction anywhere in
# routes/tickets.py -- merged into "open". "waiting_for_admin" and
# "in_progress" both just meant "an admin owns this, the submitter has
# nothing to do" -- merged into "in_progress". "reopened" was a landing pad
# identical to "open" in every allowed-transition sense, existing only to
# mark *how* a ticket got there -- a distinction audit.log_action already
# records permanently (self_ticket_reopen), with a timestamp and actor,
# more precisely than a status column ever could -- so reopening now lands
# straight on "open".
#
# "assigned"/"completed"/"failed"/"cancelled" are UNCHANGED -- these belong
# to the Upgrade Assignment Workflow (System Maintenance category, see
# CATEGORIES below) and are never offered to a regular support ticket (see
# REGULAR_STATUSES and allowed_next_statuses()'s category-aware filtering
# below). "in_progress" already existed and is reused as-is for "an admin
# is actively working an upgrade" (same meaning either way -- "someone's on
# it right now"), but "resolved"/"closed" mean something subtly different
# for a normal support conversation (the submitter's issue is settled) than
# a maintenance/upgrade action's own outcome ("completed" = the upgrade ran
# successfully; "failed" = it didn't; "cancelled" = it was called off
# without running) -- conflating them would make every status-based report/
# filter ambiguous about which kind of ticket it's summarizing. "assigned"
# fills the gap between "open" and "in_progress": an admin has claimed the
# ticket (assigned_admin_id is set, via the existing PATCH endpoint) but
# hasn't started the actual maintenance work yet.
STATUSES: tuple[str, ...] = (
    "open", "in_progress", "resolved", "waiting_for_user", "closed",
    "assigned", "completed", "failed", "cancelled",
)

STATUS_LABELS: dict[str, str] = {
    "open": "Open",
    "in_progress": "In Progress",
    "resolved": "Resolved",
    "waiting_for_user": "Waiting on Customer",
    "closed": "Closed",
    "assigned": "Assigned",
    "completed": "Completed",
    "failed": "Failed",
    "cancelled": "Cancelled",
}

# The statuses a REGULAR support ticket (any category not starting
# "sysmaint_") may ever sit in or move to. Excludes the Upgrade Assignment
# Workflow's own statuses ("assigned"/"completed"/"failed"/"cancelled"),
# which mean something specific to a maintenance action's outcome and were
# never meant to be a normal conversation's next status -- see
# allowed_next_statuses() below, which is what actually enforces this.
REGULAR_STATUSES: frozenset[str] = frozenset({"open", "in_progress", "waiting_for_user", "resolved", "closed"})

# Statuses a self-service reply is blocked from -- must be reopened first
# (POST /{id}/reopen) per the confirmed lifecycle: "Reopen allowed, but no
# replies until reopened." Admin replies are never blocked by this -- an
# admin can always add a note/reply regardless of status. "completed"/
# "failed"/"cancelled" are terminal in the same sense as "resolved"/
# "closed" (no further self-service reply expected) -- these are
# system-generated maintenance tickets, so this mostly matters for
# routes/tickets.py's own "moving OUT of a terminal status clears the
# terminal timestamps" handling treating them consistently.
TERMINAL_STATUSES: frozenset[str] = frozenset({"resolved", "closed", "completed", "failed", "cancelled"})

# Status Workflow Rules (Enhanced Ticket Management Controls) -- current
# status -> the set of statuses a PATCH is allowed to move it to next.
# Before this existed, routes/tickets.py's update_ticket() accepted any
# STATUSES value from any other one -- e.g. Closed straight back to New,
# skipping every intermediate step a real support/collaboration tool
# (Jira, Linear, Zendesk, ...) would force you through. Reported live
# 2026-08-21: "I can see that ticket can be moved to status New from
# closed ticket."
#
# Design:
#   - A terminal status (TERMINAL_STATUSES above) can ONLY move to "open"
#     -- never straight back to another active working status, and never
#     sideways to a different terminal status either (e.g. Resolved can't
#     jump straight to Cancelled -- reopen it first). This mirrors routes/
#     me_tickets.py's self-service reopen_my_ticket, which already enforces
#     exactly this ("Only a Resolved or Closed ticket can be reopened") --
#     the admin console follows the identical rule instead of being able
#     to bypass it via the generic PATCH endpoint. This is the one hard
#     rule that actually matters here -- it's what a real collaboration
#     tool (Jira's "Reopen" transition clearing the Resolution field,
#     Linear/ClickUp's "Done"/"Cancelled" columns not being drag-targets
#     from each other) universally enforces, and it's the exact bug
#     reported live 2026-08-21 ("ticket can be moved to status New from
#     closed ticket"). Reopening a terminal ticket lands it on "open"
#     directly (no separate "reopened" status, see the STATUSES comment
#     above for why) -- same destination the old rule's dedicated
#     "reopened" status meant in practice, since "reopened" only ever
#     behaved like a fresh "open" ticket from that point on anyway.
#   - Every non-terminal ("active") status can move to ANY other status --
#     including terminal ones (an admin can resolve/close/complete/fail/
#     cancel a ticket from wherever it currently sits, without being
#     forced through a rigid step-by-step sequence first) and including
#     each other (open -> in_progress directly is common -- an admin
#     picking up a fresh ticket and diving straight in shouldn't have to
#     detour through an intermediate status first). Real collaboration
#     tools are deliberately permissive here; the workflow discipline they
#     actually enforce is almost always just "terminal states are one-way
#     doors without an explicit reopen", not a rigid linear sequence for
#     everything before that.
#   - Same-status "transitions" (body.status == ticket.status) are always
#     a no-op regardless of this table -- routes/tickets.py's
#     update_ticket() only consults TRANSITIONS when the value is actually
#     changing.
#
# This table itself is category-agnostic (mirrors the raw STATUSES set,
# "assigned"/"completed"/"failed"/"cancelled" included) -- the regular-vs-
# sysmaint distinction is applied afterwards, by allowed_next_statuses()
# below, so a caller always gets back only the statuses actually meaningful
# for the ticket it's asking about.
ACTIVE_STATUSES: frozenset[str] = frozenset(set(STATUSES) - TERMINAL_STATUSES)
TRANSITIONS: dict[str, frozenset[str]] = {
    **{s: frozenset(set(STATUSES) - {s}) for s in ACTIVE_STATUSES},
    **{s: frozenset({"open"}) for s in TERMINAL_STATUSES},
}


def allowed_next_statuses(current_status: str, category: str | None = None) -> frozenset[str]:
    """The set of statuses `current_status` may PATCH into next, per
    TRANSITIONS above. An unrecognized current_status (shouldn't happen --
    DB values are only ever written from STATUSES) allows nothing rather
    than raising, so a caller can always safely iterate the result.

    `category` narrows the result to REGULAR_STATUSES whenever it's a
    regular (non-"sysmaint_") ticket -- so a normal support conversation's
    status picker never offers "Assigned"/"Completed"/"Failed"/"Cancelled",
    which mean something specific to the Upgrade Assignment Workflow and
    were never a meaningful next step for a support conversation. Passing
    None (the default) skips this narrowing -- existing callers that don't
    have a category handy (or genuinely want the full set) are unaffected.
    """
    candidates = TRANSITIONS.get(current_status, frozenset())
    if category is not None and not category.startswith("sysmaint_"):
        candidates = candidates & REGULAR_STATUSES
    return candidates


PRIORITIES: tuple[str, ...] = ("low", "medium", "high", "critical")
PRIORITY_LABELS: dict[str, str] = {"low": "Low", "medium": "Medium", "high": "High", "critical": "Critical"}
DEFAULT_PRIORITY = "medium"
DEFAULT_STATUS = "open"

# group label -> [(slug, label, guidance), ...]. `guidance` pre-fills the
# description field's placeholder/helper text once a category is picked
# (the "category selection should automatically pre-fill helpful fields
# and guidance" requirement) -- plain hint text, not a rich template.
CATEGORIES: dict[str, list[tuple[str, str, str]]] = {
    "VPN Access Issues": [
        ("vpn_cannot_connect", "Cannot connect to VPN",
         "When did this start? Which device/OS? Paste any error message OpenVPN shows."),
        ("vpn_auth_failure", "Authentication failure",
         "What error do you see when connecting? Have you changed your password recently?"),
        ("vpn_mac_issue", "Device/MAC address issue",
         "Which device are you trying to connect from? Check My VPN Profile > My Connection Issues first -- "
         "a MAC mismatch there can usually be self-resolved."),
        ("vpn_country_restriction", "Country restriction issue",
         "Which country are you connecting from? Check My Connection Issues for the exact restriction reason."),
        ("vpn_city_restriction", "City restriction issue", "Which city are you connecting from?"),
        ("vpn_asn_restriction", "ASN restriction issue", "Which ISP/network are you connecting from?"),
        ("vpn_os_restriction", "Device OS restriction issue", "Which device/OS are you connecting from? Check My Connection Issues for the exact restriction reason."),
        ("vpn_ip_restriction", "IP address restriction issue", "Which IP address are you connecting from? Check My Connection Issues for the exact restriction reason."),
        ("vpn_profile_issue", "VPN profile issue", "Describe what's wrong with your VPN profile/.ovpn file."),
    ],
    "Account Issues": [
        ("account_password_reset", "Password reset request",
         "Use the \"Forgot password\" link on the login page first -- only open a ticket if that didn't work."),
        ("account_mfa_setup_issue", "MFA setup issue", "Which authenticator app are you using, and what happens when you try to scan the QR code or enter a code?"),
        ("account_lost_authenticator", "Lost authenticator device",
         "If you still have a recovery code, use it to sign in and regenerate your codes yourself from Profile -- otherwise an admin will need to reset MFA on your account."),
        ("account_recovery_code_issue", "Recovery code issue", "What happens when you enter the recovery code? Have you used it before?"),
        ("account_mfa_reset_request", "MFA reset request", "An admin will reset your MFA enrollment -- you'll be asked to set it up again at your next login."),
        ("account_profile_issue", "Profile Issues", "Describe what's wrong with your account profile."),
        ("account_profile_update", "Profile update request", "What would you like updated on your account?"),
    ],
    "Usage & Quota": [
        ("quota_bandwidth_issue", "Bandwidth quota issue", "Check My VPN Profile for your current usage/quota first."),
        ("quota_speed_concern", "Speed limitation concern", "When and how are you measuring the slow speed?"),
        ("quota_connection_drops", "Connection drops", "How often does the connection drop, and for how long have you been connected first?"),
    ],
    "Technical Problems": [
        ("tech_portal_issue", "Portal issue", "Which page, and what happens?"),
        ("tech_dashboard_issue", "Dashboard issue", "Which page, and what happens?"),
        ("tech_bug_report", "Bug report", "Steps to reproduce, what you expected, and what actually happened."),
        ("tech_feature_request", "Feature request", "What would you like to see added or changed?"),
    ],
    "Other": [
        ("other_general_inquiry", "General inquiry", "Tell us what you need help with."),
        ("other_other", "Other", "Describe your issue."),
    ],
    # Upgrade Assignment Workflow -- system-generated tickets only
    # (release_check.py's file_upgrade_ticket, auto-created when a new
    # Cyferio release is detected), not offered on the self-service "New
    # Ticket" form (see CONTEXT_SUGGESTED_GROUPS below, and
    # me_tickets.py's category validation, which only checks
    # is_valid_category -- an admin/system creating one of these is fine,
    # a user picking "Application Upgrade" for their own VPN issue isn't
    # meaningful, but nothing here technically forbids it since this app
    # has no separate "system-only category" flag; the guidance text makes
    # that clear if a user ever does encounter it via the API).
    "System Maintenance": [
        ("sysmaint_application_upgrade", "Application Upgrade",
         "System-generated when a new Cyferio release is detected. Claim this ticket (assign it to "
         "yourself) to track your work through the upgrade."),
        ("sysmaint_security_update", "Security Update",
         "A security-relevant release is available -- treat this with priority per your maintenance policy."),
        ("sysmaint_emergency_patch", "Emergency Patch", "An urgent, out-of-band fix that shouldn't wait for the next regular maintenance window."),
        ("sysmaint_infrastructure_maintenance", "Infrastructure Maintenance", "Host/infrastructure-level maintenance unrelated to an application release."),
    ],
}

# leaf slug -> (label, guidance) -- built once at import time so routes
# don't re-flatten CATEGORIES on every request.
_CATEGORY_BY_SLUG: dict[str, tuple[str, str]] = {
    slug: (label, guidance)
    for entries in CATEGORIES.values()
    for slug, label, guidance in entries
}
# Categories whose guidance implies the "attach my current diagnostic
# context" checkbox should default to checked in the UI -- VPN/usage
# issues benefit from it, account/technical/other ones rarely do.
_CONTEXT_SUGGESTED_GROUPS = ("VPN Access Issues", "Usage & Quota")
CONTEXT_SUGGESTED_SLUGS: frozenset[str] = frozenset(
    slug for group in _CONTEXT_SUGGESTED_GROUPS for slug, _label, _guidance in CATEGORIES[group]
)


def is_valid_category(slug: str) -> bool:
    return slug in _CATEGORY_BY_SLUG


def category_label(slug: str) -> str:
    return _CATEGORY_BY_SLUG.get(slug, (slug, ""))[0]


def status_label(status: str) -> str:
    return STATUS_LABELS.get(status, status)


def status_sort_key(status: str) -> int:
    """Canonical STATUSES order (Open, In Progress, Resolved, Waiting on
    Customer, Closed, ...) rather than alphabetical -- used anywhere a
    status <select>'s options are built from a set (allowed_next_statuses
    returns a frozenset, with no ordering of its own) so the dropdown
    always lists options in the same order regardless of which subset
    happens to be allowed for a given ticket. An unrecognized status
    (shouldn't happen) sorts last rather than raising."""
    try:
        return STATUSES.index(status)
    except ValueError:
        return len(STATUSES)


def priority_label(priority: str) -> str:
    return PRIORITY_LABELS.get(priority, priority)


def categories_for_form() -> list[dict]:
    """Shape consumed by support.html's category <select> (grouped
    <optgroup>s) -- one dict per group, each with its leaf options."""
    return [
        {
            "group": group,
            "options": [
                {"slug": slug, "label": label, "guidance": guidance, "context_suggested": slug in CONTEXT_SUGGESTED_SLUGS}
                for slug, label, guidance in entries
            ],
        }
        for group, entries in CATEGORIES.items()
    ]


# One-time (idempotent, safe on every startup) data migration for the
# 2026-08-23 status simplification above: remaps every existing
# SupportTicket row still sitting on one of the 4 retired statuses to its
# replacement, so nothing is left pointing at a status value STATUSES no
# longer recognizes. Regular (non-"sysmaint_") "new"/"assigned" both merge
# into "open"/"in_progress" the same as any other regular ticket would --
# "assigned" was only ever meaningful for a sysmaint ticket in the first
# place (see the STATUSES comment above), so a regular ticket sitting on it
# was already a misuse this migration also happens to clean up. Sysmaint
# tickets keep "assigned" untouched (it's not a retired status) and their
# "new" rows merge into "open" exactly like a regular ticket's would --
# same reasoning, no sysmaint-specific case needed.
_RETIRED_STATUS_REMAP: dict[str, str] = {
    "new": "open",
    "waiting_for_admin": "in_progress",
    "reopened": "open",
}


def migrate_legacy_ticket_statuses(db: Session) -> None:
    """Idempotent: every UPDATE below is a no-op once no row matches its
    WHERE clause, which is true after the first successful run -- safe to
    call on every startup, same posture as every other one-time migration
    in this codebase (see e.g. app_settings.migrate_ticket_email_notify_
    types). A regular ticket sitting on the sysmaint-only "assigned" status
    (never valid for it, but nothing enforced that before this migration
    existed -- see REGULAR_STATUSES) is folded into "in_progress" too, the
    same destination "waiting_for_admin" gets, since both meant "an admin
    owns this" for a regular conversation.
    """
    for old_status, new_status in _RETIRED_STATUS_REMAP.items():
        db.execute(update(SupportTicket).where(SupportTicket.status == old_status).values(status=new_status))
    db.execute(
        update(SupportTicket)
        .where(SupportTicket.status == "assigned", ~SupportTicket.category.startswith("sysmaint_"))
        .values(status="in_progress")
    )
    db.commit()
