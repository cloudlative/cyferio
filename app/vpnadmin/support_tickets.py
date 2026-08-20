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

# Ordered for display (e.g. a status <select>) -- not alphabetical.
STATUSES: tuple[str, ...] = (
    "new", "open", "in_progress", "waiting_for_user", "waiting_for_admin",
    "resolved", "closed", "reopened",
)

STATUS_LABELS: dict[str, str] = {
    "new": "New",
    "open": "Open",
    "in_progress": "In Progress",
    "waiting_for_user": "Waiting for User",
    "waiting_for_admin": "Waiting for Admin",
    "resolved": "Resolved",
    "closed": "Closed",
    "reopened": "Reopened",
}

# Statuses a self-service reply is blocked from -- must be reopened first
# (POST /{id}/reopen) per the confirmed lifecycle: "Reopen allowed, but no
# replies until reopened." Admin replies are never blocked by this -- an
# admin can always add a note/reply regardless of status.
TERMINAL_STATUSES: frozenset[str] = frozenset({"resolved", "closed"})

PRIORITIES: tuple[str, ...] = ("low", "medium", "high", "critical")
PRIORITY_LABELS: dict[str, str] = {"low": "Low", "medium": "Medium", "high": "High", "critical": "Critical"}
DEFAULT_PRIORITY = "medium"
DEFAULT_STATUS = "new"

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
