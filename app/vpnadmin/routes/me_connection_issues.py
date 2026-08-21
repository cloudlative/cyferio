""""My Connection Issues" -- the self-service rejection-visibility page's
API. Same "always resolve request.user's own VpnProfileLink, never an id
taken from the request" pattern as routes/me_vpn.py (see that module's
docstring) -- require_permission("vpn_profiles", "view"/"update") is
enough on its own, there's no separate own-vs-any scope check to make
since there's no path/query param that could name someone else's record.

Data source is ConnectionRejectionLog (models.py), fed by host-scripts/
openvpn-mac-addr-check.py via routes/host_ingest.py -- a rejection is
matched to the caller by vpn_client_name (the OpenVPN common_name), the
same claimed_name-matching approach me_vpn.py's get_my_vpn_report already
uses against the flat-file-derived rejected list.

Deliberately narrow response shape: city/ASN restrictions stay admin-only
and opaque here by design (per the feature spec) -- this endpoint never
returns an admin-configured city/ASN allow-list, only the detected value
for a given rejection plus a fixed "administrator-controlled" message.
Country is the one restriction with an existing self-service field
(User Management's UpdateProfileRequest.login_country, PATCH /api/users/me
-- see routes/users.py), so recommended_action for a country rejection
points the frontend at that existing endpoint rather than a new one.
MAC whitelisting reuses routes/me_vpn.py's POST /api/me/vpn-profile/macs
outright -- no MAC-mutation logic is duplicated here.

"Request Access Review" (see request_access_review() below) used to be a
pure audit-log write with no actual notification to anyone -- the button
said "Your administrator has been notified" but nothing left this
process. It now creates a real SupportTicket (same tables/notification
path as My Support's own "New Ticket", see routes/me_tickets.py), pre-
filled with the rejection's own category/reason/detected fields so the
user doesn't have to retype anything, and DOES notify admins (ticket_
notifications.ticket_created)."""
import json
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .. import ticket_notifications
from ..app_settings import runtime
from ..audit import log_action
from ..db import get_db
from ..models import ConnectionRejectionLog, SupportTicket, SupportTicketMessage, User
from ..permissions import has_permission, require_permission
from ..policy_store import get_policy
from ..support_tickets import DEFAULT_STATUS
from .me_tickets import _rate_limited

router = APIRouter(prefix="/api/me/connection-issues", tags=["me"])

# reason -> (category, recommended_action). Category drives the summary
# cards; recommended_action drives which control (if any) the frontend
# renders for a given row -- see my_connection_issues.html.
REASON_INFO: dict[str, tuple[str, str]] = {
    "mac_mismatch": ("mac", "whitelist_mac"),
    "os_not_allowed": ("other", "contact_admin"),
    "country_not_allowed": ("country", "update_country"),
    "country_lookup_failed": ("country", "update_country"),
    "city_not_allowed": ("city", "contact_admin"),
    "city_lookup_failed": ("city", "contact_admin"),
    "asn_not_allowed": ("asn", "contact_admin"),
    "asn_lookup_failed": ("asn", "contact_admin"),
    "ip_not_allowed": ("other", "contact_admin"),
    "bandwidth_exceeded": ("other", "upgrade_quota"),
}
CATEGORY_LABELS = {"mac": "MAC Address Issues", "country": "Country Issues", "city": "City Issues",
                    "asn": "ASN Issues", "other": "Other Security Policy Violations"}

# reason -> human label, for the auto-generated ticket subject/description
# below -- same intentional per-module duplication as reports.py's
# _FAILURE_REASON_LABELS / diagnostics.html's REJECTION_REASON_LABELS (see
# that module's own comment: independently kept working rather than
# shared across Python/JS boundaries or unrelated routers).
REASON_LABELS: dict[str, str] = {
    "mac_mismatch": "MAC Address Mismatch / Unregistered Device",
    "os_not_allowed": "Device OS Restriction",
    "country_not_allowed": "Country Restriction",
    "country_lookup_failed": "Country Lookup Failed",
    "city_not_allowed": "City Restriction",
    "city_lookup_failed": "City Lookup Failed",
    "asn_not_allowed": "Network (ASN) Restriction",
    "asn_lookup_failed": "Network (ASN) Lookup Failed",
    "ip_not_allowed": "IP Address Restriction",
    "bandwidth_exceeded": "Bandwidth Quota Exceeded",
}

# reason -> support_tickets.CATEGORIES leaf slug -- what "Request Access
# Review" picks for the auto-created ticket's category, so an admin sees
# it in the same Support Center queue/filter as a manually-filed ticket of
# the matching type, not lumped into a generic catch-all.
REASON_TO_TICKET_CATEGORY: dict[str, str] = {
    "mac_mismatch": "vpn_mac_issue",
    "os_not_allowed": "vpn_os_restriction",
    "country_not_allowed": "vpn_country_restriction",
    "country_lookup_failed": "vpn_country_restriction",
    "city_not_allowed": "vpn_city_restriction",
    "city_lookup_failed": "vpn_city_restriction",
    "asn_not_allowed": "vpn_asn_restriction",
    "asn_lookup_failed": "vpn_asn_restriction",
    "ip_not_allowed": "vpn_ip_restriction",
    "bandwidth_exceeded": "quota_bandwidth_issue",
}


def _reason_info(reason: str) -> tuple[str, str]:
    return REASON_INFO.get(reason, ("other", "contact_admin"))


@router.get("")
def list_my_connection_issues(user: User = Depends(require_permission("vpn_profiles", "view")), db: Session = Depends(get_db)):
    link = user.vpn_profile_link
    if link is None:
        raise HTTPException(status_code=404, detail="No VPN profile is linked to your account yet -- ask an admin.")

    rows = (
        db.query(ConnectionRejectionLog)
        .filter(ConnectionRejectionLog.vpn_client_name == link.vpn_client_name)
        .order_by(ConnectionRejectionLog.timestamp.desc())
        .limit(500)
        .all()
    )

    cards: dict[str, dict] = {
        key: {"category": key, "label": label, "count": 0, "last_occurrence": None}
        for key, label in CATEGORY_LABELS.items()
    }
    history = []
    for r in rows:
        category, action = _reason_info(r.reason)
        card = cards[category]
        card["count"] += 1
        if card["last_occurrence"] is None:
            card["last_occurrence"] = r.timestamp.isoformat()  # rows are already newest-first
        history.append({
            "timestamp": r.timestamp.isoformat(),
            "source_ip": r.source_ip,
            "detected_mac": r.detected_mac,
            "detected_os": r.detected_os,
            "detected_country": r.detected_country,
            "detected_city": r.detected_city,
            "detected_asn": r.detected_asn,
            "detected_asn_name": r.detected_asn_name,
            "registered_mac_at_time": r.registered_mac_at_time,
            "reason": r.reason,
            "category": category,
            "recommended_action": action,
            # Set once request_access_review() below has filed a ticket for
            # this exact row -- the frontend uses this to keep showing
            # "View Ticket #N" across a refresh instead of reverting to
            # "Request Access Review" (which would otherwise look like
            # nothing happened, and invite filing a second ticket for the
            # same rejection).
            "existing_ticket_id": r.review_ticket_id,
        })

    log_action(db, user, "self_view_connection_issues", target=link.vpn_client_name)

    policy = get_policy(link.vpn_client_name) or {}
    # login_country isn't a User column -- it's the single-entry form of
    # this client's own VPN Access Restriction (see routes/users.py's
    # update_my_profile), read the same way that endpoint writes it.
    allowed_countries = policy.get("allowed_countries") or []
    login_country = allowed_countries[0] if allowed_countries else None
    # OS restriction isn't opaque the way city/ASN allow-lists deliberately
    # are (see this module's docstring) -- unlike those, there's no
    # separate "which cities/ASNs are allowed" concept an attacker could
    # map out for reconnaissance beyond what "your OS isn't allowed"
    # already implies, so showing the actual configured list alongside the
    # detected value is just useful troubleshooting info, not a policy
    # leak. A list (not a single value like login_country) since a client
    # can be allowed more than one OS.
    allowed_os = policy.get("allowed_os") or []

    return {
        "vpn_client_name": link.vpn_client_name,
        "retention_days": runtime.connection_issue_retention_days,
        "mac_self_service_enabled": has_permission(db, user, "vpn_profiles", "update"),
        "login_country": login_country,
        "allowed_os": allowed_os,
        "cards": list(cards.values()),
        "history": history,
    }


class AuditActionRequest(BaseModel):
    action: str  # "view_details" | "copy_mac"
    target: str | None = None


# "request_access_review" used to be a third action here -- see
# request_access_review() below for why it's now its own endpoint instead
# of a pure audit-log write.
_ALLOWED_AUDIT_ACTIONS = {"view_details", "copy_mac"}


@router.post("/audit")
def audit_my_connection_issue_action(
    body: AuditActionRequest,
    user: User = Depends(require_permission("vpn_profiles", "view")),
    db: Session = Depends(get_db),
):
    """Records the read-only interactions the feature spec asks to audit
    (viewing a rejection's detail, copying a MAC) -- everything else (the
    actual whitelist/country-update actions, and now the access-review
    ticket below) is already audited by the endpoints that perform them
    and does not go through here."""
    if body.action not in _ALLOWED_AUDIT_ACTIONS:
        raise HTTPException(status_code=400, detail="Unknown audit action.")
    link = user.vpn_profile_link
    log_action(db, user, f"self_{body.action}", target=body.target or (link.vpn_client_name if link else None))
    return {"ok": True}


class RequestAccessReviewRequest(BaseModel):
    timestamp: str  # the row's own `timestamp` field, as returned by GET "" above


@router.post("/request-review", status_code=201)
def request_access_review(
    body: RequestAccessReviewRequest,
    user: User = Depends(require_permission("support_tickets", "create")),
    db: Session = Depends(get_db),
):
    """Creates a real SupportTicket from one of the caller's own rejection
    rows, pre-filled with a category matching the rejection reason
    (REASON_TO_TICKET_CATEGORY) and a description built from the row's own
    detected fields -- so the user doesn't have to retype anything, and an
    admin sees it land in Support Center with real triage info attached,
    not just an invisible audit-log line. Re-looks-up the row server-side
    by (this user's own vpn_client_name, timestamp) rather than trusting
    any rejection detail the client might pass -- same "never trust
    client-supplied content for what becomes an admin-visible record"
    posture as everywhere else in this app; timestamp is enough to
    identify the exact row since it's unique per rejection.

    Shares My Support's own per-account rate limit (routes/me_tickets.py's
    _rate_limited/_RATE_LIMITED_ACTIONS, both of which already count
    "self_ticket_created") -- this creates a ticket exactly like that
    endpoint does, so it must count against the same budget rather than
    being an unlimited side door around it."""
    link = user.vpn_profile_link
    if link is None:
        raise HTTPException(status_code=404, detail="No VPN profile is linked to your account yet -- ask an admin.")

    row = (
        db.query(ConnectionRejectionLog)
        .filter(ConnectionRejectionLog.vpn_client_name == link.vpn_client_name)
        .filter(ConnectionRejectionLog.timestamp == datetime.fromisoformat(body.timestamp))
        .one_or_none()
    )
    if row is None:
        raise HTTPException(status_code=404, detail="That rejection record could not be found.")

    if row.review_ticket_id is not None:
        # Already filed -- same row, re-submitted (double click, or a
        # request that raced a page refresh). Return the existing ticket
        # rather than creating a second one for the identical rejection;
        # this is what makes GET ""'s existing_ticket_id trustworthy across
        # a refresh instead of just a client-side illusion.
        return {"ticket_id": row.review_ticket_id}

    if _rate_limited(db, user):
        s = runtime
        raise HTTPException(
            status_code=429,
            detail=f"You've submitted {s.support_ticket_rate_limit_count} ticket actions in the last "
                   f"{s.support_ticket_rate_limit_window_minutes} minutes -- please wait before sending another.",
        )

    reason_label = REASON_LABELS.get(row.reason, row.reason)
    category = REASON_TO_TICKET_CATEGORY.get(row.reason, "other_general_inquiry")

    detail_lines = ["Automatically filed from My Connection Issues for a rejected VPN connection attempt.",
                     "", f"Reason: {reason_label}", f"Timestamp: {row.timestamp.isoformat()}"]
    if row.message:
        detail_lines.append(f"Details: {row.message}")
    if row.detected_mac:
        detail_lines.append(f"Detected MAC: {row.detected_mac}")
    if row.detected_os:
        detail_lines.append(f"Detected OS: {row.detected_os}")
    if row.detected_country:
        detail_lines.append(f"Detected Country: {row.detected_country}")
    if row.detected_city:
        detail_lines.append(f"Detected City: {row.detected_city}")
    if row.detected_asn:
        asn = row.detected_asn + (f" ({row.detected_asn_name})" if row.detected_asn_name else "")
        detail_lines.append(f"Detected Network (ASN): {asn}")
    if row.source_ip:
        detail_lines.append(f"Source IP: {row.source_ip}")

    context_snapshot = {
        "rejection_reason": row.reason, "rejection_timestamp": row.timestamp.isoformat(),
        "detected_mac": row.detected_mac, "detected_os": row.detected_os,
        "detected_country": row.detected_country, "detected_city": row.detected_city,
        "detected_asn": row.detected_asn, "detected_asn_name": row.detected_asn_name,
        "source_ip": row.source_ip,
    }

    ticket = SupportTicket(
        created_by_user_id=user.id, subject=f"VPN access review requested: {reason_label}",
        category=category, priority="high", status=DEFAULT_STATUS,
        vpn_client_name=link.vpn_client_name, context_snapshot=json.dumps(context_snapshot),
    )
    db.add(ticket)
    db.flush()  # need ticket.id for the message row below and review_ticket_id below
    message = SupportTicketMessage(ticket_id=ticket.id, author_user_id=user.id, body="\n".join(detail_lines))
    db.add(message)
    row.review_ticket_id = ticket.id
    db.commit()

    log_action(db, user, "self_ticket_created", target=f"TCK-{ticket.id}", detail=ticket.subject)
    ticket_notifications.ticket_created(db, ticket)
    return {"ticket_id": ticket.id}
