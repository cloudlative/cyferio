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
outright -- no MAC-mutation logic is duplicated here."""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..app_settings import runtime
from ..audit import log_action
from ..db import get_db
from ..models import ConnectionRejectionLog, User
from ..permissions import has_permission, require_permission
from ..policy_store import get_policy

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
            "detected_country": r.detected_country,
            "detected_city": r.detected_city,
            "detected_asn": r.detected_asn,
            "detected_asn_name": r.detected_asn_name,
            "registered_mac_at_time": r.registered_mac_at_time,
            "reason": r.reason,
            "category": category,
            "recommended_action": action,
        })

    log_action(db, user, "self_view_connection_issues", target=link.vpn_client_name)

    # login_country isn't a User column -- it's the single-entry form of
    # this client's own VPN Access Restriction (see routes/users.py's
    # update_my_profile), read the same way that endpoint writes it.
    allowed_countries = (get_policy(link.vpn_client_name) or {}).get("allowed_countries") or []
    login_country = allowed_countries[0] if allowed_countries else None

    return {
        "vpn_client_name": link.vpn_client_name,
        "retention_days": runtime.connection_issue_retention_days,
        "mac_self_service_enabled": has_permission(db, user, "vpn_profiles", "update"),
        "login_country": login_country,
        "cards": list(cards.values()),
        "history": history,
    }


class AuditActionRequest(BaseModel):
    action: str  # "view_details" | "copy_mac" | "request_access_review"
    target: str | None = None


_ALLOWED_AUDIT_ACTIONS = {"view_details", "copy_mac", "request_access_review"}


@router.post("/audit")
def audit_my_connection_issue_action(
    body: AuditActionRequest,
    user: User = Depends(require_permission("vpn_profiles", "view")),
    db: Session = Depends(get_db),
):
    """Records the read-only interactions the feature spec asks to audit
    (viewing a rejection's detail, copying a MAC, requesting an access
    review) -- everything else (the actual whitelist/country-update
    actions) is already audited by the existing endpoints those buttons
    call (self_add_mac, self_update_profile) and does not go through here."""
    if body.action not in _ALLOWED_AUDIT_ACTIONS:
        raise HTTPException(status_code=400, detail="Unknown audit action.")
    link = user.vpn_profile_link
    log_action(db, user, f"self_{body.action}", target=body.target or (link.vpn_client_name if link else None))
    return {"ok": True}
