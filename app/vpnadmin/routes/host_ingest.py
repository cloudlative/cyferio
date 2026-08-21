"""Host -> app ingestion for rejected VPN connect attempts.

host-scripts/openvpn-mac-addr-check.py's reject() best-effort POSTs here on
every rejected OpenVPN client-connect, in addition to (not instead of) its
pre-existing flat-file write to /etc/openvpn/server/openvpn.log
(vpn-status.py --rejected-connections keeps parsing that file unchanged).
This is the only endpoint in the app authenticated by a static shared
secret rather than a user session -- there is no logged-in user on the
other end, just a host-side root cron/client-connect script -- so it
deliberately does NOT sit behind auth.py's session machinery or
permissions.py's RBAC, only the bearer-token check below.

Fails closed on THIS side (missing/wrong token -> 401, no row written): the
host script's own try/except around the POST is what makes the *overall*
system fail open (a network hiccup or this endpoint being unreachable never
blocks or slows a real connect decision -- see openvpn-mac-addr-check.py's
reject() for that half)."""
from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .. import slack_notifications
from ..config import settings
from ..db import get_db
from ..models import ConnectionRejectionLog

router = APIRouter(prefix="/internal", tags=["internal"])


def _require_host_token(authorization: str | None = Header(default=None)) -> None:
    token = settings.HOST_INGEST_TOKEN
    if not token:
        raise HTTPException(status_code=401, detail="Host ingestion is not configured.")
    if authorization != f"Bearer {token}":
        raise HTTPException(status_code=401, detail="Invalid or missing host ingestion token.")


class ConnectionRejectionIn(BaseModel):
    vpn_client_name: str
    reason: str
    message: str | None = None
    source_ip: str | None = None
    detected_mac: str | None = None
    detected_country: str | None = None
    detected_city: str | None = None
    detected_asn: str | None = None
    detected_asn_name: str | None = None
    detected_os: str | None = None
    # What was actually on file for this identity at the MOMENT of
    # rejection (mac_mismatch only) -- see
    # models.ConnectionRejectionLog.registered_mac_at_time's docstring for
    # why this is frozen here rather than looked up live later.
    registered_mac: str | None = None


@router.post("/connection-rejections", status_code=201, dependencies=[Depends(_require_host_token)])
def ingest_connection_rejection(body: ConnectionRejectionIn, db: Session = Depends(get_db)):
    row = ConnectionRejectionLog(
        vpn_client_name=body.vpn_client_name.strip()[:64],
        reason=body.reason.strip()[:32],
        message=(body.message or "")[:2000] or None,
        source_ip=(body.source_ip or "")[:64] or None,
        detected_mac=(body.detected_mac or "")[:32] or None,
        detected_country=(body.detected_country or "")[:8] or None,
        detected_city=(body.detected_city or "")[:128] or None,
        detected_asn=(body.detected_asn or "")[:16] or None,
        detected_asn_name=(body.detected_asn_name or "")[:255] or None,
        detected_os=(body.detected_os or "")[:64] or None,
        registered_mac_at_time=(body.registered_mac or "")[:255] or None,
    )
    db.add(row)
    db.commit()
    # Every reason this endpoint ever receives IS a VPN Access Restriction
    # violation (mac_mismatch, os_not_allowed, country/city/asn/ip_not_
    # allowed) -- host-scripts/openvpn-mac-addr-check.py's reject() is the
    # ONLY caller, and it only calls this for a rejected connect attempt.
    # Best-effort, same fail-soft posture as every other best-effort call
    # in this app -- a Slack hiccup must never affect the 201 this
    # unprivileged host-side script is waiting on.
    slack_notifications.notify(
        db, "access_restriction_violation",
        f":no_entry: VPN access restriction violation: '{row.vpn_client_name}' rejected ({row.reason})"
        + (f" from {row.source_ip}" if row.source_ip else "") + ".",
    )
    return {"id": row.id}
