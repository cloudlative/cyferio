"""VPN Device Availability Monitoring & Offline Alert Notifications --
watches VPN profiles an admin has opted into monitoring (a branch-office
gateway, an always-on server, a kiosk -- anything expected to keep a
continuous VPN connection) and raises Email/Slack alerts when one drops
offline for longer than its configured threshold, with a recovery
notification and cooldown/maintenance-mode noise controls. Sibling to
release_check.py (the periodic-check-with-admin-configurable-interval
shape) and ticket_notifications.py/slack_notifications.py (the
email+Slack fan-out shape) -- this module is mostly those two patterns
combined, not a new one.

Design decisions worth calling out (see the task's own "make these
yourself" list):

  - "Last seen"/current connection status is read straight from
    cli_wrapper.get_status_all_snapshot() -- the exact same background-
    refreshed snapshot the Clients page renders from (vpn-status.py
    --all-clients: name/status/last_seen). No new "is this device
    connected" data source was invented; this only ADDS a threshold,
    history, and alerting layer on top of data the app already collects
    every DASHBOARD_REFRESH_INTERVAL_SECONDS.

  - The periodic check (run_offline_check, below) follows release_check.py's
    "admin-configurable interval" shape (runtime.
    device_monitoring_check_interval_minutes, Settings -> Device
    Monitoring) but is run EAGERLY on its own background loop (main.py's
    _device_monitoring_loop), not lazily on page load like release_check --
    unlike a release check (a real outbound network call worth rate-
    limiting), this is a local computation over an already-cached snapshot
    plus a handful of DB rows, so there's no cost/rate-limit reason to defer
    it to a request. Same shape as main.py's _quota_notification_loop.

  - Monitoring CONFIG lives as columns on the existing VpnProfileLink (the
    only place a VPN profile and a portal user are already tied together)
    rather than a new parallel entity -- see that model's own comment.
    Mutable per-tick STATE (current status, offline-since, alert cooldown
    bookkeeping) is its own table, VpnDeviceStatus, and outage HISTORY (for
    the availability report) is VpnDeviceOutage -- see both models'
    docstrings for why state/history are split out from config.

  - "Expected Connectivity: Business Hours Only / Custom Schedule" are
    captured on the config (VpnProfileLink.expected_connectivity) and shown
    back to the admin, but the offline-check tick below does NOT yet apply
    a schedule window to them -- every monitored device is checked and
    alerted 24x7 regardless of this field today. Building real schedule-
    aware suppression (timezones, business-hour definitions, per-day
    overrides) is a meaningfully sized feature on its own; shipping a
    silent no-op for two of the three dropdown options would be worse than
    just being honest that this is a V1 gap (see this module's CHANGELOG-
    style note in the plan/report, not hidden). "Always Connected (24x7)"
    -- the option that matters for the primary "branch gateway dropped
    off the network" use case -- is fully implemented.

  - Extensibility: CHECK_TYPES below is the only "pluggable check type"
    surface actually needed to keep a future heartbeat/latency/packet-loss/
    tunnel-health check from requiring a rearchitect -- VpnDeviceStatus and
    VpnDeviceOutage are already keyed by (vpn_client_name, check_type), and
    VpnProfileLink.check_type says which check applies to a given profile.
    Nothing else is speculative: there's no plugin registry, no abstract
    "Check" base class with unused hook methods -- just the one column and
    the one dict, per the task's explicit "don't over-build" instruction.
"""
import json
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from . import app_settings, cli_wrapper, mailer, slack_notifications
from .audit import log_action
from .models import User, VpnDeviceOutage, VpnDeviceStatus, VpnProfileLink

# object_key/action reused from the existing "vpn_profiles" RBAC object for
# every route in this feature (config CRUD, the dashboard widget, and the
# report) -- see permissions.OBJECTS's own comment on why a new object_key
# isn't warranted for a feature that's really just "more detail about VPN
# profiles a role can already see/manage".

CHECK_TYPES: dict[str, str] = {
    "connectivity": "Connectivity (VPN Online/Offline)",
}

EXPECTED_CONNECTIVITY_CHOICES: dict[str, str] = {
    "always": "Always Connected (24x7)",
    "business_hours": "Business Hours Only",
    "custom": "Custom Schedule",
}

# Offline Detection Threshold dropdown -- fixed choices per the feature
# spec (not a free-typed number) so every admin picks from the same well-
# understood set; still stored as a plain int column so nothing downstream
# needs to know this is drawn from a fixed list.
OFFLINE_THRESHOLD_CHOICES_MINUTES = (1, 5, 10, 15, 30, 60)

ALERT_COOLDOWN_MODES: dict[str, str] = {
    "once": "Send one alert, then stay silent until reconnect",
    "repeat": "Repeat while still offline",
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: datetime | None) -> datetime | None:
    """SQLite (this app's test/dev backend) silently drops tzinfo on
    DateTime(timezone=True) columns on read-back, even though every
    timestamp this app ever stores is UTC regardless of backend -- see
    auth.py's own _as_aware_utc for the identical issue/fix on the
    password-reset-token path. Every DB-loaded datetime this module does
    arithmetic against goes through this first so a naive-vs-aware
    TypeError can't happen on SQLite while staying a no-op on Postgres
    (this app's real deployment target, which round-trips tzinfo fine)."""
    if dt is None:
        return None
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def _format_duration(seconds: float) -> str:
    """'42 Minutes' / '2h 15m' -- matches the feature spec's example
    message text ("Offline Duration: 15 Minutes") for anything under an
    hour, switches to an hours+minutes form beyond that so a long outage's
    duration stays readable rather than "812 Minutes"."""
    minutes = max(0, round(seconds / 60))
    if minutes < 60:
        return f"{minutes} Minute{'s' if minutes != 1 else ''}"
    hours, rem = divmod(minutes, 60)
    return f"{hours}h {rem}m"


def get_or_create_status(db: Session, vpn_client_name: str, check_type: str = "connectivity") -> VpnDeviceStatus:
    row = db.query(VpnDeviceStatus).filter_by(vpn_client_name=vpn_client_name, check_type=check_type).first()
    if row is None:
        row = VpnDeviceStatus(vpn_client_name=vpn_client_name, check_type=check_type, current_status="unknown")
        db.add(row)
        db.flush()
    return row


def device_label(link: VpnProfileLink) -> str:
    return link.monitoring_name or link.vpn_client_name


def _resolve_email_recipients(db: Session, link: VpnProfileLink) -> list[str]:
    addresses: list[str] = []
    if link.notify_assigned_user and link.user and link.user.email:
        addresses.append(link.user.email)
    if link.notify_admin_user_ids:
        try:
            admin_ids = json.loads(link.notify_admin_user_ids)
        except (TypeError, ValueError):
            admin_ids = []
        if admin_ids:
            admins = db.query(User).filter(User.id.in_(admin_ids), User.is_active.is_(True), User.deleted.is_(False)).all()
            addresses.extend(a.email for a in admins if a.email)
    if link.notify_additional_emails:
        try:
            addresses.extend(json.loads(link.notify_additional_emails) or [])
        except (TypeError, ValueError):
            pass
    return addresses


def _build_message(link: VpnProfileLink, *, kind: str, offline_duration_seconds: float, last_connected: str | None) -> tuple[str, str]:
    """Returns (subject, body_text) in the exact field layout the feature
    spec's example messages use -- one shared builder for both channels
    (email body and Slack text) since the content is identical, only the
    transport differs."""
    name = device_label(link)
    username = link.user.username if link.user else "(unlinked)"
    duration = _format_duration(offline_duration_seconds)
    if kind == "offline":
        subject = f"VPN Device Offline Alert: {name}"
        lines = [
            "\U0001f6a8 VPN Device Offline Alert",
            f"Device: {name}",
            f"User: {username}",
            f"VPN Profile: {link.vpn_client_name}",
            f"Last Connected: {last_connected or 'Unknown'}",
            f"Offline Duration: {duration}",
            "Status: Offline",
            "Action Recommended: Verify internet connectivity and VPN service availability.",
        ]
    else:
        subject = f"VPN Device Reconnected: {name}"
        lines = [
            "✅ VPN Device Reconnected",
            f"Device: {name}",
            f"User: {username}",
            f"VPN Profile: {link.vpn_client_name}",
            f"Offline Duration: {duration}",
            "Status: Connected",
        ]
    return subject, "\n".join(lines)


def _notify(db: Session, link: VpnProfileLink, *, kind: str, offline_duration_seconds: float, last_connected: str | None) -> None:
    """Fan out one offline/recovery alert to this device's configured
    channels. Best-effort throughout -- see mailer.send_device_monitoring_
    alert and slack_notifications.notify's own fail-soft postures; a
    delivery failure here must never interrupt the offline-check tick for
    every OTHER monitored device."""
    subject, body = _build_message(link, kind=kind, offline_duration_seconds=offline_duration_seconds, last_connected=last_connected)
    sent_any = False
    if link.notify_email_enabled:
        recipients = _resolve_email_recipients(db, link)
        if recipients:
            try:
                if mailer.send_device_monitoring_alert(db=db, to_addresses=recipients, subject=subject, body=body):
                    sent_any = True
            except Exception:
                pass
    if link.notify_slack_enabled:
        event_type = "vpn_device_offline" if kind == "offline" else "vpn_device_online"
        try:
            slack_notifications.notify(db, event_type, body)
            sent_any = True
        except Exception:
            pass
    if sent_any:
        system_user = link.user  # attribution: the alert is ABOUT this user's device, not performed BY anyone
        if system_user:
            log_action(
                db, system_user, "device_monitoring_notification_sent",
                target=link.vpn_client_name,
                detail=f"kind={kind}; channels=email:{link.notify_email_enabled} slack:{link.notify_slack_enabled}",
            )


def _should_send_offline_alert(link: VpnProfileLink, status: VpnDeviceStatus, now: datetime) -> bool:
    if status.last_alert_sent_at is None:
        return True
    if link.alert_cooldown_mode != "repeat":
        return False
    repeat_minutes = link.alert_cooldown_repeat_minutes or app_settings.runtime.device_monitoring_default_cooldown_minutes
    return (now - _aware(status.last_alert_sent_at)) >= timedelta(minutes=repeat_minutes)


def _open_outage(db: Session, link: VpnProfileLink, started_at: datetime) -> VpnDeviceOutage:
    outage = VpnDeviceOutage(vpn_client_name=link.vpn_client_name, check_type=link.check_type, started_at=started_at)
    db.add(outage)
    db.flush()
    return outage


def _close_open_outage(db: Session, link: VpnProfileLink, ended_at: datetime) -> None:
    outage = (
        db.query(VpnDeviceOutage)
        .filter_by(vpn_client_name=link.vpn_client_name, check_type=link.check_type, ended_at=None)
        .order_by(VpnDeviceOutage.started_at.desc())
        .first()
    )
    if outage is None:
        return
    outage.ended_at = ended_at
    outage.duration_seconds = max(0, int((ended_at - _aware(outage.started_at)).total_seconds()))


def _mark_open_outage_alerted(db: Session, link: VpnProfileLink) -> None:
    outage = (
        db.query(VpnDeviceOutage)
        .filter_by(vpn_client_name=link.vpn_client_name, check_type=link.check_type, ended_at=None)
        .order_by(VpnDeviceOutage.started_at.desc())
        .first()
    )
    if outage is not None:
        outage.alerted = True


def _expire_maintenance_mode_if_due(db: Session, link: VpnProfileLink, now: datetime) -> None:
    if link.maintenance_mode and link.maintenance_mode_until and now >= _aware(link.maintenance_mode_until):
        link.maintenance_mode = False
        link.maintenance_mode_until = None
        if link.user:
            log_action(db, link.user, "device_monitoring_maintenance_disabled", target=link.vpn_client_name, detail="auto-expired")


def _process_device(db: Session, link: VpnProfileLink, status_by_name: dict, now: datetime) -> None:
    _expire_maintenance_mode_if_due(db, link, now)

    status_row = status_by_name.get(link.vpn_client_name)
    live_online = bool(status_row and status_row.get("status") == "online")
    device_status = get_or_create_status(db, link.vpn_client_name, link.check_type)

    if live_online:
        was_offline = device_status.current_status == "offline"
        device_status.last_seen_at = now
        if was_offline:
            offline_seconds = (now - _aware(device_status.offline_since or now)).total_seconds()
            _close_open_outage(db, link, now)
            if link.notify_on_recovery and device_status.alert_count > 0 and not link.maintenance_mode:
                last_connected = device_status.offline_since.isoformat() if device_status.offline_since else None
                _notify(db, link, kind="online", offline_duration_seconds=offline_seconds, last_connected=last_connected)
            if link.user:
                log_action(db, link.user, "device_monitoring_online_restored", target=link.vpn_client_name,
                            detail=f"offline_for={_format_duration(offline_seconds)}")
        device_status.current_status = "online"
        device_status.offline_since = None
        device_status.last_alert_sent_at = None
        device_status.alert_count = 0
        return

    # Not live-online: either still connected-per-cert-but-unreachable, or
    # genuinely never seen -- either way, the monitoring engine's own
    # threshold (not the raw live status) is what decides "offline" here.
    if device_status.current_status != "offline":
        device_status.current_status = "offline"
        device_status.offline_since = now
        device_status.last_alert_sent_at = None
        device_status.alert_count = 0
        _open_outage(db, link, now)
        if link.user:
            log_action(db, link.user, "device_monitoring_offline_detected", target=link.vpn_client_name,
                        detail=f"threshold_minutes={link.offline_threshold_minutes}")

    offline_seconds = (now - _aware(device_status.offline_since or now)).total_seconds()
    if offline_seconds < link.offline_threshold_minutes * 60:
        return  # within grace period -- not yet alert-worthy (dashboard widget shows this as "warning")
    if link.maintenance_mode:
        return  # suppressed -- status/outage history still tracked above, only notification is skipped
    if not _should_send_offline_alert(link, device_status, now):
        return

    last_connected = status_row.get("last_seen") if status_row else None
    if last_connected in (None, "never", "now (connected)"):
        last_connected = device_status.last_seen_at.isoformat() if device_status.last_seen_at else None
    _notify(db, link, kind="offline", offline_duration_seconds=offline_seconds, last_connected=last_connected)
    _mark_open_outage_alerted(db, link)
    device_status.last_alert_sent_at = now
    device_status.alert_count += 1


def run_offline_check(db: Session) -> int:
    """One tick of the periodic offline check -- called by main.py's
    _device_monitoring_loop on a timer (runtime.
    device_monitoring_check_interval_minutes). Returns the number of
    monitored devices processed (surfaced nowhere critical today, just
    useful for a test/log assertion).

    Reads cli_wrapper.get_status_all_snapshot() ONCE per tick, not once per
    device -- that snapshot is itself already a cached, background-
    refreshed read (see cli_wrapper's own docstring), so this adds no new
    subprocess spawns of its own regardless of how many devices are being
    monitored."""
    links = db.query(VpnProfileLink).filter(VpnProfileLink.monitoring_enabled.is_(True)).all()
    if not links:
        return 0
    status_by_name = {row["name"]: row for row in cli_wrapper.get_status_all_snapshot()}
    for link in links:
        _process_device(db, link, status_by_name, _now())
    db.commit()
    return len(links)


# --- Config CRUD helpers (routes/clients.py) --------------------------------

def serialize_config(link: VpnProfileLink) -> dict:
    return {
        "monitoring_enabled": link.monitoring_enabled,
        "monitoring_name": link.monitoring_name,
        "check_type": link.check_type,
        "expected_connectivity": link.expected_connectivity,
        "offline_threshold_minutes": link.offline_threshold_minutes,
        "notify_email_enabled": link.notify_email_enabled,
        "notify_slack_enabled": link.notify_slack_enabled,
        "notify_assigned_user": link.notify_assigned_user,
        "notify_admin_user_ids": json.loads(link.notify_admin_user_ids) if link.notify_admin_user_ids else [],
        "notify_additional_emails": json.loads(link.notify_additional_emails) if link.notify_additional_emails else [],
        "notify_on_recovery": link.notify_on_recovery,
        "alert_cooldown_mode": link.alert_cooldown_mode,
        "alert_cooldown_repeat_minutes": link.alert_cooldown_repeat_minutes,
        "maintenance_mode": link.maintenance_mode,
        "maintenance_mode_note": link.maintenance_mode_note,
        "maintenance_mode_until": link.maintenance_mode_until.isoformat() if link.maintenance_mode_until else None,
    }


def serialize_status(db: Session, link: VpnProfileLink) -> dict:
    status = db.query(VpnDeviceStatus).filter_by(vpn_client_name=link.vpn_client_name, check_type=link.check_type).first()
    if status is None:
        return {"current_status": "unknown", "last_seen_at": None, "offline_since": None, "offline_duration_seconds": None}
    offline_seconds = None
    if status.current_status == "offline" and status.offline_since:
        offline_seconds = max(0, (_now() - _aware(status.offline_since)).total_seconds())
    return {
        "current_status": status.current_status,
        "last_seen_at": status.last_seen_at.isoformat() if status.last_seen_at else None,
        "offline_since": status.offline_since.isoformat() if status.offline_since else None,
        "offline_duration_seconds": offline_seconds,
    }


# --- Dashboard widget ("Critical VPN Devices") ------------------------------

def widget_snapshot(db: Session) -> dict:
    """GET /api/monitoring/dashboard's data -- every monitored device's
    live-ish status (from VpnDeviceStatus, at most one check interval
    stale, same trade-off as every other snapshot-backed widget in this
    app) plus the Online/Offline/Warning counts the widget's summary row
    shows. "Warning" = offline but still within its own grace threshold
    (not yet alert-worthy) -- a derived display bucket, not a stored
    status; see VpnDeviceStatus's own docstring for why a third persisted
    state was deliberately not added there."""
    links = (
        db.query(VpnProfileLink)
        .filter(VpnProfileLink.monitoring_enabled.is_(True))
        .order_by(VpnProfileLink.vpn_client_name)
        .all()
    )
    counts = {"online": 0, "offline": 0, "warning": 0}
    devices = []
    now = _now()
    for link in links:
        status = db.query(VpnDeviceStatus).filter_by(vpn_client_name=link.vpn_client_name, check_type=link.check_type).first()
        current_status = status.current_status if status else "unknown"
        offline_seconds = None
        display_status = current_status
        if current_status == "offline" and status and status.offline_since:
            offline_seconds = max(0, (now - _aware(status.offline_since)).total_seconds())
            display_status = "offline" if offline_seconds >= link.offline_threshold_minutes * 60 else "warning"
        if display_status in counts:
            counts[display_status] += 1
        devices.append({
            "vpn_client_name": link.vpn_client_name,
            "device_name": device_label(link),
            "username": link.user.username if link.user else None,
            "display_status": display_status,
            "last_seen_at": status.last_seen_at.isoformat() if status and status.last_seen_at else None,
            "offline_duration_seconds": offline_seconds,
            "maintenance_mode": link.maintenance_mode,
        })
    counts["total"] = len(links)
    return {"counts": counts, "devices": devices}


# --- Device Availability report ---------------------------------------------

def availability_report(db: Session, start: datetime, end: datetime) -> list[dict]:
    """Uptime %, downtime %, outage count, and average outage duration per
    monitored device over [start, end) -- derived by clipping every
    VpnDeviceOutage row that overlaps the window to the window itself (an
    outage that started before `start` or is still ongoing past `end`/now
    only counts its in-window portion), then aggregating. Sorted worst-
    availability-first, which doubles as the "Most Unstable Devices" view
    the spec calls for -- no separate query, just how this list is read."""
    end = min(end, _now())
    period_seconds = max(1.0, (end - start).total_seconds())
    links = db.query(VpnProfileLink).filter(VpnProfileLink.monitoring_enabled.is_(True)).order_by(VpnProfileLink.vpn_client_name).all()
    results = []
    for link in links:
        outages = (
            db.query(VpnDeviceOutage)
            .filter(
                VpnDeviceOutage.vpn_client_name == link.vpn_client_name,
                VpnDeviceOutage.check_type == link.check_type,
                VpnDeviceOutage.started_at < end,
                (VpnDeviceOutage.ended_at.is_(None)) | (VpnDeviceOutage.ended_at > start),
            )
            .all()
        )
        downtime_seconds = 0.0
        for o in outages:
            o_start = max(_aware(o.started_at), start)
            o_end = min(_aware(o.ended_at) or end, end)
            downtime_seconds += max(0.0, (o_end - o_start).total_seconds())
        downtime_seconds = min(downtime_seconds, period_seconds)
        uptime_pct = round(100 * (1 - downtime_seconds / period_seconds), 2)
        total_outages = len(outages)
        avg_outage_duration_seconds = round(downtime_seconds / total_outages, 1) if total_outages else 0.0
        results.append({
            "vpn_client_name": link.vpn_client_name,
            "device_name": device_label(link),
            "username": link.user.username if link.user else None,
            "uptime_pct": max(0.0, min(100.0, uptime_pct)),
            "downtime_pct": round(100 - max(0.0, min(100.0, uptime_pct)), 2),
            "total_outages": total_outages,
            "avg_outage_duration_seconds": avg_outage_duration_seconds,
            "downtime_seconds": round(downtime_seconds, 1),
        })
    results.sort(key=lambda r: r["uptime_pct"])
    return results
