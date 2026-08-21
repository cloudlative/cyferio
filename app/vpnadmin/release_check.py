"""Release Availability Indicator/Popup -- checks GitHub's Releases API for
`app_settings.runtime.github_repo` (default: config.RELEASE_CHECK_REPO) and
compares the latest published release's tag against the deployed
config.APP_VERSION.

Cached in-process, refreshed on a timer -- same "don't hit the remote
service on every page load, refresh via a background loop on an interval"
shape as cli_wrapper.py's dashboard snapshot (see cli_wrapper.
refresh_dashboard_snapshot/get_dashboard_snapshot's own docstrings) and
main.py's _dashboard_refresh_loop/_db_snapshot_loop. Unlike those, the
refresh INTERVAL here is admin-configurable
(runtime.release_check_interval_minutes, Settings -> System Maintenance) --
GitHub's REST API is rate-limited per source IP for unauthenticated
requests (60/hour), so a fixed code constant would either be needlessly
conservative for a deployment that wants near-real-time visibility, or
risk exhausting the rate limit for one that doesn't need it that often.

Classification ("is this update critical?") is a simple, documented,
admin-tunable heuristic, not a call to any external severity API (GitHub
Releases has no first-class "severity" field) -- an update is CRITICAL if
EITHER:
  1. the latest release's semver major component is greater than the
     currently-deployed version's (a major bump is the conventional signal
     for "expect breaking changes / this matters more than a routine
     update" -- gated by runtime.release_check_critical_major_bump so an
     admin who disagrees with that heuristic for their own versioning
     scheme can turn it off), OR
  2. the release's tag name, title, or body contains the (case-insensitive)
     word "security" or "critical" -- covers a release the maintainer
     explicitly flagged as security-relevant in its own notes, which is
     the closest signal available without a dedicated GitHub Security
     Advisory API integration (out of scope here -- this module only reads
     the public Releases endpoint, no additional GitHub API surface).
Anything newer that doesn't match either signal is classified "update
available" (yellow); no newer release at all is "up to date" (green).
"""
import json
import logging
import re
import urllib.error
import urllib.request
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from . import app_settings
from .config import settings as env_settings

logger = logging.getLogger(__name__)

_SEMVER_RE = re.compile(r"v?(\d+)\.(\d+)\.(\d+)")
_SECURITY_WORDS_RE = re.compile(r"\b(security|critical)\b", re.IGNORECASE)

# In-process cache -- module-level dict, same "single-process deployment,
# refreshed by a background task, safe to read from any request handler
# with no lock" reasoning as app_settings.runtime (see that module's own
# docstring on why this is fine for this app's deployment shape but would
# need a shared cache in a multi-worker one).
_cache: dict = {
    "checked_at": None,       # UTC datetime of the last successful check, or None if never
    "latest_tag": None,       # e.g. "v1.2.0", or None if never checked / no releases
    "latest_name": None,
    "latest_body": None,
    "latest_html_url": None,
    "published_at": None,     # ISO string from GitHub, or None
    "status": "up_to_date",   # "up_to_date" | "update_available" | "critical_update" | "unknown"
    "error": None,            # last check's error message, if any -- surfaced for admin diagnostics
}


def _parse_semver(tag: str) -> tuple[int, int, int] | None:
    m = _SEMVER_RE.search(tag or "")
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)))


def classify(current_version: str, latest_tag: str, latest_name: str | None, latest_body: str | None,
             *, critical_on_major_bump: bool) -> str:
    """Returns "up_to_date" | "update_available" | "critical_update" --
    pure function, no I/O, so it's directly unit-testable (see
    tests/test_release_check.py) independent of the network/caching layer
    below."""
    current = _parse_semver(current_version)
    latest = _parse_semver(latest_tag)
    if current is None or latest is None or latest <= current:
        return "up_to_date"
    if critical_on_major_bump and latest[0] > current[0]:
        return "critical_update"
    haystack = " ".join(filter(None, [latest_tag, latest_name, latest_body]))
    if _SECURITY_WORDS_RE.search(haystack):
        return "critical_update"
    return "update_available"


def _fetch_latest_release(repo: str, timeout: float = 10.0) -> dict | None:
    """One HTTP call to GitHub's public Releases API -- unauthenticated
    (no token needed/used, same "no new credential to manage" stance as
    every other outbound integration in this app that can get away with
    it), so it's subject to GitHub's 60 req/hour per-IP limit; the caching
    layer below is what keeps this well under that even on a busy
    deployment. Returns None (not an exception) for "no releases published
    yet" (404) -- a real, valid state for a repo with no releases, not a
    failure; other errors propagate for the caller to log/record."""
    url = f"https://api.github.com/repos/{repo}/releases/latest"
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json", "User-Agent": "Cyferio-release-check"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise


def _is_stale() -> bool:
    if _cache["checked_at"] is None:
        return True
    interval = app_settings.runtime.release_check_interval_minutes or 60
    age_seconds = (datetime.now(timezone.utc) - _cache["checked_at"]).total_seconds()
    return age_seconds >= interval * 60


def check_for_new_release(*, force: bool = False) -> dict:
    """Returns the current cached snapshot, refreshing it first if stale
    (or `force`d) and release checking is enabled. Safe to call from any
    request handler -- a stale-but-present cache is always returned even
    if a refresh attempt fails (see the except branch below), same
    fail-soft stance as cli_wrapper.get_dashboard_snapshot falling back to
    the last-good snapshot on a transient failure."""
    if not app_settings.runtime.release_check_enabled:
        return dict(_cache)
    if not (force or _is_stale()):
        return dict(_cache)

    repo = app_settings.runtime.github_repo or env_settings.RELEASE_CHECK_REPO
    try:
        release = _fetch_latest_release(repo)
        _cache["checked_at"] = datetime.now(timezone.utc)
        _cache["error"] = None
        if release is None:
            _cache["latest_tag"] = None
            _cache["status"] = "up_to_date"
        else:
            tag = release.get("tag_name") or ""
            name = release.get("name")
            body = release.get("body")
            _cache["latest_tag"] = tag
            _cache["latest_name"] = name
            _cache["latest_body"] = body
            _cache["latest_html_url"] = release.get("html_url")
            _cache["published_at"] = release.get("published_at")
            _cache["status"] = classify(
                env_settings.APP_VERSION, tag, name, body,
                critical_on_major_bump=app_settings.runtime.release_check_critical_major_bump,
            )
    except Exception as e:
        logger.warning("Release check against %s failed -- keeping last-known state", repo, exc_info=True)
        _cache["error"] = str(e)
        # checked_at deliberately NOT bumped on failure -- so the next tick
        # retries promptly rather than waiting out a full interval on the
        # strength of a failed attempt (mirrors _is_stale()'s "never
        # checked" behavior for a check that's never actually succeeded).
    return dict(_cache)


def reset_cache() -> None:
    """Test-only helper -- see tests/conftest.py's autouse fixture. Not
    used by any production code path."""
    _cache.update(checked_at=None, latest_tag=None, latest_name=None, latest_body=None,
                   latest_html_url=None, published_at=None, status="up_to_date", error=None)


def file_upgrade_ticket(db: Session):
    """Auto-creates a system-generated SupportTicket (System Maintenance ->
    Application Upgrade) for the currently-cached latest release, the same
    shape as routes/me_connection_issues.py's request_access_review()
    (a system-detected condition -> a real ticket, not a parallel tracking
    table -- see this feature's spec). Idempotent per release tag: does
    nothing if AppSettings.last_release_notified_tag already matches the
    cached latest_tag, so the background loop calling this every tick
    doesn't file a duplicate ticket every tick for the same release.

    Returns the created SupportTicket, or None if there's nothing to file
    (no cached release, or already filed for this tag)."""
    from . import ticket_notifications
    from .app_settings import get_settings_row
    from .audit import log_action
    from .models import SupportTicket, SupportTicketMessage, User
    from .permissions import has_permission_any_scope
    from .support_tickets import DEFAULT_STATUS

    latest_tag = _cache.get("latest_tag")
    if not latest_tag:
        return None
    row = get_settings_row(db)
    if row.last_release_notified_tag == latest_tag:
        return None

    system_user = db.query(User).filter(User.is_active.is_(True), User.deleted.is_(False)).order_by(User.id).first()
    if system_user is None:
        return None  # no account to attribute the ticket to yet (e.g. a brand-new, empty test DB)

    # Pre-assigned to SOME admin by default (deterministically the lowest
    # user id with support_tickets update/manage, same candidate pool as
    # routes/tickets.py's list_assignable_admins) rather than left
    # Unassigned -- per explicit admin request 2026-08-21, so an upgrade
    # ticket never just sits in the queue with nobody responsible for it.
    # Still fully reassignable afterward via the normal PATCH endpoint (see
    # that route's own reassignment/audit behavior) -- this only sets who
    # owns it FIRST, it doesn't lock ownership.
    default_assignee = next(
        (u for u in db.query(User).filter(User.is_active.is_(True), User.deleted.is_(False)).order_by(User.id)
         if has_permission_any_scope(db, u, "support_tickets", "update")),
        None,
    )

    haystack = " ".join(filter(None, [latest_tag, _cache.get("latest_name"), _cache.get("latest_body")]))
    is_security = bool(_SECURITY_WORDS_RE.search(haystack))
    category = "sysmaint_security_update" if is_security else "sysmaint_application_upgrade"
    subject = f"Upgrade Cyferio from {env_settings.APP_VERSION} to {latest_tag}"

    body_lines = [
        "Auto-filed by the Release Availability check -- a new Cyferio release was detected.",
        "",
        f"Installed version: {env_settings.APP_VERSION}",
        f"Available version: {latest_tag}",
    ]
    if _cache.get("published_at"):
        body_lines.append(f"Published: {_cache['published_at']}")
    if _cache.get("latest_html_url"):
        body_lines.append(f"Release notes: {_cache['latest_html_url']}")
    if _cache.get("latest_body"):
        body_lines += ["", "--- Release notes ---", _cache["latest_body"][:4000]]
    body_lines += ["", "To upgrade: cd /opt/cyferio && ./upgrade.sh", "",
                   "Claim this ticket (assign it to yourself) before starting work."]

    ticket = SupportTicket(
        created_by_user_id=system_user.id, subject=subject, category=category,
        # Always "high" (not conditional on is_security any more) per
        # explicit admin request 2026-08-21 -- an available upgrade is
        # worth flagging above routine tickets regardless of whether this
        # particular release happens to mention "security"/"critical" in
        # its own notes; that wording still separately drives sysmaint_
        # security_update's category choice above and could still push a
        # future critical-severity distinction if ever added.
        priority="high", status=DEFAULT_STATUS,
        assigned_admin_id=default_assignee.id if default_assignee else None,
    )
    db.add(ticket)
    db.flush()
    db.add(SupportTicketMessage(ticket_id=ticket.id, author_user_id=system_user.id, body="\n".join(body_lines)))
    row.last_release_notified_tag = latest_tag
    db.commit()

    assignee_detail = f"; assigned_admin {default_assignee.username}" if default_assignee else "; unassigned (no admin found)"
    log_action(db, system_user, "release_detected", target=f"TCK-{ticket.id}", detail=f"{env_settings.APP_VERSION} -> {latest_tag}{assignee_detail}")
    ticket_notifications.ticket_created(db, ticket)
    from . import slack_notifications
    slack_notifications.notify(db, "release_available", f":rocket: New Cyferio release available: {latest_tag} (installed: {env_settings.APP_VERSION}). Ticket #{ticket.id} filed.")
    return ticket
