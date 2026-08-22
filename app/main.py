"""
Cyferio web app -- entrypoint.

Run directly with:
    uvicorn main:app --host 0.0.0.0 --port 8000
or via the Dockerfile's CMD.
"""
import asyncio
import logging
from contextlib import asynccontextmanager
from datetime import date

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from vpnadmin import cli_wrapper
from vpnadmin import client_mac_mirror
from vpnadmin import device_monitoring
# Aliased to health_data -- routes/health.py (the API router module,
# imported below via `from vpnadmin.routes import ... health ...`) and
# vpnadmin/health.py (this data-gathering module) share the bare name
# "health"; importing both unaliased into this one file means the second
# import silently rebinds the name, leaving whichever was imported first
# unreachable. Confirmed live on the test box: this exact collision made
# write_db_stat_snapshot() resolve to routes/health.py's module object
# (which has no such attribute) instead of this one, crashing the
# snapshot loop's very first tick on every startup.
from vpnadmin import health as health_data
from vpnadmin import system_audit
from vpnadmin.app_settings import migrate_decouple_portal_and_vpn_restrictions, migrate_legacy_smtp_provider, migrate_ticket_email_notify_types, prune_audit_log, prune_connection_rejections, prune_db_stat_snapshots, refresh_runtime_cache
from vpnadmin.auth import bootstrap_admin, ensure_bootstrap_admin_flag
from vpnadmin.config import settings
from vpnadmin.db import SessionLocal, init_db, promote_bootstrap_admin_to_super_admin
from vpnadmin.permissions import (
    drop_legacy_group_membership_fk_constraints,
    ensure_super_admin_group,
    migrate_groups_and_users_to_single_assignment,
)
from vpnadmin import geo_lists, mailer, slack_notifications
from vpnadmin import app_settings
from vpnadmin.models import QuotaNotification
from vpnadmin.routes import auth, clients, diagnostics, email_providers, geo, health, host_ingest, me_connection_issues, me_tickets, me_vpn, mfa as mfa_routes, notifications, pages, release as release_routes, reports, roles, settings as settings_routes, status, system_audit as system_audit_routes, groups, tickets, users
from vpnadmin.routes.reports import _load_rows

logger = logging.getLogger(__name__)

# How often the background task recomputes the /api/dashboard snapshot --
# see cli_wrapper.py's refresh_dashboard_snapshot()/get_dashboard_snapshot()
# docstrings for the full reasoning. 10s: frequent enough that "stale"
# never really registers for a human looking at the page, infrequent enough
# not to matter for script-spawn load on a small box (still fully
# serialized through the same _script_lock as ever -- this doesn't add any
# concurrent spawning, just moves the existing sequential spawns off the
# request path and onto a timer).
DASHBOARD_REFRESH_INTERVAL_SECONDS = 10

# How often the background task takes one Postgres stats sample for
# Database Reporting's trend charts (routes/reports.py's GET
# /api/reports/database, health_data.write_db_stat_snapshot) -- 10 minutes:
# frequent enough for meaningful trend granularity on charts spanning
# days/weeks, infrequent enough that ~144 rows/day is a non-issue for
# storage or the retention pruning below. A fixed code constant, not an
# admin setting -- unlike how LONG snapshots are kept
# (runtime.db_snapshot_retention_days, Settings-page-configurable), how
# OFTEN they're taken isn't, matching DASHBOARD_REFRESH_INTERVAL_SECONDS's
# own precedent of not being admin-configurable either.
DB_SNAPSHOT_INTERVAL_SECONDS = 600

# How often the background task checks every quota-having, linked user's
# pct_used against the warning/critical thresholds -- 10 minutes, same
# reasoning as DB_SNAPSHOT_INTERVAL_SECONDS above (frequent enough that a
# freshly-crossed threshold surfaces promptly, cheap enough at this scale
# to not matter). Unlike the thresholds themselves (Settings-page
# configurable, runtime.quota_notify_warning_pct/critical_pct), how OFTEN
# this check runs is a fixed code constant, matching every other
# background loop's own "interval isn't admin-configurable, only retention/
# thresholds are" precedent.
QUOTA_NOTIFICATION_INTERVAL_SECONDS = 600


async def _dashboard_refresh_loop():
    # Despite the name, this one snapshot now backs the Dashboard, Clients,
    # Revoked, and Diagnostics pages -- see cli_wrapper.dashboard_summary()'s
    # docstring for why they all ride the same timer instead of each having
    # their own background loop and subprocess-spawn burst.
    while True:
        try:
            await asyncio.to_thread(cli_wrapper.refresh_dashboard_snapshot)
        except Exception:
            # A transient script failure (e.g. a momentary timeout) should
            # never kill the background loop -- the next tick just tries
            # again, and every route reading this snapshot falls back to
            # the last-good one (or a direct call if there's genuinely
            # never been one yet).
            logger.exception("Background snapshot refresh failed; will retry next tick")
        await asyncio.sleep(DASHBOARD_REFRESH_INTERVAL_SECONDS)


async def _db_snapshot_loop():
    # Independent of _dashboard_refresh_loop above -- a much longer
    # interval, and writes to the DB itself (via a real ORM Session) rather
    # than spawning a subprocess, so it doesn't share cli_wrapper's
    # _script_lock/cache machinery at all.
    while True:
        try:
            db = SessionLocal()
            try:
                await asyncio.to_thread(health_data.write_db_stat_snapshot, db)
            finally:
                db.close()
        except Exception:
            # Same fail-soft stance as _dashboard_refresh_loop -- a
            # transient DB hiccup should never kill the loop; the next
            # tick just tries again, leaving a gap in the time series
            # rather than crashing the whole app.
            logger.exception("DB stat snapshot write failed; will retry next tick")
        await asyncio.sleep(DB_SNAPSHOT_INTERVAL_SECONDS)


def _check_quota_notifications(db) -> None:
    """One tick's worth of work for _quota_notification_loop below --
    factored out as a plain sync function (called via asyncio.to_thread)
    since it's pure ORM/policy_store reads plus a couple of inserts, no
    async I/O of its own.

    Reuses routes.reports._load_rows(db) verbatim -- it already computes
    exactly what's needed (user_id/username/vpn_client_name/quota_gb/
    used_gb/pct_used) for every active, non-deleted, linked user with a
    quota set; no separate aggregation code needed here.

    Warning and critical are checked independently per user per tick (not
    "elif") -- a user who jumps straight from 50% to 97% between two
    checks still gets BOTH rows created (useful history of having crossed
    each threshold), not just the higher one. The unique constraint on
    (user_id, period_start, level) is what actually prevents a duplicate
    notification for an already-notified threshold this month; the
    query-first check below is just the normal, expected path (the
    constraint is a backstop, not the primary mechanism)."""
    period_start = date.today().replace(day=1)
    warning_pct = app_settings.runtime.quota_notify_warning_pct
    critical_pct = app_settings.runtime.quota_notify_critical_pct

    for row in _load_rows(db):
        pct_used = row["pct_used"]
        if pct_used is None:  # no quota set -- nothing to threshold against
            continue

        for level, threshold in (("warning", warning_pct), ("critical", critical_pct)):
            if pct_used < threshold:
                continue
            already_exists = (
                db.query(QuotaNotification)
                .filter_by(user_id=row["user_id"], period_start=period_start, level=level)
                .first()
            )
            if already_exists is not None:
                continue
            message = (
                f"Your VPN client '{row['vpn_client_name']}' has used {pct_used}% of its "
                f"{row['quota_gb']}GB monthly quota."
            )
            db.add(QuotaNotification(
                user_id=row["user_id"], vpn_client_name=row["vpn_client_name"],
                level=level, pct_used=pct_used, message=message, period_start=period_start,
            ))
            db.commit()
            if level == "critical" and app_settings.runtime.notify_admin_on_quota_critical and app_settings.runtime.admin_notification_email:
                mailer.send_admin_notification(
                    subject=f"Bandwidth quota critical: {row['username']}",
                    body=f"{row['username']}'s VPN client '{row['vpn_client_name']}' has used "
                         f"{pct_used}% of its {row['quota_gb']}GB monthly quota.",
                )
            slack_notifications.notify(
                db, "quota_warning",
                f":bar_chart: {row['username']}'s VPN client '{row['vpn_client_name']}' crossed the {level} "
                f"threshold: {pct_used}% of its {row['quota_gb']}GB monthly quota.",
            )


async def _quota_notification_loop():
    # Same independent-loop shape as _db_snapshot_loop above -- its own
    # SessionLocal(), its own interval, fail-soft try/except per tick.
    while True:
        try:
            db = SessionLocal()
            try:
                await asyncio.to_thread(_check_quota_notifications, db)
            finally:
                db.close()
        except Exception:
            logger.exception("Quota notification check failed; will retry next tick")
        await asyncio.sleep(QUOTA_NOTIFICATION_INTERVAL_SECONDS)


async def _device_monitoring_loop():
    """VPN Device Availability Monitoring's periodic offline-check tick --
    see device_monitoring.run_offline_check's own docstring for why this
    is an eager background loop (unlike release_check.py's lazy,
    request-triggered check) and models.VpnDeviceStatus/VpnDeviceOutage
    for what it writes. Unlike every other loop above, the sleep interval
    is read FRESH from app_settings.runtime on every tick (not a fixed
    module-level constant) -- it's the one interval in this feature the
    admin can tune (Settings -> Device Monitoring), same "admin-
    configurable interval" precedent as release_check.py's own
    runtime.release_check_interval_minutes, just applied to a loop
    instead of a lazy check's staleness test."""
    while True:
        try:
            db = SessionLocal()
            try:
                await asyncio.to_thread(device_monitoring.run_offline_check, db)
            finally:
                db.close()
        except Exception:
            logger.exception("VPN device offline check failed; will retry next tick")
        interval_minutes = app_settings.runtime.device_monitoring_check_interval_minutes or 5
        await asyncio.sleep(max(60, interval_minutes * 60))


async def _system_audit_loop():
    """Scheduled Auditing (spec section 13). Same shape as
    _device_monitoring_loop above -- interval read fresh from
    app_settings.runtime every tick (admin-tunable via Settings), so a
    change takes effect on the loop's next wake rather than needing a
    restart. audit_schedule_enabled defaults False (see app_settings.py)
    -- a brand-new deployment doesn't start silently auditing itself on
    a timer until an admin opts in via Settings -> System Audit, unlike
    device monitoring (which is opt-in per-device, not globally). When
    disabled, this loop still wakes on the same interval just to re-check
    the toggle, rather than needing a separate restart-the-loop mechanism
    for enabling it later."""
    while True:
        interval_hours = app_settings.runtime.audit_schedule_interval_hours or 168  # weekly default
        if app_settings.runtime.audit_schedule_enabled:
            try:
                db = SessionLocal()
                try:
                    await asyncio.to_thread(system_audit.run_audit, db, trigger="scheduled")
                finally:
                    db.close()
            except Exception:
                logger.exception("Scheduled System Audit run failed; will retry next tick")
        await asyncio.sleep(max(3600, interval_hours * 3600))

# Note: the Release Availability check (release_check.py) is deliberately
# NOT run on its own background loop like the tasks above -- unlike a
# subprocess spawn (cli_wrapper) or a local DB query (health_data/
# QuotaNotification), it's a real outbound network call to GitHub's API on
# every check, and this app has no test-vs-production signal to skip that
# safely on a fixed timer the way it can for a same-process check. It's
# checked LAZILY instead -- see routes/settings.py's GET /api/release/status,
# called by the header indicator's own poll (static/app.js) -- which is both
# an explicitly permitted design per this feature's spec ("a background/lazy
# mechanism") and what keeps GitHub calls scoped to actual admin page loads
# rather than firing unconditionally on every process's uptime, including
# every test run's.


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    db = SessionLocal()
    try:
        bootstrap_admin(db)
        ensure_bootstrap_admin_flag(db)
        # Covers the fresh-install case: init_db() (above) already ran
        # this once as part of its own RBAC seeding, but on a brand-new
        # database that first call was necessarily a no-op -- the bootstrap
        # account didn't exist yet until bootstrap_admin() just created it.
        # See db.py's promote_bootstrap_admin_to_super_admin docstring.
        promote_bootstrap_admin_to_super_admin(db)
        # Same "fresh-install first call was a no-op" reasoning as the
        # promote_bootstrap_admin_to_super_admin call just above -- see
        # permissions.py's ensure_super_admin_group/migrate_groups_and_
        # users_to_single_assignment docstrings and db.py's _seed_rbac
        # (which already ran both once, but on a brand-new database the
        # bootstrap account -- and therefore every group it's placed
        # into -- didn't exist yet at that point).
        ensure_super_admin_group(db)
        migrate_groups_and_users_to_single_assignment(db)
        # Fixes a real bug (deleting a pre-migration group 500s on the
        # user_groups table's own leftover FK constraints) rather than
        # migrating data -- see that function's own docstring. Idempotent,
        # safe to call every startup alongside the migrations above.
        drop_legacy_group_membership_fk_constraints(db)
        # Load the DB-backed settings override (Settings page) into the
        # in-process cache templates/mailer.py/auth.py actually read, then
        # prune the audit log per whatever retention that config specifies.
        # See app_settings.py's docstring for the full env->DB->cache chain.
        refresh_runtime_cache(db)
        prune_audit_log(db)
        prune_db_stat_snapshots(db)
        prune_connection_rejections(db)
        # One-time backfill: turns already-configured legacy SMTP settings
        # into the first EmailProvider row (marked default) so an upgrade
        # keeps sending mail exactly as before with no manual step -- see
        # that function's own docstring. No-op once any EmailProvider row
        # exists, so safe on every startup, not just the first.
        migrate_legacy_smtp_provider(db)
        # One-time backfill: subdivides the legacy notify_admin_on_
        # ticket_created toggle into the 4 per-event ticket admin-email
        # keys (notification_prefs.TICKET_EMAIL_EVENTS), seeded from that
        # toggle's current value so upgrading doesn't change anyone's
        # admin email behavior -- see that function's own docstring.
        # No-op once ticket_email_notify_types is already set.
        migrate_ticket_email_notify_types(db)
        # One-time backfill: copies each user's already-effective Portal
        # Login Restrictions into their linked VPN profile's policy before
        # the Portal->VPN auto-sync (routes/users.py) is removed for good --
        # see that function's own docstring for why this needs a real
        # one-time marker rather than being safely re-runnable.
        migrate_decouple_portal_and_vpn_restrictions(db)
        # Reconciles models.ClientMac (a queryable DB mirror of
        # openvpn_db.txt) against the file itself on every startup -- both
        # the first-upgrade backfill and ongoing drift repair (hand edits,
        # SSH, setup.sh provisioning) in one mechanism. Fails soft: a
        # missing/misconfigured install script (e.g. a local dev/test
        # environment) must never block startup over a reporting-only
        # mirror -- see client_mac_mirror.py's own docstring.
        try:
            client_mac_mirror.resync_client_macs(db, cli_wrapper.dump_macs())
        except Exception:
            logging.getLogger(__name__).warning("ClientMac resync failed at startup -- continuing without it", exc_info=True)
    finally:
        db.close()
    # Kick the City/ASN pick-list build (or a disk-cache load) off in a
    # background thread now rather than waiting for the first admin to
    # open the Users page -- see geo_lists.py's ensure_fresh docstring.
    # Non-blocking either way: a disk cache load is near-instant, and a
    # full rebuild (~100s) just continues in its own thread while the app
    # finishes starting up normally.
    geo_lists.ensure_fresh()
    refresh_task = asyncio.create_task(_dashboard_refresh_loop())
    db_snapshot_task = asyncio.create_task(_db_snapshot_loop())
    quota_notification_task = asyncio.create_task(_quota_notification_loop())
    device_monitoring_task = asyncio.create_task(_device_monitoring_loop())
    system_audit_task = asyncio.create_task(_system_audit_loop())
    try:
        yield
    finally:
        refresh_task.cancel()
        db_snapshot_task.cancel()
        quota_notification_task.cancel()
        device_monitoring_task.cancel()
        system_audit_task.cancel()
        for task in (refresh_task, db_snapshot_task, quota_notification_task, device_monitoring_task, system_audit_task):
            try:
                # Bounded, not a bare `await task`: each loop's current
                # tick runs its blocking work via asyncio.to_thread(), and
                # .cancel() can only mark that task for cancellation --
                # it can't actually interrupt a real OS thread already
                # inside a synchronous call (a subprocess invocation, a DB
                # query). If that call is slow or hangs, an unbounded
                # await here hangs shutdown itself waiting for it, which
                # is exactly what made CI's TestClient teardown (each test
                # runs a full lifespan startup+shutdown) deadlock -- and
                # would do the same to a real graceful restart/SIGTERM in
                # production. A timeout means shutdown always completes
                # promptly; the orphaned thread finishes or dies with the
                # process either way, it just isn't waited on.
                await asyncio.wait_for(asyncio.shield(task), timeout=5)
            except asyncio.CancelledError:
                pass
            except TimeoutError:
                logger.warning("Background task %s did not shut down within 5s; abandoning it", task.get_coro())


app = FastAPI(title="Cyferio Admin", docs_url="/api/docs", redoc_url=None, lifespan=lifespan)

app.add_middleware(
    SessionMiddleware,
    secret_key=settings.SECRET_KEY,
    max_age=settings.SESSION_MAX_AGE_SECONDS,
    session_cookie=settings.SESSION_COOKIE_NAME,
    https_only=settings.SESSION_HTTPS_ONLY,  # set SESSION_HTTPS_ONLY=true in .env once served behind TLS (see docker-compose.yml's traefik service)
)

app.mount("/static", StaticFiles(directory="vpnadmin/static"), name="static")

app.include_router(pages.router)
app.include_router(auth.router)
app.include_router(clients.router)
app.include_router(status.router)
app.include_router(status.dashboard_router)
app.include_router(diagnostics.router)
app.include_router(health.router)
app.include_router(users.router)
app.include_router(geo.router)
app.include_router(groups.router)
app.include_router(settings_routes.router)
app.include_router(roles.router)
app.include_router(me_vpn.router)
app.include_router(me_connection_issues.router)
app.include_router(host_ingest.router)
app.include_router(reports.router)
app.include_router(notifications.router)
app.include_router(me_tickets.router)
app.include_router(tickets.router)
app.include_router(email_providers.router)
app.include_router(mfa_routes.router)
app.include_router(release_routes.router)
app.include_router(system_audit_routes.router)


@app.get("/healthz")
def healthz():
    """Unauthenticated liveness check -- for Docker/orchestrator health
    probes, deliberately reveals nothing about the app's internal state."""
    return {"status": "ok"}
