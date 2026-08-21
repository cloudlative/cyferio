"""System Audit -- a server-hardening/security-assessment module distinct
from health.py's Health page (which is "is everything currently running",
a live status check) and reports.py's Reports (which is usage/analytics
trends). This module answers "is the server CONFIGURED safely" -- OS/
package/filesystem posture, SSH hardening, and firewall exposure -- as a
point-in-time snapshot (an AuditRun) with historical comparison, not a
live dashboard.

PHASE 1 SCOPE (explicit, not an oversight): read-only findings only. No
automated remediation is implemented yet -- see models.py's AuditFinding.
automated_remediation_available column, which every Phase 1 finding sets
False. Firewall checks are best-effort from readable host state (ufw's
own config files, the openvpn-iptables.service unit this project's own
installer writes, firewalld's config) rather than live kernel netfilter
state (`iptables -L`, `nft list ruleset`), because getting that requires
executing a command on the host, not just reading a file -- see the
"why file reads, not subprocess" section below. Both are deliberate,
reviewed scope decisions (2026-08-22), not gaps to silently work around.

WHY FILE READS, NOT SUBPROCESS: this app runs in a Docker container with
no docker.sock, no host PID namespace, and no host network namespace (see
docker-compose.yml) -- it cannot run `iptables -L`, `ufw status`,
`systemctl is-enabled sshd`, or `dpkg -l` against the HOST, only against
itself. What it DOES already have is a read-only bind mount of the
host's entire root filesystem (docker-compose.yml's `/:/hostfs:ro`,
already used by health.py's get_host_health() for CPU/memory/disk) --
every check in this module reads through that mount (see config.py's
HOST_ROOT_PATH) rather than shelling out. This is a real, deliberate
constraint, not a workaround: it keeps every check safely read-only by
construction (there's no command execution surface to sanitize/authorize
at all for Phase 1), at the cost of not being able to verify LIVE state
that only exists in the kernel (active netfilter rules) or requires a
running daemon's own view (systemd's actual enabled/active bits, as
opposed to inferring them from unit-file symlinks). Findings that can't
be fully verified this way say so explicitly in their own text rather
than silently guessing.

MULTI-SERVER: every AuditRun is labeled with node_hostname from day one
(see models.py's own comment) even though this deployment is single-
server -- the intent is that a future multi-node rollup is a query
against data already being collected, not a schema change. No node-
selection UI/orchestration is built in Phase 1 (per the spec's own "do
not over-engineer" instruction for section 15).

MODULE LAYOUT: run_audit() below is the orchestrator; system_checks.py/
ssh_checks.py/firewall_checks.py are independent check modules, each
exposing a single `run(host_root: str) -> list[Finding]`. Adding a new
category later (NetworkChecks, PackageChecks, VPNChecks, per the spec's
own catalog) means adding one more module with that same shape and one
line in _CHECK_MODULES below -- no other file needs to change."""
import logging
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from .. import mailer, slack_notifications
from ..audit import log_action
from ..config import settings
from ..models import AUDIT_SEVERITIES, AuditFinding, AuditLog, AuditNotification, AuditRun, User
from ..permissions import has_permission

logger = logging.getLogger(__name__)

# Points deducted per finding at each severity, subtracted from a 100
# starting score and floored at 0 -- see compute_score() below. Chosen so
# a single Critical finding is immediately visible in the score (a 100 ->
# 75 drop is impossible to read as "probably fine") while a handful of Low
# findings don't swamp the score the way one Critical does. Informational/
# Passed findings never affect the score at all -- they're context, not a
# posture problem.
_SCORE_PENALTY = {"critical": 25, "high": 10, "medium": 4, "low": 1, "info": 0, "passed": 0}


@dataclass
class Finding:
    """One check's result -- Phase 1's in-memory equivalent of an
    AuditFinding row (run_audit() converts these to rows once the run's
    check_id is known to belong to a real, persisted run). check_id must
    be globally stable across runs (see AuditFinding's own docstring for
    why -- it's the join key for new/resolved history).

    Every field here is meant to be safely operator-facing. Check authors
    are responsible for never putting secret material (a private key's
    bytes, a password hash, a token) into evidence/current_state/
    description -- e.g. ssh_checks.py reports host key file PERMISSIONS
    and fingerprints, never key contents; there is no generic redaction
    pass applied after the fact, so a new check must get this right at
    the source, not rely on a filter downstream."""
    check_id: str
    category: str  # "system" | "ssh" | "firewall"
    severity: str  # one of AUDIT_SEVERITIES
    title: str
    description: str
    why_it_matters: str | None = None
    current_state: str | None = None
    expected_state: str | None = None
    evidence: str | None = None
    remediation: str | None = None

    def __post_init__(self):
        if self.severity not in AUDIT_SEVERITIES:
            raise ValueError(f"Finding {self.check_id!r} has an unknown severity {self.severity!r}")


def compute_score(findings: list[Finding]) -> int:
    """0-100. Starts at 100, subtracts _SCORE_PENALTY per finding
    (Passed/Informational cost nothing), floored at 0 -- see the module-
    level comment for why Critical is weighted so much more heavily than
    a handful of Low findings. Deliberately simple/explainable (spec
    section 11: "avoid making the score misleading, clearly explain how
    it's calculated") -- a straight per-finding deduction, not a curve or
    a weighted-by-category formula an admin would have to take on faith."""
    score = 100
    for f in findings:
        score -= _SCORE_PENALTY.get(f.severity, 0)
    return max(0, score)


from . import firewall_checks, ssh_checks, system_checks  # noqa: E402  (after Finding is defined, which they import)

_CHECK_MODULES = (system_checks, ssh_checks, firewall_checks)


def _run_all_checks() -> list[Finding]:
    host_root = settings.HOST_ROOT_PATH
    findings: list[Finding] = []
    for module in _CHECK_MODULES:
        try:
            findings.extend(module.run(host_root))
        except Exception:
            # One check module blowing up (an unexpected host layout, a
            # permissions surprise on a file we don't own) must not lose
            # every other module's results -- surfaced as its own
            # Informational finding instead of a run-wide failure, so an
            # admin sees "this category couldn't fully run" as data, not
            # a silent gap in the findings table.
            logger.exception("System Audit: %s.run() failed", module.__name__)
            findings.append(Finding(
                check_id=f"{module.__name__.rsplit('.', 1)[-1]}.module_error",
                category=module.__name__.rsplit(".", 1)[-1].replace("_checks", ""),
                severity="info",
                title=f"{module.__name__.rsplit('.', 1)[-1].replace('_checks', '').title()} checks could not fully run",
                description="This check category raised an unexpected error and was skipped for this audit run. "
                             "See the application logs for the underlying exception.",
            ))
    return findings


def _notify_admins(db: Session, run: AuditRun, reason: str, message: str) -> None:
    """Broadcast one alert to every admin/super_admin's in-app bell (a row
    each, see AuditNotification's own docstring), plus email/Slack if
    their respective toggles are on -- same three-channel fan-out shape
    device_monitoring.py's alert path already uses, just for a system-wide
    event instead of a per-device one."""
    for user in db.query(User).filter(User.deleted.is_(False), User.is_active.is_(True)).all():
        if has_permission(db, user, "system_audit", "view"):
            db.add(AuditNotification(user_id=user.id, run_id=run.id, reason=reason, message=message))
    db.commit()

    from .. import app_settings
    s = app_settings.runtime
    if getattr(s, "notify_admin_on_audit_finding", False):
        mailer.send_admin_notification(db=db, subject=f"System Audit: {message}", body=message)
    slack_event = {
        "new_critical": "audit_critical_finding",
        "new_high": "audit_high_finding",
        "score_dropped": "audit_score_dropped",
        "finding_regressed": "audit_finding_regressed",
    }.get(reason)
    if slack_event:
        slack_notifications.notify(db, slack_event, message)


def _log_run(db: Session, run: AuditRun, triggered_by_user: User | None, detail: str, success: bool) -> None:
    """log_action() requires a real User (it reads user.username directly)
    -- fine for a manual run (routes/system_audit.py already has the
    requesting admin via Depends), but a scheduled run has no acting user
    at all. Rather than fabricate a fake User row just to satisfy that
    signature, write the AuditLog row directly for the scheduled case
    (username="system", same convention a cron-style background action
    would use) and only go through log_action for a real admin-triggered
    run -- keeps log_action's own "always a real user" contract intact
    for every OTHER caller in this codebase."""
    if triggered_by_user is not None:
        log_action(db, triggered_by_user, "run_system_audit", target=run.node_hostname, detail=detail, success=success)
        return
    db.add(AuditLog(username="system", action="run_system_audit", target=run.node_hostname,
                     detail=detail[:2000], success=success))
    db.commit()


def run_audit(db: Session, *, trigger: str, triggered_by_user: User | None = None) -> AuditRun:
    """The orchestrator. `trigger` is "manual" (routes/system_audit.py's
    POST /run, triggered_by_user=the requesting admin) or "scheduled"
    (main.py's _system_audit_loop, triggered_by_user=None). Synchronous/
    blocking by design -- callers from the async app run this via
    asyncio.to_thread(), same as every other blocking check in this app
    (cli_wrapper's subprocess calls, device_monitoring.run_offline_check).

    History diff: compares this run's non-passed check_ids against the
    immediately preceding COMPLETED run's non-passed check_ids (a
    "failed" run is skipped when looking for "previous" -- its findings,
    if any were even collected before it errored, aren't a trustworthy
    baseline). A check_id in this run but not last run's non-passed set =
    "new" (row status set to "new" if newly non-passed, else "existing").
    A check_id in last run's non-passed set but NOT in this run's =
    "resolved" -- written as this run's row for that check_id (which is
    "passed" this time) with status="resolved", so the resolution shows up
    exactly once, on the run where it happened, not forever after."""
    run = AuditRun(trigger=trigger, triggered_by=(triggered_by_user.username if triggered_by_user else None), status="running")
    db.add(run)
    db.commit()
    db.refresh(run)

    try:
        import socket
        run.node_hostname = socket.gethostname()

        prev_run = (
            db.query(AuditRun)
            .filter(AuditRun.status == "completed", AuditRun.id != run.id)
            .order_by(AuditRun.started_at.desc())
            .first()
        )
        prev_non_passed: dict[str, str] = {}  # check_id -> severity, from the previous run
        if prev_run is not None:
            for f in prev_run.findings:
                if f.severity != "passed":
                    prev_non_passed[f.check_id] = f.severity

        findings = _run_all_checks()

        counts = {sev: 0 for sev in AUDIT_SEVERITIES}
        new_count = 0
        for f in findings:
            counts[f.severity] += 1
            row_status = "existing"
            # Only meaningful relative to an actual previous run -- on the
            # very first run ever (prev_run is None), nothing is "new
            # since the previous run" because there IS no previous run;
            # every finding just starts out "existing" rather than
            # flagging the entire catalog as new on day one.
            if prev_run is not None and f.severity != "passed" and f.check_id not in prev_non_passed:
                row_status = "new"
                new_count += 1
            db.add(AuditFinding(
                run_id=run.id, check_id=f.check_id, category=f.category, severity=f.severity,
                title=f.title, description=f.description, why_it_matters=f.why_it_matters,
                current_state=f.current_state, expected_state=f.expected_state,
                evidence=f.evidence, remediation=f.remediation,
                automated_remediation_available=False, status=row_status,
            ))

        # A check_id is "resolved" if it was non-passed last run and is NOT
        # non-passed this run -- that includes both "still present but now
        # passed" (the common case: the underlying issue was actually
        # fixed) and "the check itself no longer ran at all" (removed/
        # renamed check_id). Subtracting only THIS run's non-passed ids
        # (not every check_id found) is what makes the first case count --
        # subtracting the full findings set would incorrectly treat
        # "present but now passed" as not-resolved, since the check_id is
        # still "in findings", just no longer non-passed.
        resolved_ids = set(prev_non_passed) - {f.check_id for f in findings if f.severity != "passed"}
        resolved_count = len(resolved_ids)
        for check_id in resolved_ids:
            # Re-emit the now-passed finding from THIS run's check output
            # if present (severity will be "passed"); if the check itself
            # was removed/renamed entirely, there's nothing to re-emit --
            # counted in resolved_findings_count regardless either way.
            match = next((f for f in findings if f.check_id == check_id), None)
            if match is not None:
                db.query(AuditFinding).filter(
                    AuditFinding.run_id == run.id, AuditFinding.check_id == check_id,
                ).update({"status": "resolved"})

        run.status = "completed"
        run.finished_at = datetime.now(timezone.utc)
        run.score = compute_score(findings)
        run.total_findings = len(findings)
        run.critical_count = counts["critical"]
        run.high_count = counts["high"]
        run.medium_count = counts["medium"]
        run.low_count = counts["low"]
        run.info_count = counts["info"]
        run.passed_count = counts["passed"]
        run.new_findings_count = new_count
        run.resolved_findings_count = resolved_count
        db.commit()

        _log_run(db, run, triggered_by_user,
                 detail=f"trigger={trigger} score={run.score} critical={run.critical_count} "
                        f"high={run.high_count} total={run.total_findings}",
                 success=True)

        new_critical = [f for f in findings if f.severity == "critical" and f.check_id not in prev_non_passed]
        new_high = [f for f in findings if f.severity == "high" and f.check_id not in prev_non_passed]
        if new_critical:
            _notify_admins(db, run, "new_critical",
                            f"🚨 {len(new_critical)} new Critical finding(s) detected (\"{new_critical[0].title}\""
                            f"{', ...' if len(new_critical) > 1 else ''}). Security score: {run.score}/100.")
        if new_high:
            _notify_admins(db, run, "new_high",
                            f"⚠️ {len(new_high)} new High-severity finding(s) detected. Security score: {run.score}/100.")
        if prev_run is not None and prev_run.score is not None and run.score < prev_run.score:
            _notify_admins(db, run, "score_dropped",
                            f"Security score dropped from {prev_run.score}/100 to {run.score}/100.")
        # "A previously resolved finding returns" (spec section 13) would
        # need history further back than just the immediately preceding
        # run to detect reliably (a check_id resolved two runs ago,
        # non-passed again now, looks identical to a check_id that's been
        # non-passed continuously unless the run BEFORE last is also
        # consulted) -- left for a later phase rather than approximated
        # incorrectly here.

        return run
    except Exception as e:
        db.rollback()
        run = db.get(AuditRun, run.id)
        run.status = "failed"
        run.finished_at = datetime.now(timezone.utc)
        run.error_detail = str(e)[:2000]
        db.commit()
        _log_run(db, run, triggered_by_user, detail=f"trigger={trigger} FAILED: {e}", success=False)
        raise
