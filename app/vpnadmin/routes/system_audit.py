"""System Audit -- server-hardening/security-assessment API. See
system_audit/__init__.py's module docstring for the engine design (why
read-only via /hostfs, why no remediation yet, multi-node data-model
intent). This router is thin by design: every real check/scoring/history-
diff/notification decision lives in system_audit/run_audit(); routes here
are just auth + (de)serialization + the CSV export format.

Remediation (Phase 3 chmod, Phase 4 ssh_directive/firewall, both added
2026-08-22) is the one exception to "thin router" -- POST .../remediate
below owns the confirmation-adjacent validation (finding must actually
offer automated remediation, action type must be one this router knows
how to dispatch) since that's request-shaped, not audit-engine logic; the
actual privileged operation still lives entirely in services/system/
audit_remediate.py, run on the HOST via the SSH channel, never in this
container. PDF export (Phase 4) lives in system_audit/report_pdf.py for
the same reason CSV export's formatting doesn't live here either -- it's
report-shaped, not routing logic."""
import asyncio
import csv
import io
import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session

from .. import system_audit
from ..audit import log_action
from ..db import get_db
from ..models import AuditFinding, AuditRun, User
from ..permissions import require_permission_any_scope
from ..system_audit import report_pdf

router = APIRouter(prefix="/api/system-audit", tags=["system-audit"])

# view: see runs/findings. execute: trigger a new run ("Run Audit Now") OR
# apply a remediation -- both any_scope (there's no "own" scope for a
# whole-server security posture, see AuditNotification's own docstring
# for the same point about notifications). Remediation deliberately
# shares "execute" with Run Audit Now rather than getting a stricter
# gate of its own: RBAC's action taxonomy (view/create/update/delete/
# execute/manage) has no finer-grained "run privileged host action" tier
# than execute, and a role trusted to trigger a live audit run (itself
# a host-executor round-trip, once Phase 2's live firewall probe is
# configured) is the same trust level this needs.
_require_viewer = require_permission_any_scope("system_audit", "view")
_require_runner = require_permission_any_scope("system_audit", "execute")


def _serialize_run(run: AuditRun, *, with_findings: bool = False) -> dict:
    out = {
        "id": run.id,
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "finished_at": run.finished_at.isoformat() if run.finished_at else None,
        "trigger": run.trigger,
        "triggered_by": run.triggered_by,
        "status": run.status,
        "error_detail": run.error_detail,
        "node_hostname": run.node_hostname,
        "score": run.score,
        "total_findings": run.total_findings,
        "critical_count": run.critical_count,
        "high_count": run.high_count,
        "medium_count": run.medium_count,
        "low_count": run.low_count,
        "info_count": run.info_count,
        "passed_count": run.passed_count,
        "new_findings_count": run.new_findings_count,
        "resolved_findings_count": run.resolved_findings_count,
    }
    if with_findings:
        out["findings"] = [_serialize_finding(f) for f in run.findings]
    return out


def _serialize_finding(f: AuditFinding) -> dict:
    return {
        "id": f.id,
        "check_id": f.check_id,
        "category": f.category,
        "severity": f.severity,
        "title": f.title,
        "description": f.description,
        "why_it_matters": f.why_it_matters,
        "current_state": f.current_state,
        "expected_state": f.expected_state,
        "evidence": f.evidence,
        "remediation": f.remediation,
        "remediation_risk": f.remediation_risk,
        "remediation_action": json.loads(f.remediation_action) if f.remediation_action else None,
        "automated_remediation_available": f.automated_remediation_available,
        "status": f.status,
        "remediated_at": f.remediated_at.isoformat() if f.remediated_at else None,
        "remediated_by": f.remediated_by,
        "remediation_result": json.loads(f.remediation_result) if f.remediation_result else None,
    }


@router.get("/runs")
def list_runs(limit: int = 25, _: User = Depends(_require_viewer), db: Session = Depends(get_db)):
    """Newest first, no findings (see GET /runs/{id} for those) -- this is
    the history list (spec section 9): date/time, score, per-severity
    counts, new/resolved counts, all already denormalized onto AuditRun
    itself so this is a single flat query, no join/aggregate needed."""
    limit = max(1, min(limit, 200))
    runs = db.query(AuditRun).order_by(AuditRun.started_at.desc()).limit(limit).all()
    return {"runs": [_serialize_run(r) for r in runs]}


@router.get("/runs/latest")
def get_latest_run(_: User = Depends(_require_viewer), db: Session = Depends(get_db)):
    """The main System Audit page's primary data source -- most recent
    COMPLETED run, with its full finding list, or {"run": None} if no
    audit has ever completed yet (a brand-new deployment, or one where
    every attempted run so far has failed)."""
    run = (
        db.query(AuditRun)
        .filter(AuditRun.status == "completed")
        .order_by(AuditRun.started_at.desc())
        .first()
    )
    if run is None:
        return {"run": None}
    return {"run": _serialize_run(run, with_findings=True)}


@router.get("/runs/{run_id}")
def get_run(run_id: int, _: User = Depends(_require_viewer), db: Session = Depends(get_db)):
    run = db.get(AuditRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Audit run not found.")
    return {"run": _serialize_run(run, with_findings=True)}


@router.get("/runs/{run_id}/compare/{other_run_id}")
def compare_runs(run_id: int, other_run_id: int, _: User = Depends(_require_viewer), db: Session = Depends(get_db)):
    """Spec section 9: "Current Audit vs Previous Audit". `run_id` is
    treated as the newer/current run, `other_run_id` the one to compare
    against -- caller decides which is which (usually latest vs. the run
    before it, but the run-history page lets picking any two)."""
    run = db.get(AuditRun, run_id)
    other = db.get(AuditRun, other_run_id)
    if run is None or other is None:
        raise HTTPException(status_code=404, detail="Audit run not found.")
    other_by_check = {f.check_id: f for f in other.findings}
    run_by_check = {f.check_id: f for f in run.findings}
    new_ids = sorted(set(run_by_check) - set(other_by_check))
    removed_ids = sorted(set(other_by_check) - set(run_by_check))
    changed_ids = sorted(
        cid for cid in (set(run_by_check) & set(other_by_check))
        if run_by_check[cid].severity != other_by_check[cid].severity
    )
    return {
        "run": _serialize_run(run),
        "other_run": _serialize_run(other),
        "new_checks": [_serialize_finding(run_by_check[cid]) for cid in new_ids],
        "removed_checks": [_serialize_finding(other_by_check[cid]) for cid in removed_ids],
        "changed_severity": [
            {"check_id": cid, "from": other_by_check[cid].severity, "to": run_by_check[cid].severity,
             "finding": _serialize_finding(run_by_check[cid])}
            for cid in changed_ids
        ],
    }


@router.post("/run")
async def run_audit_now(user: User = Depends(_require_runner), db: Session = Depends(get_db)):
    """"Run Audit Now" (spec section 12). Synchronous from the caller's
    point of view (the button shows a spinner until this returns) --
    system_audit.run_audit() itself typically completes in well under a
    second (file reads only, no subprocess/network calls in Phase 1), so
    there's no need for a background-job/poll-for-completion pattern the
    way e.g. a report export might need. Run via asyncio.to_thread same
    as every other blocking call from an async route in this app."""
    try:
        run = await asyncio.to_thread(system_audit.run_audit, db, trigger="manual", triggered_by_user=user)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Audit run failed: {e}")
    return {"run": _serialize_run(run, with_findings=True)}


@router.get("/runs/{run_id}/export.csv")
def export_run_csv(run_id: int, _: User = Depends(_require_viewer), db: Session = Depends(get_db)):
    """CSV export (spec section 18's CSV/JSON option -- PDF is not
    implemented, see system_audit/__init__.py's module docstring on Phase
    1 scope). Same "build the CSV text server-side, return it as a JSON
    field, let the frontend construct a downloadable Blob" pattern as
    tickets.py's bulk_export_tickets -- no StreamingResponse/file-download
    response type exists anywhere else in this app, so this doesn't
    introduce a second export mechanism."""
    run = db.get(AuditRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Audit run not found.")
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "check_id", "category", "severity", "status", "title", "description", "why_it_matters",
        "current_state", "expected_state", "evidence", "remediation",
    ])
    for f in run.findings:
        writer.writerow([
            f.check_id, f.category, f.severity, f.status, f.title, f.description, f.why_it_matters or "",
            f.current_state or "", f.expected_state or "", f.evidence or "", f.remediation or "",
        ])
    filename = f"system-audit-run-{run.id}-{(run.started_at.date().isoformat() if run.started_at else 'unknown')}.csv"
    return {"csv": buf.getvalue(), "filename": filename, "count": len(run.findings)}


@router.get("/runs/{run_id}/export.pdf")
def export_run_pdf(run_id: int, report: str = "full", _: User = Depends(_require_viewer), db: Session = Depends(get_db)):
    """PDF export (spec section 18): `report` selects "full" (default),
    "summary", "firewall", "ssh", or "system" -- see report_pdf.py's
    REPORT_TITLES/build_run_pdf() for what each contains. Unlike CSV
    export's "build text, return as a JSON field, let the frontend make a
    Blob" pattern (no native binary-download mechanism existed elsewhere
    in this app before now), a PDF is real binary content -- returned
    directly as an application/pdf Response with Content-Disposition, so
    the browser's own download handling takes it from here."""
    run = db.get(AuditRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Audit run not found.")
    if report not in report_pdf.REPORT_TITLES:
        raise HTTPException(status_code=400, detail=f"Unknown report type: {report!r}.")
    pdf_bytes = report_pdf.build_run_pdf(run, report)
    filename = f"system-audit-run-{run.id}-{report}-" \
               f"{(run.started_at.date().isoformat() if run.started_at else 'unknown')}.pdf"
    return Response(
        content=pdf_bytes, media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _host_executor_config():
    """Same construction/fail-closed shape as routes/clients.py's own
    _host_executor_config() (not imported from there directly -- that
    module's version is clients-specific in its docstring/error text,
    and duplicating four lines here avoids a cross-router import for
    something this small)."""
    from services.system.host_executor import HostExecutorConfig
    from ..config import settings
    if not settings.HOST_SSH_TARGET or not settings.HOST_SSH_KEY_PATH:
        raise HTTPException(
            status_code=400,
            detail="Host executor is not configured -- set HOST_SSH_TARGET and HOST_SSH_KEY_PATH "
                    "(see .env.example) before automated remediation can run.",
        )
    return HostExecutorConfig(
        ssh_key_path=settings.HOST_SSH_KEY_PATH,
        ssh_target=settings.HOST_SSH_TARGET,
        remote_script_path=settings.HOST_SSH_REMOTE_SCRIPT_PATH,
        use_sudo=settings.HOST_SSH_USE_SUDO,
        timeout_seconds=settings.HOST_SSH_TIMEOUT_SECONDS,
        ssh_port=settings.HOST_SSH_PORT,
    )


@router.post("/findings/{finding_id}/remediate")
async def remediate_finding(finding_id: int, user: User = Depends(_require_runner), db: Session = Depends(get_db)):
    """"Fix Automatically" (spec section 7). Dispatches by remediation_action's
    "type" -- "chmod" (Phase 3), or "ssh_directive"/"firewall" (Phase 4, see
    services/system/audit_remediate.py's module docstring for the backup/
    validate/rollback story each of those two gets). The frontend is
    expected to show its own confirmation dialog (including the finding's
    own remediation_risk text for ssh_directive/firewall actions) -- this
    endpoint itself doesn't re-confirm, matching every other state-changing
    POST in this app (Revoke, Disconnect, ...), which also rely on the
    frontend's confirmDialog() rather than a second server-side
    confirmation step.

    Re-validates independently of the frontend's own display logic: looks
    up the finding fresh, requires remediation_action to actually be
    present (not just automated_remediation_available -- belt and
    suspenders, though in practice these should never disagree). The
    remote script re-validates every value against its OWN allowlist
    regardless (see audit_remediate.py) -- this endpoint's checks are a
    fast-fail/clear-error convenience, not the actual trust boundary."""
    finding = db.get(AuditFinding, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found.")
    if not finding.remediation_action:
        raise HTTPException(status_code=400, detail="This finding has no automated remediation available.")
    action = json.loads(finding.remediation_action)
    action_type = action.get("type")

    if action_type == "chmod":
        path = action.get("path")
        if not path:
            raise HTTPException(status_code=400, detail="Remediation action is missing a target path.")
        host_action, host_args, detail_of = "remediate-chmod-permissions", [path], \
            lambda r: f"path={path} {r.get('previous_mode')} -> {r.get('new_mode')} verified={r.get('verified')}"
    elif action_type == "ssh_directive":
        directive = action.get("directive")
        if not directive:
            raise HTTPException(status_code=400, detail="Remediation action is missing a target directive.")
        host_action, host_args, detail_of = "remediate-ssh-directive", [directive], \
            lambda r: (f"directive={directive} applied={r.get('applied')} rolled_back={r.get('rolled_back')} "
                       f"new_value={r.get('new_value')}")
    elif action_type == "firewall":
        fw_action = action.get("action")
        if not fw_action:
            raise HTTPException(status_code=400, detail="Remediation action is missing a target firewall action.")
        host_action, host_args, detail_of = "remediate-firewall", [fw_action], \
            lambda r: f"action={fw_action} applied={r.get('applied')}"
    else:
        raise HTTPException(status_code=400, detail=f"Unknown remediation action type: {action_type!r}.")

    config = _host_executor_config()
    from services.openvpn.exceptions import OpenVPNError
    from services.system.host_executor import run_host_command
    try:
        result = await asyncio.to_thread(run_host_command, config, host_action, *host_args)
    except OpenVPNError as e:
        log_action(db, user, "remediate_finding", target=finding.check_id, detail=f"{host_action}: {e.detail}", success=False)
        raise HTTPException(status_code=502, detail=e.detail)

    # Only mark the finding as actually fixed if the host confirmed it
    # applied the change -- chmod/firewall actions always either apply or
    # raise, but remediate_ssh_directive can return applied=False (config
    # validated as invalid, rolled back, nothing changed) WITHOUT raising,
    # since that's an expected, handled outcome, not a transport failure.
    # A rolled-back attempt must never show as "Fixed by <admin> on <date>".
    applied = result.get("applied", True) if isinstance(result, dict) else True
    if applied:
        finding.remediated_at = datetime.now(timezone.utc)
        finding.remediated_by = user.username
    finding.remediation_result = json.dumps(result)
    db.commit()
    log_action(db, user, "remediate_finding", target=finding.check_id, detail=detail_of(result), success=applied)
    return {"finding": _serialize_finding(finding)}
