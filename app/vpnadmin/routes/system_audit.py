"""System Audit -- server-hardening/security-assessment API. See
system_audit/__init__.py's module docstring for the engine design (why
read-only via /hostfs, why no remediation yet, multi-node data-model
intent). This router is thin by design: every real check/scoring/history-
diff/notification decision lives in system_audit/run_audit(); routes here
are just auth + (de)serialization + the CSV export format."""
import asyncio
import csv
import io

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import system_audit
from ..db import get_db
from ..models import AuditFinding, AuditRun, User
from ..permissions import require_permission_any_scope

router = APIRouter(prefix="/api/system-audit", tags=["system-audit"])

# view: see runs/findings. execute: trigger a new run ("Run Audit Now").
# Both any_scope -- there's no "own" scope for a whole-server security
# posture (see AuditNotification's own docstring for the same point about
# notifications).
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
        "automated_remediation_available": f.automated_remediation_available,
        "status": f.status,
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
