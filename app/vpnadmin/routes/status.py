from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from .. import cli_wrapper as cli
from ..auth import require_admin, require_user
from ..cli_wrapper import ScriptError
from ..db import get_db
from ..models import AuditLog, User

router = APIRouter(prefix="/api/status", tags=["status"])


@router.get("")
def get_connected(_: User = Depends(require_user)):
    try:
        return cli.status_connected()
    except ScriptError as e:
        raise HTTPException(status_code=502, detail=e.message)


@router.get("/all")
def get_all(_: User = Depends(require_user)):
    try:
        return cli.status_all()
    except ScriptError as e:
        raise HTTPException(status_code=502, detail=e.message)


@router.get("/rejected")
def get_rejected(limit: int = Query(20, ge=1, le=500), _: User = Depends(require_user)):
    try:
        return cli.status_rejected(limit)
    except ScriptError as e:
        raise HTTPException(status_code=502, detail=e.message)


# Deliberately outside the /api/status prefix -- this is a cross-cutting
# summary (status + revoked clients), not purely a "status" resource. Kept
# in this module since it's a thin composition of the functions above.
dashboard_router = APIRouter(prefix="/api", tags=["status"])


@dashboard_router.get("/dashboard")
def get_dashboard(_: User = Depends(require_user)):
    """Everything the dashboard page needs in one round-trip, instead of 4
    separate fetches -- each underlying script call is still individually
    cached/serialized (see cli_wrapper), this just saves HTTP overhead and
    gives the frontend one loading state to manage instead of four."""
    try:
        return cli.dashboard_summary()
    except ScriptError as e:
        raise HTTPException(status_code=502, detail=e.message)


@dashboard_router.get("/audit")
def get_audit_log(limit: int = Query(20, ge=1, le=200), admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Most recent audit-log entries, newest first -- admin-only, since this
    is the same accountability trail as the (also admin-only) audit-log
    retention setting on the Settings page. Powers the Dashboard's Recent
    Activity section; not cached like the CLI-backed endpoints above since
    it's a cheap indexed DB query, not a subprocess call."""
    entries = (
        db.query(AuditLog)
        .order_by(AuditLog.timestamp.desc())
        .limit(limit)
        .all()
    )
    return [
        {
            "timestamp": e.timestamp.isoformat() if e.timestamp else None,
            "username": e.username,
            "action": e.action,
            "target": e.target,
            "detail": e.detail,
            "success": e.success,
        }
        for e in entries
    ]
