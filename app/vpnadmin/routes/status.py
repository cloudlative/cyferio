from fastapi import APIRouter, Depends, HTTPException, Query

from .. import cli_wrapper as cli
from ..auth import require_user
from ..cli_wrapper import ScriptError
from ..models import User

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
