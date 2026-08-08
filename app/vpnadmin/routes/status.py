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
