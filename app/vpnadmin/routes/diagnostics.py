from fastapi import APIRouter, Depends, HTTPException

from .. import cli_wrapper as cli
from ..auth import require_user
from ..cli_wrapper import ScriptError
from ..db import get_db_engine_info
from ..models import User

router = APIRouter(prefix="/api", tags=["diagnostics"])


@router.get("/check")
def get_check(_: User = Depends(require_user)):
    """This checks PKI-vs-MAC-db consistency (see check_consistency), not
    the app's own SQL database -- db_engine is included here anyway (rather
    than a separate endpoint) purely because the Diagnostics page's card
    happens to be titled "Database Consistency" and that's the natural spot
    for "which database is this app itself using" to be visible at a
    glance."""
    try:
        result = dict(cli.get_check_consistency_snapshot())
    except ScriptError as e:
        raise HTTPException(status_code=502, detail=e.message)
    result["db_engine"] = get_db_engine_info()
    return result


@router.get("/lint-db")
def get_lint_db(_: User = Depends(require_user)):
    try:
        return cli.get_lint_db_snapshot()
    except ScriptError as e:
        raise HTTPException(status_code=502, detail=e.message)
