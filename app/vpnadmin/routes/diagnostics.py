from fastapi import APIRouter, Depends, HTTPException

from .. import cli_wrapper as cli
from ..auth import require_user
from ..cli_wrapper import ScriptError
from ..models import User

router = APIRouter(prefix="/api", tags=["diagnostics"])


@router.get("/check")
def get_check(_: User = Depends(require_user)):
    try:
        return cli.check_consistency()
    except ScriptError as e:
        raise HTTPException(status_code=502, detail=e.message)


@router.get("/lint-db")
def get_lint_db(_: User = Depends(require_user)):
    try:
        return cli.lint_db()
    except ScriptError as e:
        raise HTTPException(status_code=502, detail=e.message)
