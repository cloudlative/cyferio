import re

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

from .. import cli_wrapper as cli
from ..audit import log_action
from ..auth import require_admin, require_user
from ..cli_wrapper import ScriptError
from ..db import get_db
from ..models import User

router = APIRouter(prefix="/api/clients", tags=["clients"])

# Client names: the script itself sanitizes to this character set (replacing
# anything else with "_"), and that sanitization already happened silently
# before. Validating up front here gives a clear 400 error in the UI
# instead of the client being silently created under a mangled name.
NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


class AddClientRequest(BaseModel):
    name: str
    mac: str

    @field_validator("name")
    @classmethod
    def _valid_name(cls, v: str) -> str:
        if not NAME_RE.match(v):
            raise ValueError(
                "Name must be 1-64 characters: letters, numbers, underscore, or hyphen only."
            )
        return v

    @field_validator("mac")
    @classmethod
    def _nonempty_mac(cls, v: str) -> str:
        # Deliberately not re-validating the MAC format here -- the script
        # normalizes/validates it robustly already (any separator style,
        # any case) and is the single source of truth for that logic.
        if not v.strip():
            raise ValueError("MAC address is required.")
        return v.strip()


@router.get("")
def get_clients(_: User = Depends(require_user)):
    try:
        return cli.list_clients()
    except ScriptError as e:
        raise HTTPException(status_code=502, detail=e.message)


@router.get("/revoked")
def get_revoked_clients(_: User = Depends(require_user)):
    try:
        return cli.list_revoked()
    except ScriptError as e:
        raise HTTPException(status_code=502, detail=e.message)


@router.get("/{name}/macs")
def get_client_macs(name: str, _: User = Depends(require_user)):
    if not NAME_RE.match(name):
        raise HTTPException(status_code=400, detail="Invalid client name.")
    try:
        return cli.list_macs(name)
    except ScriptError as e:
        raise HTTPException(status_code=502, detail=e.message)


class MacRequest(BaseModel):
    mac: str

    @field_validator("mac")
    @classmethod
    def _nonempty_mac(cls, v: str) -> str:
        # Not re-validating the format here either -- see AddClientRequest
        # above, same reasoning: the script normalizes/validates.
        if not v.strip():
            raise ValueError("MAC address is required.")
        return v.strip()


@router.post("/{name}/macs", status_code=201)
def add_client_mac(name: str, body: MacRequest, user: User = Depends(require_admin), db: Session = Depends(get_db)):
    if not NAME_RE.match(name):
        raise HTTPException(status_code=400, detail="Invalid client name.")
    try:
        result = cli.add_mac(name, body.mac)
    except ScriptError as e:
        log_action(db, user, "add_mac", target=name, detail=e.message, success=False)
        raise HTTPException(status_code=400, detail=e.message)
    log_action(db, user, "add_mac", target=name, detail=result, success=True)
    return {"message": result}


@router.delete("/{name}/macs/{mac}")
def remove_client_mac(name: str, mac: str, user: User = Depends(require_admin), db: Session = Depends(get_db)):
    if not NAME_RE.match(name):
        raise HTTPException(status_code=400, detail="Invalid client name.")
    try:
        result = cli.remove_mac(name, mac)
    except ScriptError as e:
        log_action(db, user, "remove_mac", target=name, detail=e.message, success=False)
        raise HTTPException(status_code=400, detail=e.message)
    log_action(db, user, "remove_mac", target=name, detail=result, success=True)
    return {"message": result}


@router.post("", status_code=201)
def add_client(body: AddClientRequest, user: User = Depends(require_admin), db: Session = Depends(get_db)):
    try:
        result = cli.add_client(body.name, body.mac)
    except ScriptError as e:
        log_action(db, user, "add_client", target=body.name, detail=e.message, success=False)
        raise HTTPException(status_code=400, detail=e.message)
    log_action(db, user, "add_client", target=body.name, detail=result, success=True)
    return {"message": result}


@router.delete("/{name}")
def revoke_client(name: str, user: User = Depends(require_admin), db: Session = Depends(get_db)):
    if not NAME_RE.match(name):
        raise HTTPException(status_code=400, detail="Invalid client name.")
    try:
        result = cli.revoke_client(name)
    except ScriptError as e:
        log_action(db, user, "revoke_client", target=name, detail=e.message, success=False)
        raise HTTPException(status_code=400, detail=e.message)
    log_action(db, user, "revoke_client", target=name, detail=result, success=True)
    return {"message": result}
