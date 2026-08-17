"""
Outbound Email Providers (Settings -> Outbound Email) -- CRUD + set-default
+ per-profile test-send for the EmailProvider table. See
email_providers.py (the provider abstraction module -- unfortunate but
accurate name collision with this routes/ file, matching this app's
existing routes/settings.py-vs-Settings-the-concept naming) for the
provider registry/interface this dispatches against, and mailer.py's
_resolve_default_provider for how a send actually picks up whichever
profile is is_default+is_active here.
"""
import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

from .. import email_providers, mailer
from ..app_settings import SMTP_PASSWORD_PLACEHOLDER
from ..audit import log_action
from ..db import get_db
from ..models import EmailProvider, User
from ..permissions import require_permission

router = APIRouter(prefix="/api/email-providers", tags=["email-providers"])

require_admin = require_permission("settings", "manage")  # same gate as the rest of Settings

# input_type values whose config value is treated as a secret -- masked on
# every GET response (see _serialize_provider) and, on PATCH/POST, a
# value exactly equal to this placeholder means "leave whatever's already
# saved for this key alone" rather than overwriting it with the literal
# placeholder text. Same masking convention app_settings.py's
# SMTP_PASSWORD_PLACEHOLDER already established for the (now-legacy)
# single-SMTP-block Settings form -- reused here rather than inventing a
# second placeholder string for the exact same purpose.
_SECRET_INPUT_TYPES = ("password",)


def _provider_type_spec(provider_type: str) -> dict:
    impl = email_providers.get_provider(provider_type)
    return {
        "type_key": impl.type_key,
        "display_name": impl.display_name,
        "fields": [
            {"key": key, "label": label, "input_type": input_type, "required": required}
            for key, label, input_type, required in impl.fields
        ],
    }


def _serialize_provider(row: EmailProvider) -> dict:
    impl = email_providers.get_provider(row.provider_type)
    config = json.loads(row.config or "{}")
    secret_keys = {key for key, _label, input_type, _required in impl.fields if input_type in _SECRET_INPUT_TYPES}
    masked_config = {
        key: (SMTP_PASSWORD_PLACEHOLDER if key in secret_keys and value else value)
        for key, value in config.items()
    }
    return {
        "id": row.id,
        "name": row.name,
        "provider_type": row.provider_type,
        "provider_display_name": impl.display_name,
        "is_active": row.is_active,
        "is_default": row.is_default,
        "config": masked_config,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


def _merge_secrets(new_config: dict, existing_config: dict, impl: email_providers.EmailProviderBase) -> dict:
    """A PATCH/test-send request's config may contain the literal
    SMTP_PASSWORD_PLACEHOLDER for a secret field the admin didn't intend
    to change (the form never shows the real value back to them, so it
    round-trips the placeholder verbatim if left untouched) -- swap those
    back for whatever's actually saved before validating/using the
    result. A secret field that's blank/absent stays blank (clearing it
    is a legitimate, distinct action from "didn't touch it")."""
    secret_keys = {key for key, _label, input_type, _required in impl.fields if input_type in _SECRET_INPUT_TYPES}
    merged = dict(new_config)
    for key in secret_keys:
        if merged.get(key) == SMTP_PASSWORD_PLACEHOLDER:
            merged[key] = existing_config.get(key)
    return merged


@router.get("/types")
def list_provider_types(_: User = Depends(require_admin)):
    """Drives the Settings page's Add/Edit Provider dialog -- one entry
    per registered provider type, each with its own field spec, so the
    dialog can render the right form without any provider-specific
    frontend code (adding a new provider type here needs zero HTML/JS
    changes, only email_providers.py's PROVIDERS registry)."""
    return [_provider_type_spec(key) for key in email_providers.PROVIDERS]


@router.get("")
def list_providers(_: User = Depends(require_admin), db: Session = Depends(get_db)):
    rows = db.query(EmailProvider).order_by(EmailProvider.created_at).all()
    return [_serialize_provider(r) for r in rows]


class ProviderRequest(BaseModel):
    name: str
    provider_type: str
    is_active: bool = True
    config: dict = {}

    @field_validator("name")
    @classmethod
    def _valid_name(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Profile name is required.")
        if len(v) > 100:
            raise ValueError("Profile name must be 100 characters or fewer.")
        return v


@router.post("")
def create_provider(body: ProviderRequest, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    try:
        impl = email_providers.get_provider(body.provider_type)
    except email_providers.ProviderConfigError as e:
        raise HTTPException(status_code=400, detail=str(e))

    try:
        cleaned_config = impl.validate_config(body.config)
    except email_providers.ProviderConfigError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # The very first provider ever created becomes the default automatically
    # -- there's no meaningful "no default yet, pick one eventually" state
    # for a fresh install to sit in (every send_* call would just fail with
    # MailerNotConfigured until an admin remembered to flip it manually).
    # Every subsequent profile stays non-default until explicitly promoted
    # via set_default below.
    is_first = db.query(EmailProvider).first() is None

    row = EmailProvider(
        name=body.name, provider_type=body.provider_type, is_active=body.is_active,
        is_default=is_first, config=json.dumps(cleaned_config),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    log_action(db, admin, "create_email_provider", target=row.name, detail=f"type={row.provider_type}; default={row.is_default}")
    return _serialize_provider(row)


@router.patch("/{provider_id}")
def update_provider(provider_id: int, body: ProviderRequest, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    row = db.get(EmailProvider, provider_id)
    if row is None:
        raise HTTPException(status_code=404, detail="No such email provider.")
    if body.provider_type != row.provider_type:
        # Changing provider TYPE isn't an "edit" of this profile -- its
        # entire field set changes, so any already-stored config becomes
        # meaningless (a Resend api_key means nothing to the SMTP
        # provider, and vice versa). An admin who wants to switch
        # providers creates a new profile instead; this profile's type is
        # fixed at creation.
        raise HTTPException(status_code=400, detail="A provider's type can't be changed after creation -- create a new profile instead.")

    impl = email_providers.get_provider(row.provider_type)
    existing_config = json.loads(row.config or "{}")
    merged_config = _merge_secrets(body.config, existing_config, impl)
    try:
        cleaned_config = impl.validate_config(merged_config)
    except email_providers.ProviderConfigError as e:
        raise HTTPException(status_code=400, detail=str(e))

    changes = []
    if body.name != row.name:
        row.name = body.name
        changes.append("name")
    if body.is_active != row.is_active:
        if not body.is_active and row.is_default:
            raise HTTPException(status_code=400, detail="Can't disable the default provider -- set a different profile as default first.")
        row.is_active = body.is_active
        changes.append("is_active")
    if cleaned_config != existing_config:
        row.config = json.dumps(cleaned_config)
        changes.append("config")

    if changes:
        row.updated_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(row)
        log_action(db, admin, "update_email_provider", target=row.name, detail="; ".join(changes))
    return _serialize_provider(row)


@router.post("/{provider_id}/set-default")
def set_default_provider(provider_id: int, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    row = db.get(EmailProvider, provider_id)
    if row is None:
        raise HTTPException(status_code=404, detail="No such email provider.")
    if not row.is_active:
        raise HTTPException(status_code=400, detail="Can't make a disabled profile the default -- enable it first.")
    if row.is_default:
        return _serialize_provider(row)  # already default, nothing to do

    # Application-level "only one default" enforcement (see EmailProvider's
    # own docstring for why this isn't a DB constraint) -- clear every
    # other row's flag in the same transaction as setting this one, so
    # there's never a moment (even under a concurrent request) where two
    # rows are default or zero are.
    db.query(EmailProvider).filter(EmailProvider.is_default.is_(True)).update({"is_default": False})
    row.is_default = True
    row.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(row)
    log_action(db, admin, "set_default_email_provider", target=row.name)
    return _serialize_provider(row)


@router.delete("/{provider_id}")
def delete_provider(provider_id: int, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    row = db.get(EmailProvider, provider_id)
    if row is None:
        raise HTTPException(status_code=404, detail="No such email provider.")
    if row.is_default:
        raise HTTPException(status_code=400, detail="Can't delete the default provider -- set a different profile as default first.")
    name = row.name
    db.delete(row)
    db.commit()
    log_action(db, admin, "delete_email_provider", target=name)
    return {"message": f"Provider '{name}' deleted."}


class TestProviderRequest(BaseModel):
    to_address: str
    config: dict = {}

    @field_validator("to_address")
    @classmethod
    def _valid_email(cls, v: str) -> str:
        v = v.strip()
        if not mailer.is_valid_email(v):
            raise ValueError("Please enter a valid destination email address.")
        return v


@router.post("/{provider_id}/test")
def test_provider(provider_id: int, body: TestProviderRequest, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Sends a real test email through THIS profile's config -- regardless
    of whether it's active or the current default (an admin needs to be
    able to test a profile they're still setting up, before committing to
    it as live). `body.config` lets the Settings-page dialog test the
    form's CURRENT (possibly unsaved) values, same "test what's in the
    form, not necessarily what's saved" precedent the old single-SMTP-
    block /api/settings/smtp/test endpoint set -- secret fields still
    equal to the placeholder are merged back from what's actually saved
    (see _merge_secrets)."""
    row = db.get(EmailProvider, provider_id)
    if row is None:
        raise HTTPException(status_code=404, detail="No such email provider.")

    impl = email_providers.get_provider(row.provider_type)
    existing_config = json.loads(row.config or "{}")
    test_config = body.config or existing_config
    merged_config = _merge_secrets(test_config, existing_config, impl)
    try:
        cleaned_config = impl.validate_config(merged_config)
    except email_providers.ProviderConfigError as e:
        raise HTTPException(status_code=400, detail=str(e))

    try:
        mailer.send_test_email_via_config(provider_type=row.provider_type, config=cleaned_config, to_address=body.to_address)
    except email_providers.ProviderSendError as e:
        log_action(db, admin, "test_email_provider", target=row.name, detail=f"failed: {e}", success=False)
        raise HTTPException(status_code=502, detail=f"Test send failed: {e}")

    log_action(db, admin, "test_email_provider", target=row.name, detail=f"sent to {body.to_address}", success=True)
    return {"message": f"Test email sent to {body.to_address} via '{row.name}'."}
