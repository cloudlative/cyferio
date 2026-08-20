"""
Multi-Factor Authentication (TOTP) -- core helpers shared by routes/auth.py
(login-flow branching), routes/mfa.py (enrollment/verification pages+API),
and routes/users.py (admin reset/disable/force-enroll actions).

This module only implements TOTP (RFC 6238, any authenticator app --
Google/Microsoft/Authy/1Password/Bitwarden/etc.) -- email/SMS/WebAuthn/
push are explicitly deferred (see the feature's plan), but nothing here
assumes TOTP is the only possible method: `effective_policy()` answers
"should this account be challenged at all", independent of by which
method, and User.mfa_enabled/mfa_secret_encrypted are TOTP-specific
columns a future method would add its own sibling columns for, not
repurpose.

Session-handling note (see the plan's "Key design decision"): nothing in
this module ever touches request.session directly -- that's routes/auth.py's
and routes/mfa.py's job. This module is pure policy/crypto/verification
logic, easy to unit test in isolation.
"""
import base64
import io
import secrets
from datetime import datetime, timedelta, timezone

import pyotp
import qrcode
from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy.orm import Session

from . import app_settings
from .config import settings as env_settings
from .models import MfaRecoveryCode, MfaTrustedDevice, User

VALID_POLICY_OVERRIDES = ("required", "optional", "exempt")

_RECOVERY_CODE_COUNT = 10


def _fernet() -> Fernet:
    # Constructed fresh per call rather than cached at import time -- cheap
    # (Fernet() is just wrapping a key), and avoids the key being frozen
    # into a module-level object before env_settings has finished loading
    # in tests that monkeypatch MFA_ENCRYPTION_KEY.
    key = env_settings.MFA_ENCRYPTION_KEY
    if isinstance(key, str):
        key = key.encode("ascii")
    return Fernet(key)


def encrypt_secret(raw_secret: str) -> str:
    return _fernet().encrypt(raw_secret.encode("utf-8")).decode("ascii")


def decrypt_secret(encrypted: str) -> str | None:
    """Returns None (rather than raising) if the value can't be decrypted
    under the CURRENT key -- e.g. MFA_ENCRYPTION_KEY was left unset and
    the process restarted, invalidating everything encrypted under the
    previous ephemeral key (see config.py's own docstring on this
    tradeoff). Callers treat None the same as "not enrolled" -- the
    account isn't silently let in without a second factor, it just needs
    to re-enroll."""
    try:
        return _fernet().decrypt(encrypted.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError, UnicodeDecodeError):
        return None


def generate_secret() -> str:
    return pyotp.random_base32()


def provisioning_uri(user: User, secret: str) -> str:
    issuer = app_settings.runtime.app_name
    return pyotp.TOTP(secret).provisioning_uri(name=user.username, issuer_name=issuer)


def qr_code_data_uri(uri: str) -> str:
    """Renders `uri` as a PNG QR code, returned as a ready-to-embed
    `data:image/png;base64,...` string -- no static-asset storage needed,
    same "ships as a data URI" approach the Support Ticketing System's
    attachment previews deliberately avoided needing for this exact
    reason (a one-off image with no reuse across requests)."""
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode("ascii")


def verify_totp(secret: str, code: str) -> bool:
    code = (code or "").strip().replace(" ", "")
    if not code:
        return False
    try:
        # valid_window=1: tolerates one 30s clock-skew step on either
        # side, matching every major authenticator app's own tolerance --
        # a code from that generated it exactly ~30s early/late otherwise
        # bogusly fails to a person who typed it correctly.
        return pyotp.TOTP(secret).verify(code, valid_window=1)
    except Exception:
        return False


def generate_recovery_codes(n: int = _RECOVERY_CODE_COUNT) -> list[str]:
    """Plaintext codes, e.g. "a1b2-c3d4" -- shown to the caller exactly
    once (see routes/mfa.py) and never stored anywhere in this form; only
    hash_recovery_code()'s output is persisted."""
    return [f"{secrets.token_hex(4)}-{secrets.token_hex(4)}" for _ in range(n)]


def hash_recovery_code(code: str) -> str:
    import hashlib
    normalized = code.strip().lower().replace(" ", "")
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def replace_recovery_codes(user: User, db: Session) -> list[str]:
    """Deletes every existing recovery code row for `user` and inserts a
    fresh batch -- this IS what "invalidate previous codes when
    regenerated" means (no separate active/inactive flag). Returns the
    new PLAINTEXT codes for one-time display; the caller is responsible
    for showing them and never persisting the plaintext anywhere else."""
    db.query(MfaRecoveryCode).filter(MfaRecoveryCode.user_id == user.id).delete()
    codes = generate_recovery_codes()
    for code in codes:
        db.add(MfaRecoveryCode(user_id=user.id, code_hash=hash_recovery_code(code)))
    db.commit()
    return codes


def consume_recovery_code(user: User, code: str, db: Session) -> bool:
    """True and marks the matching row used (single-use) if `code` matches
    an unused recovery code for `user`; False otherwise. A used code can
    never match again -- used_at being non-NULL excludes it from the
    query below."""
    code_hash = hash_recovery_code(code)
    row = (
        db.query(MfaRecoveryCode)
        .filter(MfaRecoveryCode.user_id == user.id, MfaRecoveryCode.code_hash == code_hash,
                MfaRecoveryCode.used_at.is_(None))
        .first()
    )
    if row is None:
        return False
    row.used_at = datetime.now(timezone.utc)
    db.commit()
    return True


def remaining_recovery_codes_count(user: User, db: Session) -> int:
    return db.query(MfaRecoveryCode).filter(
        MfaRecoveryCode.user_id == user.id, MfaRecoveryCode.used_at.is_(None)
    ).count()


def effective_policy(user: User, db: Session) -> str:
    """Resolves to "required" | "optional" | "exempt" -- see the feature's
    plan for the full precedence writeup. Called on every login attempt
    (cheap: at most one extra query, for the role_requirements JSON
    already cached on `runtime`) and by admin/report views that need to
    know "is this account currently supposed to have MFA."""
    s = app_settings.runtime
    if s.mfa_mode == "disabled":
        return "exempt"  # kill switch -- treat exactly like an explicit per-user exemption
    if user.mfa_policy_override in VALID_POLICY_OVERRIDES:
        return user.mfa_policy_override
    import json
    role_requirements = {}
    if s.mfa_role_requirements:
        try:
            role_requirements = json.loads(s.mfa_role_requirements)
        except (ValueError, TypeError):
            role_requirements = {}
    role_slug = user.role_slug
    if role_slug in role_requirements and role_requirements[role_slug] in VALID_POLICY_OVERRIDES:
        return role_requirements[role_slug]
    return s.mfa_mode if s.mfa_mode in ("required", "optional") else "optional"


def is_privileged(user: User, db: Session) -> bool:
    """Any role granting "manage" on "users" or "settings" -- used only for
    the notify_admin_on_mfa_disabled admin alert (see routes/mfa.py and
    routes/users.py). Computed dynamically against the role's actual
    ObjectPermission rows, not a hardcoded role-slug list -- a custom role
    an admin creates with equivalent privileges is covered automatically."""
    from .permissions import has_permission
    return has_permission(db, user, "users", "manage") or has_permission(db, user, "settings", "manage")


# --- Trusted device (Settings -> Multi-Factor Authentication -> "Remember
# this device for N days") ---------------------------------------------------

TRUSTED_DEVICE_COOKIE_NAME = "mfa_trusted_device"


def _hash_device_token(token: str) -> str:
    import hashlib
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def issue_trusted_device_token(user: User, db: Session, *, days: int, user_agent: str | None, ip: str | None) -> str:
    token = secrets.token_urlsafe(32)
    db.add(MfaTrustedDevice(
        user_id=user.id, token_hash=_hash_device_token(token), user_agent=(user_agent or "")[:255],
        created_ip=ip, expires_at=datetime.now(timezone.utc) + timedelta(days=days),
    ))
    db.commit()
    return token


def is_device_trusted(user: User, token: str | None, db: Session) -> bool:
    """True if `token` (the raw cookie value) matches a live, unexpired
    MfaTrustedDevice row for `user` -- scoped to this specific user_id, not
    just "any row with this hash", so a stolen cookie value is useless
    without also being presented on a login attempt for the SAME account
    it was issued to."""
    if not token:
        return False
    from .auth import _as_aware_utc
    row = (
        db.query(MfaTrustedDevice)
        .filter(MfaTrustedDevice.user_id == user.id, MfaTrustedDevice.token_hash == _hash_device_token(token))
        .first()
    )
    if row is None:
        return False
    if _as_aware_utc(row.expires_at) < datetime.now(timezone.utc):
        return False
    row.last_used_at = datetime.now(timezone.utc)
    db.commit()
    return True
