"""Support Request form (FAQ page's "Contact Support") -- lets a logged-in
portal user email an administrator directly from within the app when the
FAQ doesn't answer their question. Distinct from mailer.send_admin_notification
(fire-and-forget event notifications an admin opted into) in that this is
always user-initiated and always includes a Reply-To back to the sender.
"""
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

from .. import app_settings, mailer
from ..audit import log_action
from ..auth import require_user
from ..db import get_db
from ..models import AuditLog, User

router = APIRouter()

# Reasonable ceilings, not admin-configurable (same "fixed code constant"
# posture as main.py's background-loop intervals) -- generous enough that
# no genuine support request ever hits them, tight enough that a scripted
# submission can't smuggle megabytes of text through an outbound email.
MAX_SUBJECT_LENGTH = 200
MAX_MESSAGE_LENGTH = 5000

# Per-account throttle, not per-IP -- this endpoint is only reachable
# already-logged-in, so the account itself is the natural identity to
# rate-limit on (an IP-based limit would either be redundant behind the
# same login gate, or wrongly penalize a whole shared office/VPN egress
# rather than the one account spamming it). Backed by AuditLog rather
# than a new table/in-memory counter -- every submission is already
# logged there (see submit_support_request below), so counting recent
# "support_request_submitted" rows for this username IS the rate limit,
# no separate bookkeeping to keep in sync.
SUPPORT_REQUEST_RATE_LIMIT = 3
SUPPORT_REQUEST_RATE_WINDOW_MINUTES = 60


def _rate_limited(db: Session, user: User) -> bool:
    window_start = datetime.now(timezone.utc) - timedelta(minutes=SUPPORT_REQUEST_RATE_WINDOW_MINUTES)
    recent_count = (
        db.query(AuditLog)
        .filter(
            AuditLog.username == user.username,
            AuditLog.action == "support_request_submitted",
            AuditLog.timestamp >= window_start,
        )
        .count()
    )
    return recent_count >= SUPPORT_REQUEST_RATE_LIMIT


class SupportRequest(BaseModel):
    subject: str
    message: str

    @field_validator("subject")
    @classmethod
    def _valid_subject(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Subject is required.")
        if len(v) > MAX_SUBJECT_LENGTH:
            raise ValueError(f"Subject must be {MAX_SUBJECT_LENGTH} characters or fewer.")
        return v

    @field_validator("message")
    @classmethod
    def _valid_message(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Message is required.")
        if len(v) > MAX_MESSAGE_LENGTH:
            raise ValueError(f"Message must be {MAX_MESSAGE_LENGTH} characters or fewer.")
        return v


@router.post("/api/support")
def submit_support_request(body: SupportRequest, user: User = Depends(require_user), db: Session = Depends(get_db)):
    if not user.email:
        # No email on file means there's no address to set Reply-To to,
        # and no address for an admin to respond to either -- same
        # "nothing meaningful to do" case /reset-password's own email
        # dependency runs into. Caught before the rate-limit/send attempt
        # so a user in this state gets a clear, actionable message rather
        # than a generic failure.
        raise HTTPException(status_code=400, detail="Your account has no email address on file -- add one under My Profile before submitting a support request.")

    if _rate_limited(db, user):
        raise HTTPException(
            status_code=429,
            detail=f"You've submitted {SUPPORT_REQUEST_RATE_LIMIT} support requests in the last hour -- please wait before sending another.",
        )

    submitted_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    try:
        mailer.send_support_request(
            requester_name=user.display_name, requester_username=user.username, requester_email=user.email,
            subject=body.subject, message=body.message, submitted_at=submitted_at,
        )
    except mailer.MailerNotConfigured:
        log_action(db, user, "support_request_submitted", target=body.subject, detail="SMTP not configured", success=False)
        raise HTTPException(status_code=400, detail="Support requests aren't available right now -- outbound email isn't configured. Contact your administrator directly if you can.")
    except mailer.NoSupportAddress:
        log_action(db, user, "support_request_submitted", target=body.subject, detail="No support contact email configured", success=False)
        raise HTTPException(status_code=400, detail="Support requests aren't available right now -- no support contact email is configured. Contact your administrator directly if you can.")
    except Exception as e:
        log_action(db, user, "support_request_submitted", target=body.subject, detail=f"send failed: {e}", success=False)
        raise HTTPException(status_code=502, detail="Failed to send your support request. Please try again shortly.")

    log_action(
        db, user, "support_request_submitted", target=body.subject,
        detail=f"sent to {app_settings.runtime.admin_notification_email}", success=True,
    )
    return {"message": "Your support request has been submitted successfully. An administrator will review your inquiry and respond to your registered email address."}
