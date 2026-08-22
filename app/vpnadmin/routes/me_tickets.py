"""Support Ticketing System -- self-service side ("My Support" page).
Same "always resolve request.user's own records, never an id/username
taken from the request" pattern as routes/me_vpn.py/routes/
me_connection_issues.py (see those modules' docstrings): every query here
is filtered on `SupportTicket.created_by_user_id == user.id`, structurally
-- require_permission("support_tickets", ...) is enough on its own, no
separate own-vs-any scope check is needed since there's no path/query
param that could name someone else's ticket.

routes/tickets.py is the admin-console counterpart (any scope, sees every
ticket, can reply/assign/change status, can leave internal notes). Both
routers share the same underlying tables; this one only ever narrows to
"my own" and never returns an internal note (filtered out of the
serialized message list here, not merely hidden client-side).

Replaces the old routes/support.py "Contact Support" email form -- see
the Support Ticketing System plan for why that's superseded rather than
kept alongside this."""
import json
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from .. import app_settings, ticket_attachments, ticket_notifications
from ..audit import log_action
from ..client_ip import get_client_ip
from ..db import get_db
from ..models import AuditLog, SupportTicket, SupportTicketAttachment, SupportTicketMessage, User
from ..permissions import require_permission
from ..support_tickets import (
    DEFAULT_PRIORITY,
    DEFAULT_STATUS,
    PRIORITIES,
    REGULAR_STATUSES,
    STATUSES,
    TERMINAL_STATUSES,
    allowed_next_statuses,
    categories_for_form,
    category_label,
    is_valid_category,
    priority_label,
    status_label,
    status_sort_key,
)
from .me_vpn import get_my_vpn_report

router = APIRouter(prefix="/api/me/tickets", tags=["me"])

MAX_SUBJECT_LENGTH = 200
MAX_DESCRIPTION_LENGTH = 5000

_RATE_LIMITED_ACTIONS = ("self_ticket_created", "self_ticket_reply")


def _rate_limited(db: Session, user: User) -> bool:
    """Same "count recent AuditLog rows for this username" approach the
    old routes/support.py used -- see that module's own comment. The
    count/window are now admin-tweakable (app_settings.runtime.
    support_ticket_rate_limit_count/_window_minutes) rather than hardcoded,
    per the Support Ticketing System plan's explicit requirement."""
    s = app_settings.runtime
    window_start = datetime.now(timezone.utc) - timedelta(minutes=s.support_ticket_rate_limit_window_minutes)
    recent_count = (
        db.query(AuditLog)
        .filter(
            AuditLog.username == user.username,
            AuditLog.action.in_(_RATE_LIMITED_ACTIONS),
            AuditLog.timestamp >= window_start,
        )
        .count()
    )
    return recent_count >= s.support_ticket_rate_limit_count


def _attach_validated_files(db: Session, message: SupportTicketMessage, ticket_id: int, uploader_id: int,
                             validated: list[tuple[bytes, str, str]]) -> None:
    """Stores every already-validated upload (see ticket_attachments.
    validate_all, which MUST be called by the route handler BEFORE it
    creates the ticket/message row -- that ordering, not this function,
    is what guarantees a rejected attachment never leaves a half-flushed
    ticket/message in the session; see validate_all's own docstring),
    creating one SupportTicketAttachment row per file. Shared by create/
    reply on both this router and routes/tickets.py's admin counterpart."""
    for original_filename, stored_path, content_type, size_bytes in ticket_attachments.store_all(ticket_id, validated):
        db.add(SupportTicketAttachment(
            ticket_id=ticket_id, message_id=message.id, original_filename=original_filename,
            stored_path=stored_path, content_type=content_type, size_bytes=size_bytes, uploaded_by_user_id=uploader_id,
        ))


def _require_own_ticket(db: Session, user: User, ticket_id: int) -> SupportTicket:
    ticket = (
        db.query(SupportTicket)
        .filter(SupportTicket.id == ticket_id, SupportTicket.created_by_user_id == user.id, SupportTicket.deleted.is_(False))
        .one_or_none()
    )
    if ticket is None:
        # Same "don't confirm existence to a non-owner" posture as other
        # own-scope endpoints -- 404 whether it doesn't exist at all or
        # belongs to someone else.
        raise HTTPException(status_code=404, detail="Ticket not found.")
    return ticket


def _serialize_ticket_summary(t: SupportTicket) -> dict:
    return {
        "id": t.id,
        "subject": t.subject,
        "category": t.category,
        "category_label": category_label(t.category),
        "priority": t.priority,
        "priority_label": priority_label(t.priority),
        "status": t.status,
        "status_label": status_label(t.status),
        "assigned_admin": t.assigned_admin.display_name if t.assigned_admin else None,
        "assigned_admin_id": t.assigned_admin_id,
        "created_at": t.created_at.isoformat() if t.created_at else None,
        "updated_at": t.updated_at.isoformat() if t.updated_at else None,
        "created_by": t.created_by.display_name if t.created_by else None,
        # Duplicate Ticket Management -- derived at serialize time, never
        # denormalized (see SupportTicket.duplicate_of_ticket_id's own
        # docstring). duplicate_count is only meaningful for a PARENT (a
        # ticket nobody points at has an empty `duplicates` list, len 0).
        "duplicate_of_ticket_id": t.duplicate_of_ticket_id,
        "duplicate_of_subject": t.duplicate_of.subject if t.duplicate_of else None,
        "duplicate_count": len(t.duplicates) if t.duplicates else 0,
        "locked": bool(t.locked),
        "deleted": bool(t.deleted),
    }


def _serialize_message(m: SupportTicketMessage, *, is_admin_view: bool) -> dict:
    return {
        "id": m.id,
        "author": m.author.display_name if m.author else "Unknown",
        # "admin" vs "user" identification badge (feature spec's "user/
        # admin identification badges") -- derived from whether the author
        # is this ticket's own creator, not from the author's current
        # role (a demoted/promoted account after the fact shouldn't
        # rewrite history in the thread view).
        "author_is_admin": m.author_user_id != m.ticket.created_by_user_id,
        "body": m.body,
        "is_internal_note": m.is_internal_note if is_admin_view else False,
        "created_at": m.created_at.isoformat() if m.created_at else None,
        "attachments": [
            {"id": a.id, "filename": a.original_filename, "size_bytes": a.size_bytes, "content_type": a.content_type}
            for a in m.attachments
        ],
    }


def is_duplicate_locked(t: SupportTicket) -> bool:
    """Option A enforcement (see SupportTicket.duplicate_of_ticket_id's
    docstring): a ticket marked as a duplicate of another is kept open/
    readable but blocked from further independent processing -- both
    self-service replies (routes/me_tickets.py) and admin replies/status
    changes (routes/tickets.py) check this before acting."""
    return t.duplicate_of_ticket_id is not None


def _serialize_ticket_detail(t: SupportTicket, *, is_admin_view: bool) -> dict:
    messages = t.messages if is_admin_view else [m for m in t.messages if not m.is_internal_note]
    # can_reply already excludes terminal statuses; a locked ticket (admin
    # freeze) or a ticket marked as a duplicate (Option A) blocks
    # self-service replies too, on top of that -- the admin console has
    # its own separate can_reply logic in _serialize_ticket_detail's admin
    # branch below isn't needed since admins can always act EXCEPT on a
    # duplicate (see routes/tickets.py's reply_to_ticket/update_ticket,
    # which enforce this server-side regardless of what this flag says;
    # this is purely for the UI to gray out the reply box up front).
    can_reply = t.status not in TERMINAL_STATUSES and not t.locked and not is_duplicate_locked(t)
    return {
        **_serialize_ticket_summary(t),
        "created_by": t.created_by.display_name if t.created_by else "Unknown",
        "vpn_client_name": t.vpn_client_name,
        "context_snapshot": json.loads(t.context_snapshot) if t.context_snapshot else None,
        "resolved_at": t.resolved_at.isoformat() if t.resolved_at else None,
        "closed_at": t.closed_at.isoformat() if t.closed_at else None,
        "can_reply": can_reply,
        # Status Workflow Rules (see support_tickets.py's TRANSITIONS) --
        # admin-console-only, same reasoning as "duplicates" below: only
        # routes/tickets.py's status <select> needs this to build a
        # Jira/ClickUp-style transition menu that only ever offers a
        # ticket's actually-valid next statuses. Self-service has no
        # generic status picker (only the dedicated POST .../reopen
        # action), so it gets an empty list rather than exposing this.
        "allowed_next_statuses": (
            [{"value": s, "label": status_label(s)} for s in sorted(allowed_next_statuses(t.status, t.category), key=status_sort_key)]
            if is_admin_view else []
        ),
        "locked_at": t.locked_at.isoformat() if t.locked_at else None,
        "locked_by": t.locked_by.display_name if t.locked_by else None,
        "marked_duplicate_at": t.marked_duplicate_at.isoformat() if t.marked_duplicate_at else None,
        "marked_duplicate_by": t.marked_duplicate_by.display_name if t.marked_duplicate_by else None,
        # Linked duplicates -- only populated (non-empty) on a PARENT ticket,
        # for the "Linked Duplicates (N)" section (spec section 4).
        "duplicates": [
            {"id": d.id, "subject": d.subject, "status": d.status, "status_label": status_label(d.status)}
            for d in t.duplicates
        ] if is_admin_view else [],
        "messages": [_serialize_message(m, is_admin_view=is_admin_view) for m in messages],
    }


def _build_context_snapshot(user: User, db: Session, request: Request) -> tuple[dict | None, str | None]:
    """Auto-attached diagnostic context ("attach my current context") --
    calls straight into me_vpn.get_my_vpn_report's already-own-scope-safe
    logic (same require_permission("vpn_profiles","view") gate this
    router's own caller already passed) rather than re-deriving current
    IP/session/last-rejection info. Best-effort: no linked VPN profile, or
    any of the underlying script calls failing, just means no context is
    attached -- never blocks ticket creation itself."""
    if user.vpn_profile_link is None:
        return None, get_client_ip(request)
    try:
        report = get_my_vpn_report(user=user, db=db)
    except HTTPException:
        return None, get_client_ip(request)
    snapshot = {
        "vpn_client_name": report.get("vpn_client_name"),
        "current_ip": get_client_ip(request),
        "policy": report.get("policy"),
        "usage": report.get("usage"),
        "recent_rejected": report.get("rejected", [])[:1],
        "source_ip_summary": report.get("source_ip_summary"),
        "captured_at": datetime.now(timezone.utc).isoformat(),
    }
    return snapshot, report.get("vpn_client_name")


@router.get("")
def list_my_tickets(user: User = Depends(require_permission("support_tickets", "view")), db: Session = Depends(get_db)):
    rows = (
        db.query(SupportTicket)
        .filter(SupportTicket.created_by_user_id == user.id, SupportTicket.deleted.is_(False))
        .order_by(SupportTicket.updated_at.desc())
        .limit(200)
        .all()
    )
    return {"tickets": [_serialize_ticket_summary(t) for t in rows]}


@router.get("/categories")
def get_ticket_categories(_: User = Depends(require_permission("support_tickets", "view"))):
    return {
        "categories": categories_for_form(),
        "priorities": [{"value": p, "label": priority_label(p)} for p in PRIORITIES],
        # Regular-ticket statuses only, in canonical STATUSES order -- a
        # self-service ticket is never sysmaint-categorized, so those
        # statuses (assigned/completed/failed/cancelled) are excluded
        # rather than just unreachable. Lets support.html's own status
        # filter list every possible status up front instead of only
        # whichever ones happen to already appear on this user's tickets.
        "statuses": [{"value": s, "label": status_label(s)} for s in STATUSES if s in REGULAR_STATUSES],
    }


@router.post("", status_code=201)
def create_my_ticket(
    request: Request,
    subject: str = Form(...),
    category: str = Form(...),
    priority: str = Form(DEFAULT_PRIORITY),
    description: str = Form(...),
    attach_context: bool = Form(False),
    attachments: list[UploadFile] = File(default=[]),
    user: User = Depends(require_permission("support_tickets", "create")),
    db: Session = Depends(get_db),
):
    attachments = [a for a in attachments if a.filename]  # an empty file input still submits one zero-name UploadFile
    subject = subject.strip()
    description = description.strip()
    if not subject:
        raise HTTPException(status_code=422, detail="Subject is required.")
    if len(subject) > MAX_SUBJECT_LENGTH:
        raise HTTPException(status_code=422, detail=f"Subject must be {MAX_SUBJECT_LENGTH} characters or fewer.")
    if not description:
        raise HTTPException(status_code=422, detail="Description is required.")
    if len(description) > MAX_DESCRIPTION_LENGTH:
        raise HTTPException(status_code=422, detail=f"Description must be {MAX_DESCRIPTION_LENGTH} characters or fewer.")
    if not is_valid_category(category):
        raise HTTPException(status_code=422, detail="Unknown category.")
    if priority not in PRIORITIES:
        raise HTTPException(status_code=422, detail=f"Priority must be one of: {', '.join(PRIORITIES)}.")
    if _rate_limited(db, user):
        s = app_settings.runtime
        raise HTTPException(
            status_code=429,
            detail=f"You've submitted {s.support_ticket_rate_limit_count} ticket actions in the last "
                   f"{s.support_ticket_rate_limit_window_minutes} minutes -- please wait before sending another.",
        )
    # Validated (and, for magic-byte types, sniffed) BEFORE anything below
    # touches the session -- see ticket_attachments.validate_all's own
    # docstring for why a rejected attachment must never leave a half-
    # flushed ticket/message row behind.
    validated_attachments = ticket_attachments.validate_all(attachments)

    context_snapshot, vpn_client_name = (None, None)
    if attach_context:
        context_snapshot, vpn_client_name = _build_context_snapshot(user, db, request)

    ticket = SupportTicket(
        created_by_user_id=user.id, subject=subject, category=category, priority=priority,
        status=DEFAULT_STATUS, vpn_client_name=vpn_client_name,
        context_snapshot=json.dumps(context_snapshot) if context_snapshot else None,
    )
    db.add(ticket)
    db.flush()  # need ticket.id for the first message row below
    message = SupportTicketMessage(ticket_id=ticket.id, author_user_id=user.id, body=description)
    db.add(message)
    db.flush()  # need message.id for attachment rows below
    _attach_validated_files(db, message, ticket.id, user.id, validated_attachments)
    db.commit()

    log_action(db, user, "self_ticket_created", target=f"TCK-{ticket.id}", detail=subject)
    ticket_notifications.ticket_created(db, ticket)
    return _serialize_ticket_detail(ticket, is_admin_view=False)


@router.get("/{ticket_id}")
def get_my_ticket(ticket_id: int, user: User = Depends(require_permission("support_tickets", "view")), db: Session = Depends(get_db)):
    ticket = _require_own_ticket(db, user, ticket_id)
    return _serialize_ticket_detail(ticket, is_admin_view=False)


@router.post("/{ticket_id}/replies", status_code=201)
def reply_to_my_ticket(
    ticket_id: int,
    body: str = Form(...),
    attachments: list[UploadFile] = File(default=[]),
    user: User = Depends(require_permission("support_tickets", "update")),
    db: Session = Depends(get_db),
):
    attachments = [a for a in attachments if a.filename]
    ticket = _require_own_ticket(db, user, ticket_id)
    body = body.strip()
    if not body:
        raise HTTPException(status_code=422, detail="Reply cannot be empty.")
    if len(body) > MAX_DESCRIPTION_LENGTH:
        raise HTTPException(status_code=422, detail=f"Reply must be {MAX_DESCRIPTION_LENGTH} characters or fewer.")
    if ticket.status in TERMINAL_STATUSES:
        raise HTTPException(status_code=409, detail="This ticket is closed -- reopen it before replying.")
    if ticket.locked:
        raise HTTPException(status_code=409, detail="This ticket has been locked by an administrator and can't be replied to.")
    if is_duplicate_locked(ticket):
        raise HTTPException(
            status_code=409,
            detail=f"This ticket was marked as a duplicate of Ticket #{ticket.duplicate_of_ticket_id} -- "
                   f"please continue the conversation there instead.",
        )
    if _rate_limited(db, user):
        s = app_settings.runtime
        raise HTTPException(
            status_code=429,
            detail=f"You've submitted {s.support_ticket_rate_limit_count} ticket actions in the last "
                   f"{s.support_ticket_rate_limit_window_minutes} minutes -- please wait before sending another.",
        )
    validated_attachments = ticket_attachments.validate_all(attachments)

    message = SupportTicketMessage(ticket_id=ticket.id, author_user_id=user.id, body=body)
    db.add(message)
    db.flush()  # need message.id for attachment rows below
    _attach_validated_files(db, message, ticket.id, user.id, validated_attachments)
    ticket.status = "in_progress"
    ticket.updated_at = datetime.now(timezone.utc)
    db.commit()

    log_action(db, user, "self_ticket_reply", target=f"TCK-{ticket.id}", detail=body[:200])
    ticket_notifications.user_replied(db, ticket)
    return _serialize_ticket_detail(ticket, is_admin_view=False)


@router.post("/{ticket_id}/reopen")
def reopen_my_ticket(ticket_id: int, user: User = Depends(require_permission("support_tickets", "update")), db: Session = Depends(get_db)):
    ticket = _require_own_ticket(db, user, ticket_id)
    if ticket.status not in TERMINAL_STATUSES:
        raise HTTPException(status_code=409, detail="Only a Resolved or Closed ticket can be reopened.")
    if is_duplicate_locked(ticket):
        raise HTTPException(
            status_code=409,
            detail=f"This ticket was marked as a duplicate of Ticket #{ticket.duplicate_of_ticket_id} -- "
                   f"please continue the conversation there instead.",
        )
    old_status = ticket.status
    ticket.status = "open"
    ticket.resolved_at = None
    ticket.closed_at = None
    ticket.updated_at = datetime.now(timezone.utc)
    db.commit()

    log_action(db, user, "self_ticket_reopen", target=f"TCK-{ticket.id}", detail=f"status {old_status}->open")
    ticket_notifications.ticket_reopened(db, ticket)
    return _serialize_ticket_detail(ticket, is_admin_view=False)


@router.get("/{ticket_id}/attachments/{attachment_id}")
def download_my_attachment(
    ticket_id: int, attachment_id: int,
    user: User = Depends(require_permission("support_tickets", "view")),
    db: Session = Depends(get_db),
):
    _require_own_ticket(db, user, ticket_id)  # 404s if not this user's own ticket
    attachment = (
        db.query(SupportTicketAttachment)
        .join(SupportTicketMessage, SupportTicketAttachment.message_id == SupportTicketMessage.id)
        .filter(
            SupportTicketAttachment.id == attachment_id,
            SupportTicketAttachment.ticket_id == ticket_id,
            SupportTicketMessage.is_internal_note.is_(False),  # never leak an internal-note attachment to self-service
        )
        .one_or_none()
    )
    if attachment is None:
        raise HTTPException(status_code=404, detail="Attachment not found.")
    path = ticket_attachments.full_path(attachment.stored_path)
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Attachment file is missing on disk.")
    return FileResponse(path, media_type=attachment.content_type, filename=attachment.original_filename)
