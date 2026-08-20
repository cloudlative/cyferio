"""Support Ticketing System -- admin console ("Support Center"). Mirrors
routes/clients.py's any-scope admin style: require_permission_any_scope
keeps an "own"-scoped role (the "User" self-service role) off this router
even though it has view=True on "support_tickets" for its own tickets via
routes/me_tickets.py. Sees every ticket (per the confirmed "all admins see
all tickets" decision -- no per-admin restriction to "assigned only"),
can reply, leave internal notes, change status/priority/assignment.

See routes/me_tickets.py's module docstring for the self-service
counterpart and the shared serialization helpers reused here."""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .. import ticket_attachments, ticket_notifications
from ..audit import log_action
from ..db import get_db
from ..models import AuditLog, SupportTicket, SupportTicketAttachment, SupportTicketMessage, User
from ..permissions import require_permission_any_scope
from ..support_tickets import PRIORITIES, STATUSES, categories_for_form, priority_label, status_label
from .me_tickets import MAX_DESCRIPTION_LENGTH, _attach_validated_files, _serialize_ticket_detail, _serialize_ticket_summary

_require_ticket_viewer = require_permission_any_scope("support_tickets", "view")
_require_ticket_manager = require_permission_any_scope("support_tickets", "update")

router = APIRouter(prefix="/api/tickets", tags=["tickets"])


def _get_ticket_or_404(db: Session, ticket_id: int) -> SupportTicket:
    ticket = db.query(SupportTicket).filter(SupportTicket.id == ticket_id).one_or_none()
    if ticket is None:
        raise HTTPException(status_code=404, detail="Ticket not found.")
    return ticket


@router.get("")
def list_tickets(_: User = Depends(_require_ticket_viewer), db: Session = Depends(get_db)):
    """Bounded set, client-side search/filter/sort/pagination on the
    frontend -- same shape as GET /api/audit / users_activity.html, not a
    new server-side paging API (see the plan's "no pagination anywhere"
    finding)."""
    rows = db.query(SupportTicket).order_by(SupportTicket.updated_at.desc()).limit(500).all()
    return {"tickets": [_serialize_ticket_summary(t) for t in rows]}


@router.get("/categories")
def get_ticket_categories(_: User = Depends(_require_ticket_viewer)):
    return {"categories": categories_for_form(), "priorities": [{"value": p, "label": priority_label(p)} for p in PRIORITIES],
            "statuses": [{"value": s, "label": status_label(s)} for s in STATUSES]}


@router.get("/{ticket_id}")
def get_ticket(ticket_id: int, _: User = Depends(_require_ticket_viewer), db: Session = Depends(get_db)):
    ticket = _get_ticket_or_404(db, ticket_id)
    return _serialize_ticket_detail(ticket, is_admin_view=True)


@router.get("/{ticket_id}/history")
def get_ticket_history(ticket_id: int, _: User = Depends(_require_ticket_viewer), db: Session = Depends(get_db)):
    """Status/priority/assignment change log for the admin console's
    activity timeline -- reads back the AuditLog rows this router's own
    update_ticket()/reply_to_ticket() write (target=f"TCK-{id}"), rather
    than a parallel "ticket event" table (see the Support Ticketing
    System plan for why)."""
    _get_ticket_or_404(db, ticket_id)
    rows = (
        db.query(AuditLog)
        .filter(AuditLog.target == f"TCK-{ticket_id}")
        .order_by(AuditLog.timestamp.desc())
        .all()
    )
    return {"events": [
        {"timestamp": r.timestamp.isoformat(), "username": r.username, "action": r.action, "detail": r.detail}
        for r in rows
    ]}


@router.post("/{ticket_id}/replies", status_code=201)
def reply_to_ticket(
    ticket_id: int,
    body: str = Form(...),
    is_internal_note: bool = Form(False),
    attachments: list[UploadFile] = File(default=[]),
    admin: User = Depends(_require_ticket_manager),
    db: Session = Depends(get_db),
):
    attachments = [a for a in attachments if a.filename]
    ticket = _get_ticket_or_404(db, ticket_id)
    body = body.strip()
    if not body:
        raise HTTPException(status_code=422, detail="Reply cannot be empty.")
    if len(body) > MAX_DESCRIPTION_LENGTH:
        raise HTTPException(status_code=422, detail=f"Reply must be {MAX_DESCRIPTION_LENGTH} characters or fewer.")
    validated_attachments = ticket_attachments.validate_all(attachments)

    message = SupportTicketMessage(ticket_id=ticket.id, author_user_id=admin.id, body=body, is_internal_note=is_internal_note)
    db.add(message)
    db.flush()  # need message.id for attachment rows below
    _attach_validated_files(db, message, ticket.id, admin.id, validated_attachments)
    # An admin's real (non-internal) reply is what a user is actually
    # waiting on -- flips status to reflect that, same as a user's own
    # reply flips it to waiting_for_admin (routes/me_tickets.py). An
    # internal note changes nothing status-wise; it's admin-only chatter,
    # not visible to (or actionable by) the ticket's owner.
    if not is_internal_note and ticket.status not in ("resolved", "closed"):
        ticket.status = "waiting_for_user"
    ticket.updated_at = datetime.now(timezone.utc)
    db.commit()

    action = "ticket_internal_note" if is_internal_note else "ticket_reply"
    log_action(db, admin, action, target=f"TCK-{ticket.id}", detail=body[:200])
    if not is_internal_note:
        ticket_notifications.admin_replied(db, ticket)
    return _serialize_ticket_detail(ticket, is_admin_view=True)


class UpdateTicketRequest(BaseModel):
    """Partial update -- omit anything you don't want to touch, same
    convention as routes/settings.py's UpdateSettingsRequest. Assigning/
    closing/reopening are all just this endpoint changing status/
    assigned_admin_id; there's no separate "close"/"assign" endpoint."""
    status: str | None = None
    priority: str | None = None
    assigned_admin_id: int | None = None
    clear_assignment: bool = False  # explicit, since assigned_admin_id: None is indistinguishable from "omitted" in a partial update


@router.patch("/{ticket_id}")
def update_ticket(
    ticket_id: int, body: UpdateTicketRequest,
    admin: User = Depends(_require_ticket_manager), db: Session = Depends(get_db),
):
    ticket = _get_ticket_or_404(db, ticket_id)
    fields_set = body.model_fields_set
    changes: list[str] = []
    # Captured before either field is mutated below -- feeds the
    # post-commit notification fan-out at the end of this function.
    old_status = ticket.status
    status_changed_to: str | None = None
    became_critical = False

    if "status" in fields_set:
        if body.status not in STATUSES:
            raise HTTPException(status_code=400, detail=f"Status must be one of: {', '.join(STATUSES)}.")
        if body.status != ticket.status:
            changes.append(f"status {status_label(ticket.status)}->{status_label(body.status)}")
            status_changed_to = body.status
            now = datetime.now(timezone.utc)
            if body.status == "resolved":
                ticket.resolved_at = now
            elif body.status == "closed":
                ticket.closed_at = now
            elif ticket.status in ("resolved", "closed"):
                # Moving OUT of a terminal status (admin reopening on the
                # user's behalf, or just re-triaging) clears the terminal
                # timestamps -- same as routes/me_tickets.py's reopen_my_ticket.
                ticket.resolved_at = None
                ticket.closed_at = None
            ticket.status = body.status

    if "priority" in fields_set:
        if body.priority not in PRIORITIES:
            raise HTTPException(status_code=400, detail=f"Priority must be one of: {', '.join(PRIORITIES)}.")
        if body.priority != ticket.priority:
            changes.append(f"priority {ticket.priority}->{body.priority}")
            became_critical = body.priority == "critical"
            ticket.priority = body.priority

    if body.clear_assignment:
        if ticket.assigned_admin_id is not None:
            prev = ticket.assigned_admin.username if ticket.assigned_admin else ticket.assigned_admin_id
            changes.append(f"assigned_admin {prev}->none")
            ticket.assigned_admin_id = None
    elif "assigned_admin_id" in fields_set and body.assigned_admin_id is not None:
        new_admin = db.query(User).filter(User.id == body.assigned_admin_id).one_or_none()
        if new_admin is None:
            raise HTTPException(status_code=400, detail="No such admin account.")
        if new_admin.id != ticket.assigned_admin_id:
            prev = ticket.assigned_admin.username if ticket.assigned_admin else "none"
            changes.append(f"assigned_admin {prev}->{new_admin.username}")
            ticket.assigned_admin_id = new_admin.id

    if changes:
        ticket.updated_at = datetime.now(timezone.utc)
        db.commit()
        log_action(db, admin, "ticket_updated", target=f"TCK-{ticket.id}", detail="; ".join(changes))
        if status_changed_to is not None:
            ticket_notifications.status_changed(db, ticket, old_status, status_changed_to)
        if became_critical:
            ticket_notifications.ticket_marked_critical(db, ticket)
    return _serialize_ticket_detail(ticket, is_admin_view=True)


@router.get("/assignable-admins")
def list_assignable_admins(_: User = Depends(_require_ticket_viewer), db: Session = Depends(get_db)):
    """Every account whose role grants any-scope support_tickets update/
    manage -- the admin-console assignment dropdown's candidate list.
    Computed live from role grants rather than a stored subscription
    list, same reasoning as the ticket-notification fan-out in routes/
    notifications.py."""
    from ..permissions import has_permission_any_scope

    candidates = [
        u for u in db.query(User).filter(User.is_active.is_(True), User.deleted.is_(False)).all()
        if has_permission_any_scope(db, u, "support_tickets", "update")
    ]
    return {"admins": [{"id": u.id, "username": u.username, "display_name": u.display_name} for u in candidates]}


@router.get("/{ticket_id}/attachments/{attachment_id}")
def download_ticket_attachment(
    ticket_id: int, attachment_id: int,
    _: User = Depends(_require_ticket_viewer), db: Session = Depends(get_db),
):
    _get_ticket_or_404(db, ticket_id)
    # Admin view -- unlike routes/me_tickets.py's download_my_attachment,
    # an internal-note attachment IS visible here; internal notes are
    # only ever hidden from self-service.
    attachment = (
        db.query(SupportTicketAttachment)
        .filter(SupportTicketAttachment.id == attachment_id, SupportTicketAttachment.ticket_id == ticket_id)
        .one_or_none()
    )
    if attachment is None:
        raise HTTPException(status_code=404, detail="Attachment not found.")
    path = ticket_attachments.full_path(attachment.stored_path)
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Attachment file is missing on disk.")
    return FileResponse(path, media_type=attachment.content_type, filename=attachment.original_filename)
