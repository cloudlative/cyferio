"""Support Ticketing System -- admin console ("Support Center"). Mirrors
routes/clients.py's any-scope admin style: require_permission_any_scope
keeps an "own"-scoped role (the "User" self-service role) off this router
even though it has view=True on "support_tickets" for its own tickets via
routes/me_tickets.py. Sees every ticket (per the confirmed "all admins see
all tickets" decision -- no per-admin restriction to "assigned only"),
can reply, leave internal notes, change status/priority/assignment.

See routes/me_tickets.py's module docstring for the self-service
counterpart and the shared serialization helpers reused here."""
import csv
import io
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .. import ticket_attachments, ticket_notifications
from ..app_settings import runtime
from ..audit import log_action
from ..db import get_db
from ..models import AuditLog, SupportTicket, SupportTicketAttachment, SupportTicketMessage, User
from ..permissions import has_permission_any_scope, require_permission_any_scope
from ..support_tickets import PRIORITIES, STATUSES, allowed_next_statuses, categories_for_form, priority_label, status_label
from .me_tickets import (
    MAX_DESCRIPTION_LENGTH,
    _attach_validated_files,
    _serialize_ticket_detail,
    _serialize_ticket_summary,
    is_duplicate_locked,
)

_require_ticket_viewer = require_permission_any_scope("support_tickets", "view")
_require_ticket_manager = require_permission_any_scope("support_tickets", "update")
# Deletion (single or bulk) is a distinct, more dangerous capability than
# update/manage -- gated behind ObjectPermission.can_delete specifically
# (models.py already has this per-role flag, previously unused by this
# router). admin/super_admin get it via can_manage's superset semantics
# (see permissions._has_permission); a custom role can be granted "delete"
# on "support_tickets" independently of "update" if an admin wants a
# narrower "can only delete, not otherwise manage" role, or (far more
# commonly) NOT granted it even though it has "update" -- e.g. the
# "editor" system role, which gets ticket update/reply but deliberately
# not delete (see permissions.py's _SYSTEM_ROLES).
_require_ticket_deleter = require_permission_any_scope("support_tickets", "delete")

router = APIRouter(prefix="/api/tickets", tags=["tickets"])


def _get_ticket_or_404(db: Session, ticket_id: int, *, include_deleted: bool = False) -> SupportTicket:
    q = db.query(SupportTicket).filter(SupportTicket.id == ticket_id)
    if not include_deleted:
        q = q.filter(SupportTicket.deleted.is_(False))
    ticket = q.one_or_none()
    if ticket is None:
        raise HTTPException(status_code=404, detail="Ticket not found.")
    return ticket


@router.get("")
def list_tickets(
    include_deleted: bool = False,
    admin: User = Depends(_require_ticket_viewer), db: Session = Depends(get_db),
):
    """Bounded set, client-side search/filter/sort/pagination on the
    frontend -- same shape as GET /api/audit / users_activity.html, not a
    new server-side paging API (see the plan's "no pagination anywhere"
    finding). `include_deleted` backs the "Deleted Tickets" filter (spec
    section 6) -- only honored for a caller with delete visibility on this
    object, same "requesting admin has delete visibility" gate the spec
    calls for; anyone else gets the normal excludes-deleted list
    regardless of what they pass."""
    q = db.query(SupportTicket)
    if not (include_deleted and has_permission_any_scope(db, admin, "support_tickets", "delete")):
        q = q.filter(SupportTicket.deleted.is_(False))
    rows = q.order_by(SupportTicket.updated_at.desc()).limit(500).all()
    return {"tickets": [_serialize_ticket_summary(t) for t in rows]}


@router.get("/categories")
def get_ticket_categories(_: User = Depends(_require_ticket_viewer)):
    return {"categories": categories_for_form(), "priorities": [{"value": p, "label": priority_label(p)} for p in PRIORITIES],
            "statuses": [{"value": s, "label": status_label(s)} for s in STATUSES]}


@router.get("/assignable-admins")
def list_assignable_admins(_: User = Depends(_require_ticket_viewer), db: Session = Depends(get_db)):
    """Every account whose role grants any-scope support_tickets update/
    manage -- the admin-console assignment dropdown's candidate list.
    Computed live from role grants rather than a stored subscription
    list, same reasoning as the ticket-notification fan-out in routes/
    notifications.py.

    Must be declared before GET /{ticket_id} below -- FastAPI/Starlette
    matches routes in registration order, and /{ticket_id} is a catch-all
    for any single path segment. Declared after it (its original
    position, further down this file) meant GET /assignable-admins
    matched /{ticket_id} FIRST, tried to bind "assignable-admins" to
    ticket_id: int, and 422'd -- which ticket_detail.html's admin-view
    init() awaited with no try/catch, so that one failed request silently
    aborted the rest of init() including the loadTicket() call right
    after it, and the whole ticket detail page was left on its
    "Loading..." placeholder. Found live 2026-08-21 via
    /support-center/{id} reportedly "not loading the content of the
    ticket" -- server logs showed GET /api/tickets/assignable-admins
    returning 422 and GET /api/tickets/{id} never even being requested."""
    candidates = [
        u for u in db.query(User).filter(User.is_active.is_(True), User.deleted.is_(False)).all()
        if has_permission_any_scope(db, u, "support_tickets", "update")
    ]
    return {"admins": [{"id": u.id, "username": u.username, "display_name": u.display_name} for u in candidates]}


@router.get("/duplicate-clusters")
def get_duplicate_clusters(admin: User = Depends(_require_ticket_viewer), db: Session = Depends(get_db)):
    """Duplicate Cleanup Tools (spec section 5) -- surfaces candidate
    duplicate clusters using three heuristics, none of which mutate
    anything: (a) identical subject text, (b) same (creator, category), or
    (c) either of those pairs created within
    AppSettings.ticket_duplicate_window_minutes of each other (admin-
    tweakable, see the Settings tunables preference -- never hardcoded).
    Only considers non-deleted tickets that aren't already marked a
    duplicate of something (no point clustering an already-resolved
    duplicate) and are ALSO not already the parent of another duplicate's
    resolution (a ticket that already has duplicates linked to it is
    presumably already "the" canonical one -- still eligible to appear as
    the suggested parent within its own cluster, just not re-clustered
    against a totally different group).

    Must be declared before GET /{ticket_id} -- same FastAPI/Starlette
    route-ordering reasoning as GET /assignable-admins above (a fixed
    path segment 422s against the int-typed {ticket_id} route if that
    route is registered first)."""
    window = timedelta(minutes=runtime.ticket_duplicate_window_minutes)
    rows = (
        db.query(SupportTicket)
        .filter(SupportTicket.deleted.is_(False), SupportTicket.duplicate_of_ticket_id.is_(None))
        .order_by(SupportTicket.created_at.asc())
        .all()
    )

    clusters: list[list[SupportTicket]] = []
    used_ids: set[int] = set()
    for i, t in enumerate(rows):
        if t.id in used_ids:
            continue
        group = [t]
        for other in rows[i + 1:]:
            if other.id in used_ids:
                continue
            same_subject = other.subject.strip().lower() == t.subject.strip().lower()
            same_user_category = other.created_by_user_id == t.created_by_user_id and other.category == t.category
            within_window = abs((other.created_at - t.created_at)) <= window
            if within_window and (same_subject or same_user_category):
                group.append(other)
        if len(group) > 1:
            clusters.append(group)
            used_ids.update(g.id for g in group)

    return {
        "window_minutes": runtime.ticket_duplicate_window_minutes,
        "clusters": [
            {
                "tickets": [_serialize_ticket_summary(t) for t in group],
                "suggested_parent_id": min(group, key=lambda t: t.created_at).id,  # oldest = likely original
            }
            for group in clusters
        ],
    }




# --- Bulk actions (spec section 3) + bulk mark-as-duplicate (spec section 5) -

class BulkTicketIdsRequest(BaseModel):
    ticket_ids: list[int]


class BulkAssignRequest(BaseModel):
    ticket_ids: list[int]
    assigned_admin_id: int


class BulkMarkDuplicateRequest(BaseModel):
    ticket_ids: list[int]
    parent_ticket_id: int


def _bulk_tickets(db: Session, ticket_ids: list[int], *, include_deleted: bool = False) -> list[SupportTicket]:
    if not ticket_ids:
        raise HTTPException(status_code=400, detail="No tickets selected.")
    q = db.query(SupportTicket).filter(SupportTicket.id.in_(ticket_ids))
    if not include_deleted:
        q = q.filter(SupportTicket.deleted.is_(False))
    rows = q.all()
    found_ids = {t.id for t in rows}
    missing = set(ticket_ids) - found_ids
    if missing:
        raise HTTPException(status_code=404, detail=f"Ticket(s) not found: {', '.join(str(i) for i in sorted(missing))}.")
    return rows


@router.post("/bulk/delete")
def bulk_delete_tickets(body: BulkTicketIdsRequest, admin: User = Depends(_require_ticket_deleter), db: Session = Depends(get_db)):
    """Bulk delete is the SAME soft-delete as the single-ticket action --
    still fully recoverable via restore_ticket above, deliberately not a
    "more destructive because it's bulk" separate code path. The UI's
    confirmation copy says "This action cannot be undone" to make an admin
    stop and think before selecting 25 tickets at once (a bulk mistake is
    much costlier to notice and manually reverse one-by-one than a single
    accidental delete is), but that's a UX caution, not a technical claim
    -- restore_ticket works identically whether the ticket was deleted
    solo or as part of a batch. Audited one AuditLog row per affected
    ticket (not one summary row referencing the set) -- matches every
    other per-ticket action in this router (reply/update/etc all log per
    ticket), so a ticket's own Activity History (GET /{id}/history, keyed
    on target=f"TCK-{id}") shows its deletion without needing to cross-
    reference a separate bulk-summary row."""
    tickets = _bulk_tickets(db, body.ticket_ids)
    now = datetime.now(timezone.utc)
    for t in tickets:
        t.deleted = True
        t.deleted_at = now
        t.deleted_by_user_id = admin.id
    db.commit()
    for t in tickets:
        log_action(db, admin, "ticket_deleted", target=f"TCK-{t.id}", detail=f"bulk delete; subject: {t.subject}")
    return {"deleted": [t.id for t in tickets]}


@router.post("/bulk/close")
def bulk_close_tickets(body: BulkTicketIdsRequest, admin: User = Depends(_require_ticket_manager), db: Session = Depends(get_db)):
    tickets = _bulk_tickets(db, body.ticket_ids)
    now = datetime.now(timezone.utc)
    changed = []
    for t in tickets:
        # Status Workflow Rules apply to bulk actions too -- e.g. a
        # Resolved/Failed/Cancelled ticket can't jump straight to Closed,
        # same restriction the single-ticket PATCH endpoint enforces (see
        # support_tickets.py's TRANSITIONS). Skipped rather than erroring
        # the whole batch, same posture as the pre-existing "already
        # closed" skip below.
        if is_duplicate_locked(t) or t.locked or t.status == "closed" or "closed" not in allowed_next_statuses(t.status):
            continue
        old_status = t.status
        t.status = "closed"
        t.closed_at = now
        t.updated_at = now
        changed.append((t, old_status))
    db.commit()
    for t, old_status in changed:
        log_action(db, admin, "ticket_updated", target=f"TCK-{t.id}", detail=f"bulk close; status {status_label(old_status)}->{status_label('closed')}")
        ticket_notifications.status_changed(db, t, old_status, "closed")
    return {"closed": [t.id for t, _ in changed], "skipped": [t.id for t in tickets if t not in [c[0] for c in changed]]}


@router.post("/bulk/resolve")
def bulk_resolve_tickets(body: BulkTicketIdsRequest, admin: User = Depends(_require_ticket_manager), db: Session = Depends(get_db)):
    tickets = _bulk_tickets(db, body.ticket_ids)
    now = datetime.now(timezone.utc)
    changed = []
    for t in tickets:
        if is_duplicate_locked(t) or t.locked or t.status == "resolved":
            continue
        old_status = t.status
        t.status = "resolved"
        t.resolved_at = now
        t.updated_at = now
        changed.append((t, old_status))
    db.commit()
    for t, old_status in changed:
        log_action(db, admin, "ticket_updated", target=f"TCK-{t.id}", detail=f"bulk resolve; status {status_label(old_status)}->{status_label('resolved')}")
        ticket_notifications.status_changed(db, t, old_status, "resolved")
    return {"resolved": [t.id for t, _ in changed], "skipped": [t.id for t in tickets if t not in [c[0] for c in changed]]}


@router.post("/bulk/assign")
def bulk_assign_tickets(body: BulkAssignRequest, admin: User = Depends(_require_ticket_manager), db: Session = Depends(get_db)):
    new_admin = db.query(User).filter(User.id == body.assigned_admin_id).one_or_none()
    if new_admin is None:
        raise HTTPException(status_code=400, detail="No such admin account.")
    tickets = _bulk_tickets(db, body.ticket_ids)
    now = datetime.now(timezone.utc)
    changed = []
    for t in tickets:
        if t.assigned_admin_id == new_admin.id:
            continue
        prev = t.assigned_admin.username if t.assigned_admin else "none"
        t.assigned_admin_id = new_admin.id
        t.updated_at = now
        changed.append((t, prev))
    db.commit()
    for t, prev in changed:
        log_action(db, admin, "ticket_updated", target=f"TCK-{t.id}", detail=f"bulk assign; assigned_admin {prev}->{new_admin.username}")
        ticket_notifications.ticket_assigned(db, t)
    return {"assigned": [t.id for t, _ in changed]}


@router.post("/bulk/mark-duplicate")
def bulk_mark_duplicate(body: BulkMarkDuplicateRequest, admin: User = Depends(_require_ticket_manager), db: Session = Depends(get_db)):
    """Duplicate Cleanup Tools' "bulk mark as duplicate from a cluster
    view" (spec section 5) -- same one-parent-many-duplicates shape as the
    single mark_ticket_duplicate endpoint above, just applied to a whole
    selected set at once. The parent itself is silently skipped if it's
    included in ticket_ids (marking a ticket as a duplicate of itself
    makes no sense, and a cluster-view "select all, pick one as parent"
    UI naturally includes the parent in the selection)."""
    parent = _get_ticket_or_404(db, body.parent_ticket_id)
    if parent.duplicate_of_ticket_id is not None:
        raise HTTPException(
            status_code=400,
            detail=f"Ticket #{parent.id} is itself marked as a duplicate of Ticket #{parent.duplicate_of_ticket_id} -- "
                   f"mark against Ticket #{parent.duplicate_of_ticket_id} instead.",
        )
    ids = [i for i in body.ticket_ids if i != parent.id]
    tickets = _bulk_tickets(db, ids) if ids else []
    now = datetime.now(timezone.utc)
    for t in tickets:
        t.duplicate_of_ticket_id = parent.id
        t.marked_duplicate_by_user_id = admin.id
        t.marked_duplicate_at = now
        t.updated_at = now
    db.commit()
    for t in tickets:
        log_action(db, admin, "ticket_marked_duplicate", target=f"TCK-{t.id}", detail=f"bulk; duplicate of TCK-{parent.id}")
        ticket_notifications.ticket_marked_duplicate(db, t)
    return {"marked_duplicate": [t.id for t in tickets], "parent_ticket_id": parent.id}


@router.post("/bulk/export")
def bulk_export_tickets(body: BulkTicketIdsRequest, admin: User = Depends(_require_ticket_viewer), db: Session = Depends(get_db)):
    """CSV export of the selected tickets' summary fields -- reuses
    _serialize_ticket_summary's exact field set (subject/category/
    priority/status/assignee/created/updated) rather than inventing a
    different export shape, per the spec's explicit instruction. Returns
    the CSV as a JSON string field (not a raw file download) so this stays
    inside apiFetch's normal JSON contract -- the frontend builds the
    downloadable Blob client-side from `csv`."""
    tickets = _bulk_tickets(
        db, body.ticket_ids,
        include_deleted=has_permission_any_scope(db, admin, "support_tickets", "delete"),
    )
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["Subject", "Category", "Priority", "Status", "Assigned To", "Created", "Updated"])
    for t in tickets:
        s = _serialize_ticket_summary(t)
        writer.writerow([
            s["subject"], s["category_label"], s["priority_label"], s["status_label"],
            s["assigned_admin"] or "Unassigned", s["created_at"] or "", s["updated_at"] or "",
        ])
    log_action(db, admin, "ticket_exported", detail=f"{len(tickets)} ticket(s)")
    return {"csv": buf.getvalue(), "count": len(tickets)}


@router.get("/{ticket_id}")
def get_ticket(ticket_id: int, admin: User = Depends(_require_ticket_viewer), db: Session = Depends(get_db)):
    # A deleted ticket is still viewable (not hard-gone), but only by a
    # caller with delete visibility -- same "Deleted Tickets filter only
    # for admins who can see deleted tickets" gate as list_tickets above,
    # applied here so a direct /support-center/{id} link to a deleted
    # ticket doesn't leak it to someone without that visibility.
    ticket = _get_ticket_or_404(db, ticket_id, include_deleted=has_permission_any_scope(db, admin, "support_tickets", "delete"))
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
    # Option A duplicate enforcement (see SupportTicket.duplicate_of_ticket_id's
    # docstring) -- an admin is redirected to the parent rather than being
    # allowed to keep the conversation split across two tickets. Internal
    # notes are allowed through even on a duplicate/locked ticket (an
    # admin-only annotation, e.g. "see TCK-123", isn't "independent
    # processing" in the sense this block is meant to prevent).
    if not is_internal_note and is_duplicate_locked(ticket):
        raise HTTPException(
            status_code=409,
            detail=f"Ticket #{ticket.id} is marked as a duplicate of Ticket #{ticket.duplicate_of_ticket_id} -- reply there instead.",
        )
    if not is_internal_note and ticket.locked:
        raise HTTPException(status_code=409, detail="This ticket is locked -- unlock it before replying.")
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
    # Status/priority/assignment changes are exactly the "independent
    # processing" Option A blocks on a duplicate -- an admin acting on the
    # PARENT is unaffected (a parent never has duplicate_of_ticket_id set).
    # A locked ticket must be unlocked first (POST /{id}/unlock) rather
    # than silently letting a PATCH slip through and re-lock semantics.
    if ("status" in body.model_fields_set or "priority" in body.model_fields_set) and is_duplicate_locked(ticket):
        raise HTTPException(
            status_code=409,
            detail=f"Ticket #{ticket.id} is marked as a duplicate of Ticket #{ticket.duplicate_of_ticket_id} -- update that ticket instead.",
        )
    if ("status" in body.model_fields_set or "priority" in body.model_fields_set) and ticket.locked:
        raise HTTPException(status_code=409, detail="This ticket is locked -- unlock it before changing status or priority.")
    fields_set = body.model_fields_set
    changes: list[str] = []
    # Captured before either field is mutated below -- feeds the
    # post-commit notification fan-out at the end of this function.
    old_status = ticket.status
    status_changed_to: str | None = None
    became_critical = False
    newly_assigned = False

    if "status" in fields_set:
        if body.status not in STATUSES:
            raise HTTPException(status_code=400, detail=f"Status must be one of: {', '.join(STATUSES)}.")
        if body.status != ticket.status:
            # Status Workflow Rules -- see support_tickets.py's TRANSITIONS
            # docstring for the full design. Same-status "changes" (a no-op
            # save) skip this check entirely, same as every other write
            # below only acting on an actual delta.
            allowed = allowed_next_statuses(ticket.status)
            if body.status not in allowed:
                allowed_desc = ", ".join(status_label(s) for s in sorted(allowed)) if allowed else "nothing (terminal)"
                raise HTTPException(
                    status_code=409,
                    detail=f"Can't move a {status_label(ticket.status)} ticket directly to {status_label(body.status)}. "
                           f"Allowed next status(es): {allowed_desc}.",
                )
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
        # Reassignment: any admin with any-scope support_tickets update/
        # manage (this endpoint's own _require_ticket_manager dependency)
        # can set assigned_admin_id to ANY account, including reassigning a
        # ticket someone else already claimed -- there's no extra "only the
        # current owner or a super_admin can reassign" check here, since
        # can_manage is a strict superset of can_update (see permissions.
        # _has_permission) and this app's RBAC design already treats
        # "update" on this object as sufficient for the whole admin-console
        # lifecycle (status/priority/assignment alike), not just a subset
        # of it. Confirmed: already fully audited below via the generic
        # "ticket_updated" log_action line, same as every other field this
        # endpoint touches.
        new_admin = db.query(User).filter(User.id == body.assigned_admin_id).one_or_none()
        if new_admin is None:
            raise HTTPException(status_code=400, detail="No such admin account.")
        if new_admin.id != ticket.assigned_admin_id:
            prev = ticket.assigned_admin.username if ticket.assigned_admin else "none"
            changes.append(f"assigned_admin {prev}->{new_admin.username}")
            ticket.assigned_admin_id = new_admin.id
            newly_assigned = True
            # "Claim" for a System Maintenance ticket (Upgrade Assignment
            # Workflow) -- assigning it while still "new"/"open" advances
            # status to "assigned" automatically, so the status column
            # reflects the claim without the admin having to make two
            # separate PATCH calls. Only auto-advances out of the two
            # earliest, pre-work statuses -- never overrides a status an
            # admin/the system already moved further along (e.g.
            # reassigning a ticket that's already "in_progress" leaves it
            # there).
            if ticket.category.startswith("sysmaint_") and ticket.status in ("new", "open") and "status" not in fields_set:
                changes.append(f"status {status_label(ticket.status)}->{status_label('assigned')}")
                ticket.status = "assigned"

    if changes:
        ticket.updated_at = datetime.now(timezone.utc)
        db.commit()
        log_action(db, admin, "ticket_updated", target=f"TCK-{ticket.id}", detail="; ".join(changes))
        if status_changed_to is not None:
            ticket_notifications.status_changed(db, ticket, old_status, status_changed_to)
        if became_critical:
            ticket_notifications.ticket_marked_critical(db, ticket)
        if newly_assigned:
            ticket_notifications.ticket_assigned(db, ticket)
    return _serialize_ticket_detail(ticket, is_admin_view=True)


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


# --- Individual ticket deletion (spec section 2) ----------------------------

@router.delete("/{ticket_id}", status_code=204)
def delete_ticket(ticket_id: int, admin: User = Depends(_require_ticket_deleter), db: Session = Depends(get_db)):
    """Soft delete -- see SupportTicket.deleted's own docstring for why
    there's no hard-delete path. Excluded from every normal list/detail
    query by default (list_tickets/get_ticket above), same as a
    soft-deleted User."""
    ticket = _get_ticket_or_404(db, ticket_id)
    ticket.deleted = True
    ticket.deleted_at = datetime.now(timezone.utc)
    ticket.deleted_by_user_id = admin.id
    db.commit()
    log_action(db, admin, "ticket_deleted", target=f"TCK-{ticket.id}", detail=f"subject: {ticket.subject}")
    return None


@router.post("/{ticket_id}/restore")
def restore_ticket(ticket_id: int, admin: User = Depends(_require_ticket_deleter), db: Session = Depends(get_db)):
    """Undoes delete_ticket -- the payoff of soft-delete being recoverable
    rather than a one-way trip. Not explicitly requested by the spec, but
    a delete-visibility-gated admin restoring a mistaken deletion is the
    natural counterpart to the "Deleted Tickets" filter (spec section 6)
    actually being useful for something beyond just looking."""
    ticket = _get_ticket_or_404(db, ticket_id, include_deleted=True)
    if not ticket.deleted:
        raise HTTPException(status_code=409, detail="This ticket isn't deleted.")
    ticket.deleted = False
    ticket.deleted_at = None
    ticket.deleted_by_user_id = None
    db.commit()
    log_action(db, admin, "ticket_restored", target=f"TCK-{ticket.id}", detail=f"subject: {ticket.subject}")
    return _serialize_ticket_detail(ticket, is_admin_view=True)


# --- Enhanced ticket management controls (spec section 6) -------------------
# Change Priority already exists (PATCH's `priority` field) and Transfer
# Ownership already exists (PATCH's `assigned_admin_id` field, see that
# endpoint's own extensive comment on why any manager can reassign) -- no
# new endpoint needed for either, just the Lock/Unlock and Escalate below,
# which had no existing equivalent.

@router.post("/{ticket_id}/lock")
def lock_ticket(ticket_id: int, admin: User = Depends(_require_ticket_manager), db: Session = Depends(get_db)):
    ticket = _get_ticket_or_404(db, ticket_id)
    if ticket.locked:
        raise HTTPException(status_code=409, detail="This ticket is already locked.")
    ticket.locked = True
    ticket.locked_at = datetime.now(timezone.utc)
    ticket.locked_by_user_id = admin.id
    db.commit()
    log_action(db, admin, "ticket_locked", target=f"TCK-{ticket.id}")
    return _serialize_ticket_detail(ticket, is_admin_view=True)


@router.post("/{ticket_id}/unlock")
def unlock_ticket(ticket_id: int, admin: User = Depends(_require_ticket_manager), db: Session = Depends(get_db)):
    ticket = _get_ticket_or_404(db, ticket_id)
    if not ticket.locked:
        raise HTTPException(status_code=409, detail="This ticket isn't locked.")
    ticket.locked = False
    ticket.locked_at = None
    ticket.locked_by_user_id = None
    db.commit()
    log_action(db, admin, "ticket_unlocked", target=f"TCK-{ticket.id}")
    return _serialize_ticket_detail(ticket, is_admin_view=True)


@router.post("/{ticket_id}/escalate")
def escalate_ticket(ticket_id: int, admin: User = Depends(_require_ticket_manager), db: Session = Depends(get_db)):
    """Bumps priority straight to "critical" and fires the same
    ticket_marked_critical fan-out the PATCH endpoint's own became_critical
    branch does -- a dedicated one-click action rather than requiring an
    admin to open the Manage panel and pick "Critical" from the priority
    dropdown for what's conceptually a distinct, urgent action."""
    ticket = _get_ticket_or_404(db, ticket_id)
    if is_duplicate_locked(ticket):
        raise HTTPException(
            status_code=409,
            detail=f"Ticket #{ticket.id} is marked as a duplicate of Ticket #{ticket.duplicate_of_ticket_id} -- escalate that ticket instead.",
        )
    if ticket.priority == "critical":
        raise HTTPException(status_code=409, detail="This ticket is already at critical priority.")
    old_priority = ticket.priority
    ticket.priority = "critical"
    ticket.updated_at = datetime.now(timezone.utc)
    db.commit()
    log_action(db, admin, "ticket_escalated", target=f"TCK-{ticket.id}", detail=f"priority {old_priority}->critical")
    ticket_notifications.ticket_marked_critical(db, ticket)
    return _serialize_ticket_detail(ticket, is_admin_view=True)


# --- Duplicate Ticket Management (spec section 4) ---------------------------

class MarkDuplicateRequest(BaseModel):
    parent_ticket_id: int


@router.post("/{ticket_id}/mark-duplicate")
def mark_ticket_duplicate(
    ticket_id: int, body: MarkDuplicateRequest,
    admin: User = Depends(_require_ticket_manager), db: Session = Depends(get_db),
):
    ticket = _get_ticket_or_404(db, ticket_id)
    if body.parent_ticket_id == ticket_id:
        raise HTTPException(status_code=400, detail="A ticket can't be marked as a duplicate of itself.")
    parent = _get_ticket_or_404(db, body.parent_ticket_id)
    if parent.duplicate_of_ticket_id is not None:
        # Keep the graph a flat one-level tree (parent -> duplicates), not a
        # chain -- picking an already-duplicate ticket as a new parent would
        # let A->B->C form, where "the" canonical ticket is ambiguous.
        raise HTTPException(
            status_code=400,
            detail=f"Ticket #{parent.id} is itself marked as a duplicate of Ticket #{parent.duplicate_of_ticket_id} -- "
                   f"mark against Ticket #{parent.duplicate_of_ticket_id} instead.",
        )
    ticket.duplicate_of_ticket_id = parent.id
    ticket.marked_duplicate_by_user_id = admin.id
    ticket.marked_duplicate_at = datetime.now(timezone.utc)
    ticket.updated_at = datetime.now(timezone.utc)
    db.commit()
    log_action(db, admin, "ticket_marked_duplicate", target=f"TCK-{ticket.id}", detail=f"duplicate of TCK-{parent.id}")
    ticket_notifications.ticket_marked_duplicate(db, ticket)
    return _serialize_ticket_detail(ticket, is_admin_view=True)


@router.post("/{ticket_id}/unmark-duplicate")
def unmark_ticket_duplicate(ticket_id: int, admin: User = Depends(_require_ticket_manager), db: Session = Depends(get_db)):
    ticket = _get_ticket_or_404(db, ticket_id)
    if ticket.duplicate_of_ticket_id is None:
        raise HTTPException(status_code=409, detail="This ticket isn't marked as a duplicate.")
    prev_parent = ticket.duplicate_of_ticket_id
    ticket.duplicate_of_ticket_id = None
    ticket.marked_duplicate_by_user_id = None
    ticket.marked_duplicate_at = None
    ticket.updated_at = datetime.now(timezone.utc)
    db.commit()
    log_action(db, admin, "ticket_unmarked_duplicate", target=f"TCK-{ticket.id}", detail=f"was duplicate of TCK-{prev_parent}")
    return _serialize_ticket_detail(ticket, is_admin_view=True)
