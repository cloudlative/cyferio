"""Support Ticketing System -- attachment upload validation/storage. Used
by routes/me_tickets.py's/routes/tickets.py's create/reply endpoints.

Validates against BOTH a fixed type whitelist (extension AND, where the
type has a reliable one, a magic-byte signature check -- deliberately NOT
admin-tweakable, see AppSettings.support_max_attachment_size_mb's own
docstring for why) and the admin-tweakable size/count limits
(app_settings.runtime.support_max_attachment_size_mb/
support_max_attachments_per_message).

Files are stored under config.TICKET_ATTACHMENTS_DIR (a dedicated Docker
volume, see docker-compose.yml -- never under /etc/openvpn's host bind
mount, which is for OpenVPN server state, not user uploads), one
subdirectory per ticket id, each file's on-disk name prefixed with a
random uuid so two attachments with the same original filename in one
ticket never collide. That on-disk path is purely for organization, not
itself a security boundary: every download still re-checks the caller
owns or can manage the parent ticket via the DB row, never by trusting
the path alone."""
import mimetypes
import os
import re
import uuid
from pathlib import Path

from fastapi import HTTPException, UploadFile

from . import app_settings
from .config import settings

ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".txt", ".log", ".csv", ".zip"}

# Magic-byte signatures for the types that have a reliable one -- plain
# text formats (.txt/.log/.csv) have none, so they're validated by
# extension alone (same as every other type is, this is an ADDITIONAL
# check where one's actually meaningful, not a replacement for it).
_MAGIC_SIGNATURES: dict[str, tuple[bytes, ...]] = {
    ".png": (b"\x89PNG\r\n\x1a\n",),
    ".jpg": (b"\xff\xd8\xff",),
    ".jpeg": (b"\xff\xd8\xff",),
    ".gif": (b"GIF87a", b"GIF89a"),
    ".pdf": (b"%PDF-",),
    ".zip": (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"),
}


def _safe_filename(original: str | None) -> str:
    base = os.path.basename(original or "attachment")
    base = re.sub(r"[^A-Za-z0-9._-]", "_", base)
    return base[:200] or "attachment"


def validate_and_read(upload: UploadFile, *, index_in_request: int) -> tuple[bytes, str, str]:
    """Validates one UploadFile, returning (raw_bytes, sanitized_filename,
    content_type) on success, or raising HTTPException(422) with a clear,
    specific message. Reads the whole file into memory to check both size
    and magic bytes -- fine at the configured ceiling (10MB default by
    app_settings.runtime.support_max_attachment_size_mb), not a
    streaming/chunked upload path."""
    s = app_settings.runtime
    if index_in_request >= s.support_max_attachments_per_message:
        raise HTTPException(
            status_code=422,
            detail=f"No more than {s.support_max_attachments_per_message} attachments per message.",
        )

    filename = _safe_filename(upload.filename)
    ext = Path(filename).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=422,
            detail=f"'{filename}': file type not allowed. Allowed types: {', '.join(sorted(ALLOWED_EXTENSIONS))}.",
        )

    max_bytes = s.support_max_attachment_size_mb * 1024 * 1024
    data = upload.file.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise HTTPException(
            status_code=422,
            detail=f"'{filename}' exceeds the {s.support_max_attachment_size_mb}MB attachment size limit.",
        )
    if not data:
        raise HTTPException(status_code=422, detail=f"'{filename}' is empty.")

    signatures = _MAGIC_SIGNATURES.get(ext)
    if signatures and not any(data.startswith(sig) for sig in signatures):
        raise HTTPException(status_code=422, detail=f"'{filename}' doesn't look like a valid {ext} file.")

    content_type = upload.content_type or mimetypes.guess_type(filename)[0] or "application/octet-stream"
    return data, filename, content_type


def store(ticket_id: int, data: bytes, filename: str) -> str:
    """Writes `data` to TICKET_ATTACHMENTS_DIR/{ticket_id}/{uuid}_{filename},
    returning the path RELATIVE to that root -- what
    SupportTicketAttachment.stored_path persists."""
    root = Path(settings.TICKET_ATTACHMENTS_DIR)
    ticket_dir = root / str(ticket_id)
    ticket_dir.mkdir(parents=True, exist_ok=True)
    stored_name = f"{uuid.uuid4().hex}_{filename}"
    (ticket_dir / stored_name).write_bytes(data)
    return f"{ticket_id}/{stored_name}"


def full_path(stored_path: str) -> Path:
    return Path(settings.TICKET_ATTACHMENTS_DIR) / stored_path


def validate_all(uploads: list[UploadFile]) -> list[tuple[bytes, str, str]]:
    """Validates every upload in one message, raising on the first invalid
    file. Deliberately does NOT write anything to disk or touch the DB
    session -- callers run this BEFORE creating any ticket/message row, so
    a rejected attachment leaves the caller's session completely
    untouched, not just "no file written" (see routes/me_tickets.py's/
    routes/tickets.py's call sites for why that ordering matters: raising
    an HTTPException after an uncommitted db.flush() would otherwise
    leave the session mid-transaction for the rest of the request)."""
    return [validate_and_read(u, index_in_request=i) for i, u in enumerate(uploads)]


def store_all(ticket_id: int, validated: list[tuple[bytes, str, str]]) -> list[tuple[str, str, str, int]]:
    """Writes every already-validated (data, filename, content_type) tuple
    to disk, returning (original_filename, stored_path, content_type,
    size_bytes) tuples ready to become SupportTicketAttachment rows. Call
    only AFTER the parent ticket/message row is flushed (so ticket_id is
    known) -- see validate_all's own docstring for why validation itself
    happens earlier, before either of those exist."""
    return [
        (filename, store(ticket_id, data, filename), content_type, len(data))
        for data, filename, content_type in validated
    ]
