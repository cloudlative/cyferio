"""
Outbound email -- used for: emailing a VPN client's .ovpn profile, the
new-user welcome email, self-service password reset, the Contact Support
form, admin event notifications, and Settings-page provider test sends.

Every send_* function here builds the message content (Jinja template +
plaintext fallback) exactly as it always has, then hands it to
email_providers.py's currently-configured DEFAULT provider (SMTP, Resend,
...) via _resolve_default_provider() -- this module doesn't know or care
which provider is active, only email_providers.py's PROVIDERS registry
does. See that module's docstring for the full provider-abstraction
design, and app_settings.py's docstring for why this reads a live DB
query (via `db`) rather than the cached `runtime` object every other
setting uses -- sending mail is already I/O-bound and comparatively rare,
so there's no hot-path cost to always being current.
"""
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy.orm import Session

from . import app_settings, email_providers
from .email_providers import OutboundMessage

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# A separate, dedicated Jinja2 Environment for EMAIL templates
# (templates/email/*.html) -- deliberately not the same Jinja2Templates
# instances routes/pages.py and routes/auth.py each create for PAGE
# rendering (this module has no existing coupling to either, and an email
# template inheriting from base_email.html has nothing in common with
# base.html's page layout). autoescape stays on for .html -- these are
# real HTML emails (multipart/alternative), so untrusted values (a
# client/user name) must be escaped same as any other HTML render.
_EMAIL_TEMPLATES_DIR = Path(__file__).parent / "templates" / "email"
_email_env = Environment(
    loader=FileSystemLoader(str(_EMAIL_TEMPLATES_DIR)),
    autoescape=select_autoescape(["html"]),
)


def _render_email_template(name: str, **context) -> str:
    """Renders one templates/email/*.html file with `app_name`/
    `support_email` (from runtime settings) always available, plus
    whatever page-specific context the caller passes -- the shared
    defaults every email template's base_email.html footer reads, so
    individual send_* functions don't each have to remember to pass them."""
    s = app_settings.runtime
    return _email_env.get_template(name).render(
        app_name=s.app_name,
        support_email=s.admin_notification_email or None,
        **context,
    )


class MailerNotConfigured(Exception):
    """Raised when no outbound email provider is configured (or none is
    both active and marked default) -- callers turn this into a clean
    400, not a crash."""


class NoSupportAddress(Exception):
    """Raised by send_support_request when a provider IS configured but
    admin_notification_email itself is blank -- distinct from
    MailerNotConfigured so routes/support.py can show a message that
    points at the actual missing piece."""


def is_valid_email(address: str) -> bool:
    return bool(_EMAIL_RE.match(address.strip()))


def _resolve_default_provider(db: Session) -> tuple[email_providers.EmailProviderBase, dict, str] | None:
    """Returns (provider_impl, config_dict, provider_row_name) for the
    current default+active EmailProvider row, or None if none exists/
    qualifies -- the single place every send_* function below asks "how
    do we actually send mail right now". A live DB read, not cached on
    `app_settings.runtime` (unlike almost every other setting) -- Provider
    CRUD (routes/email_providers.py) would otherwise need its own cache-
    invalidation path kept in sync with every create/update/delete/
    set-default action, which is exactly the kind of place a forgotten
    invalidation call turns into a silent "why is it still using the old
    provider" bug. The DB round trip this costs is negligible next to the
    network I/O of the send itself."""
    from .models import EmailProvider

    row = db.query(EmailProvider).filter(EmailProvider.is_default.is_(True), EmailProvider.is_active.is_(True)).first()
    if row is None:
        return None
    provider = email_providers.get_provider(row.provider_type)
    config = json.loads(row.config or "{}")
    return provider, config, row.name


def is_configured(db: Session) -> bool:
    return _resolve_default_provider(db) is not None


def _send(db: Session, message: OutboundMessage) -> None:
    """Shared dispatch every send_* function below funnels through --
    resolves the default provider and calls its send(), translating "no
    provider configured" into MailerNotConfigured (a distinct, callers-
    already-handle-it exception) rather than letting a bare None-unpack
    crash. ProviderSendError (a real delivery failure) propagates as-is,
    same as smtplib.SMTPException used to before the provider
    abstraction -- every existing caller already catches it via a bare
    `except Exception`, so this is a transparent swap."""
    resolved = _resolve_default_provider(db)
    if resolved is None:
        raise MailerNotConfigured("No outbound email provider is configured.")
    provider, config, _name = resolved
    provider.send(config=config, message=message)


def send_ovpn_profile(*, db: Session, to_address: str, client_name: str, ovpn_content: str, recipient_name: str | None = None) -> None:
    """Sends `client_name`'s .ovpn profile as an attachment to `to_address`,
    using the templates/email/vpn_profile.html template (extends
    base_email.html -- see that pair's own docstring for why this is a
    reusable framework, not a one-off) and whichever provider is currently
    the default (see _resolve_default_provider). Raises MailerNotConfigured
    if none is, or ProviderSendError on a real delivery failure.

    `recipient_name`, if given, personalizes the greeting ("Welcome,
    Alice -- ...") -- optional because the existing "Email Profile" button
    (routes/clients.py) sends to an admin-typed address that isn't
    necessarily tied to a portal account with a known name; the new
    create-user "send VPN profile via email" checkbox (routes/users.py)
    does have one and passes it through."""
    app_name = app_settings.runtime.app_name
    greeting = f"Hi {recipient_name}," if recipient_name else "Hello,"
    text_body = (
        f"{greeting}\n\n"
        f"Your VPN configuration profile for \"{client_name}\" is attached "
        f"({client_name}.ovpn). Import it into your OpenVPN client to connect.\n\n"
        f"This file contains a private key -- keep it confidential and don't forward it.\n\n"
        f"If you weren't expecting this email, you can safely ignore it.\n\n"
        f"— {app_name}"
    )
    html_body = _render_email_template("vpn_profile.html", client_name=client_name, recipient_name=recipient_name)
    message = OutboundMessage(
        to_address=to_address, subject=f"Your VPN profile for {client_name} — {app_name}",
        text_body=text_body, html_body=html_body,
        attachments=[(f"{client_name}.ovpn", ovpn_content.encode("utf-8"), "application/octet-stream")],
    )
    _send(db, message)


def send_welcome_email(*, db: Session, to_address: str, username: str, password: str, client_name: str,
                        ovpn_content: str, recipient_name: str | None = None) -> None:
    """Onboarding email for the "Send VPN Profile via Email" checkbox
    (routes/users.py's create_user) -- unlike send_ovpn_profile above
    (which the standalone "Email Profile" button also uses, and which
    never has portal credentials to send since the plaintext password
    only exists in-request at creation time, never afterward), this one
    additionally includes the portal login URL, the new username, and the
    plaintext password the admin just set, alongside the same .ovpn
    attachment. Deliberately a SEPARATE function/template from
    send_ovpn_profile rather than an optional-credentials parameter on
    it -- these two emails have genuinely different content and only one
    of the two call sites ever has credentials to include at all.

    Emailing a plaintext password is a real, deliberate tradeoff (not an
    oversight) -- this is the ONLY way to get a freshly-admin-set password
    to a new user out of band, since it's hashed immediately after this
    request and never recoverable again. The template itself recommends
    changing it after first login. Raises MailerNotConfigured/
    ProviderSendError same as send_ovpn_profile -- caller decides how to
    handle a failed send (see create_user's own fire-and-forget handling)."""
    s = app_settings.runtime
    app_name = s.app_name
    greeting = f"Hi {recipient_name}," if recipient_name else "Hello,"
    portal_line = f"Portal: {s.portal_url}\n" if s.portal_url else ""
    text_body = (
        f"{greeting}\n\n"
        f"An account has been created for you on {app_name}.\n\n"
        f"{portal_line}"
        f"Username: {username}\n"
        f"Password: {password}\n"
        f"(We recommend changing this password after your first login.)\n\n"
        f"Your VPN configuration profile is attached ({client_name}.ovpn). Import it into your "
        f"OpenVPN client to connect.\n\n"
        f"Keep this email, your password, and the attached file private.\n\n"
        f"— {app_name}"
    )
    html_body = _render_email_template(
        "welcome.html", username=username, password=password, client_name=client_name,
        recipient_name=recipient_name, portal_url=s.portal_url,
    )
    message = OutboundMessage(
        to_address=to_address, subject=f"Welcome to {app_name} — your account is ready",
        text_body=text_body, html_body=html_body,
        attachments=[(f"{client_name}.ovpn", ovpn_content.encode("utf-8"), "application/octet-stream")],
    )
    _send(db, message)


def send_password_reset_email(*, db: Session, to_address: str, username: str, reset_url: str, ttl_minutes: int) -> None:
    """Self-service "Forgot password" email (routes/auth.py's
    forgot_password) -- `reset_url` is the full, already-built link
    (portal_url + /reset-password?token=...); this function only formats
    and sends the message, it doesn't know anything about token
    generation/validation (that's auth.py's issue_password_reset_token/
    get_user_by_reset_token). Same MailerNotConfigured/ProviderSendError
    propagation as every other send_* here -- the caller (forgot_password)
    already treats a failed send as "couldn't complete the request" while
    still showing the same generic "if that account exists..." response,
    so a delivery failure never confirms or denies an account's existence
    to whoever submitted the form."""
    app_name = app_settings.runtime.app_name
    text_body = (
        f"We received a request to reset the password for your {app_name} account ({username}).\n\n"
        f"Reset your password here (expires in {ttl_minutes} minutes, works once):\n{reset_url}\n\n"
        f"Didn't request this? You can safely ignore this email -- your password won't change "
        f"unless the link above is used.\n\n"
        f"— {app_name}"
    )
    html_body = _render_email_template("password_reset.html", username=username, reset_url=reset_url, ttl_minutes=ttl_minutes)
    message = OutboundMessage(to_address=to_address, subject=f"Reset your password — {app_name}", text_body=text_body, html_body=html_body)
    _send(db, message)


def send_support_request(*, db: Session, requester_name: str, requester_username: str, requester_email: str,
                          subject: str, message: str, submitted_at: str) -> None:
    """FAQ page's "Contact Support" flow (routes/support.py) -- sends to
    `runtime.admin_notification_email` (the same setting event
    notifications use, see send_admin_notification's own docstring on
    that dual purpose). Sets Reply-To to the requester's own address so
    an admin can just hit Reply in their mail client to respond directly
    -- Reply-To is a standard RFC 5322 header both providers honor, not a
    provider-specific feature; the requester's email is also included in
    the body itself as a second, always-visible copy of that same
    information. Raises MailerNotConfigured if no provider is set up, or
    NoSupportAddress if admin_notification_email itself is blank -- a
    separate, more specific failure than "no provider configured" -- the
    caller shows a different message for each."""
    s = app_settings.runtime
    if not s.admin_notification_email:
        raise NoSupportAddress("No support contact email is configured.")

    app_name = s.app_name
    text_body = (
        f"New support request from {requester_name} ({requester_username}).\n\n"
        f"From: {requester_name} <{requester_email}>\n"
        f"Submitted: {submitted_at}\n\n"
        f"Subject: {subject}\n\n"
        f"{message}\n\n"
        f"-- Reply directly to this email to respond to {requester_name}."
    )
    html_body = _render_email_template(
        "support_request.html", requester_name=requester_name, requester_username=requester_username,
        requester_email=requester_email, subject=subject, message=message, submitted_at=submitted_at,
    )
    outbound = OutboundMessage(
        to_address=s.admin_notification_email, subject=f"[{app_name} Support] {subject}",
        text_body=text_body, html_body=html_body, reply_to=requester_email,
    )
    _send(db, outbound)


def send_ticket_notification_email(*, db: Session, to_address: str, ticket_id: int, subject: str, headline: str, body_text: str | None = None) -> bool:
    """Support Ticketing System -- user-facing ticket emails (created,
    admin replied, status changed, resolved, closed). Unlike
    send_admin_notification, this is NEVER gated by an admin toggle (see
    the plan's "User-side ticket emails are not behind an admin toggle"
    decision) -- these are transactional to the ticket's own creator, same
    posture as the welcome/password-reset emails. Deliberately swallows
    delivery failures (returns False) rather than turning a successful
    reply/status-change into a 500 -- the notification is a courtesy, not
    a precondition, same stance as send_admin_notification takes for the
    admin-facing side."""
    s = app_settings.runtime
    app_name = s.app_name
    ticket_path = f"/support/{ticket_id}"
    text_body = (
        f"{headline}\n\n"
        f"Ticket #{ticket_id} -- {subject}\n\n"
        + (f"{body_text}\n\n" if body_text else "")
        + (f"View it here: {s.portal_url}{ticket_path}\n\n" if s.portal_url else "")
        + f"— {app_name}"
    )
    html_body = _render_email_template(
        "ticket_notification.html", ticket_id=ticket_id, subject=subject, headline=headline,
        body_text=body_text, portal_url=s.portal_url, ticket_path=ticket_path,
    )
    message = OutboundMessage(to_address=to_address, subject=f"[{app_name}] {headline} -- Ticket #{ticket_id}", text_body=text_body, html_body=html_body)
    try:
        _send(db, message)
        return True
    except Exception:
        return False


def send_mfa_security_notice(*, db: Session, to_address: str, username: str, event_description: str) -> bool:
    """Multi-Factor Authentication security-event emails -- enabled/
    disabled/reset/recovery-codes-regenerated/settings-changed all funnel
    through this ONE template+function, parameterized by
    `event_description`, rather than five near-identical send_* functions
    (same "one template, several call sites" approach as
    send_ticket_notification_email above). Always sent, never gated by an
    admin toggle -- these are transactional to the account they're about,
    same posture as the welcome/password-reset emails. Deliberately
    swallows delivery failures (returns False) rather than turning a
    successful MFA enable/disable/reset into a 500 -- same "courtesy, not
    a precondition" stance as send_admin_notification/
    send_ticket_notification_email."""
    app_name = app_settings.runtime.app_name
    text_body = (
        f"Security notice for your {app_name} account ({username}):\n\n"
        f"{event_description}\n\n"
        f"If this wasn't you, change your password immediately and contact an administrator.\n\n"
        f"— {app_name}"
    )
    html_body = _render_email_template("mfa_security_notice.html", username=username, event_description=event_description)
    message = OutboundMessage(to_address=to_address, subject=f"[{app_name}] Security notice for your account", text_body=text_body, html_body=html_body)
    try:
        _send(db, message)
        return True
    except Exception:
        return False


def send_test_email_via_config(*, provider_type: str, config: dict, to_address: str) -> None:
    """Settings-page "Test" button (per EmailProvider profile) -- sends a
    short confirmation message through the EXACT config passed in
    (already validate_config()'d by the caller), NOT necessarily the
    saved/default provider: an admin needs to test a profile they're
    still editing, or a non-default one, before committing to it. Never
    touches app_settings.runtime or the DB; purely a dry-run send. Raises
    ProviderSendError (or ProviderConfigError if config itself is
    malformed) as-is -- the route handler surfaces that reason to the
    admin."""
    app_name = app_settings.runtime.app_name
    portal_url = app_settings.runtime.portal_url
    provider = email_providers.get_provider(provider_type)
    from_address = config.get("from_email") or None
    sent_at = datetime.now(timezone.utc).strftime("%b %d, %Y at %H:%M UTC")
    text_body = (
        f"This is a test email from {app_name} to confirm this outbound email provider ({provider.display_name}) is configured correctly.\n\n"
        f"If you received this, delivery through this provider is working.\n\n"
        f"Sent to: {to_address}\n"
        + (f"From: {from_address}\n" if from_address else "")
        + (f"Portal: {portal_url}\n" if portal_url else "")
        + f"Sent: {sent_at}"
    )
    html_body = _render_email_template(
        "test_email.html",
        provider_label=provider.display_name,
        to_address=to_address,
        from_address=from_address,
        portal_url=portal_url,
        sent_at=sent_at,
    )
    message = OutboundMessage(
        to_address=to_address,
        subject=f"Test email from {app_name}",
        text_body=text_body,
        html_body=html_body,
    )
    provider.send(config=config, message=message)


def send_admin_notification(*, db: Session, subject: str, body: str) -> bool:
    """Fire-and-forget event notification to `runtime.admin_notification_email`
    (Settings -> Notifications) -- used by routes/users.py's create_user and
    routes/clients.py's revoke_client when the matching
    `notify_admin_on_*` toggle is on. Deliberately swallows delivery
    failures (returns False, logs nothing itself -- callers already run
    inside an audit-logged request and can note the failure there if they
    choose to) rather than letting a broken/unreachable provider turn an
    otherwise-successful user-creation or client-revoke into a 500: the
    notification is a courtesy, not a precondition for the action it's
    reporting on. Returns True on a successful send, False if not
    configured or if the send itself failed."""
    s = app_settings.runtime
    if not s.admin_notification_email:
        return False
    message = OutboundMessage(to_address=s.admin_notification_email, subject=f"[{s.app_name}] {subject}", text_body=body)
    try:
        _send(db, message)
        return True
    except Exception:
        return False
