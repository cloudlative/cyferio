"""
Minimal SMTP mailer used for two things: emailing a VPN client's .ovpn
profile, and sending a Settings-page test email to verify SMTP config
before saving it. Deliberately stdlib-only (smtplib + email.message) -- no
new pip dependency for what's a small, well-trodden piece of functionality.
"""
import re
import smtplib
from email.message import EmailMessage
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from . import app_settings

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
    """Raised when SMTP_HOST is unset -- callers turn this into a clean 400,
    not a crash."""


def is_configured() -> bool:
    return bool(app_settings.runtime.smtp_host)


def is_valid_email(address: str) -> bool:
    return bool(_EMAIL_RE.match(address.strip()))


def _send(*, host: str, port: int, username: str, password: str, use_tls: bool,
          from_address: str, to_address: str, msg: EmailMessage) -> None:
    """Low-level send shared by send_ovpn_profile (uses the saved/effective
    settings) and send_test_email (uses whatever's currently in the
    Settings-page form, not necessarily saved yet). Lets smtplib's own
    exceptions (SMTPException and friends) propagate as-is -- callers
    translate those into clean API responses, and for the test-email path
    specifically, surface the underlying reason to the admin rather than a
    generic "failed"."""
    msg["From"] = from_address or username
    msg["To"] = to_address
    with smtplib.SMTP(host, port, timeout=15) as server:
        if use_tls:
            server.starttls()
        if username:
            server.login(username, password)
        server.send_message(msg)


def send_ovpn_profile(*, to_address: str, client_name: str, ovpn_content: str, recipient_name: str | None = None) -> None:
    """Sends `client_name`'s .ovpn profile as an attachment to `to_address`,
    using the templates/email/vpn_profile.html template (extends
    base_email.html -- see that pair's own docstring for why this is a
    reusable framework, not a one-off) and the currently-effective SMTP
    settings (Settings-page override, falling back to env vars -- see
    app_settings.py). Raises MailerNotConfigured if SMTP isn't set up, or
    smtplib.SMTPException (propagated as-is) on a real delivery failure.

    `recipient_name`, if given, personalizes the greeting ("Welcome,
    Alice -- ...") -- optional because the existing "Email Profile" button
    (routes/clients.py) sends to an admin-typed address that isn't
    necessarily tied to a portal account with a known name; the new
    create-user "send VPN profile via email" checkbox (routes/users.py)
    does have one and passes it through."""
    if not is_configured():
        raise MailerNotConfigured("SMTP is not configured.")

    s = app_settings.runtime
    app_name = s.app_name
    msg = EmailMessage()
    msg["Subject"] = f"Your VPN profile for {client_name} — {app_name}"
    greeting = f"Hi {recipient_name}," if recipient_name else "Hello,"
    msg.set_content(
        f"{greeting}\n\n"
        f"Your VPN configuration profile for \"{client_name}\" is attached "
        f"({client_name}.ovpn). Import it into your OpenVPN client to connect.\n\n"
        f"This file contains a private key -- keep it confidential and don't forward it.\n\n"
        f"If you weren't expecting this email, you can safely ignore it.\n\n"
        f"— {app_name}"
    )
    msg.add_alternative(
        _render_email_template("vpn_profile.html", client_name=client_name, recipient_name=recipient_name),
        subtype="html",
    )
    msg.add_attachment(
        ovpn_content.encode("utf-8"),
        maintype="application",
        subtype="octet-stream",
        filename=f"{client_name}.ovpn",
    )

    _send(
        host=s.smtp_host, port=s.smtp_port, username=s.smtp_username, password=s.smtp_password,
        use_tls=s.smtp_use_tls, from_address=s.smtp_from, to_address=to_address, msg=msg,
    )


def send_welcome_email(*, to_address: str, username: str, password: str, client_name: str,
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
    smtplib.SMTPException same as send_ovpn_profile -- caller decides how
    to handle a failed send (see create_user's own fire-and-forget
    handling)."""
    if not is_configured():
        raise MailerNotConfigured("SMTP is not configured.")

    s = app_settings.runtime
    app_name = s.app_name
    msg = EmailMessage()
    msg["Subject"] = f"Welcome to {app_name} — your account is ready"
    greeting = f"Hi {recipient_name}," if recipient_name else "Hello,"
    portal_line = f"Portal: {s.portal_url}\n" if s.portal_url else ""
    msg.set_content(
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
    msg.add_alternative(
        _render_email_template(
            "welcome.html", username=username, password=password, client_name=client_name,
            recipient_name=recipient_name, portal_url=s.portal_url,
        ),
        subtype="html",
    )
    msg.add_attachment(
        ovpn_content.encode("utf-8"),
        maintype="application",
        subtype="octet-stream",
        filename=f"{client_name}.ovpn",
    )

    _send(
        host=s.smtp_host, port=s.smtp_port, username=s.smtp_username, password=s.smtp_password,
        use_tls=s.smtp_use_tls, from_address=s.smtp_from, to_address=to_address, msg=msg,
    )


def send_password_reset_email(*, to_address: str, username: str, reset_url: str, ttl_minutes: int) -> None:
    """Self-service "Forgot password" email (routes/auth.py's
    forgot_password) -- `reset_url` is the full, already-built link
    (portal_url + /reset-password?token=...); this function only formats
    and sends the message, it doesn't know anything about token
    generation/validation (that's auth.py's issue_password_reset_token/
    get_user_by_reset_token). Same MailerNotConfigured/SMTPException
    propagation as every other send_* here -- the caller (forgot_password)
    already treats a failed send as "couldn't complete the request" while
    still showing the same generic "if that account exists..." response,
    so a delivery failure never confirms or denies an account's existence
    to whoever submitted the form."""
    if not is_configured():
        raise MailerNotConfigured("SMTP is not configured.")

    s = app_settings.runtime
    app_name = s.app_name
    msg = EmailMessage()
    msg["Subject"] = f"Reset your password — {app_name}"
    msg.set_content(
        f"We received a request to reset the password for your {app_name} account ({username}).\n\n"
        f"Reset your password here (expires in {ttl_minutes} minutes, works once):\n{reset_url}\n\n"
        f"Didn't request this? You can safely ignore this email -- your password won't change "
        f"unless the link above is used.\n\n"
        f"— {app_name}"
    )
    msg.add_alternative(
        _render_email_template("password_reset.html", username=username, reset_url=reset_url, ttl_minutes=ttl_minutes),
        subtype="html",
    )

    _send(
        host=s.smtp_host, port=s.smtp_port, username=s.smtp_username, password=s.smtp_password,
        use_tls=s.smtp_use_tls, from_address=s.smtp_from, to_address=to_address, msg=msg,
    )


def send_test_email(*, to_address: str, host: str, port: int, username: str, password: str,
                     from_address: str, use_tls: bool) -> None:
    """Sends a short plain test message using whatever SMTP values are
    currently in the Settings-page form -- NOT necessarily what's already
    saved -- so an admin can verify a config before committing to it. Never
    touches the DB/runtime cache; purely a dry-run send. Raises
    smtplib.SMTPException (or socket errors etc) as-is on failure; the
    route handler surfaces that reason to the admin."""
    app_name = app_settings.runtime.app_name
    msg = EmailMessage()
    msg["Subject"] = f"Test email from {app_name}"
    msg.set_content(
        f"This is a test email from {app_name} to confirm your SMTP settings are working.\n\n"
        f"If you received this, outbound email is configured correctly."
    )
    _send(
        host=host, port=port, username=username, password=password,
        use_tls=use_tls, from_address=from_address, to_address=to_address, msg=msg,
    )


def send_admin_notification(*, subject: str, body: str) -> bool:
    """Fire-and-forget event notification to `runtime.admin_notification_email`
    (Settings -> Notifications) -- used by routes/users.py's create_user and
    routes/clients.py's revoke_client when the matching
    `notify_admin_on_*` toggle is on. Deliberately swallows delivery
    failures (returns False, logs nothing itself -- callers already run
    inside an audit-logged request and can note the failure there if they
    choose to) rather than letting a broken/unreachable SMTP server turn an
    otherwise-successful user-creation or client-revoke into a 500: the
    notification is a courtesy, not a precondition for the action it's
    reporting on. Returns True on a successful send, False if not
    configured or if the send itself failed."""
    s = app_settings.runtime
    if not is_configured() or not s.admin_notification_email:
        return False
    msg = EmailMessage()
    msg["Subject"] = f"[{s.app_name}] {subject}"
    msg.set_content(body)
    try:
        _send(
            host=s.smtp_host, port=s.smtp_port, username=s.smtp_username, password=s.smtp_password,
            use_tls=s.smtp_use_tls, from_address=s.smtp_from, to_address=s.admin_notification_email, msg=msg,
        )
        return True
    except Exception:
        return False
