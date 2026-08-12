"""
Minimal SMTP mailer used for two things: emailing a VPN client's .ovpn
profile, and sending a Settings-page test email to verify SMTP config
before saving it. Deliberately stdlib-only (smtplib + email.message) -- no
new pip dependency for what's a small, well-trodden piece of functionality.
"""
import re
import smtplib
from email.message import EmailMessage

from . import app_settings

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


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


def send_ovpn_profile(*, to_address: str, client_name: str, ovpn_content: str) -> None:
    """Sends `client_name`'s .ovpn profile as an attachment to `to_address`,
    using a small branded HTML template and the currently-effective SMTP
    settings (Settings-page override, falling back to env vars -- see
    app_settings.py). Raises MailerNotConfigured if SMTP isn't set up, or
    smtplib.SMTPException (propagated as-is) on a real delivery failure."""
    if not is_configured():
        raise MailerNotConfigured("SMTP is not configured.")

    s = app_settings.runtime
    app_name = s.app_name
    msg = EmailMessage()
    msg["Subject"] = f"Your VPN profile for {client_name} — {app_name}"
    msg.set_content(
        f"Hello,\n\n"
        f"Your VPN configuration profile for \"{client_name}\" is attached "
        f"({client_name}.ovpn). Import it into your OpenVPN client to connect.\n\n"
        f"If you weren't expecting this email, you can safely ignore it.\n\n"
        f"— {app_name}"
    )
    msg.add_alternative(
        f"""\
<div style="font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
            max-width:480px;margin:0 auto;padding:32px 28px;
            background:#1e2436;color:#f1f3fa;border-radius:16px;border:1px solid #3a4460;">
  <div style="display:inline-flex;align-items:center;gap:10px;margin-bottom:22px;">
    <div style="width:32px;height:32px;border-radius:10px;
                background:linear-gradient(135deg,#6366f1,#8b5cf6,#22d3ee);
                display:inline-block;text-align:center;line-height:32px;">⚡</div>
    <strong style="font-size:1.05rem;">{app_name}</strong>
  </div>
  <h2 style="margin:0 0 12px;font-size:1.2rem;">Your VPN profile is ready</h2>
  <p style="color:#aab2cc;line-height:1.6;margin:0 0 14px;">
    Attached is the OpenVPN configuration profile for <strong style="color:#f1f3fa;">{client_name}</strong>.
    Import <code>{client_name}.ovpn</code> into your OpenVPN client (Tunnelblick, OpenVPN
    Connect, the official OpenVPN GUI, etc.) to connect.
  </p>
  <p style="color:#757fa0;font-size:0.85rem;line-height:1.5;margin:22px 0 0;">
    This file contains a private key -- keep it confidential and don't forward it.
    If you weren't expecting this email, you can safely ignore it.
  </p>
</div>""",
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
