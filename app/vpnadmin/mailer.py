"""
Minimal SMTP mailer used solely to email a VPN client's .ovpn profile to a
recipient. Deliberately stdlib-only (smtplib + email.message) -- no new pip
dependency for what's a small, well-trodden piece of functionality.
"""
import re
import smtplib
from email.message import EmailMessage

from .config import settings

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class MailerNotConfigured(Exception):
    """Raised when SMTP_HOST is unset -- callers turn this into a clean 400,
    not a crash."""


def is_configured() -> bool:
    return bool(settings.SMTP_HOST)


def is_valid_email(address: str) -> bool:
    return bool(_EMAIL_RE.match(address.strip()))


def send_ovpn_profile(*, to_address: str, client_name: str, ovpn_content: str) -> None:
    """Sends `client_name`'s .ovpn profile as an attachment to `to_address`,
    using a small branded HTML template. Raises MailerNotConfigured if SMTP
    isn't set up, or smtplib.SMTPException (propagated as-is) on a real
    delivery failure -- callers translate both into clean API responses."""
    if not is_configured():
        raise MailerNotConfigured("SMTP is not configured.")

    app_name = settings.APP_NAME
    msg = EmailMessage()
    msg["Subject"] = f"Your VPN profile for {client_name} — {app_name}"
    msg["From"] = settings.SMTP_FROM or settings.SMTP_USERNAME
    msg["To"] = to_address
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

    with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=15) as server:
        if settings.SMTP_USE_TLS:
            server.starttls()
        if settings.SMTP_USERNAME:
            server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
        server.send_message(msg)
