"""
Outbound email provider abstraction (Settings -> Outbound Email) -- lets an
admin configure and switch between multiple ways of actually sending mail
(SMTP, Resend, ...) without any of mailer.py's send_* functions knowing or
caring which one is active. Every one of them just builds an
OutboundMessage and asks "send this through whatever the current default
provider is" (see mailer._resolve_default_provider).

Adding a new provider (SendGrid, Amazon SES, Mailgun, Postmark, ...) means
writing one EmailProviderBase subclass here and adding it to PROVIDERS
below -- nothing in mailer.py, routes/, models.py, or the Settings UI's
generic form-rendering needs to change, since the UI drives its per-
provider fields off `fields` and config is stored as an opaque JSON blob
(EmailProvider.config), not one DB column per field.

Deliberately stdlib-only (smtplib + urllib), same "no new pip dependency
for a small, well-trodden piece of functionality" reasoning as mailer.py's
own docstring -- Resend's HTTP API is a single JSON POST, not worth a
dependency.
"""
import base64
import json
import smtplib
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field


class ProviderConfigError(ValueError):
    """Raised by validate_config() (or from inside send() for a check that
    can only happen at send time, e.g. an unreachable host) when the
    STORED CONFIG itself is missing/malformed -- always "your settings are
    wrong", never "sending failed this time despite correct settings" (see
    ProviderSendError for that). Routes turn this into a 400."""


class ProviderSendError(Exception):
    """Raised when a provider's underlying send genuinely fails (network
    error, credentials rejected by the provider, malformed recipient,
    ...) -- config LOOKED fine, delivery didn't work. Routes turn this
    into a 502, distinct from ProviderConfigError's 400."""


@dataclass
class OutboundMessage:
    """Provider-agnostic representation of one email -- built once by
    mailer.py (from a Jinja template + plaintext fallback, exactly as
    before this module existed), then handed to whichever provider is
    currently active. Attachments are (filename, content_bytes,
    mime_type) tuples."""
    to_address: str
    subject: str
    text_body: str
    html_body: str | None = None
    reply_to: str | None = None
    from_address: str | None = None  # provider config's own from_email wins if this is None
    from_name: str | None = None
    attachments: list[tuple[str, bytes, str]] = field(default_factory=list)


class EmailProviderBase:
    type_key: str
    display_name: str
    # (field_key, label, input_type, required) -- drives BOTH the Settings
    # page's dynamically-rendered add/edit form AND validate_config()'s
    # required-field check, so the two can never drift out of sync with
    # each other (a field added to one is automatically enforced/shown by
    # the other). input_type is one of "text"/"password"/"email"/"number"/
    # "select:opt1,opt2,...".
    fields: tuple[tuple[str, str, str, bool], ...] = ()

    def validate_config(self, config: dict) -> dict:
        """Normalizes + checks required fields per `fields` above. Raises
        ProviderConfigError with a specific, field-named message on the
        first problem found. Subclasses needing a further check beyond
        "is it present" (e.g. ResendEmailProvider's API-key-shape check)
        call super().validate_config() first, then add their own."""
        cleaned = {}
        for key, label, _input_type, required in self.fields:
            raw = config.get(key)
            value = raw.strip() if isinstance(raw, str) else raw
            if required and not value:
                raise ProviderConfigError(f"{label} is required.")
            cleaned[key] = value
        return cleaned

    def send(self, *, config: dict, message: OutboundMessage) -> None:
        """Sends `message` using `config` (already validate_config()'d).
        Raises ProviderSendError on failure -- never lets a provider-
        specific exception type (smtplib.SMTPException, urllib.error.*)
        leak past this boundary, so callers only ever need to catch one
        exception type regardless of which provider is active."""
        raise NotImplementedError


class SMTPEmailProvider(EmailProviderBase):
    type_key = "smtp"
    display_name = "SMTP"
    fields = (
        ("host", "SMTP Host", "text", True),
        ("port", "SMTP Port", "number", True),
        ("username", "Username", "text", False),
        ("password", "Password", "password", False),
        # Three real states, not the old single smtp_use_tls boolean this
        # replaces: "none" (plaintext), "starttls" (upgrade an initially
        # plaintext connection -- most common, port 587), "ssl" (implicit
        # TLS from the first byte -- port 465). A bare on/off boolean
        # could only ever express starttls-or-not.
        ("encryption", "Encryption", "select:none,starttls,ssl", False),
        ("from_email", "From Email", "email", True),
        ("from_name", "From Name", "text", False),
    )

    def send(self, *, config: dict, message: OutboundMessage) -> None:
        host = config.get("host")
        try:
            port = int(config.get("port") or 587)
        except (TypeError, ValueError):
            raise ProviderConfigError("SMTP Port must be a number.") from None
        username = config.get("username") or ""
        password = config.get("password") or ""
        encryption = (config.get("encryption") or "starttls").lower()
        from_email = message.from_address or config.get("from_email") or username
        from_name = message.from_name or config.get("from_name") or ""

        from email.message import EmailMessage

        msg = EmailMessage()
        msg["Subject"] = message.subject
        msg["From"] = f"{from_name} <{from_email}>" if from_name else from_email
        msg["To"] = message.to_address
        if message.reply_to:
            msg["Reply-To"] = message.reply_to
        msg.set_content(message.text_body)
        if message.html_body:
            msg.add_alternative(message.html_body, subtype="html")
        for filename, content, mime_type in message.attachments:
            maintype, _, subtype = (mime_type or "application/octet-stream").partition("/")
            msg.add_attachment(content, maintype=maintype or "application", subtype=subtype or "octet-stream", filename=filename)

        try:
            if encryption == "ssl":
                with smtplib.SMTP_SSL(host, port, timeout=15, context=ssl.create_default_context()) as server:
                    if username:
                        server.login(username, password)
                    server.send_message(msg)
            else:
                with smtplib.SMTP(host, port, timeout=15) as server:
                    if encryption == "starttls":
                        server.starttls(context=ssl.create_default_context())
                    if username:
                        server.login(username, password)
                    server.send_message(msg)
        except (smtplib.SMTPException, OSError, TimeoutError) as e:
            raise ProviderSendError(str(e)) from e


class ResendEmailProvider(EmailProviderBase):
    type_key = "resend"
    display_name = "Resend"
    fields = (
        ("api_key", "Resend API Key", "password", True),
        ("from_email", "From Email", "email", True),
        ("from_name", "From Name", "text", False),
    )
    _API_URL = "https://api.resend.com/emails"

    def validate_config(self, config: dict) -> dict:
        cleaned = super().validate_config(config)
        # Lightweight API-key-SHAPE check ("Requirement 5: API key
        # validation"), not a live API round trip -- Resend keys are
        # always "re_"-prefixed, so this catches an obviously wrong/
        # copy-paste-truncated value immediately, without needing network
        # access at save time (the "Test" button, which does hit the real
        # API, is the actual end-to-end check).
        api_key = cleaned.get("api_key") or ""
        if api_key and not api_key.startswith("re_"):
            raise ProviderConfigError("That doesn't look like a valid Resend API key -- it should start with \"re_\".")
        return cleaned

    def send(self, *, config: dict, message: OutboundMessage) -> None:
        api_key = config.get("api_key")
        from_email = message.from_address or config.get("from_email")
        from_name = message.from_name or config.get("from_name") or ""
        from_header = f"{from_name} <{from_email}>" if from_name else from_email

        body = {
            "from": from_header,
            "to": [message.to_address],
            "subject": message.subject,
            "text": message.text_body,
        }
        if message.html_body:
            body["html"] = message.html_body
        if message.reply_to:
            body["reply_to"] = message.reply_to
        if message.attachments:
            body["attachments"] = [
                {"filename": filename, "content": base64.b64encode(content).decode("ascii")}
                for filename, content, _mime_type in message.attachments
            ]

        req = urllib.request.Request(
            self._API_URL,
            data=json.dumps(body).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                # Cloudflare fronts api.resend.com and blocks urllib's
                # default "Python-urllib/3.x" User-Agent as bot traffic
                # (HTML "error code: 1010" body, surfaced here as an
                # opaque 403 with no JSON message) -- a plain browser-
                # shaped UA clears it. Confirmed live against a real
                # account: identical request succeeds once this header
                # is present.
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                resp.read()
        except urllib.error.HTTPError as e:
            # Resend's error responses are JSON with a "message" field --
            # surfaced verbatim (truncated) rather than just the bare HTTP
            # status, since "401" alone doesn't tell an admin whether it's
            # a bad key, a suspended account, or an unverified domain.
            try:
                detail = json.loads(e.read().decode("utf-8", errors="replace")).get("message", "")
            except (ValueError, AttributeError):
                detail = ""
            raise ProviderSendError(f"Resend API error ({e.code}){': ' + detail if detail else ''}") from e
        except (urllib.error.URLError, TimeoutError) as e:
            raise ProviderSendError(str(e)) from e


# Registry every route/mailer.py call site resolves against by
# EmailProvider.provider_type -- the one place a new provider type gets
# wired in.
PROVIDERS: dict[str, EmailProviderBase] = {
    p.type_key: p for p in (SMTPEmailProvider(), ResendEmailProvider())
}


def get_provider(provider_type: str) -> EmailProviderBase:
    try:
        return PROVIDERS[provider_type]
    except KeyError:
        raise ProviderConfigError(f"Unknown provider type: {provider_type!r}") from None
