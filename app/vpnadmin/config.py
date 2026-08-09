"""
Central configuration for the OpenVPN Toolkit web app.

Everything is read from environment variables (see ../.env.example), with
sane defaults for a co-located deployment (app running directly on the same
box as openvpn-install.sh / vpn-status.py). No config value here is
hardcoded to any specific person's server -- this is the open-source app,
not a private deployment.
"""
import os
import secrets


def _env_bool(name: str, default: bool) -> bool:
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


class Settings:
    # --- Database -------------------------------------------------------
    # Either sqlite:///./data/app.db (default) or a postgresql:// URL.
    # SQLAlchemy handles both transparently through the same models.
    DATABASE_URL: str = os.environ.get("DATABASE_URL", "sqlite:///./data/app.db")

    # --- Sessions / auth --------------------------------------------------
    # MUST be overridden in production via env var -- a random one is
    # generated per-process as a safe fallback for local dev only (sessions
    # won't survive a restart, which is a deliberate nudge to set a real one).
    SECRET_KEY: str = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
    SESSION_COOKIE_NAME: str = os.environ.get("SESSION_COOKIE_NAME", "vpnadmin_session")
    SESSION_MAX_AGE_SECONDS: int = int(os.environ.get("SESSION_MAX_AGE_SECONDS", 60 * 60 * 8))  # 8h
    # Marks the session cookie Secure (browser withholds it over plain HTTP)
    # -- only safe once something in front of this app actually terminates
    # TLS (e.g. the Traefik service in docker-compose.yml). Off by default
    # so local/dev runs over plain http:// keep working without a special
    # override; set true in production's .env.
    SESSION_HTTPS_ONLY: bool = os.environ.get("SESSION_HTTPS_ONLY", "false").strip().lower() == "true"

    # --- Underlying toolkit scripts --------------------------------------
    # Paths to the two CLI tools this app is a frontend for. Defaults match
    # a fresh `git clone` of this repo placed at /opt/openvpn-toolkit; in a
    # Docker deployment these are bind-mounted from the host (see
    # docker-compose.yml) and these env vars should point at the mounted
    # paths instead.
    OPENVPN_INSTALL_SCRIPT: str = os.environ.get(
        "OPENVPN_INSTALL_SCRIPT", "/opt/openvpn-toolkit/openvpn-install.sh"
    )
    VPN_STATUS_SCRIPT: str = os.environ.get(
        "VPN_STATUS_SCRIPT", "/opt/openvpn-toolkit/vpn-status.py"
    )

    # Whether to prefix script invocations with `sudo`. Default true (the
    # scripts require root for most operations). Set to false if this
    # process itself already runs as root -- e.g. inside a container that
    # was granted root to access the bind-mounted /etc/openvpn directory,
    # where re-invoking sudo would be a needless extra dependency (and
    # sudo may not even be installed in a minimal container image).
    USE_SUDO: bool = _env_bool("USE_SUDO", True)

    # Per-call timeout for shelling out to the scripts, in seconds. Add/revoke
    # involve easyrsa key generation which can take a few seconds on slower
    # hardware; status/list calls should be near-instant.
    SCRIPT_TIMEOUT_SECONDS: int = int(os.environ.get("SCRIPT_TIMEOUT_SECONDS", 30))

    # --- Server -----------------------------------------------------------
    HOST: str = os.environ.get("HOST", "0.0.0.0")
    PORT: int = int(os.environ.get("PORT", 8000))

    # --- First-run bootstrap ------------------------------------------------
    # If no admin user exists yet at startup, one is created from these (only
    # used once -- change the password immediately after first login). Unset
    # by default so a fresh deployment is forced to set these explicitly
    # rather than silently shipping a guessable default credential.
    BOOTSTRAP_ADMIN_USERNAME: str | None = os.environ.get("BOOTSTRAP_ADMIN_USERNAME")
    BOOTSTRAP_ADMIN_PASSWORD: str | None = os.environ.get("BOOTSTRAP_ADMIN_PASSWORD")

    # --- Branding -----------------------------------------------------------
    # Purely cosmetic, env-driven so a given deployment can relabel the app
    # (sidebar header, login page, footer credit) without touching templates
    # or committing anything person/org-specific to this open-source repo.
    APP_NAME: str = os.environ.get("APP_NAME", "OpenVPN Toolkit")
    APP_TAGLINE: str = os.environ.get("APP_TAGLINE", "Sign in to manage clients, MACs & live status")
    APP_FOOTER_CREDIT: str = os.environ.get("APP_FOOTER_CREDIT", "")

    # IANA timezone name (e.g. "UTC", "Asia/Karachi") used to DISPLAY
    # timestamps in the browser -- every timestamp this app stores/emits is
    # already UTC (see e.g. host-scripts/openvpn-client-disconnect.py's
    # datetime.now(timezone.utc)), so this never touches storage, only how
    # app.js's fmtTimestamp() renders it via Intl.DateTimeFormat's
    # `timeZone` option (which relies on the browser's own IANA database,
    # not anything installed on this server -- no tzdata package needed
    # here). "UTC" is a safe, unambiguous default for a fresh install.
    APP_TIMEZONE: str = os.environ.get("APP_TIMEZONE", "UTC")
    # "24h" or "12h" -- how fmtTimestamp() (static/app.js) formats the clock
    # portion of a timestamp. Paired with APP_TIMEZONE above.
    APP_TIME_FORMAT: str = os.environ.get("APP_TIME_FORMAT", "24h")

    # --- Outbound email (SMTP) -----------------------------------------------
    # Used solely for the "email a client's .ovpn profile" action. Left blank
    # by default -- the feature stays present in the UI but the API returns a
    # clear 400 ("SMTP is not configured") until these are set, rather than
    # silently failing or crashing.
    SMTP_HOST: str = os.environ.get("SMTP_HOST", "")
    SMTP_PORT: int = int(os.environ.get("SMTP_PORT", 587))
    SMTP_USERNAME: str = os.environ.get("SMTP_USERNAME", "")
    SMTP_PASSWORD: str = os.environ.get("SMTP_PASSWORD", "")
    SMTP_FROM: str = os.environ.get("SMTP_FROM", "")
    SMTP_USE_TLS: bool = _env_bool("SMTP_USE_TLS", True)

    # --- Theming --------------------------------------------------------
    # Which named theme (login-page animated background + logged-in app
    # accent palette) is active. "auto" rotates through all 6 on a fixed
    # 2-hour schedule (see app_settings.resolve_active_theme); any other
    # value pins that one theme permanently. See app_settings.py's
    # ACTIVE_THEME_IDS for the full set of valid values.
    LOGIN_THEME: str = os.environ.get("LOGIN_THEME", "auto")

    # --- Per-client restrictions (country / OS / bandwidth quota) -----------
    # See README.md's "Per-client restrictions" section for the full design.
    # These two JSON files live under /etc/openvpn (bind-mounted rw into
    # this container already, same mount used for openvpn_db.txt etc. --
    # see docker-compose.yml), so the app reads/writes them directly in
    # Python (policy_store.py), no subprocess/CLI call needed. Enforcement
    # itself happens entirely on the OpenVPN host's client-connect/
    # client-disconnect scripts (host-scripts/ in this repo), which this
    # app does not invoke -- it only edits the policy file they read.
    # Default path is under a nobody-owned "policy/" subdirectory, NOT
    # directly in /etc/openvpn/server/ -- that top-level directory is
    # root-owned, and the client-connect/disconnect scripts (which run as
    # `nobody`, OpenVPN's unprivileged runtime user) need to atomically
    # write-then-rename client_usage.json, which requires write permission
    # on the containing directory itself, not just the file. See
    # README.md's "Per-client restrictions" setup section for the
    # `mkdir`/`chown`/`chmod` this depends on.
    CLIENT_POLICY_FILE: str = os.environ.get("CLIENT_POLICY_FILE", "/etc/openvpn/server/policy/client_policy.json")
    CLIENT_USAGE_FILE: str = os.environ.get("CLIENT_USAGE_FILE", "/etc/openvpn/server/policy/client_usage.json")

    # --- Health page -------------------------------------------------------
    # Read-only bind mounts of the Docker HOST's /proc, /sys, and root
    # filesystem (see docker-compose.yml) -- deliberately NOT the
    # container's own /proc, /sys, "/" (which would only describe this one
    # container's cgroup-limited view), so the Health page can show the
    # actual droplet's CPU/RAM/disk/uptime. Unset/missing in local dev (no
    # such mounts exist there) -- health.py's host-stats functions handle
    # that by reporting the section as unavailable rather than raising.
    HOST_PROC_PATH: str = os.environ.get("HOST_PROC_PATH", "/hostproc")
    HOST_SYS_PATH: str = os.environ.get("HOST_SYS_PATH", "/hostsys")
    HOST_ROOT_PATH: str = os.environ.get("HOST_ROOT_PATH", "/hostfs")

    # Traefik's internal API (see docker-compose.yml's traefik service --
    # --api=true bound only to the "traefik" entrypoint, which is never
    # published to the host, so this is only reachable from other
    # containers on the same compose network, never publicly). Unreachable
    # in local dev (no traefik container at all there) -- health.py
    # reports that section as unavailable rather than raising.
    TRAEFIK_API_URL: str = os.environ.get("TRAEFIK_API_URL", "http://traefik:8080")


settings = Settings()

# Note: branding/SMTP/security values above are now only the seed/fallback
# defaults -- the admin-editable, DB-backed source of truth (once anything's
# been changed via the Settings page) lives in app_settings.py, which is
# what templates/mailer.py/auth.py actually read at runtime. See that
# module's docstring for the full env-var -> DB -> in-process-cache layering.
