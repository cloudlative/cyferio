"""
Central configuration for the Cyferio web app.

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


def _default_database_url() -> str:
    """Postgres is the default DB for any real (docker-compose) deployment;
    SQLite is only used when nothing else is configured at all (bare local/
    dev runs) -- explicitly setting DATABASE_URL (to a sqlite:// URL or
    anything else) always wins over both.

    Reuses the SAME POSTGRES_USER/POSTGRES_PASSWORD/POSTGRES_DB env vars
    docker-compose.yml's `postgres` service already requires (and which
    env_file: .env already passes into this container too) -- no new env
    var needed, and no credential hardcoded here: docker-compose.yml's
    postgres service refuses to even start without POSTGRES_PASSWORD set
    (`:?Set POSTGRES_PASSWORD in .env`), so its presence in this process's
    environment is itself the signal that a real Postgres instance is
    genuinely configured and reachable at the "postgres" service name.
    setup-new-machine.sh's fresh .env generation relies on exactly this --
    it writes POSTGRES_PASSWORD unconditionally but no longer writes
    DATABASE_URL at all, letting this function supply Postgres
    automatically (pass --sqlite to that script for the explicit opt-out)."""
    if os.environ.get("DATABASE_URL"):
        return os.environ["DATABASE_URL"]
    if os.environ.get("POSTGRES_PASSWORD"):
        user = os.environ.get("POSTGRES_USER", "vpnadmin")
        db = os.environ.get("POSTGRES_DB", "vpnadmin")
        return f"postgresql://{user}:{os.environ['POSTGRES_PASSWORD']}@postgres:5432/{db}"
    return "sqlite:///./data/app.db"


class Settings:
    # --- Database -------------------------------------------------------
    # Postgres by default (see _default_database_url() above); SQLite only
    # as a zero-config local/dev fallback, or when DATABASE_URL is set
    # explicitly. SQLAlchemy handles both transparently through the same
    # models either way.
    DATABASE_URL: str = _default_database_url()

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

    # --- Host executor (Phase 1 Python service layer) --------------------------
    # Used by services/system/host_executor.py to run the ONE whitelisted
    # remote command (app/cli/openvpn_admin.py) over SSH for genuinely
    # host-namespace operations -- see the migration plan's §2a. HOST_SSH_TARGET
    # unset by default: the live-session actions (routes/clients.py --
    # list/disconnect current connections) return a clear 400/degrade until
    # it's configured, same fail-soft pattern SMTP_HOST already uses above.
    # NOT used for cert/client/MAC operations, which stay in-process via
    # cli_wrapper.py exactly as today.
    #
    # HOST_SSH_KEY_PATH is the path *inside this container* -- defaults to
    # docker-compose.yml's bind-mount target, which is a fixed path
    # regardless of where the key actually lives on the host. Deliberately
    # a DIFFERENT env var name than the one docker-compose.yml's volume line
    # uses to pick the key's *host-side* source path
    # (HOST_SSH_KEY_SOURCE_PATH) -- reusing one name for both would mean
    # whatever value configures the host-side bind-mount source also leaks
    # into this container's own environment (env_file: .env passes
    # everything through) and silently overrides the in-container path this
    # app actually reads from, pointing it at a path that only exists on the
    # host, not in here.
    HOST_SSH_KEY_PATH: str = os.environ.get("HOST_SSH_KEY_PATH", "/run/secrets/openvpn-toolkit-deploy-key")
    HOST_SSH_TARGET: str = os.environ.get("HOST_SSH_TARGET", "")  # "user@host"
    HOST_SSH_PORT: int = int(os.environ.get("HOST_SSH_PORT", 22))
    HOST_SSH_REMOTE_SCRIPT_PATH: str = os.environ.get(
        "HOST_SSH_REMOTE_SCRIPT_PATH", "/opt/openvpn-toolkit/app/cli/openvpn_admin.py"
    )
    HOST_SSH_USE_SUDO: bool = _env_bool("HOST_SSH_USE_SUDO", True)
    HOST_SSH_TIMEOUT_SECONDS: int = int(os.environ.get("HOST_SSH_TIMEOUT_SECONDS", 180))

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

    # The same domain docker-compose.yml's traefik-config service already
    # requires in .env for routing (see that file's APP_DOMAIN comment) --
    # read here too so app_settings.py's runtime.portal_url can default to
    # "https://{APP_DOMAIN}" without asking an admin to re-enter a value
    # already configured elsewhere. Settings -> Platform Settings' Portal
    # URL field can still override this per-deployment (e.g. a different
    # public URL than the routing domain), same "env default, DB override"
    # shape as every other SMTP/system setting in this app.
    APP_DOMAIN: str = os.environ.get("APP_DOMAIN", "")

    # CAPTCHA on /login, /forgot-password, /reset-password (see captcha.py
    # and routes/auth.py) -- provider-agnostic on purpose: this is a
    # self-hosted, open-source app (see README's "nothing here hardcodes
    # any specific ... organization" stance), and a community deployment
    # has no reason to be forced onto Cloudflare specifically. Set
    # CAPTCHA_PROVIDER to "turnstile" or "recaptcha" plus that provider's
    # own SITE_KEY/SECRET_KEY pair below; leave it unset (the default) and
    # captcha.is_configured() returns False everywhere, so a deployment
    # that hasn't set this up simply doesn't get CAPTCHA gating rather
    # than breaking login entirely. Every *_SITE_KEY is public (goes
    # straight into the page HTML); every *_SECRET_KEY never leaves this
    # process -- only used server-side against the provider's siteverify
    # endpoint.
    CAPTCHA_PROVIDER: str = os.environ.get("CAPTCHA_PROVIDER", "").strip().lower()
    TURNSTILE_SITE_KEY: str | None = os.environ.get("TURNSTILE_SITE_KEY")
    TURNSTILE_SECRET_KEY: str | None = os.environ.get("TURNSTILE_SECRET_KEY")
    RECAPTCHA_SITE_KEY: str | None = os.environ.get("RECAPTCHA_SITE_KEY")
    RECAPTCHA_SECRET_KEY: str | None = os.environ.get("RECAPTCHA_SECRET_KEY")

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
    # Small, same-directory JSON cache of the handful of AppSettings values
    # host-scripts/quota_enforcer.py (which has no DB access -- it runs
    # standalone as `nobody`, no app dependency, same posture as every
    # other host-scripts/ file) needs to know about -- currently just
    # default_quota_enforcement_policy. Written by
    # policy_store.write_global_defaults() whenever the runtime settings
    # cache is refreshed (see app_settings.py's refresh_runtime_cache);
    # read with the same fail-open ("missing/unreadable -> built-in
    # default") stance as every other file in this directory.
    GLOBAL_DEFAULTS_FILE: str = os.environ.get("GLOBAL_DEFAULTS_FILE", "/etc/openvpn/server/policy/global_defaults.json")

    # Same GeoLite2-Country mmdb used by the VPN client country-restriction
    # feature (see host-scripts/policy_lib.py's geoip_lookup_country and
    # vpn-tools.conf.example's MAXMIND_DB_PATH) -- the default path matches
    # that one exactly, and lives under /etc/openvpn, which this app
    # already bind-mounts rw (see docker-compose.yml), so no extra mount is
    # needed to let the web app's own login-country check read the same
    # database. Used by vpnadmin/geoip.py; unrelated to the host-level
    # scripts' own separate geoip2 install -- this app has its own
    # requirements.txt entry for the geoip2 package.
    GEOIP_DB_PATH: str = os.environ.get("GEOIP_DB_PATH", "/etc/openvpn/server/GeoLite2-Country.mmdb")

    # City and ASN (network operator) login-restriction lookups -- same
    # /etc/openvpn/server bind mount as GEOIP_DB_PATH above, just the two
    # other GeoLite2 database editions. Both optional independently of
    # GEOIP_DB_PATH and of each other: a missing file just means that one
    # restriction type fails soft to "can't determine, so block if the
    # admin turned it on" the same way a missing GEOIP_DB_PATH already
    # does for country (see geoip.py).
    GEOIP_CITY_DB_PATH: str = os.environ.get("GEOIP_CITY_DB_PATH", "/etc/openvpn/server/GeoLite2-City.mmdb")
    GEOIP_ASN_DB_PATH: str = os.environ.get("GEOIP_ASN_DB_PATH", "/etc/openvpn/server/GeoLite2-ASN.mmdb")

    # --- Real client IP source (proxy/CDN detection) -------------------------
    # Which header client_ip.py::get_client_ip() trusts for the visitor's real
    # IP (used by the GeoIP/country/city/ASN/IP login restrictions above, and
    # everything downstream of get_client_ip()). Auto-detected and written
    # here by setup-new-machine.sh, based on whether APP_DOMAIN resolves into
    # Cloudflare's published ranges (proxied) or straight to this host's own
    # public IP (direct -- also covers Cloudflare DNS-only and any other DNS
    # provider, since Traefik is the sole hop in front of the app either way).
    # Safe to hand-edit for a setup auto-detection can't infer (e.g. your own
    # reverse proxy in front of Traefik). Accepted values:
    #   ""                (default) auto: CF-Connecting-IP, else
    #                      X-Forwarded-For's rightmost/Traefik-appended hop,
    #                      else the raw socket peer.
    #   "CF-Connecting-IP" Cloudflare-proxied deployments. Pair with
    #                      CLIENT_IP_TRUST_MIDDLEWARE=cloudflare-only in
    #                      docker-compose.yml's traefik-config rendering (see
    #                      app/traefik/dynamic.yml.tmpl) so Traefik itself
    #                      only accepts inbound connections from Cloudflare's
    #                      ranges -- otherwise this header is just a claim.
    #   "X-Forwarded-For"  Direct deployments (no CDN in front of Traefik).
    #                      Always takes the LAST (rightmost) hop -- the one
    #                      Traefik itself appended -- never the first, which
    #                      is attacker-controlled.
    #   "X-Real-IP"        Set by some reverse proxies (not Traefik itself) --
    #                      for an operator's own extra proxy layer.
    #   "Forwarded"        RFC 7239 -- same rightmost-hop handling as XFF.
    CLIENT_IP_HEADER: str = os.environ.get("CLIENT_IP_HEADER", "")

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
