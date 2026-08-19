# Optional Integrations: MaxMind GeoIP & CAPTCHA

Both are opt-in, runtime-manageable, and fully hidden from every page and
API endpoint until configured. This doc covers installation, the Settings
UI, and what "disabled" actually looks like.

## Architecture

`app/vpnadmin/features.py` is a small generic registry, not a per-
integration one-off:

- `is_enabled(key)` -- the one function everything else calls.
- `require_feature(key)` -- a FastAPI dependency (same shape as
  `permissions.require_permission`) that 404s a route when the feature is
  off. **404, not 403** -- a disabled integration should look to a direct
  API call exactly like the route doesn't exist, not like a permission
  problem (which would confirm it exists).
- Every page's Jinja context gets a `features` dict for free (see
  `routes/pages.py`'s `_ctx()`), so any template does
  `{% if features.geoip %}` / `{% if features.captcha %}` around a
  section.

Both integrations' configuration lives in the same runtime-editable
`AppSettings` singleton row every other Settings-page setting already
uses (`app_settings.runtime`, DB-backed, env-var fallback, no restart
needed -- see `app_settings.py`'s own docstring for the full mechanism).
New nullable columns get added to existing databases automatically on
next startup (`db._sync_missing_columns()`) -- no manual migration step.

## MaxMind GeoIP

**What it powers:** country/city/ASN/IP restrictions (VPN Access
Restrictions on Clients, Portal Login Restrictions on Users, the
self-service country picker on My VPN Profile) and geo distribution
charts on Reports/My Reports.

**Installation (`setup.sh`):** unchanged from before this feature --
Phase 3 already asks interactively (or via `--maxmind-key`), validates
the key live against MaxMind, runs `geoip-update.sh` to download all
3 GeoLite2 editions, and installs the weekly refresh timer
(`systemd/openvpn-geoip-update.timer`).

**Settings page (Geo/IP (MaxMind) card):**
- Enter a license key, click **Validate Key** (a fast HEAD request against
  MaxMind's own download endpoint -- checks the key is accepted without
  downloading anything) before saving.
- **Save & Refresh Databases** saves the key/toggle, then triggers the
  same host-side `geoip-update.sh` the weekly timer runs, over the
  existing whitelisted-SSH host-executor mechanism (`services/system/
  host_executor.py` + a new `geoip-update` action in `cli/
  openvpn_admin.py` -- no new privilege boundary, reuses the exact
  posture already documented for VPN session actions).
- Disabling only flips the DB toggle -- the key and downloaded `.mmdb`
  files are left alone, so re-enabling later is instant.

**Why "enabled" checks two things:** `features.geoip_enabled()` is
`runtime.geoip_enabled AND the Country .mmdb file actually exists on
disk`. An admin can flip the toggle on before the first download
finishes; the file-presence check is what keeps the UI honest about
that window rather than showing a picker that's actually empty.

**Existing deployments:** GeoIP was never previously gated by an
"enabled" flag -- it just worked whenever the `.mmdb` files happened to
exist. The enabled flag defaults to `True` (not unset/off) specifically
so an already-working deployment keeps working with zero admin action
after upgrading; a genuinely fresh install with no `.mmdb` yet still
correctly shows nothing, since the file-presence half of the check is
what's false there.

**When disabled:** every `/api/geo/*` endpoint 404s; the country/city/
ASN restriction fields (not the IP-restriction field next to them, which
doesn't depend on MaxMind) disappear from Clients/Users/My VPN Profile;
the Country Distribution chart disappears from Reports/My Reports.

## CAPTCHA (Cloudflare Turnstile / Google reCAPTCHA)

**What it powers:** the widget on Login, Forgot Password, and Reset
Password (`captcha.py`'s existing provider-agnostic `is_configured()`/
`widget_context()`/`verify()` -- unchanged logic, now DB-overridable).

**Installation (`setup.sh`):** an interactive prompt (or
`--captcha-provider turnstile|recaptcha` + that provider's
`--*-site-key`/`--*-secret-key` flags) mirrors the MaxMind prompt.
Skipping it (or a plain no-flags run answered "no") leaves CAPTCHA
disabled, same as before this feature existed.

**Settings page (CAPTCHA card):** pick a provider (or "Disabled"), enter
its site/secret key pair. A saved secret key (and, for Turnstile, the
public site key too) loads locked -- greyed out, not a live editable
box holding the real value -- with an **Edit** button that clears it and
hands control back; leaving it alone re-saves it unchanged.

**Test** calls the provider's siteverify with a deliberately-invalid
token and checks for a normal JSON response, using whatever's currently
in the provider dropdown and that provider's secret field right now --
not necessarily the already-saved config, so it's safe to try a
not-yet-saved value or a provider you haven't switched to yet. A blank
or still-locked secret field falls back to that specific provider's own
saved value (never a different, currently-active provider's). This
confirms the provider is reachable **without** needing a real solved
challenge, and -- for Turnstile specifically -- that the secret key
itself is genuinely valid, since Turnstile's siteverify returns a
distinct error for a bad secret. Google's reCAPTCHA API validates the
token before the secret and can't be made to reveal a bad-secret error
this way, so a reCAPTCHA Test result only ever confirms Google is
reachable, never that the secret is correct -- the response says this
plainly (`secret_verifiable: false`) rather than reporting a false
positive. Either way, this is a save-time sanity check, not a full
widget test -- it can't prove the actual browser flow works, only that
the credentials/network path are good.

**Switching providers:** just change the Provider dropdown and its
key pair -- no reinstall, no restart. The DB-backed value always wins
over `CAPTCHA_PROVIDER`/`TURNSTILE_*`/`RECAPTCHA_*` env vars once
anything's been saved through this page.

**When disabled:** no widget renders on any of the three pages (this
was already true before this feature -- `{% if captcha %}` in the shared
login/forgot-password/reset-password templates), and login/reset
continue to work normally with no CAPTCHA step.

## Security review notes

- Every `routes/geo.py` endpoint is behind `require_feature("geoip")` --
  confirmed via `tests/test_features.py` that a direct call returns 404
  (not an empty `200` list) when disabled, and 401 (not 404) when merely
  unauthenticated, so a disabled feature never masks a real auth
  requirement.
- Secret fields (`maxmind_license_key`, `turnstile_secret_key`,
  `recaptcha_secret_key`) are masked on every `GET /api/settings`
  response (`SECRET_PLACEHOLDER`, same convention the SMTP/email-provider
  system already established) and never round-trip in plaintext; `PATCH`
  treats an incoming value exactly equal to the placeholder as "leave
  unchanged". Site keys are intentionally **not** masked -- they're
  public by design, already shipped to every visitor's browser in the
  login page's HTML.
- `app_settings.runtime` is refreshed synchronously in the same request
  that saves settings (`refresh_runtime_cache()`), so there's no window
  where a just-saved CAPTCHA config is inconsistently read as
  unconfigured by a concurrent request.
- The `geoip-update` host action writes only `MAXMIND_LICENSE_KEY` into
  `vpn-tools.conf` (format-validated) and execs the existing,
  unmodified `geoip-update.sh` -- it does not grant any new host
  capability beyond what the existing VPN-session host actions already
  have.
