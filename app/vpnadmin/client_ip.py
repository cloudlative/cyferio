"""
Real client IP extraction for the login-restriction feature (routes/
auth.py) -- used to enforce per-user allowed-IP/allowed-country/allowed-
city/allowed-ASN login restrictions, and to feed the MaxMind lookups in
geoip.py that back those checks.

Which header actually carries the real visitor IP depends entirely on how
traffic reaches this app, which setup-new-machine.sh auto-detects at
install time and writes to CLIENT_IP_HEADER in .env (see config.py):

- Cloudflare-proxied (orange cloud on): every real request arrives FROM
  Cloudflare's edge, never directly from the visitor, so
  `request.client.host` (and a bare X-Forwarded-For) would only ever show
  a Cloudflare edge IP. Cloudflare's own CF-Connecting-IP header carries
  the real visitor IP instead -- Cloudflare's edge always sets/overwrites
  this header itself rather than passing through whatever a client sent.
  Traefik's `cloudflare-only` ipAllowList middleware (see
  app/traefik/dynamic.yml.tmpl) additionally enforces, at the edge, that
  only Cloudflare's published ranges can reach this app at all -- so a
  request that reaches this code with a CF-Connecting-IP header has to
  have actually come through Cloudflare for that header to be present,
  not just claimed by an arbitrary direct client.

- Direct (no CDN in front of Traefik, whether that's a plain A/AAAA
  record, a DNS-only Cloudflare record, or any other DNS provider):
  Traefik itself is the only hop between the internet and this app, and
  Traefik APPENDS the real connecting peer's address to X-Forwarded-For
  rather than overwriting it -- so the last (rightmost) entry is the
  trustworthy one Traefik itself observed, while the first (leftmost)
  entry is just whatever the client's own request claimed, and is fully
  attacker-controlled. Taking the first entry here would be a spoofable
  fallback; this module always takes the last one.

CLIENT_IP_HEADER lets an operator override the strategy by hand (e.g. a
second reverse proxy of their own in front of Traefik, using X-Real-IP or
RFC 7239's Forwarded header) -- see config.py's docstring for the full set
of accepted values. Left unset ("auto"), this module tries CF-Connecting-IP
first and falls back to the X-Forwarded-For rightmost-hop logic, which
covers both of the auto-detected modes above without needing the config
value set at all (useful for local/dev runs with no Traefik in front,
where every branch below simply falls through to the raw socket peer).
"""
import ipaddress

from fastapi import Request

from .config import settings


def ip_matches_allowlist(ip: str | None, allowed: list[str]) -> bool:
    """True if `ip` matches any entry in `allowed` -- each entry is either a
    single IP address ("203.0.113.5") or a CIDR range ("10.0.0.0/24"),
    dual-stack (IPv4 and IPv6 both work transparently via the stdlib
    `ipaddress` module). A malformed `ip` (lookup somehow failed to produce
    anything usable) or a malformed allowlist entry (an admin typo) never
    raises -- it's simply treated as not matching, which is the correct
    fail-closed behavior for an allowlist: a mistake should never
    accidentally widen access, only narrow it further than intended."""
    if not ip or not allowed:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for entry in allowed:
        entry = (entry or "").strip()
        if not entry:
            continue
        try:
            if "/" in entry:
                if addr in ipaddress.ip_network(entry, strict=False):
                    return True
            elif addr == ipaddress.ip_address(entry):
                return True
        except ValueError:
            continue  # malformed entry -- skip it, don't let it crash the whole check
    return False


def _cf_connecting_ip(request: Request) -> str | None:
    cf_ip = request.headers.get("cf-connecting-ip")
    return cf_ip.strip() if cf_ip else None


def _xff_rightmost(request: Request) -> str | None:
    """Last (rightmost) entry of X-Forwarded-For -- the hop closest to this
    app, i.e. the one Traefik itself appended from the real TCP peer it
    saw. The leftmost entry is whatever the client's own request claimed
    and is not trustworthy on its own (see module docstring)."""
    xff = request.headers.get("x-forwarded-for")
    if not xff:
        return None
    hops = [h.strip() for h in xff.split(",") if h.strip()]
    return hops[-1] if hops else None


def _x_real_ip(request: Request) -> str | None:
    real_ip = request.headers.get("x-real-ip")
    return real_ip.strip() if real_ip else None


def _forwarded_rightmost(request: Request) -> str | None:
    """RFC 7239 `Forwarded` header, e.g.
    `Forwarded: for=192.0.2.60;proto=http, for=198.51.100.17` -- takes the
    last `for=` param (same rightmost-hop reasoning as X-Forwarded-For),
    stripping quotes and IPv6 brackets/port (`for="[2001:db8::1]:4711"`)."""
    forwarded = request.headers.get("forwarded")
    if not forwarded:
        return None
    last_for: str | None = None
    for part in forwarded.split(","):
        for directive in part.split(";"):
            directive = directive.strip()
            if directive.lower().startswith("for="):
                last_for = directive[4:].strip()
    if not last_for:
        return None
    val = last_for.strip('"')
    if val.startswith("["):
        # "[2001:db8::1]:4711" or "[2001:db8::1]" -> "2001:db8::1"
        val = val[1 : val.index("]")] if "]" in val else val
    elif ":" in val and val.count(":") == 1:
        # "203.0.113.5:4711" (IPv4 with port, single colon) -> strip port
        val = val.split(":", 1)[0]
    return val or None


def _socket_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _auto(request: Request) -> str | None:
    return _cf_connecting_ip(request) or _xff_rightmost(request) or _socket_ip(request)


def get_client_ip(request: Request) -> str | None:
    header = (settings.CLIENT_IP_HEADER or "").strip().lower()

    if header in ("", "auto"):
        return _auto(request)
    if header == "cf-connecting-ip":
        return _cf_connecting_ip(request) or _auto(request)
    if header == "x-forwarded-for":
        return _xff_rightmost(request) or _auto(request)
    if header == "x-real-ip":
        return _x_real_ip(request) or _auto(request)
    if header == "forwarded":
        return _forwarded_rightmost(request) or _auto(request)

    # Unrecognized value -- fail soft to the auto chain rather than ever
    # raising out of a login attempt over a config typo.
    return _auto(request)
