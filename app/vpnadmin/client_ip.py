"""
Real client IP extraction for the login-restriction feature (routes/
auth.py) -- used to enforce per-user allowed-IP/allowed-country login
restrictions.

vpn-mgmt.cloudlative.com's Cloudflare DNS record is proxied (orange
cloud): every real request into Traefik/this app arrives FROM Cloudflare's
edge, never directly from the visitor, so `request.client.host` (and a
bare X-Forwarded-For) would only ever show a Cloudflare edge IP -- useless
for a per-visitor restriction. Cloudflare's own CF-Connecting-IP header
carries the real visitor IP instead, and -- unlike X-Forwarded-For --
Cloudflare's edge always sets/overwrites this header itself rather than
passing through whatever a client sent, so a request that reaches the
origin with a spoofed CF-Connecting-IP would have had to originate from
Cloudflare's edge in the first place for that header to still be present
and trusted at this layer.

Caveat worth knowing (infrastructure-level, not something this code can
fix): this only holds as long as the origin droplet itself is unreachable
directly, bypassing Cloudflare entirely (e.g. by restricting inbound on
the droplet's firewall to Cloudflare's published IP ranges). If the origin
IS reachable directly, a request could forge its own CF-Connecting-IP.
That firewall-level lockdown is outside this app's scope to enforce.
"""
import ipaddress

from fastapi import Request


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


def get_client_ip(request: Request) -> str | None:
    cf_ip = request.headers.get("cf-connecting-ip")
    if cf_ip:
        return cf_ip.strip()
    # Fallbacks for local/dev runs and any deployment not behind Cloudflare
    # (this header is checked first everywhere else too, so a self-hoster
    # running without Cloudflare still gets a sane real-IP-of-the-request
    # value from whatever reverse proxy they do have in front, or the
    # directly-connecting socket if there's none at all).
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else None
