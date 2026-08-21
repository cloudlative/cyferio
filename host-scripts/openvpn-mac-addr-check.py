#!/usr/bin/python3

#  https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/
#  1) add following lines into /etc/openvpn/server/server.conf file
#   script-security 2
#   client-connect openvpn-mac-addr-check.py
#
#  2) add following line into .ovpn client auth file
#   push-peer-info
#
#  3) Create this file in the /etc/openvpn/server/ location with the name openvpn-mac-addr-check.py
#     (alongside policy_lib.py -- deployed as a sibling file, see host-scripts/ in the git repo)
#  4) Create openvpn_db.txt and openvpn.log files in the same locations with following cmd
#       touch /etc/openvpn/server/openvpn_db.txt
#       touch /etc/openvpn/server/openvpn.log
#
#  5) set permissions
#       chown nobody:nogroup openvpn-mac-addr-check.py policy_lib.py openvpn_db.txt openvpn.log
#  6) chmod +x openvpn-mac-addr-check.py openvpn-client-disconnect.py
#  7) Add the user data to the openvpn_db.txt file with the following format.
#       {openvpn-user}={system-mac-address}
#     e.g
#       sheraz-ahmed=ff:f2:a7:f4:b2:7b
#
#  8) (optional) Set per-client restrictions (allowed OS, allowed
#     countries/cities/ASNs/IPs, monthly bandwidth quota) via
#     client_policy.json -- see the web app's "Manage Restrictions" dialog
#     (Clients page) or Edit User's "Location & Network Restrictions" /
#     "Device & Access Policy" sections (synced onto the linked VPN
#     profile automatically), or openvpn-install.sh's
#     --set-country/--set-os/--set-bandwidth CLI subcommands for the
#     fields that predate the web app. A client with no policy entry at
#     all is fully unrestricted (only the MAC check above applies to
#     them).
#
#     IMPORTANT: /etc/openvpn/server/ is root-owned, and this script (and
#     openvpn-client-disconnect.py) run as `nobody` -- `nobody` can create
#     NEW files there. Pre-create client_policy.json/client_usage.json (and
#     the .lock files policy_lib.py uses for locking) as root, THEN chown
#     them to nobody:nogroup, exactly like step 4/5 above already does for
#     openvpn_db.txt/openvpn.log -- otherwise the first-ever policy lookup
#     will hit a PermissionError trying to create the lock file. This
#     failure mode is caught and fails OPEN (treated as unrestricted, see
#     below) rather than blocking every connection, but usage tracking in
#     particular will silently never persist until this is done:
#       cd /etc/openvpn/server
#       echo '{}' > client_policy.json && echo '{}' > client_usage.json
#       touch client_policy.json.lock client_usage.json.lock
#       chown nobody:nogroup client_policy.json client_usage.json client_policy.json.lock client_usage.json.lock
#       chmod 664 client_policy.json client_usage.json client_policy.json.lock client_usage.json.lock
#
# Gate order (each stage only runs once identity is established by the
# stage before it -- see README.md's "Per-client restrictions" section for
# the full design rationale):
#   1. common_name + IV_HWADDR against openvpn_db.txt   (reason: mac_mismatch
#      -- this IS the Device MAC Address restriction; it's enforced here,
#      identity-binding, rather than as a client_policy.json field, since
#      it's the very thing that establishes which client this even is)
#   2. IV_PLAT against client_policy.json's allowed_os   (reason: os_not_allowed)
#   3. trusted_ip's GeoIP country against client_policy.json's
#      allowed_countries (reason: country_not_allowed, or
#      country_lookup_failed if the restriction can't be verified -- see
#      policy_lib.geoip_lookup_country docstring for the fail-closed
#      rationale)
#   4. trusted_ip's GeoIP city against client_policy.json's allowed_cities
#      (reason: city_not_allowed / city_lookup_failed -- same fail-closed
#      rationale as country)
#   5. trusted_ip's GeoIP ASN against client_policy.json's allowed_asns
#      (reason: asn_not_allowed / asn_lookup_failed -- same fail-closed
#      rationale as country)
#   6. trusted_ip itself against client_policy.json's allowed_ips
#      (reason: ip_not_allowed -- pure ipaddress stdlib comparison, no
#      GeoIP database involved, so there's no separate "lookup failed"
#      case: an empty/unparseable trusted_ip simply never matches, see
#      policy_lib.ip_matches_allowlist)
#   7. client_usage.json's current-month bytes_used against
#      client_policy.json's bandwidth_monthly_gb (reason: bandwidth_exceeded
#      -- soft cutoff, connect-time only: an already-connected session
#      that goes over quota mid-session is NOT killed, see
#      openvpn-client-disconnect.py)
#
# Every one of gates 3-6 is independently opt-in per client (an empty/
# absent allowed_* list for that gate is a no-op, same as the original
# single-country gate always was) and every one mirrors -- field for
# field -- the exact same restriction a portal user can set on their own
# login (User.restrict_login_by_country/city/asn/ip, routes/auth.py), kept
# in sync onto the linked VPN profile by routes/users.py's create_user/
# update_user. The two are deliberately independent enforcement points for
# two different things (a portal admin-app login vs. an actual OpenVPN
# tunnel), not one check reused for both, but an admin configuring one
# from Edit User's "Location & Network Restrictions" section gets both for
# free.
#
# Every rejection (and the final accept) is logged the same way the
# original script always logged the MAC check: a full os.environ dump
# followed by a result line, to openvpn.log -- vpn-status.py's
# --rejected-connections parses this. New rejection reasons are additionally
# logged as a "reason: <reason>" line, parsed the same way as any other
# "KEY: value" env line; vpn-status.py defaults missing/old-format entries
# (logged before this change) to reason "mac_mismatch" for backward
# compatibility.
#
# Every rejection is ALSO best-effort POSTed to the app's "My Connection
# Issues" ingestion endpoint (see report_rejection() below), which is what
# backs a portal user's own per-user rejection history/retention -- this is
# additional to, never a replacement for, the flat-file logging above.
# Requires APP_INGEST_URL/APP_INGEST_TOKEN in vpn-tools.conf (set by
# setup.sh); if either is unset, or the app is unreachable, this is
# silently skipped -- it can never affect the connect decision.

import sys
import os
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import policy_lib  # noqa: E402

env_user = os.getenv('common_name')
env_mac_addr = os.getenv('IV_HWADDR')
env_iv_plat = os.getenv('IV_PLAT', '')
env_trusted_ip = os.getenv('trusted_ip', '')

db_file = policy_lib.CFG.get('DB_FILE', '/etc/openvpn/server/openvpn_db.txt')
log_file = policy_lib.CFG.get('CONN_LOG', '/etc/openvpn/server/openvpn.log')


def db_lookup(user, mac):
    try:
        with open(db_file, 'r') as db:
            for line in db.readlines():
                if '=' not in line:
                    continue
                name, val = line.split('=', 1)
                name = name.rstrip('\n')
                val = val.rstrip('\n')
                if user == name and mac == val:
                    return True
    except FileNotFoundError:
        pass
    return False


def db_lookup_registered(user):
    """Every MAC currently on file for `user` (openvpn_db.txt allows
    multiple "name=mac" lines per person, for multi-device users), as a
    comma-joined string, or None if there are none. Called ONLY at the
    moment of a mac_mismatch rejection, to freeze "what was actually
    registered right now" onto that row (report_rejection()'s
    registered_mac kwarg) -- so vpn-status.py's rejected-connections view
    never has to recompute this later against a file that may have since
    changed. See that function's own docstring for the full rationale."""
    macs = []
    try:
        with open(db_file, 'r') as db:
            for line in db.readlines():
                if '=' not in line:
                    continue
                name, val = line.split('=', 1)
                name = name.rstrip('\n')
                val = val.rstrip('\n')
                if user == name and val:
                    macs.append(val)
    except FileNotFoundError:
        pass
    return ",".join(macs) if macs else None


def report_rejection(reason, message, **detected):
    """Best-effort POST of this rejection to the app's "My Connection
    Issues" ingestion endpoint (routes/host_ingest.py) -- ADDITIONAL to,
    never a replacement for, the flat-file write reject() below already
    does (vpn-status.py --rejected-connections keeps parsing that file
    unchanged). Every failure mode here (no token configured, app
    unreachable, timeout, bad response) is swallowed -- this must never
    change the connect decision or slow it down noticeably. `detected` may
    include source_ip/detected_mac/detected_country/detected_city/
    detected_asn/detected_asn_name/detected_os; any omitted key is sent as null."""
    url = policy_lib.CFG.get("APP_INGEST_URL")
    token = policy_lib.CFG.get("APP_INGEST_TOKEN")
    if not url or not token:
        return
    try:
        import json
        import urllib.request

        payload = {"vpn_client_name": env_user, "reason": reason, "message": message}
        payload.update(detected)
        req = urllib.request.Request(
            url.rstrip("/") + "/internal/connection-rejections",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "Authorization": "Bearer " + token},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=2)
    except Exception:
        pass  # see docstring -- never allowed to affect the reject() call site


def reject(log, reason, message, **detected):
    """Prints/logs the reason + message, then exits 1. `message` must
    contain either "could not be found" (the original MAC-mismatch
    detector string vpn-status.py's iter_env_blocks already matches on) or
    "connection rejected" (the new, equally-unambiguous marker added for
    every other reason) -- see that function's own comment for why both
    phrases are recognized rather than replacing the original one.
    `detected` (source_ip/detected_mac/detected_country/detected_city/
    detected_asn/detected_asn_name/detected_os/registered_mac, whichever are known at
    this call site) is passed straight through to report_rejection()
    above (the new DB-backed history). When "registered_mac" is one of
    the given keys (mac_mismatch only -- see its call site), it's
    ADDITIONALLY written to the flat log as its own
    "registered_mac_at_time:" line (sentinel "none" if the identity had
    NO MAC registered at all, so this is distinguishable from an older
    log line that simply predates this field, which has no
    "registered_mac_at_time:" line at all) -- same "KEY: value" shape
    every other env/reason line already uses, so vpn-status.py's
    iter_env_blocks parses it for free. This is what lets cmd_rejected()
    show a frozen historical value instead of re-deriving it live against
    whatever's on file when the report is viewed (see that function's own
    docstring for why that mattered)."""
    report_rejection(reason, message, **detected)
    print("reason: {0}".format(reason))
    # No space before the colon -- vpn-status.py's ENV_LINE_RE
    # (r"^([A-Za-z_][A-Za-z0-9_]*): (.*)$") requires exactly "KEY: value".
    # This line previously had a stray space before its colon (same class
    # of bug this file's own env-dump loop already had and fixed further
    # down) -- unparseable by that regex, so `reason` was NEVER actually
    # captured into a rejected-connection's block dict for ANY rejection,
    # mac_mismatch included. cmd_rejected()'s `b.get("reason",
    # "mac_mismatch")` fallback masked this completely: every reason
    # silently defaulted to "mac_mismatch" instead of raising a KeyError,
    # so os_not_allowed/country_not_allowed/city_not_allowed/
    # asn_not_allowed/ip_not_allowed/bandwidth_exceeded rejections all
    # showed up mislabeled as MAC mismatches in the admin's "Recent
    # Rejected Connection Attempts" list -- found live 2026-08-21: the
    # flat log had 4 os_not_allowed + 2 bandwidth_exceeded entries, but
    # vpn-status.py --rejected-connections reported 100% mac_mismatch.
    log.write("reason: {0}\n".format(reason))
    if "registered_mac" in detected:
        registered_mac_line = detected["registered_mac"] or "none"
        print("registered_mac_at_time: {0}".format(registered_mac_line))
        log.write("registered_mac_at_time: {0}\n".format(registered_mac_line))
    print(message)
    log.write("\n" + message + "\n\n")
    sys.exit(1)


with open(log_file, 'a') as LogFile:
    LogFile.write("---------------------------------------\n")
    LogFile.write(datetime.now().isoformat() + "\n")
    LogFile.write("---------------------------------------\n")

    for name, value in os.environ.items():
        # Both writers MUST use the identical "KEY: value" (colon, single
        # space, no space before the colon) format -- vpn-status.py's
        # iter_env_blocks() parses openvpn.log with a regex anchored on
        # exactly that shape (see its ENV_LINE_RE / module docstring: "New
        # rejection reasons are... parsed the same way as any other 'KEY:
        # value' env line"). This LogFile.write() call previously wrote
        # "KEY : value" (a stray space before the colon) -- silently
        # unparseable by that regex, so every env var dumped to this file
        # (IV_HWADDR, IV_PLAT, UV_PLAT_REL, etc.) was invisible to
        # vpn-status.py even though it looked present when tailing the log
        # by eye. Live via stdout->journal (print(), above) worked fine;
        # only this file-based copy -- the one vpn-status.py actually reads
        # (CONN_LOG) -- was broken, which is why the OS column has been
        # showing "n/a" for connections logged before this fix.
        print("{0}: {1}".format(name, value))
        LogFile.write(name + ": " + value + "\n")

    # 1) MAC-binding check -- unchanged from the original script's behavior
    # and exact message text (backward-compatible with existing log
    # parsing/monitoring). ------------------------------------------------
    if not db_lookup(env_user, env_mac_addr):
        reject(LogFile, "mac_mismatch",
               "The MAC address of the client machine could not be found in the database",
               source_ip=env_trusted_ip, detected_mac=env_mac_addr, detected_os=env_iv_plat,
               registered_mac=db_lookup_registered(env_user))

    # Identity established (cert CN + device MAC both matched) -- look up
    # this client's restrictions, if any. An empty/absent policy means
    # fully unrestricted; every check below is a no-op in that case.
    #
    # Fails OPEN (treated as unrestricted, connection proceeds) if the
    # policy file/lock itself can't be read for any reason -- e.g. a fresh
    # install where client_policy.json hasn't been created yet, or a
    # permissions problem. This is a deliberately different call than the
    # GeoIP fail-CLOSED behavior below: here, the failure means "we don't
    # even know whether a restriction exists", not "we know one exists and
    # can't verify it" -- and an operational hiccup in this add-on feature
    # must never be able to lock every client (including ones with no
    # restriction at all) out of the VPN. The MAC-binding check above --
    # the actual security boundary -- is completely unaffected either way.
    # Always logged loudly so it's not silently invisible to an admin.
    try:
        policy = policy_lib.get_policy(env_user)
    except Exception as e:
        policy = {}
        print("policy lookup failed for {0}: {1} -- treating as unrestricted".format(env_user, e))
        LogFile.write("policy lookup failed for {0}: {1} -- treating as unrestricted\n".format(env_user, e))

    # 2) OS restriction -----------------------------------------------------
    allowed_os = policy.get("allowed_os") or []
    if allowed_os:
        client_os = policy_lib.IV_PLAT_TO_OS.get(env_iv_plat)
        if client_os not in allowed_os:
            reject(LogFile, "os_not_allowed",
                   "OpenVPN connection rejected: client OS '{0}' is not in {1}'s allowed OS list ({2})".format(
                       env_iv_plat or "unknown", env_user, ", ".join(allowed_os)),
                   source_ip=env_trusted_ip, detected_os=env_iv_plat)

    # 3) Country restriction (GeoIP) -----------------------------------------
    # Fail-safe: only even attempts a GeoIP lookup at all if this specific
    # client has a country restriction configured -- an unrestricted
    # client's connection is never slowed down or blocked by GeoIP
    # infrastructure (missing mmdb, missing geoip2 package, etc.). A list
    # now (was a single string before the Location & Network Restrictions
    # sync) -- policy_lib.get_policy already lifts an old-shape entry's
    # `country` onto a one-item allowed_countries list, so this is the only
    # gate that needs to read here.
    allowed_countries = policy.get("allowed_countries") or []
    if allowed_countries:
        mmdb_path = policy_lib.CFG.get("MAXMIND_DB_PATH")
        country, err = policy_lib.geoip_lookup_country(env_trusted_ip, mmdb_path)
        if err:
            # A configured restriction that can't be verified is rejected,
            # not silently let through -- see policy_lib.geoip_lookup_country.
            reject(LogFile, "country_lookup_failed",
                   "OpenVPN connection rejected: GeoIP country lookup failed ({0}) for {1} while a country restriction is configured for {2}".format(
                       err, env_trusted_ip or "unknown", env_user),
                   source_ip=env_trusted_ip, detected_os=env_iv_plat)
        if country not in allowed_countries:
            reject(LogFile, "country_not_allowed",
                   "OpenVPN connection rejected: client country '{0}' is not in {1}'s allowed countries ({2})".format(
                       country or "unknown", env_user, ", ".join(allowed_countries)),
                   source_ip=env_trusted_ip, detected_country=country, detected_os=env_iv_plat)

    # 4) City restriction (GeoIP) --------------------------------------------
    allowed_cities = policy.get("allowed_cities") or []
    if allowed_cities:
        mmdb_path = policy_lib.CFG.get("MAXMIND_CITY_DB_PATH")
        city, err = policy_lib.geoip_lookup_city(env_trusted_ip, mmdb_path)
        if err:
            reject(LogFile, "city_lookup_failed",
                   "OpenVPN connection rejected: GeoIP city lookup failed ({0}) for {1} while a city restriction is configured for {2}".format(
                       err, env_trusted_ip or "unknown", env_user),
                   source_ip=env_trusted_ip, detected_os=env_iv_plat)
        allowed_cities_lower = {c.lower() for c in allowed_cities}
        if (city or "").lower() not in allowed_cities_lower:
            reject(LogFile, "city_not_allowed",
                   "OpenVPN connection rejected: client city '{0}' is not in {1}'s allowed cities ({2})".format(
                       city or "unknown", env_user, ", ".join(allowed_cities)),
                   source_ip=env_trusted_ip, detected_city=city, detected_os=env_iv_plat)

    # 5) Network/ASN restriction (GeoIP) --------------------------------------
    allowed_asns = policy.get("allowed_asns") or []
    if allowed_asns:
        mmdb_path = policy_lib.CFG.get("MAXMIND_ASN_DB_PATH")
        asn, err = policy_lib.geoip_lookup_asn(env_trusted_ip, mmdb_path)
        if err:
            reject(LogFile, "asn_lookup_failed",
                   "OpenVPN connection rejected: GeoIP ASN lookup failed ({0}) for {1} while a network restriction is configured for {2}".format(
                       err, env_trusted_ip or "unknown", env_user),
                   source_ip=env_trusted_ip, detected_os=env_iv_plat)
        if asn not in allowed_asns:
            reject(LogFile, "asn_not_allowed",
                   "OpenVPN connection rejected: client network '{0}' is not in {1}'s allowed networks ({2})".format(
                       asn or "unknown", env_user, ", ".join(allowed_asns)),
                   source_ip=env_trusted_ip, detected_asn=asn, detected_os=env_iv_plat)

    # 6) IP address restriction ------------------------------------------------
    # No GeoIP database involved -- a direct trusted_ip-vs-allowlist
    # comparison, so there's no separate "lookup failed" reason: an empty
    # trusted_ip just never matches (see policy_lib.ip_matches_allowlist).
    allowed_ips = policy.get("allowed_ips") or []
    if allowed_ips:
        if not policy_lib.ip_matches_allowlist(env_trusted_ip, allowed_ips):
            reject(LogFile, "ip_not_allowed",
                   "OpenVPN connection rejected: client IP '{0}' is not in {1}'s allowed IP list ({2})".format(
                       env_trusted_ip or "unknown", env_user, ", ".join(allowed_ips)),
                   source_ip=env_trusted_ip, detected_os=env_iv_plat)

    # 7) Monthly bandwidth quota (soft cutoff, connect-time only) -----------
    quota_gb = policy.get("bandwidth_monthly_gb")
    if quota_gb:
        # Same fail-open rationale as the policy lookup above: a quota IS
        # configured here (we know that much), but if the usage file can't
        # be read, treat usage as unknown-but-not-yet-over-quota rather
        # than blocking the connection outright.
        try:
            used_bytes = policy_lib.get_usage(env_user)
        except Exception as e:
            used_bytes = 0
            print("usage lookup failed for {0}: {1} -- treating this month's usage as 0".format(env_user, e))
            LogFile.write("usage lookup failed for {0}: {1} -- treating this month's usage as 0\n".format(env_user, e))
        quota_bytes = float(quota_gb) * (1024 ** 3)
        if used_bytes >= quota_bytes:
            reject(LogFile, "bandwidth_exceeded",
                   "OpenVPN connection rejected: {0}'s monthly bandwidth quota exceeded ({1:.2f} / {2} GB used this month)".format(
                       env_user, used_bytes / (1024 ** 3), quota_gb),
                   source_ip=env_trusted_ip, detected_os=env_iv_plat)

    print("The MAC address of the client machine has been successfully matched to the database")
    LogFile.write("\nThe MAC address of the client machine has been successfully matched to the database\n\n")
    sys.exit(0)
