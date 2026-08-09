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
#  8) (optional) Set per-client restrictions (allowed OS, restricted
#     country, weekly bandwidth quota) via client_policy.json -- see the
#     web app's "Manage Restrictions" dialog, or openvpn-install.sh's
#     --set-country/--set-os/--set-bandwidth CLI subcommands. A client with
#     no policy entry at all is fully unrestricted (only the MAC check
#     above applies to them).
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
#   1. common_name + IV_HWADDR against openvpn_db.txt   (reason: mac_mismatch)
#   2. IV_PLAT against client_policy.json's allowed_os   (reason: os_not_allowed)
#   3. trusted_ip's GeoIP country against client_policy.json's country
#      (reason: country_not_allowed, or country_lookup_failed if the
#      restriction can't be verified -- see policy_lib.geoip_lookup_country
#      docstring for the fail-closed rationale)
#   4. client_usage.json's current-week bytes_used against
#      client_policy.json's bandwidth_weekly_gb (reason: bandwidth_exceeded
#      -- soft cutoff, connect-time only: an already-connected session
#      that goes over quota mid-session is NOT killed, see
#      openvpn-client-disconnect.py)
#
# Every rejection (and the final accept) is logged the same way the
# original script always logged the MAC check: a full os.environ dump
# followed by a result line, to openvpn.log -- vpn-status.py's
# --rejected-connections parses this. New rejection reasons are additionally
# logged as a "reason: <reason>" line, parsed the same way as any other
# "KEY: value" env line; vpn-status.py defaults missing/old-format entries
# (logged before this change) to reason "mac_mismatch" for backward
# compatibility.

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


def reject(log, reason, message):
    """Prints/logs the reason + message, then exits 1. `message` must
    contain either "could not be found" (the original MAC-mismatch
    detector string vpn-status.py's iter_env_blocks already matches on) or
    "connection rejected" (the new, equally-unambiguous marker added for
    every other reason) -- see that function's own comment for why both
    phrases are recognized rather than replacing the original one."""
    print("reason: {0}".format(reason))
    log.write("reason : {0}\n".format(reason))
    print(message)
    log.write("\n" + message + "\n\n")
    sys.exit(1)


with open(log_file, 'a') as LogFile:
    LogFile.write("---------------------------------------\n")
    LogFile.write(datetime.now().isoformat() + "\n")
    LogFile.write("---------------------------------------\n")

    for name, value in os.environ.items():
        print("{0}: {1}".format(name, value))
        LogFile.write(name + " : " + value + "\n")

    # 1) MAC-binding check -- unchanged from the original script's behavior
    # and exact message text (backward-compatible with existing log
    # parsing/monitoring). ------------------------------------------------
    if not db_lookup(env_user, env_mac_addr):
        reject(LogFile, "mac_mismatch",
               "The MAC address of the client machine could not be found in the database")

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
                       env_iv_plat or "unknown", env_user, ", ".join(allowed_os)))

    # 3) Country restriction (GeoIP) -----------------------------------------
    # Fail-safe: only even attempts a GeoIP lookup at all if this specific
    # client has a country restriction configured -- an unrestricted
    # client's connection is never slowed down or blocked by GeoIP
    # infrastructure (missing mmdb, missing geoip2 package, etc.).
    restricted_country = policy.get("country")
    if restricted_country:
        mmdb_path = policy_lib.CFG.get("MAXMIND_DB_PATH")
        country, err = policy_lib.geoip_lookup_country(env_trusted_ip, mmdb_path)
        if err:
            # A configured restriction that can't be verified is rejected,
            # not silently let through -- see policy_lib.geoip_lookup_country.
            reject(LogFile, "country_lookup_failed",
                   "OpenVPN connection rejected: GeoIP country lookup failed ({0}) for {1} while a country restriction is configured for {2}".format(
                       err, env_trusted_ip or "unknown", env_user))
        if country != restricted_country:
            reject(LogFile, "country_not_allowed",
                   "OpenVPN connection rejected: client country '{0}' does not match {1}'s required country '{2}'".format(
                       country or "unknown", env_user, restricted_country))

    # 4) Weekly bandwidth quota (soft cutoff, connect-time only) ------------
    quota_gb = policy.get("bandwidth_weekly_gb")
    if quota_gb:
        # Same fail-open rationale as the policy lookup above: a quota IS
        # configured here (we know that much), but if the usage file can't
        # be read, treat usage as unknown-but-not-yet-over-quota rather
        # than blocking the connection outright.
        try:
            used_bytes = policy_lib.get_usage(env_user)
        except Exception as e:
            used_bytes = 0
            print("usage lookup failed for {0}: {1} -- treating this week's usage as 0".format(env_user, e))
            LogFile.write("usage lookup failed for {0}: {1} -- treating this week's usage as 0\n".format(env_user, e))
        quota_bytes = float(quota_gb) * (1024 ** 3)
        if used_bytes >= quota_bytes:
            reject(LogFile, "bandwidth_exceeded",
                   "OpenVPN connection rejected: {0}'s weekly bandwidth quota exceeded ({1:.2f} / {2} GB used this week)".format(
                       env_user, used_bytes / (1024 ** 3), quota_gb))

    print("The MAC address of the client machine has been successfully matched to the database")
    LogFile.write("\nThe MAC address of the client machine has been successfully matched to the database\n\n")
    sys.exit(0)
