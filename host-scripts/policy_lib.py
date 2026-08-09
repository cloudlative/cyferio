#!/usr/bin/env python3
"""
policy_lib.py -- shared helpers for the OpenVPN client-connect/disconnect
policy-enforcement scripts (openvpn-mac-addr-check.py, openvpn-client-
disconnect.py). Deployed alongside them in /etc/openvpn/server/ on the
host -- NOT shipped inside the app's Docker image. These run as
host-level Python via OpenVPN's script-security, entirely outside Docker,
exactly like openvpn-mac-addr-check.py always has.

Two JSON files this module deals with:
  client_policy.json  -- admin-configured per-client restrictions, written
                          by the web app / client_policy_cli.py (the
                          openvpn-install.sh companion, a SEPARATE script
                          that ships in the git repo -- see its own
                          docstring for why this isn't shared code across
                          the two different install locations). Read-only
                          from here.
  client_usage.json   -- weekly bandwidth usage. Read here (by the
                          connect script, to check quota) AND written here
                          (by the disconnect script, after each session).

Both files use an atomic write-to-tmp-then-os.rename pattern guarded by an
flock-based lock (see _locked()/atomic_write_json()) so the app (writing
client_policy.json from a different process/container) and these scripts
(writing client_usage.json -- possibly two sessions disconnecting at the
same instant) never see a half-written file or clobber each other.
"""
import fcntl
import os
import json
import tempfile
from contextlib import contextmanager
from datetime import date, timedelta

CONFIG_FILE = "/etc/openvpn/vpn-tools.conf"

DEFAULTS = {
    "CLIENT_POLICY_FILE": "/etc/openvpn/server/client_policy.json",
    "CLIENT_USAGE_FILE": "/etc/openvpn/server/client_usage.json",
    "MAXMIND_LICENSE_KEY": "",
    "MAXMIND_DB_PATH": "/etc/openvpn/server/GeoLite2-Country.mmdb",
    "DB_FILE": "/etc/openvpn/server/openvpn_db.txt",
    "CONN_LOG": "/etc/openvpn/server/openvpn.log",
}


def load_config():
    cfg = dict(DEFAULTS)
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                cfg[k.strip()] = v.strip()
    return cfg


CFG = load_config()
CLIENT_POLICY_FILE = CFG["CLIENT_POLICY_FILE"]
CLIENT_USAGE_FILE = CFG["CLIENT_USAGE_FILE"]


@contextmanager
def _locked(path):
    """Holds an exclusive advisory lock on `path + ".lock"` for the
    duration of the with-block. A dedicated lock file (rather than flock
    on the data file itself) so a plain open()/read of the data file --
    e.g. the web app's own read path -- is never blocked by, or interferes
    with, this lock."""
    lock_path = path + ".lock"
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o666)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def read_json(path, default):
    if not os.path.exists(path):
        return default
    try:
        with open(path) as f:
            content = f.read().strip()
            if not content:
                return default
            return json.loads(content)
    except (OSError, json.JSONDecodeError):
        return default


def atomic_write_json(path, data):
    """Write-to-tmp-then-os.rename, preserving the original file's
    owner/mode if it already existed -- same concern as openvpn-install.sh's
    do_remove_mac: a careless overwrite could replace a nobody:nogroup 0664
    file with a root:root 0600 one and break the next connect/disconnect
    script's read/write (they run as `nobody`, OpenVPN's unprivileged
    runtime user). Defaults to nobody:nogroup 0664 for a brand-new file,
    since both the app (root, in its own container) and these host scripts
    (nobody) need read+write access."""
    orig_mode = 0o664
    orig_uid = orig_gid = None
    if os.path.exists(path):
        st = os.stat(path)
        orig_mode = st.st_mode & 0o777
        orig_uid, orig_gid = st.st_uid, st.st_gid
    else:
        try:
            import grp
            import pwd
            orig_uid = pwd.getpwnam("nobody").pw_uid
            orig_gid = grp.getgrnam("nogroup").gr_gid
        except (KeyError, ImportError):
            pass

    d = os.path.dirname(path) or "."
    fd, tmp_path = tempfile.mkstemp(prefix=".tmp-", dir=d)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2, sort_keys=True)
            f.write("\n")
        os.chmod(tmp_path, orig_mode)
        if orig_uid is not None:
            try:
                os.chown(tmp_path, orig_uid, orig_gid)
            except PermissionError:
                pass  # not running as root -- best effort
        os.replace(tmp_path, path)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def get_policy(name):
    """Returns the policy dict for one client ({} if unrestricted)."""
    with _locked(CLIENT_POLICY_FILE):
        all_policies = read_json(CLIENT_POLICY_FILE, {})
    return all_policies.get(name, {}) or {}


def current_week_start(today=None):
    """Monday 00:00 server-local time of the current calendar week."""
    today = today or date.today()
    return today - timedelta(days=today.weekday())


def get_usage(name):
    """Returns bytes_used for `name` THIS week, applying the lazy weekly
    rollover on read (if the stored week_start isn't this week's Monday,
    usage reads as 0 -- the stale row itself is only rewritten by
    add_usage()'s write path, see its own docstring for why a read-only
    quota check shouldn't take the write lock)."""
    with _locked(CLIENT_USAGE_FILE):
        all_usage = read_json(CLIENT_USAGE_FILE, {})
    entry = all_usage.get(name)
    if not entry:
        return 0
    if entry.get("week_start") != current_week_start().isoformat():
        return 0
    return int(entry.get("bytes_used", 0))


def add_usage(name, bytes_delta):
    """Adds `bytes_delta` to `name`'s usage for the current week,
    resetting first if the stored week has rolled over since the last
    write (lazy reset -- see client_usage.json's schema notes). Read-
    modify-write under lock; this is the only place client_usage.json is
    written (by the disconnect script, once per ended session)."""
    week_start = current_week_start().isoformat()
    with _locked(CLIENT_USAGE_FILE):
        all_usage = read_json(CLIENT_USAGE_FILE, {})
        entry = all_usage.get(name) or {}
        if entry.get("week_start") != week_start:
            entry = {"week_start": week_start, "bytes_used": 0}
        entry["bytes_used"] = int(entry.get("bytes_used", 0)) + int(bytes_delta)
        entry["week_start"] = week_start
        all_usage[name] = entry
        atomic_write_json(CLIENT_USAGE_FILE, all_usage)
    return all_usage[name]


# OpenVPN's own IV_PLAT env var -> this project's allowed_os vocabulary.
IV_PLAT_TO_OS = {"win": "windows", "linux": "linux", "mac": "mac"}


def geoip_lookup_country(ip, mmdb_path):
    """Looks up `ip`'s ISO 3166-1 alpha-2 country code in the
    GeoLite2-Country mmdb at `mmdb_path`.

    Returns (country_code_or_None, error_or_None):
      - (code, None)        -- lookup succeeded, country identified
      - (None, None)        -- lookup succeeded, IP not found in the db
                                (private/reserved range, etc.) -- NOT an
                                error, just "no country known"
      - (None, "mmdb_missing")        -- db file absent/unreadable
      - (None, "geoip2_not_installed") -- the geoip2 package isn't
                                installed on this host
      - (None, "lookup_error")        -- any other failure

    Callers implement the fail-safe policy themselves (see
    openvpn-mac-addr-check.py): skip entirely when the client has no
    country restriction configured; fail CLOSED (reject) when it does and
    any of the error cases above occurs.
    """
    if not mmdb_path or not os.path.exists(mmdb_path):
        return None, "mmdb_missing"
    try:
        import geoip2.database
        import geoip2.errors
    except ImportError:
        return None, "geoip2_not_installed"
    try:
        with geoip2.database.Reader(mmdb_path) as reader:
            resp = reader.country(ip)
            return resp.country.iso_code, None
    except geoip2.errors.AddressNotFoundError:
        return None, None
    except Exception:
        return None, "lookup_error"
