"""
Read/write access to the two per-client-restriction JSON files
(client_policy.json, client_usage.json) that live under the bind-mounted
/etc/openvpn directory (see docker-compose.yml) -- the same files the
OpenVPN host's client-connect/client-disconnect scripts (host-scripts/ in
this repo, NOT part of this Docker image) enforce against.

This app reads/writes these files directly in Python rather than shelling
out (unlike everything in cli_wrapper.py) because it already has rw
filesystem access to them via the bind mount, and because a plain
read-modify-write is simple enough not to need a subprocess boundary --
the equivalent CLI path for openvpn-install.sh (which does NOT have that
mount) is client_policy_cli.py at the repo root instead.

Concurrency: this module, host-scripts/policy_lib.py (imported by the
connect/disconnect scripts), and client_policy_cli.py (openvpn-install.sh's
companion) can all touch these files independently. All three use the same
atomic write-to-tmp-then-os.rename pattern guarded by an flock-based lock
on a dedicated `<path>.lock` file, kept in sync by hand across the three
(deliberately not shared code -- see policy_lib.py's and
client_policy_cli.py's own docstrings for why they're not a shared import
across the app's container / the OpenVPN host / wherever openvpn-install.sh
is installed).
"""
import fcntl
import json
import os
import tempfile
from contextlib import contextmanager
from datetime import date

from .config import settings
from .geo_validators import valid_asn_list, valid_city_list, valid_country_list, valid_ip_list

VALID_OS = {"windows", "linux", "mac"}
VALID_QUOTA_ENFORCEMENT_POLICIES = {"soft", "hard"}


def _ensure_dir_writable_by_nobody(d: str) -> None:
    """If `d` doesn't exist yet, create it AND chown/chmod it so the
    OpenVPN host's client-connect/disconnect scripts (running as
    `nobody`, see host-scripts/policy_lib.py) can also create files
    inside it -- a plain os.makedirs would leave a fresh directory
    root:root, which wouldn't help. This app runs as root in its
    container, so this reliably succeeds here."""
    if os.path.isdir(d):
        return
    os.makedirs(d, exist_ok=True)
    try:
        import grp
        import pwd
        os.chown(d, pwd.getpwnam("nobody").pw_uid, grp.getgrnam("nogroup").gr_gid)
        os.chmod(d, 0o770)
    except (OSError, KeyError):
        pass


@contextmanager
def _locked(path: str):
    lock_path = path + ".lock"
    _ensure_dir_writable_by_nobody(os.path.dirname(lock_path) or ".")
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o666)
    # os.open's mode is masked by this process's umask -- since this app
    # runs as root, a lock file it creates (or re-opens) could otherwise
    # end up unwritable by the OpenVPN host's `nobody`-run connect/
    # disconnect scripts. Force 0666 + nobody:nogroup ownership every time,
    # self-healing any bad state left by a previous process.
    try:
        os.fchmod(fd, 0o666)
        import grp
        import pwd
        os.fchown(fd, pwd.getpwnam("nobody").pw_uid, grp.getgrnam("nogroup").gr_gid)
    except (OSError, KeyError):
        pass
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _read_json(path: str) -> dict:
    if not os.path.exists(path):
        return {}
    try:
        with open(path) as f:
            content = f.read().strip()
            return json.loads(content) if content else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _atomic_write_json(path: str, data: dict) -> None:
    """Write-to-tmp-then-os.rename, preserving the original file's
    owner/mode if it already existed -- defaults to nobody:nogroup 0664
    for a brand-new file, since the host's client-connect/disconnect
    scripts run as `nobody` (OpenVPN's unprivileged runtime user) and need
    read (and, for client_usage.json, write) access too. This app itself
    runs as root in its container (see USE_SUDO=false in a typical Docker
    deployment), so chown never fails here the way it might for an
    unprivileged caller."""
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
    _ensure_dir_writable_by_nobody(d)
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
                pass
        os.replace(tmp_path, path)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _normalize_policy_shape(entry: dict) -> dict:
    """Backward-compat read-side migration: entries written before the
    Location & Network Restrictions sync (single `country` string, no
    city/ASN/IP fields at all) are lifted onto the new list-based shape
    on every read, without rewriting the file -- the next set_policy()
    call for that client persists the new shape for real. Doing this at
    read time (once, here) rather than as a one-off migration script means
    every consumer (this module's own callers, the Clients-page API,
    host-scripts/policy_lib.py's own mirrored version of this same logic)
    sees the new shape uniformly, and a client nobody has touched since
    before this change keeps its restriction enforced in the meantime
    instead of silently reading as unrestricted."""
    if not entry:
        return entry
    if "allowed_countries" not in entry and entry.get("country"):
        entry = dict(entry)
        entry["allowed_countries"] = [entry.pop("country")]
    return entry


def get_policy(name: str) -> dict:
    """Returns the policy dict for one client ({} if unrestricted).

    Read paths (this, get_all_policies, get_usage, get_all_usage below) all
    fail OPEN on an OSError acquiring the lock/reading the file (e.g. the
    bind-mounted /etc/openvpn directory not existing/writable in this
    environment) -- same fail-open rationale as
    openvpn-mac-addr-check.py's own policy lookup: these are now called
    from routes/users.py's list_users/create_user/update_user too (not just
    the Clients page), so a filesystem hiccup here must never be able to
    break loading the Users page or saving an otherwise-valid user edit,
    only degrade "show/apply this restriction" down to "treat as
    unrestricted for this read", surfaced by returning empty results rather
    than raising."""
    try:
        with _locked(settings.CLIENT_POLICY_FILE):
            all_policies = _read_json(settings.CLIENT_POLICY_FILE)
    except OSError:
        return {}
    return _normalize_policy_shape(all_policies.get(name, {}) or {})


def get_all_policies() -> dict:
    try:
        with _locked(settings.CLIENT_POLICY_FILE):
            all_policies = _read_json(settings.CLIENT_POLICY_FILE)
    except OSError:
        return {}
    return {name: _normalize_policy_shape(entry) for name, entry in all_policies.items()}


class PolicyValidationError(ValueError):
    pass


def set_policy(name: str, *,
               allowed_os: list[str] | None | object = ...,
               bandwidth_monthly_gb: float | None | object = ...,
               allowed_countries: list[str] | None | object = ...,
               allowed_cities: list[str] | None | object = ...,
               allowed_asns: list[str] | None | object = ...,
               allowed_ips: list[str] | None | object = ...,
               quota_enforcement_policy: str | None | object = ...) -> dict:
    """Partial update of one client's policy -- any parameter left at its
    `...` sentinel default is untouched; pass an explicit `None` (or `[]`
    for the list fields) to clear that field. A resulting policy with no
    meaningful fields left removes the client's entry entirely rather than
    leaving a stale `{}` row. Returns the resulting (post-update) policy
    dict for this client (already in the new, `_normalize_policy_shape`d
    form -- a plain `country` key is never written by this function
    anymore, only ever read for backward compat, see that function).

    Validates every input (country/city/ASN/IP list shape, OS names,
    positive bandwidth) via geo_validators.py -- the exact same rules
    User.allowed_login_* uses (routes/users.py), so a restriction that's
    valid on one side is guaranteed valid on the other. This is the only
    write path into client_policy.json from the web UI, so it's the
    natural enforcement point, matching cli_wrapper's general pattern of
    "the underlying tool validates its own inputs" even though here "the
    underlying tool" is this module itself rather than a script.

    allowed_countries/allowed_cities/allowed_asns/allowed_ips are this
    client's VPN Access Restrictions -- independent from a linked User's
    own Portal Login Restrictions (User.restrict_login_by_*/
    allowed_login_*, enforced only by routes/auth.py's login check). The
    two used to be silently kept in sync by routes/users.py's
    create_user/update_user (a coupling bug: an admin restricting a
    user's VPN could only do so by ALSO restricting that same user's
    portal sign-in, and vice versa); see
    app_settings.migrate_decouple_portal_and_vpn_restrictions's docstring
    for the one-time backfill that separated them for good. This function
    -- reached only via routes/clients.py's PUT /{name}/policy -- is now
    the sole write path for these four fields.

    quota_enforcement_policy: "soft" (the pre-existing, only-ever behavior --
    an already-connected session that crosses its bandwidth_monthly_gb
    quota is left alone until it naturally disconnects; only the NEXT
    connection attempt is refused, see openvpn-mac-addr-check.py's gate 7)
    or "hard" (host-scripts/quota_enforcer.py's poller actively kills an
    in-progress session the moment it crosses quota, via the OpenVPN
    management interface -- see management_client.py). None/absent means
    "use app_settings.runtime.default_quota_enforcement_policy" -- this
    field is meaningless for a client with no bandwidth_monthly_gb set at
    all (nothing to enforce), but is not rejected in that case; it simply
    has no effect until a quota is also set.
    """
    if allowed_os is not ...:
        if allowed_os is not None:
            allowed_os = sorted({o.strip().lower() for o in allowed_os if o.strip()})
            bad = [o for o in allowed_os if o not in VALID_OS]
            if bad:
                raise PolicyValidationError(
                    f"Invalid OS name(s): {', '.join(bad)} -- expected any of: {', '.join(sorted(VALID_OS))}."
                )
            if not allowed_os:
                allowed_os = None
    if bandwidth_monthly_gb is not ...:
        if bandwidth_monthly_gb is not None:
            try:
                bandwidth_monthly_gb = float(bandwidth_monthly_gb)
            except (TypeError, ValueError):
                raise PolicyValidationError("Bandwidth quota must be a number.")
            if bandwidth_monthly_gb < 0.1:
                raise PolicyValidationError(
                    "Bandwidth quota must be at least 0.1 GB (100 MB) -- leave blank to clear it."
                )
    if allowed_countries is not ... and allowed_countries is not None:
        try:
            allowed_countries = valid_country_list(allowed_countries) or None
        except ValueError as e:
            raise PolicyValidationError(str(e))
    if allowed_cities is not ... and allowed_cities is not None:
        try:
            allowed_cities = valid_city_list(allowed_cities) or None
        except ValueError as e:
            raise PolicyValidationError(str(e))
    if allowed_asns is not ... and allowed_asns is not None:
        try:
            allowed_asns = valid_asn_list(allowed_asns) or None
        except ValueError as e:
            raise PolicyValidationError(str(e))
    if allowed_ips is not ... and allowed_ips is not None:
        try:
            allowed_ips = valid_ip_list(allowed_ips) or None
        except ValueError as e:
            raise PolicyValidationError(str(e))
    if quota_enforcement_policy is not ... and quota_enforcement_policy is not None:
        quota_enforcement_policy = quota_enforcement_policy.strip().lower()
        if quota_enforcement_policy not in VALID_QUOTA_ENFORCEMENT_POLICIES:
            raise PolicyValidationError(
                f"Invalid quota enforcement policy: '{quota_enforcement_policy}' -- "
                f"expected one of: {', '.join(sorted(VALID_QUOTA_ENFORCEMENT_POLICIES))}."
            )

    with _locked(settings.CLIENT_POLICY_FILE):
        all_policies = _read_json(settings.CLIENT_POLICY_FILE)
        entry = _normalize_policy_shape(dict(all_policies.get(name) or {}))

        if allowed_os is not ...:
            if allowed_os is None:
                entry.pop("allowed_os", None)
            else:
                entry["allowed_os"] = allowed_os
        if bandwidth_monthly_gb is not ...:
            if bandwidth_monthly_gb is None:
                entry.pop("bandwidth_monthly_gb", None)
            else:
                entry["bandwidth_monthly_gb"] = bandwidth_monthly_gb
        if allowed_countries is not ...:
            if allowed_countries is None:
                entry.pop("allowed_countries", None)
            else:
                entry["allowed_countries"] = allowed_countries
        if allowed_cities is not ...:
            if allowed_cities is None:
                entry.pop("allowed_cities", None)
            else:
                entry["allowed_cities"] = allowed_cities
        if allowed_asns is not ...:
            if allowed_asns is None:
                entry.pop("allowed_asns", None)
            else:
                entry["allowed_asns"] = allowed_asns
        if allowed_ips is not ...:
            if allowed_ips is None:
                entry.pop("allowed_ips", None)
            else:
                entry["allowed_ips"] = allowed_ips
        if quota_enforcement_policy is not ...:
            if quota_enforcement_policy is None:
                entry.pop("quota_enforcement_policy", None)
            else:
                entry["quota_enforcement_policy"] = quota_enforcement_policy
        # Legacy singular key never persists past a write, even if this
        # particular call didn't touch country-restriction fields at all --
        # _normalize_policy_shape above already lifted it onto
        # allowed_countries in `entry` before any of the branches ran.
        entry.pop("country", None)

        if entry:
            all_policies[name] = entry
        else:
            all_policies.pop(name, None)
        _atomic_write_json(settings.CLIENT_POLICY_FILE, all_policies)
    return entry


def remove_policy(name: str) -> None:
    """Fully clears every restriction for `name` (equivalent to setting
    country/allowed_os/bandwidth_monthly_gb all to None at once)."""
    with _locked(settings.CLIENT_POLICY_FILE):
        all_policies = _read_json(settings.CLIENT_POLICY_FILE)
        if name in all_policies:
            del all_policies[name]
            _atomic_write_json(settings.CLIENT_POLICY_FILE, all_policies)


def write_global_defaults(*, quota_enforcement_policy: str) -> None:
    """Writes GLOBAL_DEFAULTS_FILE -- see config.py's docstring on that
    setting for why this small cache exists at all (host-scripts/
    quota_enforcer.py has no DB access). Called from
    app_settings.py's refresh_runtime_cache() on every settings save/
    startup, so it's always kept in sync with whatever's actually
    effective, not just what's explicitly configured.

    Fails silently (logs nothing, raises nothing) on OSError -- same
    fail-open stance as every read in this module: a bind-mount hiccup
    here must never be able to break a settings save. The consequence is
    narrow (quota_enforcer.py falls back to its own built-in "soft"
    default until the next successful write), not a security or
    correctness issue for anything else."""
    try:
        _atomic_write_json(settings.GLOBAL_DEFAULTS_FILE, {"quota_enforcement_policy": quota_enforcement_policy})
    except OSError:
        pass


def _current_month_start() -> str:
    """Renamed from _current_week_start (Monday-anchored) -- the reset
    cadence is now the 1st of the calendar month, not a calendar week. The
    on-disk key also changed (week_start -> period_start, see get_usage
    below): an old row with a stale week_start key simply won't match on
    read and reads back as 0, the same "unrecognized period -> reset"
    behavior the old weekly logic already had for a stale week_start --
    a one-time, expected usage-counter reset on the deploy that ships this,
    not a bug."""
    today = date.today()
    return today.replace(day=1).isoformat()


def get_usage(name: str) -> dict:
    """Returns {"period_start": ..., "bytes_used": ...} for `name`'s CURRENT
    month -- applying the same lazy rollover the connect/disconnect scripts
    use (see host-scripts/policy_lib.py's get_usage docstring): a stored
    row from a previous month reads as zero rather than being rewritten
    here (this is a read path; only the disconnect script's write path
    actually persists a rollover). This is a best-effort, read-only view
    for the UI ("X / Y GB this month") -- it reflects usage as of the last
    disconnect, not a live mid-session total (see the soft-cutoff design
    in README.md)."""
    try:
        with _locked(settings.CLIENT_USAGE_FILE):
            all_usage = _read_json(settings.CLIENT_USAGE_FILE)
    except OSError:
        all_usage = {}
    entry = all_usage.get(name) or {}
    period_start = _current_month_start()
    if entry.get("period_start") != period_start:
        return {"period_start": period_start, "bytes_used": 0}
    return {"period_start": period_start, "bytes_used": int(entry.get("bytes_used", 0))}


def get_all_usage() -> dict:
    """name -> current-month usage dict, for every name with a usage row on
    disk (regardless of whether that row is still current-month -- callers
    that need the rollover applied should use get_usage() per-name, or
    apply the same period_start check themselves; this bulk accessor exists
    for the Clients page's table, which wants one fetch instead of N)."""
    try:
        with _locked(settings.CLIENT_USAGE_FILE):
            all_usage = _read_json(settings.CLIENT_USAGE_FILE)
    except OSError:
        all_usage = {}
    period_start = _current_month_start()
    result = {}
    for name, entry in all_usage.items():
        if entry.get("period_start") == period_start:
            result[name] = {"period_start": period_start, "bytes_used": int(entry.get("bytes_used", 0))}
        else:
            result[name] = {"period_start": period_start, "bytes_used": 0}
    return result


def reset_usage(name: str) -> None:
    """Admin override -- zeroes `name`'s CURRENT-month bytes_used
    immediately (e.g. to lift a soft-cutoff block early, or after
    correcting a billing dispute), unlike the automatic rollover
    get_usage()/get_all_usage() apply on read: those only ever show 0 for
    a genuinely NEW period, they never rewrite an old period's stored
    value. This is the first write path this module has ever needed --
    every write to client_usage.json was previously host-side only (see
    host-scripts/policy_lib.py's add_usage(), called from
    openvpn-client-disconnect.py). Same locked-read-modify-atomic-write
    shape as every other writer of this file, so a concurrent disconnect-
    script write can't interleave with this and corrupt the file --
    different processes, same lock file.

    Deliberately does NOT touch `period_start` -- this zeroes usage
    for the period that's already current, it isn't a rollover to a new
    one. If `name` has no usage row yet at all, this is a no-op (there's
    nothing to reset)."""
    with _locked(settings.CLIENT_USAGE_FILE):
        all_usage = _read_json(settings.CLIENT_USAGE_FILE)
        if name not in all_usage:
            return
        all_usage[name]["bytes_used"] = 0
        _atomic_write_json(settings.CLIENT_USAGE_FILE, all_usage)
