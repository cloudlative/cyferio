"""Client + MAC-binding lifecycle -- Python port of openvpn-install.sh's
do_add_client (:252-302), do_revoke_client (:304-333), do_show_ovpn
(:335-356), do_purge_revoked (:358-384), do_clean_stale_db_entry (:386-417),
do_restore_client (:419-440), do_list_clients (:442-479), do_list_macs
(:481-510), do_add_mac (:512-550), do_remove_mac (:552-606), do_list_revoked
(:620-665), do_check_consistency (:667-715), do_lint_db (:717-800).

Unlike the bash script (which has separate text/--json rendering baked into
each do_* function), every function here returns plain Python data
(dataclasses/dicts/lists) -- callers (the CLI entrypoint, and eventually
FastAPI routes in Phase 2) decide how to render it. Every mutating function
raises a typed exception (exceptions.py) instead of printing to stderr and
returning 1.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import tempfile
from dataclasses import dataclass, field

from . import certificate_manager, config_manager, crl_manager
from .exceptions import (
    ClientAlreadyExistsError,
    ClientNotFoundError,
    ClientNotRevokedError,
    MacAlreadyRegisteredError,
    MacNotFoundError,
)
from .paths import OpenVPNPaths
from .validator import require_mac, require_name, sanitize_client_name

_DB_LINE_RE = re.compile(r"^[A-Za-z0-9_.\-]+=([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")
_ASN1_TIME_RE = re.compile(r"^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$")


# --- shared helpers ----------------------------------------------------------


def ensure_trailing_newline(path: str) -> None:
    """Mirrors ensure_trailing_newline() at :175-182."""
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return
    with open(path, "rb") as f:
        f.seek(-1, os.SEEK_END)
        last_byte = f.read(1)
    if last_byte != b"\n":
        with open(path, "a", encoding="utf-8") as f:
            f.write("\n")


def _read_db_lines(paths: OpenVPNPaths) -> list[str]:
    if not os.path.exists(paths.db_file):
        return []
    with open(paths.db_file, encoding="utf-8") as f:
        return [line.rstrip("\n") for line in f if line.strip()]


def find_mac_owner(paths: OpenVPNPaths, mac: str, exclude: str | None = None) -> str | None:
    """Mirrors find_mac_owner() at :222-250."""
    for line in _read_db_lines(paths):
        owner, _, line_mac = line.partition("=")
        if exclude and owner == exclude:
            continue
        if line_mac.lower() == mac.lower():
            return owner
    return None


def _append_db_entry(paths: OpenVPNPaths, name: str, mac: str) -> None:
    os.makedirs(os.path.dirname(paths.db_file) or ".", exist_ok=True)
    if not os.path.exists(paths.db_file):
        open(paths.db_file, "a", encoding="utf-8").close()
    ensure_trailing_newline(paths.db_file)
    with open(paths.db_file, "a", encoding="utf-8") as f:
        f.write(f"{name}={mac}\n")


def _remove_db_entries_for(paths: OpenVPNPaths, name: str) -> None:
    """Mirrors `sed -i "/^${client}=/d" "$DB_FILE"` used by revoke/purge/
    clean-stale-db (:324, :379, :413)."""
    if not os.path.exists(paths.db_file):
        return
    lines = _read_db_lines(paths)
    kept = [line for line in lines if not line.startswith(f"{name}=")]
    with open(paths.db_file, "w", encoding="utf-8") as f:
        for line in kept:
            f.write(line + "\n")
    ensure_trailing_newline(paths.db_file)


def _index_txt_rows(paths: OpenVPNPaths) -> list[list[str]]:
    """Reads easyrsa's pki/index.txt, skipping its header-less first
    (implicit) line the way `tail -n +2` does -- easyrsa's index.txt in
    practice has no header row, but the bash script always skips line 1
    regardless; matched here for exact parity even though it means the
    very first row is silently dropped, same as bash."""
    if not os.path.exists(paths.index_txt):
        return []
    with open(paths.index_txt, encoding="utf-8") as f:
        lines = f.read().splitlines()
    return [line.split("\t") for line in lines[1:] if line.strip()]


def _cn_from_index_field(field_value: str) -> str:
    return field_value[len("/CN=") :] if field_value.startswith("/CN=") else field_value


def format_asn1_time(raw: str) -> str:
    """Mirrors format_asn1_time() at :608-618."""
    m = _ASN1_TIME_RE.match(raw)
    if not m:
        return raw
    yy, mo, dd, hh, mi, ss = m.groups()
    return f"20{yy}-{mo}-{dd} {hh}:{mi}:{ss} UTC"


# --- do_add_client / do_revoke_client / do_show_ovpn ------------------------


@dataclass(frozen=True)
class AddClientResult:
    client: str
    mac: str
    ovpn_path: str


def add_client(paths: OpenVPNPaths, raw_name: str, raw_mac: str) -> AddClientResult:
    """Mirrors do_add_client() at :252-302."""
    client = sanitize_client_name(raw_name)
    if os.path.exists(paths.issued_crt(client)):
        raise ClientAlreadyExistsError(
            f"{client}: a client with this name already exists.",
            client=client,
        )
    mac = require_mac(raw_mac)
    existing_owner = find_mac_owner(paths, mac)
    if existing_owner:
        raise MacAlreadyRegisteredError(
            f"MAC address {mac} is already assigned to client '{existing_owner}'.",
            mac=mac,
            existing_owner=existing_owner,
        )

    certificate_manager.build_client_cert(paths, client)
    db_entry_written = False
    try:
        # .ovpn is assembled and written to its FINAL location before the
        # DB_FILE entry is appended (bash's own order is the reverse --
        # DB_FILE append, then generate+move the .ovpn -- which leaves a
        # window where a failed final `mv` still leaves a DB_FILE entry
        # behind with no delivered .ovpn). Doing the write-that's-more-
        # likely-to-fail (a real filesystem path, possibly unwritable) first
        # means DB_FILE is only touched once success is otherwise certain --
        # the genuine improvement over bash called out in the Phase 1 plan's
        # §4 idempotency/rollback contract.
        ovpn_content = config_manager.generate_ovpn(paths, client)
        os.makedirs(paths.ovpn_output_dir, exist_ok=True)
        ovpn_path = paths.ovpn_output(client)
        with open(ovpn_path, "w", encoding="utf-8") as f:
            f.write(ovpn_content)
        os.chmod(ovpn_path, int(paths.ovpn_output_mode, 8))
        _chown_output(ovpn_path, paths.ovpn_output_owner)

        _append_db_entry(paths, client, mac)
        db_entry_written = True
    except Exception:
        # Unwind whatever partially succeeded: the issued cert/key/req
        # files, the .ovpn if it made it to disk, and -- belt and suspenders
        # in case a future edit reorders the steps above -- any DB_FILE
        # entry that got written before the failure.
        _cleanup_client_pki_files(paths, client)
        ovpn_path = paths.ovpn_output(client)
        if os.path.exists(ovpn_path):
            os.remove(ovpn_path)
        if db_entry_written:
            _remove_db_entries_for(paths, client)
        raise

    return AddClientResult(client=client, mac=mac, ovpn_path=ovpn_path)


def _chown_output(path: str, owner: str) -> None:
    if ":" not in owner:
        return
    user, _, group = owner.partition(":")
    import grp
    import pwd

    try:
        uid = pwd.getpwnam(user).pw_uid
        gid = grp.getgrnam(group).gr_gid
        os.chown(path, uid, gid)
    except (KeyError, PermissionError, OSError):
        pass


def _cleanup_client_pki_files(paths: OpenVPNPaths, name: str) -> None:
    for path in (paths.issued_crt(name), paths.private_key(name), paths.req_file(name)):
        if os.path.exists(path):
            try:
                os.remove(path)
            except OSError:
                pass


def revoke_client(paths: OpenVPNPaths, raw_name: str) -> None:
    """Mirrors do_revoke_client() at :304-333."""
    name = require_name(raw_name)
    if not os.path.exists(paths.issued_crt(name)):
        raise ClientNotFoundError(f"{name}: no such client.", client=name)
    certificate_manager.revoke_client_cert(paths, name)
    crl_manager.install_crl(paths)
    _remove_db_entries_for(paths, name)


def show_ovpn(paths: OpenVPNPaths, raw_name: str) -> str:
    """Mirrors do_show_ovpn() at :335-356."""
    name = require_name(raw_name)
    if not os.path.exists(paths.issued_crt(name)):
        raise ClientNotFoundError(f"{name}: no such client (no valid certificate).", client=name)
    ovpn_path = paths.ovpn_output(name)
    if not os.path.isfile(ovpn_path):
        raise ClientNotFoundError(
            f"{name}: no .ovpn file found at {ovpn_path} (it may have been moved or deleted after issuance).",
            client=name,
        )
    with open(ovpn_path, encoding="utf-8") as f:
        return f.read()


# --- do_purge_revoked / do_clean_stale_db_entry / do_restore_client --------


def _is_revoked(paths: OpenVPNPaths, name: str) -> bool:
    target = f"/CN={name}"
    for row in _index_txt_rows(paths):
        if len(row) >= 6 and row[0] == "R" and row[5] == target:
            return True
    return False


def purge_revoked(paths: OpenVPNPaths, raw_name: str) -> None:
    """Mirrors do_purge_revoked() at :358-384. Deliberately does not remove
    the index.txt row -- see that function's own docstring in the bash
    script for why (CRL/audit-trail integrity)."""
    name = require_name(raw_name)
    if not _is_revoked(paths, name):
        raise ClientNotRevokedError(
            f"{name}: not a revoked client -- nothing to purge (use revoke_client first).",
            client=name,
        )
    for path in (paths.issued_crt(name), paths.private_key(name), paths.req_file(name), paths.ovpn_output(name)):
        if os.path.exists(path):
            os.remove(path)
    _remove_db_entries_for(paths, name)


def clean_stale_db_entry(paths: OpenVPNPaths, raw_name: str) -> None:
    """Mirrors do_clean_stale_db_entry() at :386-417."""
    name = require_name(raw_name)
    if not os.path.exists(paths.db_file):
        raise ClientNotFoundError(f"{paths.db_file} does not exist -- nothing to clean.", client=name)
    if os.path.exists(paths.issued_crt(name)):
        raise ClientAlreadyExistsError(
            f"{name} has a currently-valid certificate -- refusing to remove its {paths.db_file} entry (use remove_mac for a specific MAC instead).",
            client=name,
        )
    if not any(line.startswith(f"{name}=") for line in _read_db_lines(paths)):
        raise ClientNotFoundError(f"{name} has no {paths.db_file} entry -- nothing to clean.", client=name)
    _remove_db_entries_for(paths, name)


def restore_client(paths: OpenVPNPaths, raw_name: str, raw_mac: str) -> AddClientResult:
    """Mirrors do_restore_client() at :419-440 -- NOT an un-revoke (not
    possible once a cert is on the CRL); purges the old leftover files and
    issues a brand-new cert under the same name."""
    name = require_name(raw_name)
    if not _is_revoked(paths, name):
        raise ClientNotRevokedError(f"{name}: not a revoked client -- nothing to restore.", client=name)
    for path in (paths.issued_crt(name), paths.private_key(name), paths.req_file(name), paths.ovpn_output(name)):
        if os.path.exists(path):
            os.remove(path)
    return add_client(paths, name, raw_mac)


# --- do_list_clients / do_list_macs / do_add_mac / do_remove_mac -----------


@dataclass(frozen=True)
class ClientSummary:
    name: str
    in_db: bool
    mac_count: int


def list_clients(paths: OpenVPNPaths) -> list[ClientSummary]:
    """Mirrors do_list_clients() at :442-479."""
    db_lines = _read_db_lines(paths)
    names = [_cn_from_index_field(row[5]) for row in _index_txt_rows(paths) if row and row[0] == "V" and len(row) >= 6]
    result = []
    for name in names:
        mac_count = sum(1 for line in db_lines if line.startswith(f"{name}="))
        result.append(ClientSummary(name=name, in_db=mac_count > 0, mac_count=mac_count))
    return result


@dataclass(frozen=True)
class MacList:
    name: str
    count: int
    macs: list[str]


def list_macs(paths: OpenVPNPaths, raw_name: str) -> MacList:
    """Mirrors do_list_macs() at :481-510."""
    name = require_name(raw_name)
    macs = [line.split("=", 1)[1] for line in _read_db_lines(paths) if line.startswith(f"{name}=")]
    return MacList(name=name, count=len(macs), macs=macs)


def add_mac(paths: OpenVPNPaths, raw_name: str, raw_mac: str) -> str:
    """Mirrors do_add_mac() at :512-550. Returns the normalized MAC."""
    name = require_name(raw_name)
    if not os.path.exists(paths.issued_crt(name)):
        raise ClientNotFoundError(
            f"{name}: no such client (no valid certificate). Use add_client to create a new client.",
            client=name,
        )
    mac = require_mac(raw_mac)
    if any(line.lower() == f"{name}={mac}".lower() for line in _read_db_lines(paths)):
        raise MacAlreadyRegisteredError(f"{name} is already registered with MAC {mac}.", client=name, mac=mac)
    existing_owner = find_mac_owner(paths, mac, exclude=name)
    if existing_owner:
        raise MacAlreadyRegisteredError(
            f"MAC address {mac} is already assigned to client '{existing_owner}'.",
            mac=mac,
            existing_owner=existing_owner,
        )
    _append_db_entry(paths, name, mac)
    return mac


def remove_mac(paths: OpenVPNPaths, raw_name: str, raw_mac: str) -> str:
    """Mirrors do_remove_mac() at :552-606 -- including its careful
    mode/owner preservation (the DB file is normally owned by an
    unprivileged user so openvpn-mac-addr-check.py, running as `nobody`,
    can still read it on every connection attempt)."""
    name = require_name(raw_name)
    mac = require_mac(raw_mac)
    target = f"{name}={mac}".lower()
    lines = _read_db_lines(paths)
    if not any(line.lower() == target for line in lines):
        raise MacNotFoundError(f"{name} has no registration for MAC {mac}.", client=name, mac=mac)

    orig_stat = os.stat(paths.db_file)
    fd, tmp_path = tempfile.mkstemp(dir=os.path.dirname(paths.db_file) or ".", prefix=os.path.basename(paths.db_file) + ".")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            for line in lines:
                if line.lower() != target:
                    f.write(line + "\n")
        os.chmod(tmp_path, stat.S_IMODE(orig_stat.st_mode))
        try:
            os.chown(tmp_path, orig_stat.st_uid, orig_stat.st_gid)
        except (PermissionError, OSError):
            pass
        shutil.move(tmp_path, paths.db_file)
    except Exception:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise
    return mac


# --- do_list_revoked / do_check_consistency / do_lint_db -------------------


@dataclass(frozen=True)
class RevokedClient:
    name: str
    revoked_at: str
    stale_db_entry: bool
    files_present: bool


def list_revoked(paths: OpenVPNPaths) -> list[RevokedClient]:
    """Mirrors do_list_revoked() at :620-665."""
    db_names = {line.split("=", 1)[0] for line in _read_db_lines(paths)}
    result = []
    for row in _index_txt_rows(paths):
        if not row or row[0] != "R" or len(row) < 6:
            continue
        name = _cn_from_index_field(row[5])
        revoked_at = format_asn1_time(row[2]) if len(row) > 2 else ""
        result.append(
            RevokedClient(
                name=name,
                revoked_at=revoked_at,
                stale_db_entry=name in db_names,
                files_present=os.path.exists(paths.issued_crt(name)),
            )
        )
    return result


@dataclass(frozen=True)
class ConsistencyReport:
    clean: bool
    orphan_pki: list[str]
    orphan_db: list[str]


def check_consistency(paths: OpenVPNPaths) -> ConsistencyReport:
    """Mirrors do_check_consistency() at :667-715."""
    pki_names = {_cn_from_index_field(row[5]) for row in _index_txt_rows(paths) if row and row[0] == "V" and len(row) >= 6}
    db_names = {line.split("=", 1)[0] for line in _read_db_lines(paths)}
    orphan_pki = sorted(pki_names - db_names)
    orphan_db = sorted(db_names - pki_names)
    return ConsistencyReport(clean=not orphan_pki and not orphan_db, orphan_pki=orphan_pki, orphan_db=orphan_db)


@dataclass(frozen=True)
class LintReport:
    clean: bool
    entries: int
    trailing_newline_ok: bool
    issues: list[str] = field(default_factory=list)


def lint_db(paths: OpenVPNPaths) -> LintReport:
    """Mirrors do_lint_db() at :717-800."""
    if not os.path.exists(paths.db_file):
        raise ClientNotFoundError(f"{paths.db_file} does not exist.")

    with open(paths.db_file, encoding="utf-8") as f:
        raw_lines = f.read().split("\n")
    # Mirrors bash's `while read -r line || [[ -n "$line" ]]` semantics: a
    # trailing empty element from split("\n") on a file that DOES end with
    # "\n" is not a real extra line; one that does NOT end with "\n" (so the
    # last real line has content but str.split still doesn't add a phantom
    # trailing "") is already handled correctly by split.
    if raw_lines and raw_lines[-1] == "":
        raw_lines = raw_lines[:-1]

    # `problems` is the full report text (bash's `problems` array); `has_issues`
    # is the separate exit-status/clean flag (bash's `issues` int) -- a blank
    # line is reported in `problems` but deliberately does NOT flip
    # `has_issues`, matching do_lint_db()'s own distinction (:741-744 adds to
    # `problems` only, no `issues=1`, unlike the malformed/duplicate-MAC/
    # trailing-newline cases which set both).
    problems: list[str] = []
    has_issues = False
    mac_owners: dict[str, list[str]] = {}
    for lineno, line in enumerate(raw_lines, start=1):
        if not line:
            problems.append(f"Line {lineno}: blank line (harmless but unexpected).")
            continue
        if not _DB_LINE_RE.match(line):
            problems.append(f"Line {lineno}: malformed entry: '{line}'")
            has_issues = True
            continue
        name, _, mac = line.partition("=")
        mac = mac.lower()
        owners = mac_owners.setdefault(mac, [])
        if name not in owners:
            owners.append(name)

    for mac, owners in mac_owners.items():
        if len(owners) > 1:
            problems.append(f"MAC {mac} is assigned to multiple clients: {', '.join(owners)}")
            has_issues = True

    trailing_ok = True
    if os.path.getsize(paths.db_file) > 0:
        with open(paths.db_file, "rb") as f:
            f.seek(-1, os.SEEK_END)
            if f.read(1) != b"\n":
                trailing_ok = False
                has_issues = True
                problems.append(f"{paths.db_file} does not end with a trailing newline -- the next appended entry could get glued onto the last line.")

    return LintReport(
        clean=not has_issues,
        entries=len(raw_lines),
        trailing_newline_ok=trailing_ok,
        issues=problems,
    )
