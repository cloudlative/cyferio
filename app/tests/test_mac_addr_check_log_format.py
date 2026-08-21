"""Regression guard for the OS-detection bug fixed in
host-scripts/openvpn-mac-addr-check.py: the per-connection env dump written
to CONN_LOG must use the exact same "KEY: value" shape (colon, single
space, nothing before the colon) that vpn-status.py's ENV_LINE_RE actually
parses -- see that regex and iter_env_blocks()'s docstring in vpn-status.py,
and this script's own comment at the LogFile.write() call site.

Previously this file wrote "KEY : value" (a stray space before the colon),
silently unparseable by vpn-status.py's regex -- every live connection's
IV_HWADDR/IV_PLAT/UV_PLAT_REL env vars were invisible to it even though
the same values were logged correctly to stdout (-> journal) via print()
on the very same loop iteration. This test doesn't run the script itself
(it's a client-connect hook with real os.environ/sys.exit side effects,
not import-safe) -- it inspects the source text directly, which is
sufficient to catch a regression back to the old format."""
import os
import re

_HOST_SCRIPTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "host-scripts")
_SCRIPT_PATH = os.path.join(_HOST_SCRIPTS_DIR, "openvpn-mac-addr-check.py")

# Matches vpn-status.py's own ENV_LINE_RE shape: "KEY: value", no space
# before the colon.
_LOGFILE_WRITE_RE = re.compile(r'LogFile\.write\(name \+ "(.*?)" \+ value')


def test_env_dump_write_matches_vpn_status_parser_format():
    with open(_SCRIPT_PATH) as f:
        source = f.read()
    m = _LOGFILE_WRITE_RE.search(source)
    assert m, "couldn't find the env-dump LogFile.write() call to check"
    separator = m.group(1)
    assert separator == ": ", (
        f"LogFile.write() env-dump separator is {separator!r}, expected ': ' "
        "(matching vpn-status.py's ENV_LINE_RE) -- a stray space before the "
        "colon makes every env var in this log file unparseable, which is "
        "exactly the bug that made the OS column always show 'n/a'."
    )


def test_registered_mac_at_time_line_matches_vpn_status_parser_format():
    """Regression guard for the "now matches -- likely fixed" fix: reject()'s
    new registered_mac_at_time line (see models.ConnectionRejectionLog's
    docstring and vpn-status.py's cmd_rejected()) must use the exact same
    "KEY: value" shape (no space before the colon) as every other env/
    reason line, in BOTH its print() and LogFile.write() forms -- otherwise
    it silently never lands as a parseable field and cmd_rejected() falls
    back to the live (misleading) lookup for every row, defeating the
    whole point of freezing this value at rejection time."""
    with open(_SCRIPT_PATH) as f:
        source = f.read()
    assert 'print("registered_mac_at_time: {0}".format(' in source, (
        "couldn't find the print() form of the registered_mac_at_time line"
    )
    assert 'log.write("registered_mac_at_time: {0}\\n".format(' in source, (
        "couldn't find the LogFile.write() form of the registered_mac_at_time line"
    )
    # Guard against a stray space creeping in before the colon on either
    # form (the exact class of bug the sibling test above already guards
    # against for the env dump loop).
    assert 'registered_mac_at_time : ' not in source, (
        "registered_mac_at_time has a space before its colon -- unparseable "
        "by vpn-status.py's ENV_LINE_RE, same bug class as the OS-detection regression."
    )


def test_reason_line_matches_vpn_status_parser_format():
    """Regression guard for the bug found live 2026-08-21: reject()'s
    "reason" line had a stray space before its colon in the LogFile.write()
    form ("reason : {0}") while its print() form correctly had none
    ("reason: {0}") -- same bug class as the two tests above, but this one
    silently corrupted every non-mac_mismatch rejection: with "reason"
    never actually parsing into iter_env_blocks()'s dict,
    cmd_rejected()'s `b.get("reason", "mac_mismatch")` fallback made
    os_not_allowed/country_not_allowed/city_not_allowed/asn_not_allowed/
    ip_not_allowed/bandwidth_exceeded rejections all display as
    "mac_mismatch" in the admin's Recent Rejected Connection Attempts,
    even though the flat log genuinely had the correct reason recorded."""
    with open(_SCRIPT_PATH) as f:
        source = f.read()
    assert 'print("reason: {0}".format(' in source, (
        "couldn't find the print() form of the reason line"
    )
    assert 'log.write("reason: {0}\\n".format(' in source, (
        "couldn't find the LogFile.write() form of the reason line"
    )
    assert 'reason : ' not in source, (
        "reason has a space before its colon -- unparseable by vpn-status.py's "
        "ENV_LINE_RE, silently mislabeling every non-mac_mismatch rejection reason "
        "as mac_mismatch via cmd_rejected()'s fallback default."
    )
