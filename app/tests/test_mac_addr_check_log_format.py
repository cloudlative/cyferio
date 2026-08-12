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
