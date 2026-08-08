"""
Thin, safety-conscious wrapper around the two CLI tools this app is a
frontend for: openvpn-install.sh and vpn-status.py.

Every call here uses subprocess with an explicit argument list -- never
shell=True or a string-interpolated command -- so there is no command
injection surface even though some of these arguments (client names) are
ultimately user-supplied from the web UI. The scripts themselves remain the
single source of truth for validation (name sanitization, MAC
normalization, etc.); this wrapper does not re-implement that logic, only
invokes it and relays the result.
"""
import json
import subprocess

from .config import settings


class ScriptError(Exception):
    """Raised when a wrapped script exits non-zero (unexpectedly) or times
    out. Carries enough detail for API routes to turn into a clean error
    response without leaking raw tracebacks to the frontend."""

    def __init__(self, message: str, *, stdout: str = "", stderr: str = "", returncode: int | None = None):
        super().__init__(message)
        self.message = message
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


def _run(args: list[str]) -> subprocess.CompletedProcess:
    if settings.USE_SUDO:
        # -n (non-interactive): fail fast with a clear error instead of
        # hanging on a password prompt this app has no way to answer.
        args = ["sudo", "-n"] + args
    try:
        return subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=settings.SCRIPT_TIMEOUT_SECONDS,
            check=False,
            shell=False,  # explicit: never let this become shell=True
        )
    except subprocess.TimeoutExpired as e:
        raise ScriptError(
            f"Command timed out after {settings.SCRIPT_TIMEOUT_SECONDS}s"
        ) from e
    except FileNotFoundError as e:
        raise ScriptError(
            f"Command not found: {args[0]} -- check OPENVPN_INSTALL_SCRIPT/"
            f"VPN_STATUS_SCRIPT/sudo paths in the app's config"
        ) from e


def _run_install_script(*args: str) -> subprocess.CompletedProcess:
    return _run(["bash", settings.OPENVPN_INSTALL_SCRIPT, *args])


def _run_status_script(*args: str) -> subprocess.CompletedProcess:
    return _run(["python3", settings.VPN_STATUS_SCRIPT, *args])


def _parse_json_or_raise(proc: subprocess.CompletedProcess, *, allow_nonzero_json: bool = False):
    """Most read-only --json commands print valid JSON on success. --check,
    --lint-db, and --macs intentionally exit 1 (with still-valid JSON) when
    they find issues / an empty result -- that's informative output, not a
    failed call, so callers for those pass allow_nonzero_json=True."""
    if proc.returncode != 0 and not allow_nonzero_json:
        raise ScriptError(
            proc.stderr.strip() or f"Command failed with exit code {proc.returncode}",
            stdout=proc.stdout, stderr=proc.stderr, returncode=proc.returncode,
        )
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        raise ScriptError(
            "Command did not return valid JSON",
            stdout=proc.stdout, stderr=proc.stderr, returncode=proc.returncode,
        ) from e


# --- openvpn-install.sh ------------------------------------------------------

def list_clients() -> list[dict]:
    return _parse_json_or_raise(_run_install_script("--list", "--json"))


def list_revoked() -> list[dict]:
    return _parse_json_or_raise(_run_install_script("--list-revoked", "--json"))


def list_macs(name: str) -> dict:
    proc = _run_install_script("--macs", name, "--json")
    return _parse_json_or_raise(proc, allow_nonzero_json=True)


def check_consistency() -> dict:
    return _parse_json_or_raise(_run_install_script("--check", "--json"), allow_nonzero_json=True)


def lint_db() -> dict:
    return _parse_json_or_raise(_run_install_script("--lint-db", "--json"), allow_nonzero_json=True)


def add_client(name: str, mac: str) -> str:
    """Returns the script's plain-text confirmation on success. --add has
    no --json support by design (see openvpn-install.sh --help) -- it's a
    mutating action best surfaced with its real stdout, not silently
    swallowed. Raises ScriptError with the script's own stderr message on
    failure (bad name, bad MAC, duplicate client, etc.) -- already
    human-readable, written for exactly this purpose."""
    proc = _run_install_script("--add", name, mac)
    if proc.returncode != 0:
        raise ScriptError(
            proc.stderr.strip() or "Failed to add client",
            stdout=proc.stdout, stderr=proc.stderr, returncode=proc.returncode,
        )
    return proc.stdout.strip()


def revoke_client(name: str) -> str:
    proc = _run_install_script("--revoke", name)
    if proc.returncode != 0:
        raise ScriptError(
            proc.stderr.strip() or "Failed to revoke client",
            stdout=proc.stdout, stderr=proc.stderr, returncode=proc.returncode,
        )
    return proc.stdout.strip()


# --- vpn-status.py ------------------------------------------------------------

def status_connected() -> list[dict]:
    return _parse_json_or_raise(_run_status_script("--json"))


def status_all() -> list[dict]:
    return _parse_json_or_raise(_run_status_script("--all", "--json"))


def status_rejected(limit: int = 20) -> list[dict]:
    return _parse_json_or_raise(_run_status_script("--rejected", str(limit), "--json"))
