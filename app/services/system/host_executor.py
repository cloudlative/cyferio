"""SSH-based remote execution of the one whitelisted host-namespace command
(app/cli/openvpn_admin.py) -- the Phase 1 plan's §2a "thinnest possible
preview of the Phase 4 Host Agent". Used ONLY for genuinely host-namespace
operations (install/uninstall today; any future firewall/systemd change
tomorrow) -- everything else (cert/client/MAC operations that only touch the
already-bind-mounted /etc/openvpn) stays in-process, no SSH hop, exactly as
app/vpnadmin/cli_wrapper.py already does.

Security model (see the plan for the full rationale): the app container's
own Docker privileges are unchanged by this module -- no network_mode:host,
no pid:host. Instead, a scoped SSH deploy key is used to run exactly one
remote command; the corresponding host-side authorized_keys/sudoers entry
should be restricted to that same command so a compromised app container
can't run arbitrary commands on the host.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass

from ..openvpn.exceptions import HostExecutorError, from_remote_error
from .process_manager import CommandError, run

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class HostExecutorConfig:
    ssh_key_path: str
    ssh_target: str  # "user@host", e.g. "ubuntu@34.182.51.24"
    remote_script_path: str = "/opt/openvpn-toolkit/app/cli/openvpn_admin.py"
    use_sudo: bool = True
    timeout_seconds: int = 120
    ssh_port: int = 22


def run_host_command(config: HostExecutorConfig, action: str, *args: str) -> object:
    """Runs `sudo python3 <remote_script_path> <action> <args...>` on
    config.ssh_target over SSH, and returns the parsed `data` field of the
    remote command's JSON output on success.

    Raises the same OpenVPNError subclass the remote command itself raised
    (reconstructed via exceptions.from_remote_error) if it reported a
    handled failure, or HostExecutorError for anything at the transport
    level (SSH connection failure, timeout, malformed output) -- callers
    don't need to know or care that this ran over SSH rather than
    in-process."""
    remote_args = ["sudo", "-n", "python3", config.remote_script_path] if config.use_sudo \
        else ["python3", config.remote_script_path]
    remote_args += [action, *args]

    ssh_args = [
        "ssh",
        "-i", config.ssh_key_path,
        "-p", str(config.ssh_port),
        # Non-interactive, fail fast rather than hang on a host-key prompt
        # or a password this caller has no way to answer -- consistent with
        # cli_wrapper.py's own `sudo -n` rationale for the same reason.
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", f"ConnectTimeout={min(config.timeout_seconds, 30)}",
        config.ssh_target,
        "--",
        *remote_args,
    ]

    try:
        result = run(ssh_args, timeout=config.timeout_seconds)
    except CommandError as e:
        raise HostExecutorError(f"SSH connection to {config.ssh_target} failed: {e.message}") from e

    if result.returncode == 255:
        # ssh's own reserved exit code for a connection-level failure
        # (auth, host unreachable, ...) -- distinct from the remote
        # command's own exit code, which openvpn_admin.py always keeps
        # inside {0, 1, 2} (see its own docstring).
        raise HostExecutorError(
            f"SSH to {config.ssh_target} failed (exit 255): {result.stderr.strip() or 'connection error'}"
        )

    try:
        payload = json.loads(result.stdout.strip() or "{}")
    except json.JSONDecodeError as e:
        raise HostExecutorError(
            f"Remote command produced non-JSON output (exit {result.returncode}): "
            f"{result.stdout[:500]!r} / stderr: {result.stderr[:500]!r}"
        ) from e

    if not payload.get("ok"):
        error = payload.get("error") or {}
        raise from_remote_error(
            error.get("type", "OpenVPNError"),
            error.get("detail", "Remote command failed with no detail."),
            error.get("context", {}),
        )
    return payload.get("data")
