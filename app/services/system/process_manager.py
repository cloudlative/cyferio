"""Single choke point for running host commands (easyrsa, openssl, systemctl,
iptables, apt-get, ...) from the OpenVPN service layer.

Mirrors app/vpnadmin/cli_wrapper.py's own rule (see that module's docstring):
subprocess.run with an explicit argument list only, never shell=True or a
string-interpolated command, even though several arguments (client names,
MACs) are ultimately user-supplied. Validation of *those* happens in
validator.py before a value ever reaches here -- this module's job is only
safe execution + structured errors + optional retry, not input sanitization.
"""
from __future__ import annotations

import logging
import subprocess
import time
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS = 30


@dataclass
class CommandResult:
    args: list[str]
    returncode: int
    stdout: str
    stderr: str
    duration_seconds: float = 0.0

    @property
    def ok(self) -> bool:
        return self.returncode == 0


class CommandError(Exception):
    """Raised by run()/run_checked() when a command times out or the binary
    itself isn't found -- distinct from a non-zero exit, which run_checked()
    signals via this same exception but run() (unchecked) simply reports in
    the returned CommandResult."""

    def __init__(self, message: str, *, result: CommandResult | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.result = result


def run(
    args: list[str],
    *,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
    input_text: str | None = None,
) -> CommandResult:
    """Runs args (a real argument list -- never a shell string) and returns a
    CommandResult regardless of exit code. Raises CommandError only for a
    timeout or a missing binary, matching how cli_wrapper.py's _run()
    already distinguishes "the command ran and failed" (a normal
    CommandResult with returncode != 0) from "the command couldn't run at
    all" (an exception)."""
    started = time.monotonic()
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            shell=False,  # explicit: never let this become shell=True
            cwd=cwd,
            env=env,
            input=input_text,
        )
    except subprocess.TimeoutExpired as e:
        raise CommandError(f"Command timed out after {timeout}s: {args!r}") from e
    except FileNotFoundError as e:
        raise CommandError(f"Command not found: {args[0]!r}") from e

    duration = time.monotonic() - started
    result = CommandResult(
        args=args, returncode=proc.returncode, stdout=proc.stdout,
        stderr=proc.stderr, duration_seconds=duration,
    )
    if not result.ok:
        logger.warning(
            "command failed (exit %s, %.2fs): %s -- stderr: %s",
            proc.returncode, duration, args, proc.stderr.strip()[:500],
        )
    return result


def run_checked(
    args: list[str],
    *,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
    input_text: str | None = None,
    error_prefix: str = "Command failed",
) -> CommandResult:
    """Same as run(), but raises CommandError on a non-zero exit too --
    convenient for the many call sites (easyrsa, systemctl, ...) where any
    failure should abort the calling operation rather than be inspected."""
    result = run(args, timeout=timeout, cwd=cwd, env=env, input_text=input_text)
    if not result.ok:
        detail = result.stderr.strip() or result.stdout.strip() or f"exit code {result.returncode}"
        raise CommandError(f"{error_prefix}: {detail}", result=result)
    return result


def run_with_retry(
    args: list[str],
    *,
    attempts: int = 3,
    backoff_seconds: float = 1.0,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
    error_prefix: str = "Command failed",
) -> CommandResult:
    """Retries transient failures (e.g. a flaky network fetch during easyrsa
    download, or a package-manager lock held by another process) with linear
    backoff. Not used for operations where a retry could duplicate an
    effect (e.g. issuing a cert) -- callers pick this only for genuinely
    idempotent/read-style commands."""
    last_error: CommandError | None = None
    for attempt in range(1, attempts + 1):
        try:
            return run_checked(
                args, timeout=timeout, cwd=cwd, env=env, error_prefix=error_prefix,
            )
        except CommandError as e:
            last_error = e
            if attempt < attempts:
                logger.warning(
                    "attempt %d/%d failed for %s, retrying in %.1fs: %s",
                    attempt, attempts, args, backoff_seconds, e,
                )
                time.sleep(backoff_seconds * attempt)
    assert last_error is not None
    raise last_error
