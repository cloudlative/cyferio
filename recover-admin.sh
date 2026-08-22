#!/bin/bash
#
# recover-admin.sh -- Super Admin Recovery Mechanism: the only way back onto
# the bootstrap admin account (User.is_bootstrap_admin) once its password,
# MFA enrollment, or lockout state is lost. Every in-app write path
# (routes/users.py, routes/groups.py) deliberately refuses to touch that
# one account, and no other account can hold the super_admin role to act on
# its behalf -- so recovery has to happen outside the RBAC system entirely,
# on a trust boundary that system doesn't cover: root/shell access to this
# box. Same posture as upgrade.sh/add-machine.sh -- if you can run this,
# you already have unmediated access to the database this recovers into,
# this just gives that access an audited, supported path instead of a
# hand-rolled `psql UPDATE`.
#
# Deliberately NOT an API endpoint, local-only or otherwise -- see the
# approved design proposal's own reasoning (bigger attack surface for no
# benefit, and depends on the very thing that might be broken -- the app
# being up and healthy -- to even reach it).
#
# What it does:
#   1. Confirms you really mean it -- re-type the bootstrap account's
#      username, unless --yes is also passed (e.g. non-interactive/scripted
#      use, which should already imply confident automation).
#   2. Finds the currently-running app container (same blue/green slot
#      detection upgrade.sh uses) and `docker exec`s into it, running
#      vpnadmin/cli_recover_admin.py with whichever flags you passed --
#      that module does the actual work, reusing the exact same password-
#      hashing/MFA primitives the normal admin console uses, and writes an
#      audit log entry for every action.
#
# Every recovery action is idempotent-safe to combine in one run (e.g.
# --reset-password --clear-mfa --unlock together, the common "I'm fully
# locked out" case) -- see cli_recover_admin.py's own docstring for exactly
# what each flag touches.
#
# Usage (run as root, or as a user in the `docker` group):
#   ./recover-admin.sh --reset-password [--clear-mfa] [--unlock] [--regenerate-recovery-codes] [--repo-dir /opt/cyferio] [--yes]
#
# Flags:
#   --reset-password              Generate a new one-time password, printed
#                                   once to this terminal only -- never
#                                   written to a file, never logged, never
#                                   emailed. Forces a real password change
#                                   at the very next login.
#   --clear-mfa                   Disable the current TOTP enrollment and
#                                   require re-enrollment at next login.
#   --unlock                      Clear both the password-lockout and the
#                                   MFA-lockout failed-attempt counters.
#   --regenerate-recovery-codes   Issue a fresh set of MFA recovery codes
#                                   (only meaningful if MFA is enabled --
#                                   skipped with a message otherwise).
#   --repo-dir DIR                Defaults to this script's own directory,
#                                   same convention as upgrade.sh.
#   --yes                         Skip the interactive re-type-the-username
#                                   confirmation.
#
# At least one action flag is required -- this script (like
# cli_recover_admin.py itself) refuses to run with none.
#
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
ASSUME_YES=0
declare -a PY_ARGS=()

log() { echo "[recover-admin] $*"; }
die() { echo "[recover-admin] ERROR: $*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
	case "$1" in
	--reset-password)
		PY_ARGS+=("--reset-password")
		shift
		;;
	--clear-mfa)
		PY_ARGS+=("--clear-mfa")
		shift
		;;
	--unlock)
		PY_ARGS+=("--unlock")
		shift
		;;
	--regenerate-recovery-codes)
		PY_ARGS+=("--regenerate-recovery-codes")
		shift
		;;
	--repo-dir)
		REPO_DIR="$2"
		shift 2
		;;
	--yes)
		ASSUME_YES=1
		shift
		;;
	-h | --help)
		# Print this file's own header comment block -- single source of
		# truth for usage, same trick upgrade.sh uses rather than a
		# hand-maintained duplicate.
		sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^#//; s/^ //'
		exit 0
		;;
	*)
		die "Unknown argument: $1 (see --help)"
		;;
	esac
done

if [[ ${#PY_ARGS[@]} -eq 0 ]]; then
	die "Nothing to do -- pass at least one of --reset-password, --clear-mfa, --unlock, --regenerate-recovery-codes (see --help)."
fi

cd "$REPO_DIR" 2>/dev/null || die "--repo-dir '$REPO_DIR' does not exist."
[[ -f docker-compose.yml ]] || die "'$REPO_DIR' doesn't look like a Cyferio checkout (no docker-compose.yml). Pass --repo-dir."
[[ -f .env ]] || die "No .env in '$REPO_DIR' -- this isn't a deployed install."

command -v docker >/dev/null 2>&1 || die "docker not found on PATH."
if ! docker info >/dev/null 2>&1; then
	die "Cannot talk to the Docker daemon as $(whoami). Either run this with sudo, or (if you were just added to the docker group) start a NEW shell session."
fi

# Same blue/green active-slot detection as upgrade.sh -- see that script's
# own comment for the full design. Falls back to the pre-blue/green fixed
# container name for a host that hasn't upgraded onto that scheme yet.
ACTIVE_SLOT=$(grep -E '^COMPOSE_PROFILES=' .env | head -1 | cut -d= -f2- || echo "")
if [[ "$ACTIVE_SLOT" == "blue" || "$ACTIVE_SLOT" == "green" ]]; then
	CONTAINER="cyferio-app-${ACTIVE_SLOT}"
else
	CONTAINER="cyferio-app"
fi

if ! docker inspect --format='{{.State.Running}}' "$CONTAINER" 2>/dev/null | grep -q true; then
	die "Container '$CONTAINER' isn't running -- bring the app up first ('docker compose up -d' in $REPO_DIR), then re-run this. This tool recovers account access, not a down app."
fi

# Find the bootstrap admin's username for the confirmation prompt below --
# read straight out of the running container's DB, same connection the
# recovery itself will use a moment later, so this always reflects the
# real account, never a guess.
BOOTSTRAP_USERNAME=$(docker exec "$CONTAINER" python -c "
from vpnadmin.db import SessionLocal
from vpnadmin.models import User
db = SessionLocal()
admin = db.query(User).filter(User.is_bootstrap_admin.is_(True)).one_or_none()
print(admin.username if admin else '')
db.close()
" 2>/dev/null || echo "")

[[ -n "$BOOTSTRAP_USERNAME" ]] || die "Could not find a bootstrap admin account in the database -- nothing for this tool to recover (see cli_recover_admin.py's own error for the exact reason)."

log "Bootstrap admin account: $BOOTSTRAP_USERNAME"
log "About to run: ${PY_ARGS[*]}"

if [[ "$ASSUME_YES" -ne 1 ]]; then
	read -r -p "Type the username ('$BOOTSTRAP_USERNAME') to confirm: " TYPED
	[[ "$TYPED" == "$BOOTSTRAP_USERNAME" ]] || die "Username didn't match -- aborted, nothing changed."
fi

log "Recovering..."
docker exec "$CONTAINER" python -m vpnadmin.cli_recover_admin --yes "${PY_ARGS[@]}"
log "Done. This run is recorded in the admin console's own Audit Log (action: bootstrap_admin_recovered)."
