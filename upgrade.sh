#!/bin/bash
#
# upgrade.sh -- brings an already-deployed Cyferio host (this repo checkout
# + its docker-compose.yml stack) up to the latest published release, or a
# specific one with --tag. This is the real implementation behind the
# "cd /opt/cyferio && ./upgrade.sh" instructions shown in the Release
# Availability popup (static/app.js) and the auto-filed Upgrade Assignment
# ticket (vpnadmin/release_check.py's file_upgrade_ticket) -- both used to
# reference a script that didn't actually exist yet.
#
# Deliberately NOT the same job as setup-new-machine.sh: that one bootstraps
# a BRAND NEW host from nothing (installs Docker, generates the host-
# executor key, writes a first .env, brings the stack up for the first
# time). This one assumes all of that already happened -- it only ever
# updates an EXISTING install to a newer release. Re-running setup-new-
# machine.sh on a live box would be destructive-adjacent (regenerates keys,
# rewrites .env under some flag combos); this script never touches anything
# setup-new-machine.sh owns other than IMAGE_TAG in .env and this repo
# checkout's own git state.
#
# What it does, every run, in order:
#   1. Preflight checks (repo checkout looks right, docker/compose present,
#      current user can actually run docker, .env is writable, git working
#      tree is clean before touching it).
#   2. Resolves the target release tag (latest published GitHub release by
#      default, or --tag vX.Y.Z to pin one).
#   3. Compares target against .env's current IMAGE_TAG -- if they already
#      match, this is a genuine no-op (exit 0, nothing touched). Idempotent:
#      safe to run on a cron/timer, or by hand, any number of times.
#   4. Fast-forwards this checkout's master branch to the tag's commit (the
#      bind-mounted openvpn-install.sh/vpn-status.py -- see
#      docker-compose.yml's OPENVPN_INSTALL_SCRIPT/VPN_STATUS_SCRIPT -- come
#      from THIS checkout, not the app image, so they'd otherwise silently
#      drift out of sync with whatever the new app image expects). That
#      fast-forward just rewrote THIS SCRIPT on disk too -- since bash
#      doesn't re-read an already-running script mid-execution, step 4
#      re-execs itself right after (`exec "$0" ...`) so steps 5-7 below
#      always run whatever fix/change actually landed in THEM as part of
#      this same release, not stale pre-upgrade logic. Transparent to an
#      operator -- same phase numbering/log lines either way, just now
#      guaranteed to reflect the code this run just pulled.
#   5. Backs up .env (timestamped copy), updates IMAGE_TAG. Rolling
#      (blue/green) deploy from there, not a plain `docker compose up -d`
#      recreate -- see docker-compose.yml's app-blue/app-green "Zero-
#      downtime rollout" comment for the full design: starts the slot
#      that ISN'T currently active alongside the one that is, waits for
#      its Docker healthcheck, then stops the old slot only once the new
#      one is confirmed healthy. Traefik (dynamic.yml.tmpl) already lists
#      both slots permanently with its own active healthCheck, so the
#      moment the new slot passes, real traffic starts reaching it --
#      nothing to explicitly "cut over". The very first run under this
#      scheme (upgrading a host that predates it) is the one exception --
#      no prior slot to roll from, so that one deploy still has the old
#      brief-downtime swap; every deploy after it is zero-downtime.
#   6. Verifies: HTTPS /login returns 200 (retried, containers can take a
#      few seconds to bind), and the new slot's actual running image tag
#      matches the target -- not just "the command exited 0".
#
# Never auto-rolls-back a failed health check -- same philosophy as setup-
# new-machine.sh's own _curl_check_retry: a slow-to-start container on an
# otherwise fine upgrade shouldn't make the script itself start improvising
# recovery actions. It prints exactly what to check/how to roll back by hand
# and exits non-zero instead.
#
# Usage (run as root, or as a user in the `docker` group):
#   ./upgrade.sh [--tag v2.6.2] [--repo-dir /opt/cyferio] [--yes]
#                [--skip-git-sync] [--dry-run]
#
# Flags:
#   --tag TAG          Upgrade to this exact tag instead of the latest
#                        published release (e.g. --tag v2.6.1 to pin/roll
#                        back to an older-than-latest release; this script
#                        doesn't distinguish "upgrade" from "change version
#                        to" -- both are just "make IMAGE_TAG match TAG").
#   --repo-dir DIR      Defaults to this script's own directory (works
#                        whether invoked as ./upgrade.sh from inside the
#                        checkout or via an absolute path from a ticket/
#                        cron entry).
#   --yes               Skip the interactive confirmation prompt.
#   --skip-git-sync     Only bump IMAGE_TAG + redeploy -- don't touch this
#                        checkout's git state at all. Use this if the box's
#                        toolkit scripts are intentionally hand-patched and
#                        a fast-forward would be unwelcome; understand this
#                        means the bind-mounted openvpn-install.sh/
#                        vpn-status.py stay whatever they already are.
#   --dry-run           Print what would happen (target tag, current vs.
#                        new IMAGE_TAG, whether a git fast-forward is
#                        needed) and exit 0 without changing anything.
#
set -euo pipefail

TAG=""
REPO_DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
ASSUME_YES=0
SKIP_GIT_SYNC=0
DRY_RUN=0

log() { echo "[upgrade] $*"; }
die() { echo "[upgrade] ERROR: $*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
	case "$1" in
	--tag)
		TAG="$2"
		shift 2
		;;
	--repo-dir)
		REPO_DIR="$2"
		shift 2
		;;
	--yes)
		ASSUME_YES=1
		shift
		;;
	--skip-git-sync)
		SKIP_GIT_SYNC=1
		shift
		;;
	--dry-run)
		DRY_RUN=1
		shift
		;;
	-h | --help)
		# Print this file's own header comment block -- single source of
		# truth for usage, same trick used elsewhere in this repo rather
		# than a hand-maintained duplicate.
		sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^#//; s/^ //'
		exit 0
		;;
	*)
		die "Unknown argument: $1 (see --help)"
		;;
	esac
done

# --- Phase 1: preflight ---------------------------------------------------
log "Phase 1: preflight checks"
cd "$REPO_DIR" 2>/dev/null || die "--repo-dir '$REPO_DIR' does not exist."

[[ -f docker-compose.yml ]] || die "'$REPO_DIR' doesn't look like a Cyferio checkout (no docker-compose.yml). Pass --repo-dir."
[[ -f .env ]] || die "No .env in '$REPO_DIR' -- this script upgrades an EXISTING install; run setup-new-machine.sh for a first-time install instead."

command -v docker >/dev/null 2>&1 || die "docker not found on PATH."
docker compose version >/dev/null 2>&1 || die "'docker compose' (v2, the compose PLUGIN, not the standalone docker-compose v1 binary) not found."

# Confirms the CURRENT user/session can actually talk to the Docker daemon
# -- catches both "not root and not in the docker group" and "just added to
# the docker group but this SSH session predates that" (the exact reminder
# setup-new-machine.sh prints at the end of a fresh install) BEFORE this
# script gets any further, rather than failing confusingly mid-upgrade on
# the first `docker compose pull`.
if ! docker info >/dev/null 2>&1; then
	die "Cannot talk to the Docker daemon as $(whoami). Either run this with sudo, or (if you were just added to the docker group) start a NEW shell session -- 'newgrp docker' or reconnect over SSH."
fi

[[ -w .env ]] || die ".env is not writable by $(whoami)."

GIT_AVAILABLE=1
if [[ ! -d .git ]]; then
	log "  no .git directory here -- this checkout wasn't cloned with git (a tarball drop, maybe). Skipping git sync; IMAGE_TAG will still be updated."
	GIT_AVAILABLE=0
	SKIP_GIT_SYNC=1
fi
if [[ "$GIT_AVAILABLE" -eq 1 && "$SKIP_GIT_SYNC" -eq 0 ]]; then
	command -v git >/dev/null 2>&1 || die "git not found on PATH (needed for the repo sync step -- pass --skip-git-sync to bypass it)."
	# Tracked-file changes only (staged or unstaged) -- deliberately NOT
	# `git status --porcelain`, which also flags untracked files. An
	# untracked scratch file sitting in the checkout is harmless to a
	# fast-forward merge and shouldn't block an upgrade; a local edit to a
	# file the release itself might also touch is what actually needs to
	# stop this.
	if ! git diff --quiet || ! git diff --cached --quiet; then
		die "Working tree in '$REPO_DIR' has uncommitted changes to tracked files -- refusing to fast-forward over local edits. Commit/stash them, or re-run with --skip-git-sync to only update IMAGE_TAG and redeploy without touching git state."
	fi
	CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")
	if [[ "$CURRENT_BRANCH" != "master" ]]; then
		die "This checkout is on branch/ref '$CURRENT_BRANCH', not master -- releases are only ever cut from master (see the repo's own release policy). Check out master first, or re-run with --skip-git-sync."
	fi
fi

log "  OK -- docker reachable, .env writable, repo checkout looks right."

# --- Phase 2: resolve target tag ------------------------------------------
log "Phase 2: resolving target release"
if [[ "$GIT_AVAILABLE" -eq 1 ]]; then
	# Explicitly names BOTH master and --tags -- a plain `git fetch origin
	# --tags` already pulls master too under this repo's normal clone
	# refspec, but naming it here removes any doubt this actually fetches
	# the latest code (not just tag pointers) regardless of how a given
	# checkout's remote.origin.fetch happens to be configured (e.g. a
	# sparse/single-branch clone that only tracks something other than
	# master by default).
	git fetch origin master --tags --quiet || log "  (git fetch failed -- continuing with whatever tags/refs are already local)"
fi

if [[ -z "$TAG" ]]; then
	if [[ "$GIT_AVAILABLE" -eq 1 ]]; then
		# Same "vX.Y.Z, highest semver wins" tag shape this repo's whole
		# release pipeline already assumes (build.yml's `push: tags:
		# ["v*.*.*"]` trigger) -- sort -V handles the numeric ordering
		# correctly (plain sort would put v2.10.0 before v2.9.0).
		TAG=$(git tag --list 'v*.*.*' | sort -V | tail -1)
	fi
	if [[ -z "$TAG" ]] && command -v gh >/dev/null 2>&1; then
		log "  no local tags found -- falling back to 'gh release view'"
		TAG=$(gh release view --repo cloudlative/cyferio --json tagName -q .tagName 2>/dev/null || echo "")
	fi
	[[ -n "$TAG" ]] || die "Could not determine the latest release tag (no local git tags, and 'gh release view' unavailable/failed). Pass --tag explicitly."
fi
[[ "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "'$TAG' doesn't look like a release tag (expected vX.Y.Z)."

# docker/metadata-action's semver tagging strips the leading "v" for the
# actual image tag (git tag v2.6.2 -> image tag "2.6.2") -- see build.yml
# and .env.example's own IMAGE_TAG comment for this same conversion.
TARGET_IMAGE_TAG="${TAG#v}"
CURRENT_IMAGE_TAG=$(grep -E '^IMAGE_TAG=' .env | head -1 | cut -d= -f2-)

log "  target release:  $TAG  (image tag: $TARGET_IMAGE_TAG)"
log "  current image:   ${CURRENT_IMAGE_TAG:-<unset, currently tracking 'latest'>}"

if [[ "$CURRENT_IMAGE_TAG" == "$TARGET_IMAGE_TAG" ]]; then
	log "Already up to date ($TARGET_IMAGE_TAG). Nothing to do."
	exit 0
fi

NEEDS_FF=0
if [[ "$GIT_AVAILABLE" -eq 1 && "$SKIP_GIT_SYNC" -eq 0 ]]; then
	if [[ "$(git rev-parse HEAD)" != "$(git rev-parse "$TAG")" ]]; then
		NEEDS_FF=1
	fi
fi

if [[ "$DRY_RUN" -eq 1 ]]; then
	log "--dry-run: would update IMAGE_TAG $CURRENT_IMAGE_TAG -> $TARGET_IMAGE_TAG"
	[[ "$NEEDS_FF" -eq 1 ]] && log "--dry-run: would fast-forward master to $TAG ($(git rev-parse --short "$TAG"))"
	log "--dry-run: would run 'docker compose pull && docker compose up -d' and verify /login"
	exit 0
fi

if [[ "$ASSUME_YES" -eq 0 ]]; then
	read -r -p "[upgrade] Upgrade this host from ${CURRENT_IMAGE_TAG:-<none>} to $TARGET_IMAGE_TAG ($TAG)? [y/N] " reply
	[[ "$reply" =~ ^[Yy]$ ]] || die "Aborted."
fi

# --- Phase 3: sync this checkout to the release commit ---------------------
if [[ "$NEEDS_FF" -eq 1 ]]; then
	log "Phase 3: fast-forwarding master to $TAG"
	# --ff-only, not --hard reset: if this ever ISN'T a clean fast-forward
	# (a local commit that never got pushed, an unexpected remote history
	# rewrite), fail loudly here rather than silently discarding a commit
	# nobody else has a copy of.
	git merge --ff-only "$TAG" || die "master could not be fast-forwarded to $TAG -- master has diverged from origin. Resolve manually (this repo's convention is 100% linear direct-to-master history, so a divergence here means something unusual happened)."

	# This merge just rewrote upgrade.sh itself (this very file) on disk,
	# along with everything else -- but bash does NOT re-read an
	# already-running script from disk mid-execution; it keeps using
	# whatever this process already has buffered from before the pull.
	# Phases 4/5 below would silently run stale, pre-upgrade logic,
	# ignorant of any fix that landed in THEM between the commit this run
	# started on and $TAG. Reproduced live 2026-08-21: upgrading to
	# v2.8.0 (which fixed Phase 5's running-tag parsing, see the
	# RUNNING_TAG comment further down) still hit the exact bug that
	# release fixed, because this process had already started running
	# the pre-fix Phase 5 before this exact line pulled the fix onto
	# disk -- confirmed by re-running the (now on-disk) fixed parser by
	# hand right after, which worked correctly. The very NEXT invocation
	# (NEEDS_FF=0, nothing left to pull) used the fixed code fine on its
	# own -- this makes that reliably true on the FIRST invocation too,
	# by re-executing from the freshly-pulled file instead of limping
	# through the rest of this run on stale in-memory logic. `--yes` is
	# forced on the re-exec since the operator already confirmed this
	# exact upgrade above -- asking again would be a confusing double-
	# prompt for what's now this script's own implementation detail, not
	# a new decision. `--tag`/`--repo-dir` are pinned to the already-
	# resolved values (not re-derived) so a re-exec can never land on a
	# DIFFERENT tag than the one just confirmed, however unlikely.
	log "  re-executing the freshly-pulled upgrade.sh to pick up any fix that just landed in it"
	exec "$0" --tag "$TAG" --repo-dir "$REPO_DIR" --yes
else
	log "Phase 3: git sync (already at $TAG, or --skip-git-sync)"
fi

# --- Phase 4: rolling (blue/green) deploy -----------------------------------
#
# Zero-downtime rollout -- see docker-compose.yml's app-blue/app-green
# "Zero-downtime rollout" comment for the full design (a plain `docker
# compose up -d` always stops the old container before starting the new
# one; there's no "start new, wait healthy, THEN stop old" outside Swarm
# mode). Reported live 2026-08-21: "the app goes down for a few seconds"
# on every rollout.
log "Phase 4: rolling deploy (blue/green)"
ENV_BACKUP=".env.bak.$(date +%Y%m%dT%H%M%S)"
cp .env "$ENV_BACKUP"
log "  backed up .env -> $ENV_BACKUP"

if grep -q '^IMAGE_TAG=' .env; then
	sed -i "s|^IMAGE_TAG=.*|IMAGE_TAG=${TARGET_IMAGE_TAG}|" .env
else
	echo "IMAGE_TAG=${TARGET_IMAGE_TAG}" >>.env
fi

ACTIVE_SLOT=$(grep -E '^COMPOSE_PROFILES=' .env | head -1 | cut -d= -f2- || echo "")

if [[ "$ACTIVE_SLOT" != "blue" && "$ACTIVE_SLOT" != "green" ]]; then
	# First run under the blue/green scheme -- an install that was on an
	# older release still has the single fixed-named `cyferio-app`
	# container and no COMPOSE_PROFILES line in .env at all (this repo's
	# docker-compose.yml only just gained app-blue/app-green). No prior
	# slot to roll from, so THIS ONE deploy still does the old stop-then-
	# start swap -- every deploy after this one is zero-downtime. Said
	# plainly in the log rather than silently falling back.
	log "  first run under the blue/green scheme -- this ONE deploy still has the old brief-downtime swap; every deploy after this is zero-downtime"
	NEW_SLOT="blue"
	if grep -q '^COMPOSE_PROFILES=' .env; then
		sed -i "s|^COMPOSE_PROFILES=.*|COMPOSE_PROFILES=${NEW_SLOT}|" .env
	else
		echo "COMPOSE_PROFILES=${NEW_SLOT}" >>.env
	fi
	# The old container's fixed 8000/tcp host-IP bind would otherwise
	# conflict with Traefik's new vpninternal entrypoint claiming that
	# exact same host IP:port below -- docker-compose.yml no longer even
	# has an `app` service definition for `docker compose` itself to stop
	# this via, so it's genuinely orphaned from the new compose file's
	# perspective and has to be removed directly.
	if docker ps -a --format '{{.Names}}' | grep -qx "cyferio-app"; then
		log "  stopping the old (pre-blue/green) cyferio-app container"
		docker stop cyferio-app >/dev/null 2>&1 || true
		docker rm cyferio-app >/dev/null 2>&1 || true
	fi
	docker compose pull
	docker compose up -d
else
	NEW_SLOT="green"
	[[ "$ACTIVE_SLOT" == "green" ]] && NEW_SLOT="blue"
	log "  active slot: $ACTIVE_SLOT -- starting $NEW_SLOT alongside it"

	docker compose pull "app-${NEW_SLOT}"
	# Both profiles active for this one call -- brings up the NEW slot
	# without touching the still-running OLD one (a bare `docker compose
	# up -d`, honoring only .env's current COMPOSE_PROFILES, wouldn't even
	# attempt to start the new slot's service at all).
	docker compose --profile blue --profile green up -d "app-${NEW_SLOT}"

	log "  waiting for app-${NEW_SLOT} to report healthy..."
	NEW_HEALTHY=0
	for _ in $(seq 1 30); do
		status=$(docker inspect --format='{{.State.Health.Status}}' "cyferio-app-${NEW_SLOT}" 2>/dev/null || echo "")
		if [[ "$status" == "healthy" ]]; then
			NEW_HEALTHY=1
			break
		fi
		sleep 3
	done

	if [[ "$NEW_HEALTHY" -ne 1 ]]; then
		log "  app-${NEW_SLOT} did not become healthy within 90s -- leaving it running for inspection ('docker compose logs app-${NEW_SLOT}'), NOT touching the still-live app-${ACTIVE_SLOT}."
		log "  To abandon this attempt: 'docker compose stop app-${NEW_SLOT} && docker compose rm -f app-${NEW_SLOT}', then restore IMAGE_TAG from $ENV_BACKUP into .env."
		exit 1
	fi
	log "  app-${NEW_SLOT} is healthy -- Traefik is already routing to it (dynamic.yml.tmpl's own healthCheck picks this up independently, nothing to explicitly cut over)."

	# A longer graceful-stop timeout than Compose's 10s default, so any
	# request app-OLD is still mid-flight on gets a real chance to finish
	# rather than being cut off outright -- doesn't fully close the small
	# residual request-loss window this design has (Traefik's health
	# check is polled every 1s, not push-notified the instant a container
	# stops -- see dynamic.yml.tmpl's own comment; measured locally as
	# ~0.7% of requests under a 10 req/s synthetic hammer, effectively
	# negligible against this app's real traffic patterns).
	log "  stopping app-${ACTIVE_SLOT}..."
	docker compose stop --timeout 15 "app-${ACTIVE_SLOT}"
	docker compose rm -f "app-${ACTIVE_SLOT}"

	sed -i "s|^COMPOSE_PROFILES=.*|COMPOSE_PROFILES=${NEW_SLOT}|" .env
	log "  active slot is now $NEW_SLOT."
fi

# --- Phase 5: verify ---------------------------------------------------
log "Phase 5: verifying"
APP_DOMAIN=$(grep -E '^APP_DOMAIN=' .env | head -1 | cut -d= -f2- || echo "")

_check_once() {
	local code
	# Same "curl's own -w already prints 000 on a hard failure, don't
	# double it up with || echo 000" reasoning as setup-new-machine.sh's
	# _curl_check_once.
	code=$(curl -sk -m 10 -o /dev/null -w "%{http_code}" "https://${APP_DOMAIN:-localhost}/login" 2>/dev/null) || true
	echo "${code:-000}"
}

ok=0
for _ in 1 2 3 4 5 6; do
	code=$(_check_once)
	if [[ "$code" == "200" ]]; then
		ok=1
		break
	fi
	sleep 5
done

# `docker compose images --format json` isn't consistent across Compose
# versions: older ones emit JSON Lines (one object per line), newer ones
# (reproduced live with Compose v5.4.0 on the test box 2026-08-21) emit a
# single JSON array on one line instead. Parsing that array as if it were
# one JSONL row makes rows[0] a list, not a dict, so rows[0]["Tag"] throws
# -- silently swallowed by the `2>/dev/null || echo ""` below, surfacing
# as "<could not determine>" even though the upgrade itself succeeded.
# Handle both shapes: try whole-stdin JSON first (array or single object),
# fall back to JSONL only if that fails.
RUNNING_TAG=$(docker compose images "app-${NEW_SLOT}" --format json 2>/dev/null | python3 -c '
import json, sys
data = sys.stdin.read()
try:
	parsed = json.loads(data)
except json.JSONDecodeError:
	parsed = [json.loads(l) for l in data.splitlines() if l.strip()]
if isinstance(parsed, dict):
	parsed = [parsed]
print(parsed[0]["Tag"] if parsed else "")
' 2>/dev/null || echo "")

if [[ "$ok" -eq 1 && "$RUNNING_TAG" == "$TARGET_IMAGE_TAG" ]]; then
	log "Upgrade complete: https://${APP_DOMAIN:-localhost}/login -> HTTP 200, running image tag $RUNNING_TAG (slot: $NEW_SLOT)."
	log "If a System Maintenance ticket was auto-filed for this release, remember to mark it resolved in Support Center."
	exit 0
fi

log "Upgrade finished but verification didn't fully pass:"
log "  /login check:        $([[ "$ok" -eq 1 ]] && echo OK || echo "FAILED (last HTTP code: ${code:-unknown})")"
log "  running image tag:   ${RUNNING_TAG:-<could not determine>} (expected $TARGET_IMAGE_TAG, slot: $NEW_SLOT)"
log "Check 'docker compose ps' / 'docker compose logs app-${NEW_SLOT}' in $REPO_DIR."
log "To roll back: restore IMAGE_TAG (and COMPOSE_PROFILES, if this was a blue/green rollout) from $ENV_BACKUP into .env, then 'docker compose up -d' again."
exit 1
