#!/bin/bash
#
# setup-new-machine.sh -- one-time bootstrap for a fresh Ubuntu+Docker host
# to run the OpenVPN Toolkit portal (Traefik + app + Postgres, see
# docker-compose.yml) with the web-triggered install/uninstall page working
# (see app/vpnadmin/routes/openvpn_install.py and
# app/services/system/host_executor.py's own docstrings for the design this
# automates -- an SSH connection, scoped to one exact command, rather than
# widening the app container's own Docker privileges).
#
# This is everything a fresh machine needs BEYOND a bare OS install --
# installing Docker Engine itself (Docker's official apt repo for Ubuntu, see
# install_docker() below), generating the host-executor SSH key +
# forced-command wrapper + sudoers grant, writing .env, enabling the
# deploy-key volume mount, and bringing the stack up (staging cert first,
# then production).
#
# UBUNTU ONLY: this script installs Docker via Docker's official Ubuntu apt
# repository (docs.docker.com/engine/install/ubuntu) and uses apt-get
# elsewhere -- it refuses to run (see the os-release check below) on any
# other distro. This matches every other install-time assumption already
# baked into this repo (see e.g. the migration plan's target-machine facts).
#
# Prereqs this script does NOT do for you:
#   1. A DNS A record for --domain already pointing at this host's public IP
#      (needed for Let's Encrypt's HTTP-01 challenge to succeed).
#   2. This repo already cloned here (private repo -- add a read-only GitHub
#      deploy key first: `ssh-keygen -t ed25519 -f ~/.ssh/cyferio-deploy`,
#      then `gh repo deploy-key add --repo cloudlative/cyferio
#      ~/.ssh/cyferio-deploy.pub`, then clone via that key -- or just
#      use add-machine.sh, which does exactly this).
#
# Idempotent: every phase checks its own current state before acting, so
# re-running this (e.g. after changing --deploy-user, or just to pick up a
# newer .env.example) is safe and won't reinstall Docker if it's already
# present, won't duplicate keys/sudoers entries/authorized_keys lines,
# won't re-issue a cert that's already valid, and won't clobber an .env
# you've since hand-edited (see --force-env).
#
# Usage (run as root, or via sudo):
#   sudo ./setup-new-machine.sh \
#     --domain portal.cyferio.com \
#     --acme-email you@example.com \
#     [--captcha-provider turnstile --turnstile-site-key XXX --turnstile-secret-key YYY] \
#     [--deploy-user ubuntu] [--image-tag 1.0.36] [--repo-dir /opt/cyferio] \
#     [--use-staging-first] [--force-env] [--skip-stack] [--skip-docker]
#
# Flags:
#   --domain DOMAIN         Required. Public hostname Traefik requests a
#                            cert for (sets APP_DOMAIN in .env).
#   --acme-email EMAIL      Required unless .env already has ACME_EMAIL.
#   --captcha-provider P     Opt-in. P is "turnstile" (Cloudflare) or
#                            "recaptcha" (Google reCAPTCHA v2) -- sets
#                            CAPTCHA_PROVIDER in .env. Requires that
#                            provider's --*-site-key and --*-secret-key
#                            below. Only takes effect when writing a FRESH
#                            .env (no existing file, or --force-env) -- see
#                            write_env()'s own comments for why an existing
#                            .env's CAPTCHA_PROVIDER/*_KEY lines are left
#                            untouched otherwise, the same limitation this
#                            script already has for every other value in
#                            the main .env heredoc (HOST_SSH_TARGET/
#                            CLIENT_IP_HEADER are the only two exceptions,
#                            explicitly patched into an existing .env by
#                            name below -- CAPTCHA isn't one of them).
#   --turnstile-site-key K   Required with --captcha-provider turnstile.
#   --turnstile-secret-key K  Required with --captcha-provider turnstile.
#   --recaptcha-site-key K   Required with --captcha-provider recaptcha.
#   --recaptcha-secret-key K  Required with --captcha-provider recaptcha.
#   --deploy-user USER      Non-root user the host-executor SSH key logs in
#                            as, granted narrowly-scoped sudo for exactly
#                            app/cli/openvpn_admin.py (default: ubuntu).
#                            NEVER root -- see this script's own comments in
#                            setup_host_executor() for why.
#   --image-tag TAG         Sets IMAGE_TAG in .env (default: latest).
#   --repo-dir DIR          Where this repo is checked out (default:
#                            /opt/cyferio -- must match
#                            HOST_SSH_REMOTE_SCRIPT_PATH's directory).
#   --use-staging-first     Request a Let's Encrypt STAGING cert first,
#                            verify it issues, then switch to production and
#                            reissue -- recommended for a genuinely first-time
#                            domain, to avoid burning production rate-limit
#                            attempts on a config that isn't verified working
#                            yet. Skipped by default (assumes you've already
#                            verified DNS/port-80 reachability, e.g. by
#                            re-running this script on a box that already has
#                            a working cert).
#   --force-env              Overwrite an existing .env instead of leaving it
#                            untouched (secrets are re-generated -- existing
#                            sessions/logins will be invalidated).
#   --proxy-mode MODE        auto (default) | cloudflare | direct. Controls
#                            CLIENT_IP_HEADER/CLIENT_IP_TRUST_MIDDLEWARE in
#                            .env (see config.py and dynamic.yml.tmpl) --
#                            which header the app trusts for the visitor's
#                            real IP, and whether Traefik itself enforces
#                            that only Cloudflare's published ranges may
#                            reach it. "auto" resolves --domain and compares
#                            against this host's own public IP and against
#                            Cloudflare's published ranges; pass "cloudflare"
#                            or "direct" to force a choice instead (e.g. if
#                            outbound DNS/HTTP from this host can't reach the
#                            resolvers/IP-echo services auto-detection needs).
#   --skip-stack             Do everything except `docker compose up`
#                            (useful to only (re)provision the host-executor
#                            SSH pipeline, e.g. when migrating --deploy-user).
#   --skip-docker            Skip installing Docker and skip adding
#                            --deploy-user to the docker group -- use if you
#                            already manage Docker yourself (a different
#                            install method/version pin) and just want this
#                            script's other phases.
#   --sqlite                 Use a local SQLite file instead of the
#                            docker-compose `postgres` service (writes
#                            DATABASE_URL=sqlite:///./data/app.db into a
#                            fresh .env explicitly). Postgres is the default
#                            otherwise -- see config.py's
#                            _default_database_url() docstring for why this
#                            script no longer writes DATABASE_URL at all in
#                            the non-sqlite case.

set -euo pipefail

# --- Defaults -----------------------------------------------------------
DOMAIN=""
ACME_EMAIL=""
# See setup.sh's own CAPTCHA_PROVIDER/TURNSTILE_*/RECAPTCHA_* defaults
# block for why each `*_KEY=` default is deliberately unquoted-empty and
# separated from the next `*_KEY`-shaped line by a comment (gitleaks
# false-positive avoidance, verified with a real local gitleaks run, not
# just reasoned about -- a `*_SET` breaker variable does NOT work here, it
# re-triggers the same rule since its own name is `*_KEY`-shaped too).
CAPTCHA_PROVIDER=
# (separator -- see comment above)
TURNSTILE_SITE_KEY=
# (separator -- see comment above)
TURNSTILE_SECRET_KEY=
# (separator -- see comment above)
RECAPTCHA_SITE_KEY=
# (separator -- see comment above)
RECAPTCHA_SECRET_KEY=
DEPLOY_USER="ubuntu"
IMAGE_TAG="latest"
REPO_DIR="/opt/cyferio"
USE_STAGING_FIRST=0
FORCE_ENV=0
SKIP_STACK=0
SKIP_DOCKER=0
PROXY_MODE="auto"
USE_SQLITE=0

log() { echo "[setup-new-machine] $*"; }
die() { echo "[setup-new-machine] ERROR: $*" >&2; exit 1; }

# --- Arg parsing ----------------------------------------------------------
while [[ $# -gt 0 ]]; do
	case "$1" in
		--domain) DOMAIN="$2"; shift 2 ;;
		--acme-email) ACME_EMAIL="$2"; shift 2 ;;
		--captcha-provider) CAPTCHA_PROVIDER="$2"; shift 2 ;;
		--turnstile-site-key) TURNSTILE_SITE_KEY="$2"; shift 2 ;;
		--turnstile-secret-key) TURNSTILE_SECRET_KEY="$2"; shift 2 ;;
		--recaptcha-site-key) RECAPTCHA_SITE_KEY="$2"; shift 2 ;;
		--recaptcha-secret-key) RECAPTCHA_SECRET_KEY="$2"; shift 2 ;;
		--deploy-user) DEPLOY_USER="$2"; shift 2 ;;
		--image-tag) IMAGE_TAG="$2"; shift 2 ;;
		--repo-dir) REPO_DIR="$2"; shift 2 ;;
		--use-staging-first) USE_STAGING_FIRST=1; shift ;;
		--force-env) FORCE_ENV=1; shift ;;
		--proxy-mode) PROXY_MODE="$2"; shift 2 ;;
		--skip-stack) SKIP_STACK=1; shift ;;
		--skip-docker) SKIP_DOCKER=1; shift ;;
		--sqlite) USE_SQLITE=1; shift ;;
		-h|--help) sed -n '2,118p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
		*) die "Unknown argument: $1 (see --help)" ;;
	esac
done

case "$PROXY_MODE" in
	auto|cloudflare|direct) ;;
	*) die "--proxy-mode must be one of: auto, cloudflare, direct (got '$PROXY_MODE')." ;;
esac

# Same per-provider required-key-pair shape as setup.sh's own
# --captcha-provider validation (kept here too since this script is meant
# to be safely callable on its own, not only via setup.sh -- see this
# script's header).
if [[ -n "$CAPTCHA_PROVIDER" ]]; then
	case "$CAPTCHA_PROVIDER" in
		turnstile)
			[[ -n "$TURNSTILE_SITE_KEY" ]] || die "--captcha-provider turnstile requires --turnstile-site-key."
			[[ -n "$TURNSTILE_SECRET_KEY" ]] || die "--captcha-provider turnstile requires --turnstile-secret-key."
			;;
		recaptcha)
			[[ -n "$RECAPTCHA_SITE_KEY" ]] || die "--captcha-provider recaptcha requires --recaptcha-site-key."
			[[ -n "$RECAPTCHA_SECRET_KEY" ]] || die "--captcha-provider recaptcha requires --recaptcha-secret-key."
			;;
		*) die "--captcha-provider must be 'turnstile' or 'recaptcha' (got '$CAPTCHA_PROVIDER')." ;;
	esac
fi

[[ "$EUID" -eq 0 ]] || die "Must run as root (sudo ./setup-new-machine.sh ...)."

# UBUNTU ONLY -- install_docker() below uses Docker's official Ubuntu apt
# repo, and everything else in this script (and the rest of this repo's
# bootstrap scripts) assumes apt-get. Fail loudly and immediately rather
# than getting partway through and hitting a confusing "apt-get: command
# not found" deep inside install_docker().
if [[ -r /etc/os-release ]]; then
	# shellcheck disable=SC1091
	. /etc/os-release
else
	die "Cannot read /etc/os-release to confirm this is Ubuntu -- refusing to guess."
fi
[[ "${ID:-}" == "ubuntu" ]] || die "This script only supports Ubuntu (detected: ${PRETTY_NAME:-${ID:-unknown}}). See this script's header for why."
log "Confirmed OS: ${PRETTY_NAME:-Ubuntu} (${VERSION_CODENAME:-unknown codename})"

[[ "$DEPLOY_USER" != "root" ]] || die "--deploy-user must not be root -- see this script's header for why."
[[ -d "$REPO_DIR" ]] || die "$REPO_DIR does not exist -- clone the repo there first (see this script's header, prereq 3)."
id "$DEPLOY_USER" &>/dev/null || die "User '$DEPLOY_USER' does not exist on this host."

# If --domain wasn't given (e.g. re-running this script only to migrate
# --deploy-user against an existing, already-configured box), fall back to
# whatever's already in .env -- needed for the final curl check below to
# hit the right hostname rather than a meaningless "localhost".
if [[ -z "$DOMAIN" && -f "$REPO_DIR/.env" ]]; then
	DOMAIN=$(grep -E '^APP_DOMAIN=' "$REPO_DIR/.env" | head -1 | cut -d= -f2-)
fi

SECRETS_DIR="$REPO_DIR/secrets"
DEPLOY_KEY="$SECRETS_DIR/cyferio-deploy-key"
# The project was renamed from "openvpn-toolkit" to "cyferio" (2026-08-19)
# -- setup_host_executor() below detects and migrates a box provisioned
# under these old names instead of generating a parallel duplicate set.
LEGACY_DEPLOY_KEY="$SECRETS_DIR/openvpn-toolkit-deploy-key"
FORCED_COMMAND_SCRIPT="$REPO_DIR/scripts/ssh_forced_command.sh"
REMOTE_SCRIPT_PATH="$REPO_DIR/app/cli/openvpn_admin.py"
SUDOERS_FILE="/etc/sudoers.d/cyferio-host-executor"
LEGACY_SUDOERS_FILE="/etc/sudoers.d/openvpn-toolkit-host-executor"
DEPLOY_USER_HOME=$(getent passwd "$DEPLOY_USER" | cut -d: -f6)
DEPLOY_USER_SSH_DIR="$DEPLOY_USER_HOME/.ssh"

# --- Phase 1: install Docker (Ubuntu apt repo) ----------------------------
#
# Follows docs.docker.com/engine/install/ubuntu exactly: remove old
# conflicting packages, add Docker's GPG key + apt repo, install the CE
# packages (including the docker-compose-plugin this whole stack depends
# on -- `docker compose`, not the standalone `docker-compose` binary).
# Idempotent: if `docker` and `docker compose` both already work, this is a
# no-op -- doesn't touch apt sources or reinstall anything, so re-running
# this script never fights a differently-pinned Docker version an operator
# installed by hand.
install_docker() {
	log "Phase 1: Docker installation"

	if command -v docker &>/dev/null && docker compose version &>/dev/null; then
		log "  docker + docker compose already present ($(docker --version)) -- skipping install."
		return
	fi

	log "  removing any conflicting distro-packaged docker bits (safe no-op if none installed)..."
	for pkg in docker.io docker-doc docker-compose podman-docker containerd runc; do
		apt-get remove -y "$pkg" >/dev/null 2>&1 || true
	done

	log "  adding Docker's official apt repo..."
	apt-get update -qq
	apt-get install -y -qq ca-certificates curl
	install -m 0755 -d /etc/apt/keyrings
	curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
	chmod a+r /etc/apt/keyrings/docker.asc

	# shellcheck disable=SC1091
	local codename
	codename=$(. /etc/os-release && echo "$VERSION_CODENAME")
	echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $codename stable" \
		| tee /etc/apt/sources.list.d/docker.list > /dev/null

	log "  installing docker-ce, docker-compose-plugin, and friends..."
	apt-get update -qq
	apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

	systemctl is-active --quiet docker || systemctl enable --now docker

	command -v docker &>/dev/null || die "Docker install completed but 'docker' still isn't on PATH -- something went wrong."
	docker compose version &>/dev/null || die "Docker install completed but 'docker compose' doesn't work -- docker-compose-plugin may have failed to install."
	log "  installed: $(docker --version)"
}

# --deploy-user needs to run `docker`/`docker compose` by hand (debugging,
# manual `docker compose logs`, etc.) without sudo -- membership in the
# `docker` group grants that. This script's OWN docker/compose calls below
# never depend on this (the script runs as root throughout, which always
# has docker.sock access regardless of group membership) -- this phase is
# purely for the human operator's convenience afterward.
#
# SECURITY NOTE (worth being explicit about, matching this repo's existing
# "minimal privilege footprint" stance elsewhere -- see add-machine.sh's own
# header): membership in the docker group is root-equivalent on this host --
# anyone in it can bind-mount the root filesystem into a container and read/
# write anything as root. This is not a stronger claim than Docker's own
# docs make; it's just worth restating next to the line of code that grants
# it, rather than only in Docker's own documentation.
#
# Group membership changes do NOT apply to already-open sessions -- only to
# NEW logins (or a subshell started with `newgrp`/`sg`). This script cannot
# reach into your current SSH session and rewrite its process's supplementary
# group list for you (nothing running outside this script's own process tree
# can), so instead of pretending to "handle" that, it prints the two ways to
# actually pick it up (see the log lines below) and moves on -- nothing else
# in this script needs $DEPLOY_USER's docker-group membership to succeed.
configure_docker_group() {
	log "Phase 1b: docker group for $DEPLOY_USER"

	if id -nG "$DEPLOY_USER" | tr ' ' '\n' | grep -qx docker; then
		log "  $DEPLOY_USER is already in the docker group."
		return
	fi

	usermod -aG docker "$DEPLOY_USER"
	log "  added $DEPLOY_USER to the docker group."
	log "  NOTE: this does NOT apply to any SSH session already open as $DEPLOY_USER"
	log "  (this script itself is unaffected -- it runs as root, which always has"
	log "  docker.sock access). For $DEPLOY_USER to run 'docker'/'docker compose'"
	log "  WITHOUT sudo in an existing session, either start a NEW SSH session, or"
	log "  run 'newgrp docker' inside the current one (applies immediately, no"
	log "  reconnect needed, but only affects that one shell)."
}

# --- Phase 2: host-executor SSH key + forced command + sudoers -----------
#
# Deliberately the deploy user (ubuntu), never root: even with the forced-
# command wrapper restricting *what* this key can run, a root SSH session is
# categorically higher blast-radius than a regular user's session escalated
# via a sudo rule scoped to one exact absolute command -- and "root login
# enabled" is flagged by most security scanners/compliance checks regardless
# of what restricts it. This mirrors how Ansible/Terraform-style
# provisioners actually operate: connect as a normal deploy user, escalate
# only for the specific need.
setup_host_executor() {
	log "Phase 2: host-executor SSH key + forced command + sudoers (user: $DEPLOY_USER)"

	mkdir -p "$SECRETS_DIR"
	if [[ -f "$DEPLOY_KEY" ]]; then
		log "  key already exists at $DEPLOY_KEY -- reusing."
	elif [[ -f "$LEGACY_DEPLOY_KEY" ]]; then
		# Renamed in place rather than regenerated -- the authorized_keys
		# entry below is keyed off this file's actual bytes (via
		# $DEPLOY_KEY.pub), not its filename or -C comment, so reusing it
		# needs no new authorized_keys/sudoers churn beyond what this
		# function already does unconditionally on every run.
		log "  found an older-named key ($LEGACY_DEPLOY_KEY) from before the openvpn-toolkit -> cyferio rename -- renaming it to $DEPLOY_KEY instead of generating a new one."
		mv "$LEGACY_DEPLOY_KEY" "$DEPLOY_KEY"
		mv "${LEGACY_DEPLOY_KEY}.pub" "${DEPLOY_KEY}.pub"
	else
		ssh-keygen -t ed25519 -f "$DEPLOY_KEY" -N "" -C "cyferio-app-host-executor" -q
		log "  generated new key at $DEPLOY_KEY"
	fi
	chmod 600 "$DEPLOY_KEY"
	chmod 644 "$DEPLOY_KEY.pub"

	mkdir -p "$(dirname "$FORCED_COMMAND_SCRIPT")"
	cat > "$FORCED_COMMAND_SCRIPT" <<SCRIPT
#!/bin/bash
# Restricts the cyferio-app-host-executor SSH key (see
# services/system/host_executor.py) to exactly one command shape:
#   sudo -n python3 $REMOTE_SCRIPT_PATH <action> [args...]
# Installed as the forced \`command=\` for that key in $DEPLOY_USER's
# authorized_keys -- SSH always runs this wrapper instead of whatever the
# client asked for, with the client's actual request in
# \$SSH_ORIGINAL_COMMAND, so a compromised app container can't use this key
# to run anything else on the host. Generated by setup-new-machine.sh --
# re-run that script to regenerate if REPO_DIR ever changes.
set -euo pipefail
ALLOWED_PREFIX="sudo -n python3 $REMOTE_SCRIPT_PATH "
if [[ "\${SSH_ORIGINAL_COMMAND:-}" != \${ALLOWED_PREFIX}* ]]; then
    echo "Rejected: only openvpn_admin.py invocations are permitted via this key." >&2
    exit 1
fi
exec \${SSH_ORIGINAL_COMMAND}
SCRIPT
	chmod 755 "$FORCED_COMMAND_SCRIPT"
	chown root:root "$FORCED_COMMAND_SCRIPT"
	log "  wrote forced-command wrapper at $FORCED_COMMAND_SCRIPT"

	# sudoers grant: exactly one absolute command, NOPASSWD (the SSH session
	# itself is the authentication factor -- see the plan's §2a). Written to
	# a temp file and validated with visudo -c before installing, so a typo
	# here can never leave sudo itself broken.
	local tmp_sudoers
	tmp_sudoers=$(mktemp)
	echo "$DEPLOY_USER ALL=(root) NOPASSWD: /usr/bin/python3 $REMOTE_SCRIPT_PATH *" > "$tmp_sudoers"
	visudo -c -f "$tmp_sudoers" || die "Generated sudoers rule failed validation -- not installed."
	install -m 440 -o root -g root "$tmp_sudoers" "$SUDOERS_FILE"
	rm -f "$tmp_sudoers"
	log "  installed sudoers grant at $SUDOERS_FILE"
	if [[ -f "$LEGACY_SUDOERS_FILE" ]]; then
		rm -f "$LEGACY_SUDOERS_FILE"
		log "  removed the older-named sudoers file at $LEGACY_SUDOERS_FILE (superseded by $SUDOERS_FILE)."
	fi

	# authorized_keys entry for $DEPLOY_USER -- appended, never overwritten
	# wholesale (that file may already carry the operator's own login
	# key). Matched by the actual KEY MATERIAL (the "type base64blob"
	# fields), not by the -C comment string -- found live on a box
	# provisioned before a naming convention settled ("openvpn-toolkit-
	# host-executor", no "-app-" in the middle, unlike every other box's
	# "openvpn-toolkit-app-host-executor"): matching on comment text is
	# only ever as good as having enumerated every historical variant,
	# and this one wasn't. A key's base64 material can't have that kind
	# of drift, so it's the one thing safe to match on regardless of
	# whatever comment any past version of this script (or a manual
	# setup) happened to embed. The line's content can still be stale
	# even when the key matches: its command="$FORCED_COMMAND_SCRIPT"
	# path is REPO_DIR-dependent, and a box migrated from
	# /opt/openvpn-toolkit to /opt/cyferio has an old path baked in that
	# a bare "this key is already present -> skip" check would leave
	# broken forever (same "detect stale content, replace in place"
	# reasoning host_scripts_manager.py's server.conf block uses) --
	# found exactly this live on a real box: the stale line's forced-
	# command script no longer existed at its old path, so every
	# invocation over this key failed with "No such file or directory"
	# until the entry was corrected.
	mkdir -p "$DEPLOY_USER_SSH_DIR"
	touch "$DEPLOY_USER_SSH_DIR/authorized_keys"
	chmod 700 "$DEPLOY_USER_SSH_DIR"
	chmod 600 "$DEPLOY_USER_SSH_DIR/authorized_keys"
	chown -R "$DEPLOY_USER:$DEPLOY_USER" "$DEPLOY_USER_SSH_DIR"
	KEY_MATERIAL=$(awk '{print $1, $2}' "$DEPLOY_KEY.pub")
	DESIRED_AUTHKEYS_LINE=$(printf 'command="%s",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty %s' \
		"$FORCED_COMMAND_SCRIPT" "$(cat "$DEPLOY_KEY.pub")")
	if grep -qF "$DESIRED_AUTHKEYS_LINE" "$DEPLOY_USER_SSH_DIR/authorized_keys" 2>/dev/null; then
		log "  authorized_keys entry for $DEPLOY_USER already present and up to date -- left as-is."
	elif grep -qF "$KEY_MATERIAL" "$DEPLOY_USER_SSH_DIR/authorized_keys" 2>/dev/null; then
		# Drop every line carrying this key's material (there could be
		# more than one stale duplicate left over from an earlier bad
		# run) and append one fresh, correct line.
		grep -vF "$KEY_MATERIAL" "$DEPLOY_USER_SSH_DIR/authorized_keys" > "$DEPLOY_USER_SSH_DIR/authorized_keys.tmp"
		mv "$DEPLOY_USER_SSH_DIR/authorized_keys.tmp" "$DEPLOY_USER_SSH_DIR/authorized_keys"
		chmod 600 "$DEPLOY_USER_SSH_DIR/authorized_keys"
		chown "$DEPLOY_USER:$DEPLOY_USER" "$DEPLOY_USER_SSH_DIR/authorized_keys"
		printf '%s\n' "$DESIRED_AUTHKEYS_LINE" >> "$DEPLOY_USER_SSH_DIR/authorized_keys"
		log "  updated a stale authorized_keys entry for $DEPLOY_USER (command= path had changed)."
	else
		printf '%s\n' "$DESIRED_AUTHKEYS_LINE" >> "$DEPLOY_USER_SSH_DIR/authorized_keys"
		log "  added authorized_keys entry for $DEPLOY_USER"
	fi

	# Clean up any earlier root-based setup from before this script existed
	# (see the migration this was written for) -- safe no-op if none exists.
	# Matched by key material, same reasoning as above.
	if [[ -f /root/.ssh/authorized_keys ]] && grep -qF "$KEY_MATERIAL" /root/.ssh/authorized_keys 2>/dev/null; then
		grep -vF "$KEY_MATERIAL" /root/.ssh/authorized_keys > /root/.ssh/authorized_keys.tmp
		mv /root/.ssh/authorized_keys.tmp /root/.ssh/authorized_keys
		chmod 600 /root/.ssh/authorized_keys
		log "  removed a pre-existing root authorized_keys entry for this key (migrating off root login)."
	fi

	# Self-test: confirm the key can run the allowed command and is
	# rejected for anything else, using the actual openvpn_admin.py `status`
	# action (harmless, read-only).
	log "  verifying key works and is properly restricted..."
	if ssh -i "$DEPLOY_KEY" -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
		"$DEPLOY_USER@127.0.0.1" -- sudo -n python3 "$REMOTE_SCRIPT_PATH" status >/dev/null 2>&1; then
		log "  OK: allowed command succeeds."
	else
		die "Self-test failed: '$DEPLOY_USER' could not run the allowed command over the new key. Check sshd_config allows key auth for this user, and that $REMOTE_SCRIPT_PATH exists."
	fi
	if ssh -i "$DEPLOY_KEY" -o BatchMode=yes "$DEPLOY_USER@127.0.0.1" -- whoami >/dev/null 2>&1; then
		die "Self-test failed: an arbitrary command ('whoami') was NOT rejected -- the forced-command restriction isn't working. Refusing to continue with a broken security boundary."
	else
		log "  OK: arbitrary commands are rejected."
	fi
}

# --- Phase 3: .env -----------------------------------------------------
write_env() {
	log "Phase 3: .env"
	local env_file="$REPO_DIR/.env"

	if [[ -f "$env_file" && "$FORCE_ENV" -eq 0 ]]; then
		log "  $env_file already exists -- leaving it otherwise untouched (pass --force-env to regenerate)."
		# Still make sure the values this script cares about are present...
		_ensure_env_line "$env_file" "HOST_SSH_TARGET" "$DEPLOY_USER@$(_private_ip)"
		_ensure_env_line "$env_file" "HOST_SSH_KEY_SOURCE_PATH" "./secrets/cyferio-deploy-key"
		# ...and if HOST_SSH_TARGET already exists but under a different
		# user than --deploy-user (e.g. re-running this script with
		# --deploy-user ubuntu against a box previously set up with root),
		# update just that user, preserving the existing host/IP.
		_sync_host_ssh_target_user "$env_file"
		# CLIENT_IP_HEADER/CLIENT_IP_TRUST_MIDDLEWARE: only add if genuinely
		# missing (an existing deployment's choice here -- possibly
		# hand-edited -- is never overwritten just by re-running this
		# script; --proxy-mode + --force-env is the explicit way to redo
		# detection).
		if ! grep -q '^CLIENT_IP_HEADER=' "$env_file" 2>/dev/null; then
			detect_proxy_mode
			_ensure_env_line "$env_file" "CLIENT_IP_HEADER" "$CLIENT_IP_HEADER"
			_ensure_env_line "$env_file" "CLIENT_IP_TRUST_MIDDLEWARE" "$CLIENT_IP_TRUST_MIDDLEWARE"
			log "  proxy mode: CLIENT_IP_HEADER=$CLIENT_IP_HEADER CLIENT_IP_TRUST_MIDDLEWARE=$CLIENT_IP_TRUST_MIDDLEWARE"
		fi
		# CAPTCHA_PROVIDER/*_KEY: unlike HOST_SSH_TARGET/CLIENT_IP_HEADER
		# above, this script has no in-place upsert for these -- an existing
		# .env's CAPTCHA config (on, off, or a different provider) is an
		# admin's own choice, possibly hand-edited since this script last
		# ran, and is left exactly as-is. If --captcha-provider was passed
		# against an existing .env, say so loudly rather than silently
		# discarding it, so it's obvious why nothing changed.
		if [[ -n "$CAPTCHA_PROVIDER" ]]; then
			log "  NOTE: --captcha-provider $CAPTCHA_PROVIDER was given, but $env_file already exists and --force-env wasn't passed -- CAPTCHA settings in the existing file are left untouched (same limitation as every other value in the main .env template; re-run with --force-env to apply it, or edit $env_file by hand)."
		fi
		return
	fi

	[[ -n "$DOMAIN" ]] || die "--domain is required to write a fresh .env."
	[[ -n "$ACME_EMAIL" ]] || die "--acme-email is required to write a fresh .env."

	detect_proxy_mode
	log "  proxy mode: CLIENT_IP_HEADER=$CLIENT_IP_HEADER CLIENT_IP_TRUST_MIDDLEWARE=$CLIENT_IP_TRUST_MIDDLEWARE"

	local secret_key admin_password pg_password
	secret_key=$(python3 -c "import secrets; print(secrets.token_hex(32))")
	admin_password=$(python3 -c "import secrets; print(secrets.token_urlsafe(18))")
	pg_password=$(python3 -c "import secrets; print(secrets.token_urlsafe(24))")

	# Postgres is the default (config.py's _default_database_url() builds it
	# automatically from POSTGRES_PASSWORD below, which is always written) --
	# DATABASE_URL is only written here explicitly for --sqlite, the opt-out.
	local database_url_line=""
	if [[ "$USE_SQLITE" -eq 1 ]]; then
		database_url_line="DATABASE_URL=sqlite:///./data/app.db"
	fi

	# CAPTCHA_PROVIDER/TURNSTILE_*/RECAPTCHA_*: written blank (disabled,
	# matching .env.example's own documented default) unless
	# --captcha-provider was given -- the non-active provider's key pair is
	# always left blank too, e.g. choosing turnstile writes empty
	# RECAPTCHA_SITE_KEY/RECAPTCHA_SECRET_KEY lines, exactly mirroring how
	# config.py/captcha.py only ever look at the pair matching
	# CAPTCHA_PROVIDER and ignore the other provider's vars regardless of
	# their value.
	local turnstile_site_key_line="" turnstile_secret_key_line=""
	local recaptcha_site_key_line="" recaptcha_secret_key_line=""
	case "$CAPTCHA_PROVIDER" in
		turnstile)
			turnstile_site_key_line="$TURNSTILE_SITE_KEY"
			turnstile_secret_key_line="$TURNSTILE_SECRET_KEY"
			;;
		recaptcha)
			recaptcha_site_key_line="$RECAPTCHA_SITE_KEY"
			recaptcha_secret_key_line="$RECAPTCHA_SECRET_KEY"
			;;
	esac

	cat > "$env_file" <<ENVFILE
$database_url_line
SECRET_KEY=$secret_key
SESSION_HTTPS_ONLY=true

OPENVPN_INSTALL_SCRIPT=$REPO_DIR/openvpn-install.sh
VPN_STATUS_SCRIPT=$REPO_DIR/vpn-status.py
USE_SUDO=false

HOST=0.0.0.0
PORT=8000

BOOTSTRAP_ADMIN_USERNAME=admin
BOOTSTRAP_ADMIN_PASSWORD=$admin_password

APP_DOMAIN=$DOMAIN
ACME_EMAIL=$ACME_EMAIL
ACME_CASERVER=$([[ "$USE_STAGING_FIRST" -eq 1 ]] && echo "https://acme-staging-v02.api.letsencrypt.org/directory" || echo "")

CLIENT_IP_HEADER=$CLIENT_IP_HEADER
CLIENT_IP_TRUST_MIDDLEWARE=$CLIENT_IP_TRUST_MIDDLEWARE

IMAGE_TAG=$IMAGE_TAG

POSTGRES_USER=vpnadmin
POSTGRES_PASSWORD=$pg_password
POSTGRES_DB=vpnadmin

HOST_SSH_TARGET=$DEPLOY_USER@$(_private_ip)
HOST_SSH_KEY_SOURCE_PATH=./secrets/cyferio-deploy-key
HOST_SSH_PORT=22
HOST_SSH_REMOTE_SCRIPT_PATH=$REMOTE_SCRIPT_PATH
HOST_SSH_USE_SUDO=true
HOST_SSH_TIMEOUT_SECONDS=180

CAPTCHA_PROVIDER=$CAPTCHA_PROVIDER
TURNSTILE_SITE_KEY=$turnstile_site_key_line
TURNSTILE_SECRET_KEY=$turnstile_secret_key_line
RECAPTCHA_SITE_KEY=$recaptcha_site_key_line
RECAPTCHA_SECRET_KEY=$recaptcha_secret_key_line
ENVFILE
	chmod 600 "$env_file"
	mkdir -p "$REPO_DIR/app/data"

	log "  wrote $env_file"
	log "  BOOTSTRAP_ADMIN_USERNAME=admin  BOOTSTRAP_ADMIN_PASSWORD=$admin_password"
	log "  (shown once -- also readable later via: grep BOOTSTRAP_ADMIN_PASSWORD $env_file)"
	if [[ -n "$CAPTCHA_PROVIDER" ]]; then
		log "  CAPTCHA_PROVIDER=$CAPTCHA_PROVIDER (enabled on /login and /forgot-password)"
	else
		log "  CAPTCHA_PROVIDER= (disabled -- pass --captcha-provider to setup.sh/setup-new-machine.sh to enable, or edit .env by hand later)"
	fi
}

# --- Proxy/CDN detection: decides CLIENT_IP_HEADER + CLIENT_IP_TRUST_MIDDLEWARE
#
# Pinned Cloudflare edge ranges (https://www.cloudflare.com/ips-v4,
# https://www.cloudflare.com/ips-v6, as of 2026-08-11 -- same list committed
# in app/traefik/dynamic.yml.tmpl's cloudflare-only middleware, kept in sync
# manually since this is a plain bash bootstrap script, not something that
# parses that YAML file).
_CF_RANGES="173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 141.101.64.0/18 108.162.192.0/18 190.93.240.0/20 188.114.96.0/20 197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/13 104.24.0.0/14 172.64.0.0/13 131.0.72.0/22 2400:cb00::/32 2606:4700::/32 2803:f800::/32 2405:b500::/32 2405:8100::/32 2a06:98c0::/29 2c0f:f248::/32"

_public_ip() {
	curl -s -4 -m 8 https://api.ipify.org 2>/dev/null \
		|| curl -s -4 -m 8 https://ifconfig.me 2>/dev/null \
		|| true
}

# Sets globals CLIENT_IP_HEADER and CLIENT_IP_TRUST_MIDDLEWARE. Called with
# PROXY_MODE and (for "auto") $DOMAIN already populated.
detect_proxy_mode() {
	if [[ "$PROXY_MODE" == "cloudflare" ]]; then
		log "  --proxy-mode cloudflare (forced): CLIENT_IP_HEADER=CF-Connecting-IP, enforcing Cloudflare-only ingress."
		CLIENT_IP_HEADER="CF-Connecting-IP"
		CLIENT_IP_TRUST_MIDDLEWARE="cloudflare-only"
		return
	fi
	if [[ "$PROXY_MODE" == "direct" ]]; then
		log "  --proxy-mode direct (forced): CLIENT_IP_HEADER=X-Forwarded-For, no ingress IP enforcement."
		CLIENT_IP_HEADER="X-Forwarded-For"
		CLIENT_IP_TRUST_MIDDLEWARE="allow-all"
		return
	fi

	# auto
	[[ -n "$DOMAIN" ]] || die "--domain is required to auto-detect --proxy-mode (or pass --proxy-mode cloudflare|direct explicitly)."
	local resolved_ip public_ip
	resolved_ip=$(getent ahostsv4 "$DOMAIN" 2>/dev/null | awk '{print $1; exit}')
	public_ip=$(_public_ip)

	if [[ -z "$resolved_ip" ]]; then
		log "  auto-detect: could not resolve $DOMAIN -- defaulting to direct (no enforcement). Fix DNS and re-run, or pass --proxy-mode explicitly."
		CLIENT_IP_HEADER="X-Forwarded-For"
		CLIENT_IP_TRUST_MIDDLEWARE="allow-all"
		return
	fi

	if python3 -c "
import ipaddress, sys
ip = ipaddress.ip_address('$resolved_ip')
ranges = '$_CF_RANGES'.split()
sys.exit(0 if any(ip in ipaddress.ip_network(r) for r in ranges) else 1)
" 2>/dev/null; then
		log "  auto-detect: $DOMAIN resolves to $resolved_ip, inside Cloudflare's published ranges -> Cloudflare-proxied."
		CLIENT_IP_HEADER="CF-Connecting-IP"
		CLIENT_IP_TRUST_MIDDLEWARE="cloudflare-only"
	elif [[ -n "$public_ip" && "$resolved_ip" == "$public_ip" ]]; then
		log "  auto-detect: $DOMAIN resolves to $resolved_ip, matching this host's own public IP ($public_ip) -> direct."
		CLIENT_IP_HEADER="X-Forwarded-For"
		CLIENT_IP_TRUST_MIDDLEWARE="allow-all"
	else
		log "  auto-detect: $DOMAIN resolves to $resolved_ip, which is neither a Cloudflare range nor this host's own public IP (${public_ip:-<could not determine>}) -- inconclusive (stale DNS? another CDN/load balancer?). Defaulting to direct/no-enforcement rather than guessing wrong; pass --proxy-mode explicitly once you know which applies."
		CLIENT_IP_HEADER="X-Forwarded-For"
		CLIENT_IP_TRUST_MIDDLEWARE="allow-all"
	fi
}

_private_ip() {
	# Prefers the host's real (non-loopback, non-Docker) interface address --
	# same filtering logic as services/system/network_manager.py's
	# resolve_install_ip(), kept in sync manually since this is a plain bash
	# bootstrap script, not something that imports that module.
	ip -4 addr show scope global \
		| awk '/inet /{print $2, $NF}' \
		| cut -d/ -f1,3 \
		| awk '{print $1, $2}' \
		| while read -r addr iface; do
			case "$iface" in
				docker*|br-*|veth*|cni*|flannel*|cali*|tun*|tap*) continue ;;
				*) echo "$addr"; break ;;
			esac
		done
}

_ensure_env_line() {
	local file="$1" key="$2" value="$3"
	if grep -q "^${key}=" "$file" 2>/dev/null; then
		return
	fi
	echo "${key}=${value}" >> "$file"
	log "  added missing ${key} to existing .env"
}

_sync_host_ssh_target_user() {
	local file="$1" current current_user current_host
	current=$(grep -E '^HOST_SSH_TARGET=' "$file" | head -1 | cut -d= -f2-)
	[[ -n "$current" && "$current" == *"@"* ]] || return
	current_user="${current%%@*}"
	current_host="${current#*@}"
	if [[ "$current_user" != "$DEPLOY_USER" ]]; then
		sed -i "s|^HOST_SSH_TARGET=.*|HOST_SSH_TARGET=${DEPLOY_USER}@${current_host}|" "$file"
		log "  updated HOST_SSH_TARGET user: '$current_user' -> '$DEPLOY_USER' (host unchanged: $current_host)"
	fi
}

# --- Phase 3b: vpn-tools.conf OVPN_OUTPUT_DIR (Docker-visible delivery) --
#
# openvpn-install.sh's default OVPN_OUTPUT_DIR (whoever ran sudo's home
# dir, see openvpn-install.sh:124-141) is NOT visible inside the app
# container -- only /etc/openvpn (rw) and /var/log/openvpn (ro) are
# bind-mounted (see docker-compose.yml). Without this override, every
# --show-ovpn/--add-client call the containerized app makes reports "no
# .ovpn file found" even though the file genuinely exists on the host,
# just outside the container's view -- reproduced and root-caused on the
# 34.182.51.24 test box on 2026-08-11 (vpn-tools.conf.example has long
# documented this gotcha; nothing previously acted on it automatically).
# Idempotent: only appends if OVPN_OUTPUT_DIR isn't already set in the
# file (commented or not) -- never touches an operator's own override.
configure_vpn_tools_conf() {
	log "Phase 3b: vpn-tools.conf OVPN_OUTPUT_DIR (Docker-visible delivery path)"
	local conf_file="/etc/openvpn/vpn-tools.conf"
	mkdir -p /etc/openvpn

	if [[ -f "$conf_file" ]] && grep -qE '^OVPN_OUTPUT_DIR=' "$conf_file"; then
		log "  OVPN_OUTPUT_DIR already set in $conf_file -- left as-is."
		return
	fi

	{
		echo ""
		echo "# Docker-visible delivery path for generated .ovpn files -- the"
		echo "# containerized app only bind-mounts /etc/openvpn, so the default"
		echo "# (whoever ran sudo's home dir) is invisible to it. Added by"
		echo "# setup-new-machine.sh; see vpn-tools.conf.example for the full"
		echo "# explanation. Safe to change if you have a different path in mind,"
		echo "# as long as it's under /etc/openvpn."
		echo "OVPN_OUTPUT_DIR=/etc/openvpn/client"
		echo "OVPN_OUTPUT_OWNER=root:root"
	} >> "$conf_file"
	chmod 640 "$conf_file"
	chown root:root "$conf_file"
	mkdir -p /etc/openvpn/client
	log "  set OVPN_OUTPUT_DIR=/etc/openvpn/client in $conf_file."
}

# --- Phase 4: enable the deploy-key volume mount -------------------------
enable_deploy_key_mount() {
	log "Phase 4: enable deploy-key volume mount in docker-compose.yml"
	local compose_file="$REPO_DIR/docker-compose.yml"
	if grep -qE '^\s*-\s*\$\{HOST_SSH_KEY_SOURCE_PATH' "$compose_file"; then
		log "  already enabled."
		return
	fi
	sed -i -E 's|^(\s*)#\s*(-\s*\$\{HOST_SSH_KEY_SOURCE_PATH.*)|\1\2|' "$compose_file"
	if grep -qE '^\s*-\s*\$\{HOST_SSH_KEY_SOURCE_PATH' "$compose_file"; then
		log "  enabled."
	else
		die "Could not find the HOST_SSH_KEY_SOURCE_PATH volume line to uncomment in $compose_file -- has it moved? (This script's sed pattern may need updating.)"
	fi
}

# --- Phase 5: bring the stack up, staging cert first if requested --------
bring_up_stack() {
	log "Phase 5: docker compose up"
	cd "$REPO_DIR"

	docker compose pull
	docker compose up -d

	if [[ "$USE_STAGING_FIRST" -eq 1 ]]; then
		log "  waiting for staging cert to issue..."
		_curl_check_retry || log "  (staging check didn't get a clean 200 yet -- check 'docker compose logs traefik')"

		log "  switching to production Let's Encrypt CA..."
		sed -i 's|^ACME_CASERVER=.*|ACME_CASERVER=|' .env
		docker compose stop traefik
		docker run --rm -v "$(docker compose config --format json | python3 -c 'import json,sys; print(json.load(sys.stdin)["volumes"]["traefik-acme"]["name"])'):/letsencrypt" \
			alpine:3.20 sh -c 'rm -f /letsencrypt/acme.json'
		docker compose up -d traefik
		_curl_check_retry || log "  (production cert check didn't get a clean 200 yet -- check 'docker compose logs traefik')"
	else
		_curl_check_retry || log "  (connectivity check didn't get a clean 200 yet -- containers may still be starting; check 'docker compose ps'/'docker compose logs')"
	fi
}

# Retries for up to ~30s (freshly (re)started containers -- app in
# particular, which runs full Python/uvicorn startup, RBAC seeding, etc. --
# can take a few seconds to bind their port) rather than failing on the
# first attempt. Deliberately never propagates a hard failure via `set -e`
# (every call site above uses `|| log ...`) -- a slow-to-start container on
# an otherwise-successful run shouldn't make the whole script look like it
# failed; the operator can always re-check manually.
_curl_check_retry() {
	local attempt code
	for attempt in 1 2 3 4 5 6; do
		code=$(_curl_check_once)
		if [[ "$code" == "200" ]]; then
			log "  https://${DOMAIN:-localhost}/login -> HTTP $code"
			return 0
		fi
		sleep 5
	done
	log "  https://${DOMAIN:-localhost}/login -> HTTP $code (after $attempt attempts)"
	return 1
}

_curl_check_once() {
	# NOTE: curl's own -w "%{http_code}" already prints "000" on a total
	# connection failure (before it exits non-zero) -- appending `|| echo
	# "000"` here would double that up into a bogus "000000". Capture
	# whatever curl printed and fall back to "000" only if it printed
	# nothing at all (e.g. curl itself failed to start).
	local code
	# `|| true`: under `set -e`, `code=$(cmd)` aborts the whole script the
	# instant curl returns non-zero (e.g. connection refused while the
	# container is still starting) -- exactly the premature-exit bug this
	# retry helper exists to avoid, just one level deeper. The `|| true`
	# only affects how this statement's exit status is treated; `code`
	# still captures whatever curl wrote to stdout either way.
	code=$(curl -sk -m 10 -o /dev/null -w "%{http_code}" "https://${DOMAIN:-localhost}/login" 2>/dev/null) || true
	echo "${code:-000}"
}

# --- Main -----------------------------------------------------------------
DOCKER_GROUP_JUST_ADDED=0
if [[ "$SKIP_DOCKER" -eq 0 ]]; then
	install_docker
	if ! id -nG "$DEPLOY_USER" | tr ' ' '\n' | grep -qx docker; then
		DOCKER_GROUP_JUST_ADDED=1
	fi
	configure_docker_group
else
	log "Skipping Docker install/group setup (--skip-docker)."
fi
setup_host_executor
write_env
configure_vpn_tools_conf
enable_deploy_key_mount
if [[ "$SKIP_STACK" -eq 0 ]]; then
	bring_up_stack
else
	log "Skipping docker compose up (--skip-stack). Run 'docker compose up -d' in $REPO_DIR when ready."
fi

log "Done."
if [[ "$DOCKER_GROUP_JUST_ADDED" -eq 1 ]]; then
	log ""
	log "REMINDER: $DEPLOY_USER was just added to the docker group. If you SSH in"
	log "as $DEPLOY_USER to run docker/docker compose by hand, start a NEW SSH"
	log "session (or run 'newgrp docker' in your current one) -- an already-open"
	log "session won't pick this up on its own."
fi
