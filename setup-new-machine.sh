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
# This is everything a fresh machine needs BEYOND `docker compose up -d`
# itself -- generating the host-executor SSH key + forced-command wrapper +
# sudoers grant, writing .env, enabling the deploy-key volume mount, and
# bringing the stack up (staging cert first, then production).
#
# Prereqs this script does NOT do for you:
#   1. Docker + the Compose plugin already installed on this host.
#   2. A DNS A record for --domain already pointing at this host's public IP
#      (needed for Let's Encrypt's HTTP-01 challenge to succeed).
#   3. This repo already cloned here (private repo -- add a read-only GitHub
#      deploy key first: `ssh-keygen -t ed25519 -f ~/.ssh/openvpn-toolkit-deploy`,
#      then `gh repo deploy-key add --repo cloudlative/openvpn-toolkit
#      ~/.ssh/openvpn-toolkit-deploy.pub`, then clone via that key).
#
# Idempotent: every phase checks its own current state before acting, so
# re-running this (e.g. after changing --deploy-user, or just to pick up a
# newer .env.example) is safe and won't duplicate keys/sudoers
# entries/authorized_keys lines, re-issue a cert that's already valid, or
# clobber an .env you've since hand-edited (see --force-env).
#
# Usage (run as root, or via sudo):
#   sudo ./setup-new-machine.sh \
#     --domain vpn-project.cloudlative.com \
#     --acme-email you@example.com \
#     [--deploy-user ubuntu] [--image-tag 1.0.36] [--repo-dir /opt/openvpn-toolkit] \
#     [--use-staging-first] [--force-env] [--skip-stack]
#
# Flags:
#   --domain DOMAIN         Required. Public hostname Traefik requests a
#                            cert for (sets APP_DOMAIN in .env).
#   --acme-email EMAIL      Required unless .env already has ACME_EMAIL.
#   --deploy-user USER      Non-root user the host-executor SSH key logs in
#                            as, granted narrowly-scoped sudo for exactly
#                            app/cli/openvpn_admin.py (default: ubuntu).
#                            NEVER root -- see this script's own comments in
#                            setup_host_executor() for why.
#   --image-tag TAG         Sets IMAGE_TAG in .env (default: latest).
#   --repo-dir DIR          Where this repo is checked out (default:
#                            /opt/openvpn-toolkit -- must match
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
#   --skip-stack             Do everything except `docker compose up`
#                            (useful to only (re)provision the host-executor
#                            SSH pipeline, e.g. when migrating --deploy-user).

set -euo pipefail

# --- Defaults -----------------------------------------------------------
DOMAIN=""
ACME_EMAIL=""
DEPLOY_USER="ubuntu"
IMAGE_TAG="latest"
REPO_DIR="/opt/openvpn-toolkit"
USE_STAGING_FIRST=0
FORCE_ENV=0
SKIP_STACK=0

log() { echo "[setup-new-machine] $*"; }
die() { echo "[setup-new-machine] ERROR: $*" >&2; exit 1; }

# --- Arg parsing ----------------------------------------------------------
while [[ $# -gt 0 ]]; do
	case "$1" in
		--domain) DOMAIN="$2"; shift 2 ;;
		--acme-email) ACME_EMAIL="$2"; shift 2 ;;
		--deploy-user) DEPLOY_USER="$2"; shift 2 ;;
		--image-tag) IMAGE_TAG="$2"; shift 2 ;;
		--repo-dir) REPO_DIR="$2"; shift 2 ;;
		--use-staging-first) USE_STAGING_FIRST=1; shift ;;
		--force-env) FORCE_ENV=1; shift ;;
		--skip-stack) SKIP_STACK=1; shift ;;
		-h|--help) sed -n '2,60p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
		*) die "Unknown argument: $1 (see --help)" ;;
	esac
done

[[ "$EUID" -eq 0 ]] || die "Must run as root (sudo ./setup-new-machine.sh ...)."
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
DEPLOY_KEY="$SECRETS_DIR/openvpn-toolkit-deploy-key"
FORCED_COMMAND_SCRIPT="$REPO_DIR/scripts/ssh_forced_command.sh"
REMOTE_SCRIPT_PATH="$REPO_DIR/app/cli/openvpn_admin.py"
SUDOERS_FILE="/etc/sudoers.d/openvpn-toolkit-host-executor"
DEPLOY_USER_HOME=$(getent passwd "$DEPLOY_USER" | cut -d: -f6)
DEPLOY_USER_SSH_DIR="$DEPLOY_USER_HOME/.ssh"

# --- Phase 1: host-executor SSH key + forced command + sudoers -----------
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
	log "Phase 1: host-executor SSH key + forced command + sudoers (user: $DEPLOY_USER)"

	mkdir -p "$SECRETS_DIR"
	if [[ -f "$DEPLOY_KEY" ]]; then
		log "  key already exists at $DEPLOY_KEY -- reusing."
	else
		ssh-keygen -t ed25519 -f "$DEPLOY_KEY" -N "" -C "openvpn-toolkit-app-host-executor" -q
		log "  generated new key at $DEPLOY_KEY"
	fi
	chmod 600 "$DEPLOY_KEY"
	chmod 644 "$DEPLOY_KEY.pub"

	mkdir -p "$(dirname "$FORCED_COMMAND_SCRIPT")"
	cat > "$FORCED_COMMAND_SCRIPT" <<SCRIPT
#!/bin/bash
# Restricts the openvpn-toolkit-app-executor SSH key (see
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

	# authorized_keys entry for $DEPLOY_USER -- appended, never overwritten
	# (that file may already carry the operator's own login key).
	mkdir -p "$DEPLOY_USER_SSH_DIR"
	touch "$DEPLOY_USER_SSH_DIR/authorized_keys"
	chmod 700 "$DEPLOY_USER_SSH_DIR"
	chmod 600 "$DEPLOY_USER_SSH_DIR/authorized_keys"
	chown -R "$DEPLOY_USER:$DEPLOY_USER" "$DEPLOY_USER_SSH_DIR"
	if ! grep -q "openvpn-toolkit-app-host-executor" "$DEPLOY_USER_SSH_DIR/authorized_keys" 2>/dev/null; then
		{
			printf 'command="%s",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty %s\n' \
				"$FORCED_COMMAND_SCRIPT" "$(cat "$DEPLOY_KEY.pub")"
		} >> "$DEPLOY_USER_SSH_DIR/authorized_keys"
		log "  added authorized_keys entry for $DEPLOY_USER"
	else
		log "  authorized_keys entry for $DEPLOY_USER already present -- left as-is."
	fi

	# Clean up any earlier root-based setup from before this script existed
	# (see the migration this was written for) -- safe no-op if none exists.
	if [[ -f /root/.ssh/authorized_keys ]] && grep -q "openvpn-toolkit-app-host-executor" /root/.ssh/authorized_keys 2>/dev/null; then
		sed -i '/openvpn-toolkit-app-host-executor/d' /root/.ssh/authorized_keys
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

# --- Phase 2: .env -----------------------------------------------------
write_env() {
	log "Phase 2: .env"
	local env_file="$REPO_DIR/.env"

	if [[ -f "$env_file" && "$FORCE_ENV" -eq 0 ]]; then
		log "  $env_file already exists -- leaving it otherwise untouched (pass --force-env to regenerate)."
		# Still make sure the values this script cares about are present...
		_ensure_env_line "$env_file" "HOST_SSH_TARGET" "$DEPLOY_USER@$(_private_ip)"
		_ensure_env_line "$env_file" "HOST_SSH_KEY_SOURCE_PATH" "./secrets/openvpn-toolkit-deploy-key"
		# ...and if HOST_SSH_TARGET already exists but under a different
		# user than --deploy-user (e.g. re-running this script with
		# --deploy-user ubuntu against a box previously set up with root),
		# update just that user, preserving the existing host/IP.
		_sync_host_ssh_target_user "$env_file"
		return
	fi

	[[ -n "$DOMAIN" ]] || die "--domain is required to write a fresh .env."
	[[ -n "$ACME_EMAIL" ]] || die "--acme-email is required to write a fresh .env."

	local secret_key admin_password pg_password
	secret_key=$(python3 -c "import secrets; print(secrets.token_hex(32))")
	admin_password=$(python3 -c "import secrets; print(secrets.token_urlsafe(18))")
	pg_password=$(python3 -c "import secrets; print(secrets.token_urlsafe(24))")

	cat > "$env_file" <<ENVFILE
DATABASE_URL=sqlite:///./data/app.db
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

IMAGE_TAG=$IMAGE_TAG

POSTGRES_USER=vpnadmin
POSTGRES_PASSWORD=$pg_password
POSTGRES_DB=vpnadmin

HOST_SSH_TARGET=$DEPLOY_USER@$(_private_ip)
HOST_SSH_KEY_SOURCE_PATH=./secrets/openvpn-toolkit-deploy-key
HOST_SSH_PORT=22
HOST_SSH_REMOTE_SCRIPT_PATH=$REMOTE_SCRIPT_PATH
HOST_SSH_USE_SUDO=true
HOST_SSH_TIMEOUT_SECONDS=180
ENVFILE
	chmod 600 "$env_file"
	mkdir -p "$REPO_DIR/app/data"

	log "  wrote $env_file"
	log "  BOOTSTRAP_ADMIN_USERNAME=admin  BOOTSTRAP_ADMIN_PASSWORD=$admin_password"
	log "  (shown once -- also readable later via: grep BOOTSTRAP_ADMIN_PASSWORD $env_file)"
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

# --- Phase 3: enable the deploy-key volume mount -------------------------
enable_deploy_key_mount() {
	log "Phase 3: enable deploy-key volume mount in docker-compose.yml"
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

# --- Phase 4: bring the stack up, staging cert first if requested --------
bring_up_stack() {
	log "Phase 4: docker compose up"
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
setup_host_executor
write_env
enable_deploy_key_mount
if [[ "$SKIP_STACK" -eq 0 ]]; then
	bring_up_stack
else
	log "Skipping docker compose up (--skip-stack). Run 'docker compose up -d' in $REPO_DIR when ready."
fi

log "Done."
