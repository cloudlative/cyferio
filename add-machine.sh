#!/bin/bash
#
# add-machine.sh -- run from YOUR OWN machine (not the target host) to
# bootstrap a fresh box's read-only access to this private repo, then clone
# it there. This is step 1-2 of the "new machine" flow (see app/README.md's
# "First-time setup on a new machine" section) -- setup-new-machine.sh
# (step 3, run ON the target host) picks up from where this leaves off.
#
# Why this has to run locally, not on the target host: registering a GitHub
# deploy key needs an authenticated `gh` session, and this repo's operators
# authenticate `gh` on their own machines, not on every new box they spin
# up. This script generates the actual keypair ON the target host (the
# private half never has to leave it) but registers the public half with
# GitHub from wherever `gh` is already logged in -- i.e. here.
#
# Prereqs:
#   - `gh` CLI installed and authenticated locally (gh auth status).
#   - You can already SSH to the target host as --user (password or an
#     existing key/agent) -- this script only sets up REPO access, not your
#     own login to the box.
#
# What this does, in order:
#   1. SSH to the target host; generate an ed25519 deploy keypair there if
#      one doesn't already exist (idempotent -- never regenerates/orphans
#      an existing one).
#   2. Register the public half as a READ-ONLY deploy key on
#      cloudlative/openvpn-toolkit via `gh repo deploy-key add`, run HERE
#      (skips cleanly if a key with this exact content is already
#      registered).
#   3. Add an SSH config alias on the target host so git operations against
#      this repo unambiguously use that key.
#   4. Clone the repo to --repo-dir on the target host (or `git pull` if
#      it's already cloned there).
#
# Usage:
#   ./add-machine.sh --host 203.0.113.10 [--user ubuntu] \
#     [--repo cloudlative/openvpn-toolkit] [--repo-dir /opt/openvpn-toolkit] \
#     [--key-title "<label shown in GitHub's deploy-key list>"]
#
# After this, log into --host and run setup-new-machine.sh there.

set -euo pipefail

HOST=""
SSH_USER="ubuntu"
GH_REPO="cloudlative/openvpn-toolkit"
REPO_DIR="/opt/openvpn-toolkit"
KEY_TITLE=""

log() { echo "[add-machine] $*"; }
die() { echo "[add-machine] ERROR: $*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
	case "$1" in
		--host) HOST="$2"; shift 2 ;;
		--user) SSH_USER="$2"; shift 2 ;;
		--repo) GH_REPO="$2"; shift 2 ;;
		--repo-dir) REPO_DIR="$2"; shift 2 ;;
		--key-title) KEY_TITLE="$2"; shift 2 ;;
		-h|--help) sed -n '2,45p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
		*) die "Unknown argument: $1 (see --help)" ;;
	esac
done

[[ -n "$HOST" ]] || die "--host is required."
[[ -n "$KEY_TITLE" ]] || KEY_TITLE="$HOST ($(date +%Y-%m-%d), read-only)"

command -v gh >/dev/null 2>&1 || die "gh CLI not found -- install it and run 'gh auth login' first."
gh auth status >/dev/null 2>&1 || die "gh is not authenticated -- run 'gh auth login' first."

SSH_TARGET="$SSH_USER@$HOST"
SSH() { ssh -o BatchMode=yes -o ConnectTimeout=10 "$SSH_TARGET" -- "$@"; }

log "Checking SSH connectivity to $SSH_TARGET..."
SSH "true" >/dev/null 2>&1 || die "Cannot SSH to $SSH_TARGET (key-based, non-interactive). Make sure your own key/agent is already authorized there -- this script bootstraps REPO access, not your login to the box."

# --- Phase 1: generate the deploy keypair on the target host ---------------
#
# Deliberately under /root/.ssh, not $SSH_USER's own home: Phase 4 clones
# via `sudo git clone` (the repo ends up root-owned, matching how
# docker-compose is run there too -- see setup-new-machine.sh), which means
# git runs as root and only ever reads root's own ~/.ssh/config. A key/alias
# placed under $SSH_USER's home would be invisible to that `sudo` git
# process -- the clone would silently fail to resolve the alias and error
# out trying to resolve "github.com-<repo>" as a literal (nonexistent) DNS
# name. Using sudo for every command in this phase (not just the clone
# itself) keeps it consistent with where the key/config actually need to
# live.
REMOTE_KEY_PATH="/root/.ssh/openvpn-toolkit-deploy"
log "Phase 1: deploy keypair on $HOST"
if SSH "sudo test -f $REMOTE_KEY_PATH"; then
	log "  key already exists at $REMOTE_KEY_PATH on $HOST -- reusing."
else
	SSH "sudo mkdir -p /root/.ssh && sudo chmod 700 /root/.ssh && sudo ssh-keygen -t ed25519 -f $REMOTE_KEY_PATH -N '' -C 'openvpn-toolkit-deploy@$HOST' -q"
	log "  generated new key on $HOST"
fi
PUBLIC_KEY=$(SSH "sudo cat ${REMOTE_KEY_PATH}.pub")
[[ -n "$PUBLIC_KEY" ]] || die "Could not read the generated public key back from $HOST."

# --- Phase 2: register with GitHub (runs HERE, where gh is authenticated) --
log "Phase 2: registering deploy key with $GH_REPO"
EXISTING_KEY_ID=$(gh api "repos/$GH_REPO/keys" --jq \
	".[] | select(.key == \"${PUBLIC_KEY% *}\") | .id" 2>/dev/null || true)
if [[ -n "$EXISTING_KEY_ID" ]]; then
	log "  this exact key is already registered (id $EXISTING_KEY_ID) -- skipping."
else
	printf '%s\n' "$PUBLIC_KEY" | gh repo deploy-key add --repo "$GH_REPO" --title "$KEY_TITLE" /dev/stdin
	log "  registered as: $KEY_TITLE"
fi

# --- Phase 3: SSH config alias on the target host, so git uses this key ---
# Same reasoning as Phase 1 -- root's own ~/.ssh/config, since Phase 4's
# `sudo git clone` runs as root and would never see an alias placed under
# $SSH_USER's home.
log "Phase 3: SSH config alias for github.com on $HOST"
ALIAS="github.com-$(basename "$GH_REPO")"
if SSH "sudo grep -q '^Host $ALIAS\$' /root/.ssh/config 2>/dev/null"; then
	log "  alias '$ALIAS' already present -- reusing."
else
	SSH "sudo tee -a /root/.ssh/config > /dev/null <<CFG
Host $ALIAS
    HostName github.com
    User git
    IdentityFile ${REMOTE_KEY_PATH}
    IdentitiesOnly yes
CFG
sudo chmod 600 /root/.ssh/config"
	log "  added alias '$ALIAS' -> github.com"
fi
# Prime known_hosts non-interactively (as root, since that's who'll actually
# run the clone) so Phase 4 doesn't hang on a host-key prompt.
SSH "sudo ssh -o StrictHostKeyChecking=accept-new -T git@github.com -i $REMOTE_KEY_PATH" >/dev/null 2>&1 || true

# --- Phase 4: clone (or update) the repo on the target host ---------------
log "Phase 4: repo at $REPO_DIR on $HOST"
if SSH "sudo test -d $REPO_DIR/.git"; then
	log "  already cloned -- fetching latest instead."
	SSH "cd $REPO_DIR && sudo git fetch origin && sudo git status --short | head -5"
else
	SSH "sudo mkdir -p $REPO_DIR && sudo git clone $ALIAS:$GH_REPO.git $REPO_DIR"
	log "  cloned to $REPO_DIR"
fi
SSH "cd $REPO_DIR && sudo git log --oneline -1"

log "Done. Next: ssh $SSH_TARGET, then run:"
log "  cd $REPO_DIR && sudo ./setup-new-machine.sh --domain <your-domain> --acme-email <you@example.com> --use-staging-first"
