#!/bin/bash
#
# setup.sh -- single guided entrypoint that orchestrates this repo's three
# existing bootstrap scripts (add-machine.sh, openvpn-install.sh,
# setup-new-machine.sh) so a fresh box can go from nothing to a working
# OpenVPN server (optionally with the web admin portal) in one run, instead
# of three separately-remembered steps. Does NOT reimplement any of their
# logic -- it only decides which of them to call, in what order, with what
# flags, based on either interactive prompts or the flags below.
#
# STEP 0 -- NOT done by this script, and it structurally can't be: run
# add-machine.sh from YOUR OWN machine (not this host) first, to bootstrap
# this box's read-only deploy-key access to the private repo and clone it
# here. That script needs a local, already-authenticated `gh` session
# (registering a GitHub deploy key), which only exists on an operator's own
# machine, never on a brand-new target host -- see add-machine.sh's own
# header for the full explanation. By the time setup.sh itself runs (ON the
# target host, from within the clone add-machine.sh created), that
# prerequisite is implicitly satisfied -- this script IS running from
# inside the cloned repo, which is the only proof it needs.
#
#   From your own machine:
#     ./add-machine.sh --host 203.0.113.10 --user ubuntu
#     ssh ubuntu@203.0.113.10
#     cd /opt/cyferio && sudo ./setup.sh
#
# What setup.sh itself does, in order:
#   1. Refuses to run on a machine it doesn't recognize as its own (see
#      "Idempotency & the foreign-machine guard" below) -- everything past
#      this point assumes it's safe to reconcile this box's state.
#   2. Interactive-by-default: asks whether you want OpenVPN only, or
#      OpenVPN + the web admin portal; for the portal, asks for a domain
#      and an ACME email; asks once whether to set up MaxMind GeoIP
#      restrictions, then once whether to set up CAPTCHA on the login/
#      reset pages. Pass flags instead (see below) for a fully
#      non-interactive run.
#   3. OpenVPN: if `/etc/openvpn/server/server.conf` doesn't exist yet,
#      runs openvpn-install.sh's normal first-time install non-interactively
#      (accepting its own defaults -- auto-detected IP, UDP, port 1194,
#      system DNS resolvers, a first client named "client"). If it already
#      exists, this phase is a no-op -- openvpn-install.sh is never re-run
#      against an existing install (re-running its own interactive flow
#      against an existing server.conf drops into its management MENU, not
#      a reinstall -- so there's nothing meaningful for this script to
#      automate there beyond what it already skips).
#   4. CAPTCHA (optional, only if requested, --mode webapp only): light
#      offline format check only (non-empty, no obviously-wrong shape) --
#      unlike MaxMind's live download-and-verify below, there's no
#      read-only way to confirm a Turnstile/reCAPTCHA secret actually works
#      without completing a real widget round-trip, which needs a browser,
#      not this script. Runs before the web app phase (next) because its
#      values are forwarded as flags into that same call, not written
#      independently the way MaxMind's key is.
#   5. Web app (only in --mode webapp): calls setup-new-machine.sh with the
#      translated flags below (including any CAPTCHA values from step 4).
#      That script is already fully idempotent on its own (see its own
#      header) -- setup.sh doesn't duplicate any of its state checks, just
#      forwards flags to it.
#   6. GeoIP (optional, only if requested): writes MAXMIND_LICENSE_KEY into
#      /etc/openvpn/vpn-tools.conf, ensures the `geoip2` Python package is
#      importable, runs geoip-update.sh to actually download the databases,
#      then opens the resulting .mmdb with geoip2 to confirm the key
#      actually works -- catching a bad/expired/typo'd key at setup time
#      instead of the first time a client's country/city/ASN restriction
#      silently fails closed at connect time.
#   7. Writes a provisioning marker (see below) on first successful run,
#      and prints either a summary of what changed or "nothing to do".
#
# Idempotency & the foreign-machine guard:
#   Every phase checks current state before acting (same pattern
#   setup-new-machine.sh already uses) -- safe to re-run any number of
#   times. On first successful run, this script writes a marker file at
#   /etc/cyferio/.setup-provisioned recording that THIS script
#   provisioned the machine. On every subsequent run, if OpenVPN or the app
#   stack already looks installed (server.conf exists, or REPO_DIR/.env
#   exists) but that marker is MISSING, this script refuses to touch
#   anything and exits loudly -- that combination means this is a machine
#   it never provisioned (e.g. real production, set up some other way),
#   and reconciling it automatically would be exactly the wrong thing to
#   do. If you're certain a given box genuinely was set up by this script
#   before the marker existed, create the marker file by hand to proceed:
#     sudo mkdir -p /etc/cyferio && sudo touch /etc/cyferio/.setup-provisioned
#
# Usage (run as root, or via sudo), OpenVPN only:
#   sudo ./setup.sh --mode openvpn
#
# Usage, OpenVPN + web app portal:
#   sudo ./setup.sh --mode webapp --domain portal.example.com \
#     --acme-email you@example.com [--maxmind-key XXXXXXXXXXXXXXXX] \
#     [--captcha-provider turnstile --turnstile-site-key XXX --turnstile-secret-key YYY] \
#     [--deploy-user ubuntu] [--image-tag 1.0.36] [--repo-dir /opt/cyferio] \
#     [--use-staging-first] [--force-env] [--skip-stack] [--skip-docker] \
#     [--proxy-mode auto|cloudflare|direct] [--sqlite]
#
# No arguments at all -> interactive prompts for everything above.
#
# Flags (webapp-mode ones are forwarded to setup-new-machine.sh -- see
# `setup-new-machine.sh --help` for the authoritative description of each):
#   --mode MODE             openvpn | webapp. Required for a non-interactive
#                            run (any flag at all switches this script out
#                            of interactive mode) -- omit every flag for
#                            guided prompts instead.
#   --domain DOMAIN          Required for --mode webapp.
#   --acme-email EMAIL       Required for --mode webapp (unless .env
#                            already has ACME_EMAIL -- see
#                            setup-new-machine.sh).
#   --maxmind-key KEY        Opt-in. Enables GeoIP country/city/ASN
#                            restrictions -- validated end-to-end (format,
#                            live download, geoip2 can open the result)
#                            before this script reports success. Omit
#                            entirely to skip GeoIP setup with zero
#                            validation attempted.
#   --captcha-provider P     Opt-in (--mode webapp only). P is "turnstile"
#                            (Cloudflare) or "recaptcha" (Google reCAPTCHA
#                            v2) -- see .env.example's CAPTCHA_PROVIDER
#                            comment for how to obtain each provider's own
#                            keys. Requires that provider's --*-site-key and
#                            --*-secret-key below. Omit entirely to leave
#                            CAPTCHA disabled (the default) -- only light
#                            offline format validation is done, no live
#                            call to Cloudflare/Google (see Phase 1b).
#   --turnstile-site-key K   Required with --captcha-provider turnstile.
#   --turnstile-secret-key K  Required with --captcha-provider turnstile.
#   --recaptcha-site-key K   Required with --captcha-provider recaptcha.
#   --recaptcha-secret-key K  Required with --captcha-provider recaptcha.
#   --deploy-user USER       Forwarded to setup-new-machine.sh (default: ubuntu).
#   --image-tag TAG          Forwarded to setup-new-machine.sh (default: latest).
#   --repo-dir DIR           Where this repo is checked out. Defaults to
#                            wherever setup.sh itself is running from --
#                            override only if that's somehow not also
#                            where setup-new-machine.sh should operate.
#   --use-staging-first      Forwarded to setup-new-machine.sh.
#   --force-env              Forwarded to setup-new-machine.sh.
#   --skip-stack             Forwarded to setup-new-machine.sh.
#   --skip-docker            Forwarded to setup-new-machine.sh.
#   --proxy-mode MODE        Forwarded to setup-new-machine.sh (default: auto).
#   --sqlite                 Forwarded to setup-new-machine.sh.
#   -h, --help               Show this help and exit.

set -euo pipefail

# --- Locate the other scripts (this repo's own clone, wherever it lives) --
SETUP_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
ADD_MACHINE_SH="$SETUP_DIR/add-machine.sh"
OPENVPN_INSTALL_SH="$SETUP_DIR/openvpn-install.sh"
SETUP_NEW_MACHINE_SH="$SETUP_DIR/setup-new-machine.sh"
GEOIP_UPDATE_SH="$SETUP_DIR/geoip-update.sh"

log() { echo "[setup] $*"; }
die() { echo "[setup] ERROR: $*" >&2; exit 1; }

CHANGES=()
note_change() { CHANGES+=("$1"); log "  -> $1"; }

# --- Defaults ---------------------------------------------------------------
MODE=""
DOMAIN=""
ACME_EMAIL=""
# MAXMIND_KEY_SET declared *before* MAXMIND_KEY itself, deliberately: a
# `*_KEY=<empty>` line immediately followed by another `*_KEY`-shaped
# variable name trips gitleaks' generic-api-key rule, which spans the
# newline looking for a value and grabs the next line's `VAR_NAME=0` as if
# it were the secret. Genuinely tested against a local gitleaks run, not
# just an offline guess -- neither an unquoted empty assignment alone nor
# a quoted `""` avoided this on its own; only separating the two `*_KEY`
# lines actually clears the finding. See .gitleaks.toml for why this
# needs explaining at all (this used to be an allowlist entry that, it
# turned out, never actually matched in practice).
MAXMIND_KEY_SET=0
MAXMIND_KEY=
# Same gitleaks false-positive avoidance for the four CAPTCHA key vars --
# but this time a `*_SET` breaker variable doesn't actually help: it's
# itself `*_KEY`-shaped (e.g. `TURNSTILE_SITE_KEY_SET`), so an empty
# `TURNSTILE_SITE_KEY=` line immediately followed by
# `TURNSTILE_SECRET_KEY_SET=0` still trips the same rule -- confirmed by
# actually running gitleaks locally (it wasn't enough to reason about this
# offline; the MAXMIND_KEY_SET-style breaker genuinely re-triggered the
# finding here). A plain `# comment` line between each empty `*_KEY=`
# assignment clears it instead, verified the same way. No `_SET` flags are
# needed for these four anyway -- CAPTCHA_PROVIDER itself (like MODE) is
# already the "was this opted into" gate; the individual keys are just
# required-if-that-provider-is-chosen values, checked with a plain `-n`
# test below rather than a separate per-key "was it passed" flag.
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
REPO_DIR="$SETUP_DIR"
USE_STAGING_FIRST=0
FORCE_ENV=0
SKIP_STACK=0
SKIP_DOCKER=0
PROXY_MODE="auto"
USE_SQLITE=0
INTERACTIVE=1

# --- Arg parsing -------------------------------------------------------------
while [[ $# -gt 0 ]]; do
	INTERACTIVE=0
	case "$1" in
		--mode) MODE="$2"; shift 2 ;;
		--domain) DOMAIN="$2"; shift 2 ;;
		--acme-email) ACME_EMAIL="$2"; shift 2 ;;
		--maxmind-key) MAXMIND_KEY="$2"; MAXMIND_KEY_SET=1; shift 2 ;;
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
		--skip-stack) SKIP_STACK=1; shift ;;
		--skip-docker) SKIP_DOCKER=1; shift ;;
		--proxy-mode) PROXY_MODE="$2"; shift 2 ;;
		--sqlite) USE_SQLITE=1; shift ;;
		-h|--help) sed -n '2,138p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
		*) die "Unknown argument: $1 (see --help)" ;;
	esac
done

[[ "$EUID" -eq 0 ]] || die "Must run as root (sudo ./setup.sh ...)."

# UBUNTU ONLY -- matches every other bootstrap script in this repo (see
# setup-new-machine.sh's own header for why).
if [[ -r /etc/os-release ]]; then
	# shellcheck disable=SC1091
	. /etc/os-release
else
	die "Cannot read /etc/os-release to confirm this is Ubuntu -- refusing to guess."
fi
[[ "${ID:-}" == "ubuntu" ]] || die "This script only supports Ubuntu (detected: ${PRETTY_NAME:-${ID:-unknown}})."

for f in "$ADD_MACHINE_SH" "$OPENVPN_INSTALL_SH" "$SETUP_NEW_MACHINE_SH" "$GEOIP_UPDATE_SH"; do
	[[ -f "$f" ]] || die "Expected to find $(basename "$f") next to setup.sh at $SETUP_DIR -- is this script actually running from inside the cloned repo? (See this script's own header, step 0 -- add-machine.sh must have already cloned the repo here.)"
done

# --- Foreign-machine guard ---------------------------------------------------
# See this script's own header ("Idempotency & the foreign-machine guard").
MARKER_DIR="/etc/cyferio"
MARKER_FILE="$MARKER_DIR/.setup-provisioned"

_looks_already_installed() {
	[[ -e /etc/openvpn/server/server.conf ]] && return 0
	[[ -f "$REPO_DIR/.env" ]] && return 0
	return 1
}

if _looks_already_installed && [[ ! -f "$MARKER_FILE" ]]; then
	cat >&2 <<EOF
[setup] ERROR: This machine already looks like it has OpenVPN and/or the
[setup] app stack installed (found /etc/openvpn/server/server.conf and/or
[setup] $REPO_DIR/.env), but there is no $MARKER_FILE
[setup] marker -- meaning setup.sh did not provision this machine itself.
[setup]
[setup] This is the safety signal that distinguishes a box setup.sh set up
[setup] (safe to reconcile) from an unknown/foreign machine -- e.g. real
[setup] production, set up some other way -- which is out of scope for this
[setup] script to touch automatically. Refusing to continue.
[setup]
[setup] If you are certain this machine genuinely was provisioned by
[setup] setup.sh before this marker existed, create it by hand and re-run:
[setup]   sudo mkdir -p $MARKER_DIR && sudo touch $MARKER_FILE
EOF
	exit 1
fi

# --- Interactive prompts (only when zero flags were given) ------------------
if [[ "$INTERACTIVE" -eq 1 ]]; then
	echo "OpenVPN Toolkit -- guided setup"
	echo
	echo "1) OpenVPN only"
	echo "2) OpenVPN + web admin portal (app)"
	read -rp "Choice [1]: " mode_choice
	case "${mode_choice:-1}" in
		1|"") MODE="openvpn" ;;
		2) MODE="webapp" ;;
		*) die "Invalid choice: $mode_choice" ;;
	esac

	if [[ "$MODE" == "webapp" ]]; then
		read -rp "Domain (public hostname, e.g. portal.example.com): " DOMAIN
		[[ -n "$DOMAIN" ]] || die "A domain is required for the web app portal."
		read -rp "ACME email (for Let's Encrypt): " ACME_EMAIL
		[[ -n "$ACME_EMAIL" ]] || die "An ACME email is required for the web app portal."
		read -rp "Request a Let's Encrypt STAGING cert first, then switch to production? [Y/n]: " staging_choice
		case "${staging_choice:-y}" in
			y|Y|"") USE_STAGING_FIRST=1 ;;
			*) USE_STAGING_FIRST=0 ;;
		esac
	fi

	read -rp "Set up MaxMind GeoIP country/city/ASN restrictions? [y/N]: " geoip_choice
	case "${geoip_choice:-n}" in
		y|Y)
			read -rp "MaxMind GeoLite2 license key: " MAXMIND_KEY
			MAXMIND_KEY_SET=1
			[[ -n "$MAXMIND_KEY" ]] || die "A license key is required if GeoIP is wanted (or answer 'n' to skip it)."
			;;
		*) ;;
	esac

	if [[ "$MODE" == "webapp" ]]; then
		read -rp "Set up CAPTCHA on the login/reset-password pages? [y/N]: " captcha_choice
		case "${captcha_choice:-n}" in
			y|Y)
				echo "1) Cloudflare Turnstile"
				echo "2) Google reCAPTCHA v2"
				read -rp "Provider [1]: " captcha_provider_choice
				case "${captcha_provider_choice:-1}" in
					1|"")
						CAPTCHA_PROVIDER="turnstile"
						read -rp "Turnstile site key: " TURNSTILE_SITE_KEY
						read -rp "Turnstile secret key: " TURNSTILE_SECRET_KEY
						[[ -n "$TURNSTILE_SITE_KEY" && -n "$TURNSTILE_SECRET_KEY" ]] || die "Both a Turnstile site key and secret key are required if CAPTCHA is wanted (or answer 'n' to skip it)."
						;;
					2)
						CAPTCHA_PROVIDER="recaptcha"
						read -rp "reCAPTCHA site key: " RECAPTCHA_SITE_KEY
						read -rp "reCAPTCHA secret key: " RECAPTCHA_SECRET_KEY
						[[ -n "$RECAPTCHA_SITE_KEY" && -n "$RECAPTCHA_SECRET_KEY" ]] || die "Both a reCAPTCHA site key and secret key are required if CAPTCHA is wanted (or answer 'n' to skip it)."
						;;
					*) die "Invalid choice: $captcha_provider_choice" ;;
				esac
				;;
			*) ;;
		esac
	fi
	echo
fi

# --- Non-interactive validation ---------------------------------------------
missing=()
if [[ -z "$MODE" ]]; then
	missing+=("--mode (openvpn|webapp)")
elif [[ "$MODE" != "openvpn" && "$MODE" != "webapp" ]]; then
	die "--mode must be 'openvpn' or 'webapp' (got '$MODE')."
fi
if [[ "$MODE" == "webapp" ]]; then
	[[ -n "$DOMAIN" ]] || missing+=("--domain")
	[[ -n "$ACME_EMAIL" ]] || missing+=("--acme-email (unless $REPO_DIR/.env already has ACME_EMAIL)")
fi
if [[ ${#missing[@]} -gt 0 ]]; then
	log "Missing required option(s) for a non-interactive run:"
	for m in "${missing[@]}"; do log "  - $m"; done
	die "Re-run with the missing flags above, or with no flags at all for guided prompts."
fi

case "$PROXY_MODE" in
	auto|cloudflare|direct) ;;
	*) die "--proxy-mode must be one of: auto, cloudflare, direct (got '$PROXY_MODE')." ;;
esac

# --captcha-provider's own required-flag shape (which site/secret key pair
# is mandatory) can't be expressed via the generic `missing` list above --
# it depends on which provider was chosen, not a fixed set of flags -- so
# it's checked separately here, same non-interactive-only timing as every
# other flag-shape check in this section.
if [[ -n "$CAPTCHA_PROVIDER" ]]; then
	[[ "$MODE" == "webapp" ]] || die "--captcha-provider is only meaningful with --mode webapp."
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

log "Mode: $MODE"

# --- Phase 1: OpenVPN install/reconcile --------------------------------------
log "Phase 1: OpenVPN"
if [[ -e /etc/openvpn/server/server.conf ]]; then
	log "  /etc/openvpn/server/server.conf already exists -- OpenVPN is already installed, skipping install."
else
	log "  no existing install found -- running openvpn-install.sh non-interactively (accepting its own defaults: auto-detected IP, UDP/1194, system DNS, first client 'client')..."
	# openvpn-install.sh's first-time install flow is a plain interactive
	# `read -p` sequence with no AUTO_INSTALL/env-var override of its own
	# (see this script's header) -- every prompt already has a documented
	# bracketed default that a blank line (Enter) accepts, so piping an
	# effectively unlimited stream of blank lines drives it to completion
	# unattended without changing a single line of openvpn-install.sh
	# itself. `yes ""` never exits on its own; it's killed by SIGPIPE the
	# moment openvpn-install.sh exits and closes its end of the pipe --
	# the standard idiom for scripting an installer built around
	# read-with-default prompts.
	if ! yes "" | bash "$OPENVPN_INSTALL_SH"; then
		die "openvpn-install.sh did not complete successfully -- see its output above."
	fi
	[[ -e /etc/openvpn/server/server.conf ]] || die "openvpn-install.sh reported success but /etc/openvpn/server/server.conf still doesn't exist -- something went wrong."
	note_change "installed OpenVPN (openvpn-install.sh)"
fi

# --- Phase 1b: CAPTCHA (optional, light format check only) ------------------
#
# Deliberately NOT a live validation call to Cloudflare/Google (unlike
# MaxMind's Phase 3 below, which downloads-and-verifies against a service
# this script already needs network access to anyway, for an entirely
# different class of credential). A Turnstile/reCAPTCHA secret key can only
# genuinely be proven correct by completing a real widget round-trip in a
# browser -- out of reach for a headless bootstrap script -- so this step
# only catches obvious paste errors (blank, whitespace-only) fast and
# offline, the same way a bad value would otherwise silently sit unused
# until the first real login attempt. Runs before Phase 2 so a caught
# mistake here fails before setup-new-machine.sh does any real work.
if [[ -n "$CAPTCHA_PROVIDER" ]]; then
	log "Phase 1b: CAPTCHA ($CAPTCHA_PROVIDER)"
	case "$CAPTCHA_PROVIDER" in
		turnstile)
			[[ "$TURNSTILE_SITE_KEY" =~ ^[^[:space:]]+$ ]] || die "--turnstile-site-key doesn't look like a valid key (blank or contains whitespace)."
			[[ "$TURNSTILE_SECRET_KEY" =~ ^[^[:space:]]+$ ]] || die "--turnstile-secret-key doesn't look like a valid key (blank or contains whitespace)."
			;;
		recaptcha)
			[[ "$RECAPTCHA_SITE_KEY" =~ ^[^[:space:]]+$ ]] || die "--recaptcha-site-key doesn't look like a valid key (blank or contains whitespace)."
			[[ "$RECAPTCHA_SECRET_KEY" =~ ^[^[:space:]]+$ ]] || die "--recaptcha-secret-key doesn't look like a valid key (blank or contains whitespace)."
			;;
	esac
	log "  OK: $CAPTCHA_PROVIDER site/secret key pair present and well-formed (format check only -- see this script's header for why no live provider call is made here)."
else
	log "Phase 1b: CAPTCHA -- skipped (no --captcha-provider given / declined at the prompt). CAPTCHA stays disabled on /login and /forgot-password until this is set up."
fi

# --- Phase 2: web app portal (setup-new-machine.sh) --------------------------
if [[ "$MODE" == "webapp" ]]; then
	log "Phase 2: web app portal (setup-new-machine.sh)"
	sm_args=(--deploy-user "$DEPLOY_USER" --image-tag "$IMAGE_TAG" --repo-dir "$REPO_DIR" --proxy-mode "$PROXY_MODE")
	[[ -n "$DOMAIN" ]] && sm_args+=(--domain "$DOMAIN")
	[[ -n "$ACME_EMAIL" ]] && sm_args+=(--acme-email "$ACME_EMAIL")
	[[ "$USE_STAGING_FIRST" -eq 1 ]] && sm_args+=(--use-staging-first)
	[[ "$FORCE_ENV" -eq 1 ]] && sm_args+=(--force-env)
	[[ "$SKIP_STACK" -eq 1 ]] && sm_args+=(--skip-stack)
	[[ "$SKIP_DOCKER" -eq 1 ]] && sm_args+=(--skip-docker)
	[[ "$USE_SQLITE" -eq 1 ]] && sm_args+=(--sqlite)
	if [[ -n "$CAPTCHA_PROVIDER" ]]; then
		sm_args+=(--captcha-provider "$CAPTCHA_PROVIDER")
		case "$CAPTCHA_PROVIDER" in
			turnstile) sm_args+=(--turnstile-site-key "$TURNSTILE_SITE_KEY" --turnstile-secret-key "$TURNSTILE_SECRET_KEY") ;;
			recaptcha) sm_args+=(--recaptcha-site-key "$RECAPTCHA_SITE_KEY" --recaptcha-secret-key "$RECAPTCHA_SECRET_KEY") ;;
		esac
	fi

	env_existed_before=0
	[[ -f "$REPO_DIR/.env" ]] && env_existed_before=1

	if ! bash "$SETUP_NEW_MACHINE_SH" "${sm_args[@]}"; then
		die "setup-new-machine.sh did not complete successfully -- see its output above."
	fi
	if [[ "$env_existed_before" -eq 0 || "$FORCE_ENV" -eq 1 ]]; then
		note_change "provisioned/updated the web app portal (setup-new-machine.sh)"
	else
		log "  setup-new-machine.sh completed -- see its own output above for whether anything actually changed (it reports its own idempotency)."
	fi
else
	log "Phase 2: web app portal -- skipped (--mode openvpn)."
fi

# --- Phase 3: MaxMind GeoIP (optional, full validation) ----------------------
if [[ "$MAXMIND_KEY_SET" -eq 1 ]]; then
	log "Phase 3: MaxMind GeoIP"

	# Format check -- MaxMind license keys are a short alphanumeric
	# (+ underscore/hyphen) token; this is a sanity check to fail fast on
	# an obvious paste error (blank, whitespace, an email address, ...),
	# not an attempt to fully validate MaxMind's own key format.
	[[ "$MAXMIND_KEY" =~ ^[A-Za-z0-9_-]{10,}$ ]] || die "--maxmind-key '$MAXMIND_KEY' doesn't look like a valid MaxMind license key (expected 10+ alphanumeric/_/- characters)."

	VPN_TOOLS_CONF=/etc/openvpn/vpn-tools.conf
	mkdir -p /etc/openvpn
	touch "$VPN_TOOLS_CONF"
	if grep -qE '^MAXMIND_LICENSE_KEY=' "$VPN_TOOLS_CONF"; then
		if grep -qE "^MAXMIND_LICENSE_KEY=${MAXMIND_KEY}\$" "$VPN_TOOLS_CONF"; then
			log "  MAXMIND_LICENSE_KEY already set in $VPN_TOOLS_CONF to the given key -- leaving as-is."
		else
			sed -i "s|^MAXMIND_LICENSE_KEY=.*|MAXMIND_LICENSE_KEY=${MAXMIND_KEY}|" "$VPN_TOOLS_CONF"
			note_change "updated MAXMIND_LICENSE_KEY in $VPN_TOOLS_CONF"
		fi
	else
		{
			echo ""
			echo "# MaxMind GeoLite2 license key -- added by setup.sh. See"
			echo "# geoip-update.sh's own header for what this enables."
			echo "MAXMIND_LICENSE_KEY=${MAXMIND_KEY}"
		} >> "$VPN_TOOLS_CONF"
		note_change "set MAXMIND_LICENSE_KEY in $VPN_TOOLS_CONF"
	fi
	chmod 640 "$VPN_TOOLS_CONF"

	# geoip2 must be importable for the validation step below (and for
	# host-scripts/policy_lib.py's own lookups later) -- installed the
	# same way app/services/openvpn/host_scripts_manager.py's
	# ensure_geoip2_package does it on this same class of host, kept in
	# sync manually since this is a plain bash bootstrap script.
	if ! python3 -c "import geoip2" &>/dev/null; then
		log "  installing geoip2 Python package..."
		apt-get install -y -qq python3-pip >/dev/null 2>&1 || true
		python3 -m pip install --break-system-packages geoip2 >/dev/null 2>&1 \
			|| python3 -m pip install geoip2 >/dev/null 2>&1 \
			|| true
		python3 -c "import geoip2" &>/dev/null || die "Could not install/import the geoip2 Python package -- cannot validate the MaxMind key. Check outbound network/pip access and re-run."
		note_change "installed the geoip2 Python package"
	fi

	log "  attempting a live download via geoip-update.sh..."
	if ! bash "$GEOIP_UPDATE_SH"; then
		die "geoip-update.sh failed with the given key -- check MAXMIND_LICENSE_KEY is valid and not revoked (see geoip-update.sh's output above)."
	fi

	MAXMIND_DB_PATH=/etc/openvpn/server/GeoLite2-Country.mmdb
	[[ -f "$MAXMIND_DB_PATH" ]] || die "geoip-update.sh reported success but $MAXMIND_DB_PATH still doesn't exist -- something went wrong."

	log "  confirming geoip2 can open $MAXMIND_DB_PATH..."
	if ! python3 -c "
import sys
import geoip2.database
try:
    reader = geoip2.database.Reader('$MAXMIND_DB_PATH')
    reader.country('8.8.8.8')
    reader.close()
except Exception as e:
    print(f'geoip2 could not open/read the database: {e}', file=sys.stderr)
    sys.exit(1)
"; then
		die "MaxMind key downloaded a database, but geoip2 could not open/read it -- see the error above. GeoIP restrictions would fail closed at connect time if left in this state."
	fi
	log "  OK: MaxMind key validated end-to-end (format, live download, geoip2 can read the result)."
else
	log "Phase 3: MaxMind GeoIP -- skipped (no --maxmind-key given / declined at the prompt). Country/city/ASN restrictions will fail closed for any client that has one configured until this is set up."
fi

# --- Provisioning marker ------------------------------------------------------
if [[ ! -f "$MARKER_FILE" ]]; then
	mkdir -p "$MARKER_DIR"
	{
		echo "# Written by setup.sh on first successful run. Its presence is what lets"
		echo "# setup.sh treat this machine as safe to reconcile on future runs, instead"
		echo "# of refusing to touch what might be an unrecognized/foreign machine -- see"
		echo "# setup.sh's own header, 'Idempotency & the foreign-machine guard'. Do not"
		echo "# delete this file on a machine you want setup.sh to keep managing."
		echo "PROVISIONED_AT=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
		echo "MODE=$MODE"
		echo "DOMAIN=${DOMAIN:-}"
	} > "$MARKER_FILE"
	chmod 644 "$MARKER_FILE"
	note_change "wrote provisioning marker at $MARKER_FILE"
fi

# --- Summary -------------------------------------------------------------------
echo
if [[ ${#CHANGES[@]} -eq 0 ]]; then
	log "Nothing to do -- configuration already reconciled."
else
	log "Done. Summary of changes made this run:"
	for c in "${CHANGES[@]}"; do log "  - $c"; done
fi
if [[ "$MODE" == "webapp" ]]; then
	log ""
	log "Web app portal: https://${DOMAIN}/ (see setup-new-machine.sh's own output above for the bootstrap admin password, shown once)."
fi
