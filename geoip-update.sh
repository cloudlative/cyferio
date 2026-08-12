#!/bin/bash
#
# geoip-update.sh -- downloads/refreshes the GeoLite2 databases used by
# openvpn-mac-addr-check.py's country/city/ASN-restriction checks (see
# host-scripts/policy_lib.py's geoip_lookup_country/geoip_lookup_city/
# geoip_lookup_asn). Intended to run on a schedule via the companion
# systemd timer (see systemd/openvpn-geoip-update.timer/.service in this
# repo) -- not required for a normal install; only needed if you actually
# use one or more of the per-client Location & Network Restrictions.
#
# Requires a free MaxMind GeoLite2 account and license key:
#   https://www.maxmind.com/en/geolite2/signup
# Put the key in /etc/openvpn/vpn-tools.conf as:
#   MAXMIND_LICENSE_KEY=your_key_here
#
# If no key is configured, this script logs a clear message and exits 0
# (not an error) -- so the systemd timer can be installed ahead of time
# harmlessly, before a self-hoster has gotten around to signing up.
#
# Fetches all three editions (Country, City, ASN) each run -- City/ASN are
# larger downloads than Country, but this only runs on a weekly timer, and
# fetching all three unconditionally is simpler and more predictable than
# trying to detect which restriction types are actually configured
# anywhere in client_policy.json/User.allowed_login_*. Each edition is
# independent: a failure fetching one (rare -- MaxMind serves all editions
# from the same endpoint) is logged and does NOT abort the others, so e.g.
# a transient City-edition hiccup never leaves Country/ASN stale too.
#
# Uses MaxMind's official `geoipupdate` tool if it's installed (the
# recommended, most robust path -- handles retries/incremental updates
# itself, and a single geoipupdate run already refreshes every edition
# listed in /etc/GeoIP.conf's EditionIDs line); otherwise falls back to a
# direct HTTPS download per edition, extracting each .mmdb into place
# atomically (temp file + mv, so a lookup never sees a half-written db).

set -uo pipefail

VPN_TOOLS_CONF=/etc/openvpn/vpn-tools.conf
MAXMIND_LICENSE_KEY=""
MAXMIND_DB_PATH=/etc/openvpn/server/GeoLite2-Country.mmdb
MAXMIND_CITY_DB_PATH=/etc/openvpn/server/GeoLite2-City.mmdb
MAXMIND_ASN_DB_PATH=/etc/openvpn/server/GeoLite2-ASN.mmdb

if [[ -f "$VPN_TOOLS_CONF" ]]; then
	# shellcheck disable=SC1090
	source "$VPN_TOOLS_CONF"
fi

log() {
	echo "[geoip-update] $*"
}

if [[ -z "$MAXMIND_LICENSE_KEY" ]]; then
	log "MAXMIND_LICENSE_KEY is not set in $VPN_TOOLS_CONF -- skipping update."
	log "Sign up for a free key at https://www.maxmind.com/en/geolite2/signup and set MAXMIND_LICENSE_KEY there to enable country/city/ASN restrictions."
	exit 0
fi

if command -v geoipupdate >/dev/null 2>&1 && [[ -f /etc/GeoIP.conf ]]; then
	log "Using geoipupdate (found /etc/GeoIP.conf) -- refreshes every edition listed in its EditionIDs line in one run."
	geoipupdate
	log "geoipupdate finished -- verify $MAXMIND_DB_PATH / $MAXMIND_CITY_DB_PATH / $MAXMIND_ASN_DB_PATH match your /etc/GeoIP.conf DatabaseDirectory."
	exit 0
fi

log "geoipupdate not available (or /etc/GeoIP.conf not configured) -- falling back to a direct per-edition download."

# fetch_edition <MaxMind edition id> <destination .mmdb path>
# Downloads/extracts/installs one GeoLite2 edition, atomically. Returns
# non-zero on failure -- the caller decides whether that's fatal for this
# run overall (only Country is treated as must-succeed, see below, since
# it's the original/most commonly used restriction; City/ASN failures are
# logged but don't fail the whole script).
fetch_edition() {
	local edition_id="$1" dest_path="$2"
	local tmp_dir archive http_status mmdb_found final_tmp

	mkdir -p "$(dirname "$dest_path")"
	tmp_dir=$(mktemp -d)
	# shellcheck disable=SC2064
	trap "rm -rf '$tmp_dir'" RETURN

	local download_url="https://download.maxmind.com/app/geoip_download?edition_id=${edition_id}&license_key=${MAXMIND_LICENSE_KEY}&suffix=tar.gz"
	archive="$tmp_dir/${edition_id}.tar.gz"

	if command -v curl >/dev/null 2>&1; then
		# -L: MaxMind's download endpoint issues a 302 redirect to the actual
		# file location -- without follow-redirects, curl reports the
		# redirect's own 302 status and writes its (non-archive) body to
		# $archive instead of the real .tar.gz, which then fails to extract.
		http_status=$(curl -sS -L -w '%{http_code}' -o "$archive" "$download_url")
	elif command -v wget >/dev/null 2>&1; then
		wget -q -O "$archive" "$download_url" && http_status=200 || http_status=000
	else
		log "Neither curl nor wget is available -- cannot download $edition_id."
		return 1
	fi

	if [[ "$http_status" != "200" ]] || [[ ! -s "$archive" ]]; then
		log "$edition_id download failed (HTTP $http_status). Check MAXMIND_LICENSE_KEY is valid and not revoked."
		return 1
	fi

	tar xzf "$archive" -C "$tmp_dir"

	mmdb_found=$(find "$tmp_dir" -name "${edition_id}.mmdb" -print -quit)
	if [[ -z "$mmdb_found" ]]; then
		log "Downloaded $edition_id archive did not contain a ${edition_id}.mmdb -- MaxMind may have changed the archive layout."
		return 1
	fi

	# Atomic: write to a temp path in the FINAL destination directory, then
	# mv (same filesystem, so mv is a rename -- a concurrent lookup in
	# openvpn-mac-addr-check.py never sees a partially-written file).
	final_tmp="${dest_path}.tmp.$$"
	cp "$mmdb_found" "$final_tmp"
	chmod 644 "$final_tmp"
	mv "$final_tmp" "$dest_path"

	log "Updated $dest_path ($(date -u '+%Y-%m-%d %H:%M:%S UTC'))."
	return 0
}

overall_status=0

fetch_edition "GeoLite2-Country" "$MAXMIND_DB_PATH" || overall_status=1
fetch_edition "GeoLite2-City" "$MAXMIND_CITY_DB_PATH" || log "City edition update failed -- city restriction lookups will fail closed for any client that has one configured, until the next successful run."
fetch_edition "GeoLite2-ASN" "$MAXMIND_ASN_DB_PATH" || log "ASN edition update failed -- network restriction lookups will fail closed for any client that has one configured, until the next successful run."

exit "$overall_status"
