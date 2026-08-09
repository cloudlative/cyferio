#!/bin/bash
#
# geoip-update.sh -- downloads/refreshes the GeoLite2-Country.mmdb used by
# openvpn-mac-addr-check.py's country-restriction check (see
# host-scripts/policy_lib.py's geoip_lookup_country). Intended to run on a
# schedule via the companion systemd timer (see
# systemd/openvpn-geoip-update.timer/.service in this repo) -- not required
# for a normal install; only needed if you actually use the per-client
# country restriction feature.
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
# Uses MaxMind's official `geoipupdate` tool if it's installed (the
# recommended, most robust path -- handles retries/incremental updates
# itself); otherwise falls back to a direct HTTPS download of the
# GeoLite2-Country.tar.gz archive using the license key, extracting the
# .mmdb into place atomically (temp file + mv, so a lookup never sees a
# half-written db).

set -euo pipefail

VPN_TOOLS_CONF=/etc/openvpn/vpn-tools.conf
MAXMIND_LICENSE_KEY=""
MAXMIND_DB_PATH=/etc/openvpn/server/GeoLite2-Country.mmdb

if [[ -f "$VPN_TOOLS_CONF" ]]; then
	# shellcheck disable=SC1090
	source "$VPN_TOOLS_CONF"
fi

log() {
	echo "[geoip-update] $*"
}

if [[ -z "$MAXMIND_LICENSE_KEY" ]]; then
	log "MAXMIND_LICENSE_KEY is not set in $VPN_TOOLS_CONF -- skipping update."
	log "Sign up for a free key at https://www.maxmind.com/en/geolite2/signup and set MAXMIND_LICENSE_KEY there to enable country restrictions."
	exit 0
fi

mkdir -p "$(dirname "$MAXMIND_DB_PATH")"

if command -v geoipupdate >/dev/null 2>&1 && [[ -f /etc/GeoIP.conf ]]; then
	log "Using geoipupdate (found /etc/GeoIP.conf)."
	geoipupdate
	log "geoipupdate finished -- verify $MAXMIND_DB_PATH matches your /etc/GeoIP.conf DatabaseDirectory."
	exit 0
fi

log "geoipupdate not available (or /etc/GeoIP.conf not configured) -- falling back to a direct download."

tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT

download_url="https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key=${MAXMIND_LICENSE_KEY}&suffix=tar.gz"
archive="$tmp_dir/GeoLite2-Country.tar.gz"

if command -v curl >/dev/null 2>&1; then
	# -L: MaxMind's download endpoint issues a 302 redirect to the actual
	# file location -- without follow-redirects, curl reports the
	# redirect's own 302 status and writes its (non-archive) body to
	# $archive instead of the real .tar.gz, which then fails to extract.
	http_status=$(curl -sS -L -w '%{http_code}' -o "$archive" "$download_url")
elif command -v wget >/dev/null 2>&1; then
	wget -q -O "$archive" "$download_url" && http_status=200 || http_status=000
else
	log "Neither curl nor wget is available -- cannot download the GeoLite2 database."
	exit 1
fi

if [[ "$http_status" != "200" ]] || [[ ! -s "$archive" ]]; then
	log "Download failed (HTTP $http_status). Check MAXMIND_LICENSE_KEY is valid and not revoked."
	exit 1
fi

tar xzf "$archive" -C "$tmp_dir"

mmdb_found=$(find "$tmp_dir" -name 'GeoLite2-Country.mmdb' -print -quit)
if [[ -z "$mmdb_found" ]]; then
	log "Downloaded archive did not contain a GeoLite2-Country.mmdb -- MaxMind may have changed the archive layout."
	exit 1
fi

# Atomic: write to a temp path in the FINAL destination directory, then mv
# (same filesystem, so mv is a rename -- a concurrent lookup in
# openvpn-mac-addr-check.py never sees a partially-written file).
final_tmp="${MAXMIND_DB_PATH}.tmp.$$"
cp "$mmdb_found" "$final_tmp"
chmod 644 "$final_tmp"
mv "$final_tmp" "$MAXMIND_DB_PATH"

log "Updated $MAXMIND_DB_PATH ($(date -u '+%Y-%m-%d %H:%M:%S UTC'))."
