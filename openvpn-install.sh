#!/bin/bash
#
# https://github.com/shahzadmasud/openvpn.git


# Detect Debian users running the script with "sh" instead of bash
if readlink /proc/$$/exe | grep -q "dash"; then
	echo 'This installer needs to be run with "bash", not "sh".'
	exit
fi

# Discard stdin. Needed when running from an one-liner which includes a newline
read -N 999999 -t 0.001

# Detect OpenVZ 6
if [[ $(uname -r | cut -d "." -f 1) -eq 2 ]]; then
	echo "The system is running an old kernel, which is incompatible with this installer."
	exit
fi

# Detect OS
# $os_version variables aren't always in use, but are kept here for convenience
if grep -qs "ubuntu" /etc/os-release; then
	os="ubuntu"
	os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
	group_name="nogroup"
elif [[ -e /etc/debian_version ]]; then
	os="debian"
	os_version=$(grep -oE '[0-9]+' /etc/debian_version | head -1)
	group_name="nogroup"
elif [[ -e /etc/almalinux-release || -e /etc/rocky-release || -e /etc/centos-release ]]; then
	os="centos"
	os_version=$(grep -shoE '[0-9]+' /etc/almalinux-release /etc/rocky-release /etc/centos-release | head -1)
	group_name="nobody"
elif [[ -e /etc/fedora-release ]]; then
	os="fedora"
	os_version=$(grep -oE '[0-9]+' /etc/fedora-release | head -1)
	group_name="nobody"
else
	echo "This installer seems to be running on an unsupported distribution.
Supported distros are Ubuntu, Debian, AlmaLinux, Rocky Linux, CentOS and Fedora."
	exit
fi

if [[ "$os" == "ubuntu" && "$os_version" -lt 1804 ]]; then
	echo "Ubuntu 18.04 or higher is required to use this installer.
This version of Ubuntu is too old and unsupported."
	exit
fi

if [[ "$os" == "debian" && "$os_version" -lt 9 ]]; then
	echo "Debian 9 or higher is required to use this installer.
This version of Debian is too old and unsupported."
	exit
fi

if [[ "$os" == "centos" && "$os_version" -lt 7 ]]; then
	echo "CentOS 7 or higher is required to use this installer.
This version of CentOS is too old and unsupported."
	exit
fi

# Detect environments where $PATH does not include the sbin directories
if ! grep -q sbin <<< "$PATH"; then
	echo '$PATH does not include sbin. Try using "su -" instead of "su".'
	exit
fi

if [[ "$EUID" -ne 0 ]]; then
	echo "This installer needs to be run with superuser privileges."
	exit
fi

if [[ ! -e /dev/net/tun ]] || ! ( exec 7<>/dev/net/tun ) 2>/dev/null; then
	echo "The system does not have the TUN device available.
TUN needs to be enabled before running this installer."
	exit
fi

# --- Configuration ----------------------------------------------------------
# Defaults match a stock install; every one of these can be overridden by
# /etc/openvpn/vpn-tools.conf (plain KEY=VALUE lines, no quoting) without
# touching this script -- see vpn-tools.conf.example in this repo. This same
# file is also read by vpn-status.py, so keep both in sync if you rename a key.
OPENVPN_DIR=/etc/openvpn/server
EASYRSA_DIR=/etc/openvpn/server/easy-rsa
DB_FILE=/etc/openvpn/server/openvpn_db.txt
CLIENT_COMMON_FILE=/etc/openvpn/server/client-common.txt
STATUS_LOG=/var/log/openvpn/openvpn-status.log
CONN_LOG=/etc/openvpn/server/openvpn.log
SERVICE_NAME=openvpn-server@server.service
OVPN_OUTPUT_MODE=600

# OVPN_OUTPUT_DIR / OVPN_OUTPUT_OWNER (where generated .ovpn files are
# delivered, and to whom) default to whoever actually ran `sudo` to invoke
# this script -- not a hardcoded "ubuntu", since the community running this
# won't all be on Ubuntu-style cloud images with that exact account name.
# Falls back to the first regular human account on the box if not run via
# sudo, and to root as a last resort. Set OVPN_OUTPUT_DIR/OWNER explicitly
# in vpn-tools.conf to override this on any given install.
_ovpn_default_user="${SUDO_USER:-}"
if [[ -z "$_ovpn_default_user" || "$_ovpn_default_user" == "root" ]]; then
	_ovpn_default_user=$(awk -F: '$3>=1000 && $3<60000 && $7 !~ /nologin|false/ {print $1; exit}' /etc/passwd)
fi
if [[ -n "$_ovpn_default_user" ]] && id "$_ovpn_default_user" &>/dev/null; then
	_ovpn_default_home=$(getent passwd "$_ovpn_default_user" | cut -d: -f6)
	_ovpn_default_group=$(id -gn "$_ovpn_default_user")
else
	_ovpn_default_user=root
	_ovpn_default_home=/root
	_ovpn_default_group=root
fi
OVPN_OUTPUT_DIR="$_ovpn_default_home"
OVPN_OUTPUT_OWNER="$_ovpn_default_user:$_ovpn_default_group"
unset _ovpn_default_user _ovpn_default_home _ovpn_default_group

VPN_TOOLS_CONF=/etc/openvpn/vpn-tools.conf
if [[ -f "$VPN_TOOLS_CONF" ]]; then
	# shellcheck disable=SC1090
	source "$VPN_TOOLS_CONF"
fi

# --- Shared functions --------------------------------------------------------

new_client () {
	# Generates the custom client .ovpn for the given client name
	local client="$1"
	{
	cat "$CLIENT_COMMON_FILE"
	echo "<ca>"
	cat "$EASYRSA_DIR/pki/ca.crt"
	echo "</ca>"
	echo "<cert>"
	sed -ne '/BEGIN CERTIFICATE/,$ p' "$EASYRSA_DIR/pki/issued/$client.crt"
	echo "</cert>"
	echo "<key>"
	cat "$EASYRSA_DIR/pki/private/$client.key"
	echo "</key>"
	echo "<tls-crypt>"
	sed -ne '/BEGIN OpenVPN Static key/,$ p' "$OPENVPN_DIR/tc.key"
	echo "</tls-crypt>"
	} > ~/"$client".ovpn
}

ensure_trailing_newline () {
	# Guarantees the file ends with exactly one newline, so a later ">>"
	# append always starts a genuinely new line instead of gluing onto the
	# previous entry (which would corrupt openvpn_db.txt's "name=mac" parsing).
	local f="$1"
	[[ -s "$f" ]] || return 0
	[[ -z "$(tail -c1 "$f")" ]] || printf '\n' >> "$f"
}

json_escape () {
	# Minimal JSON string escaping -- adequate for the values this script
	# actually emits (client names, MACs, dates, short messages); not a
	# general-purpose JSON encoder.
	local s="$1"
	s="${s//\\/\\\\}"
	s="${s//\"/\\\"}"
	printf '%s' "$s"
}

json_string_array () {
	# Prints a JSON array of strings from newline-separated input on $1.
	local input="$1" item first=1
	if [[ -z "$input" ]]; then
		printf '[]'
		return 0
	fi
	printf '['
	while IFS= read -r item; do
		[[ $first -eq 1 ]] && first=0 || printf ','
		printf '"%s"' "$(json_escape "$item")"
	done <<< "$input"
	printf ']'
}

normalize_mac () {
	# Accepts a MAC in any common separator style/case on stdin-like arg $1,
	# prints the normalized lowercase colon-separated form on success, or
	# nothing (with a non-zero return) if it isn't 12 hex characters.
	local raw="$1" hex
	hex=$(tr -d ':.-' <<< "$raw" | tr '[:upper:]' '[:lower:]')
	if [[ "$hex" =~ ^[0-9a-f]{12}$ ]]; then
		sed -E 's/(..)/\1:/g; s/:$//' <<< "$hex"
		return 0
	fi
	return 1
}

do_add_client () {
	# Usage: do_add_client <name> <mac>
	# Issues a client cert, generates the .ovpn, registers the client in
	# the MAC-binding db, and delivers the .ovpn to OVPN_OUTPUT_DIR.
	local unsanitized_client="$1" raw_mac="$2" client mac

	client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
	if [[ -z "$client" ]]; then
		echo "Invalid client name: '$unsanitized_client'." >&2
		return 1
	fi
	if [[ -e "$EASYRSA_DIR/pki/issued/$client.crt" ]]; then
		echo "$client: a client with this name already exists." >&2
		return 1
	fi

	if [[ -z "$raw_mac" ]]; then
		echo "A MAC address is required." >&2
		return 1
	fi
	if ! mac=$(normalize_mac "$raw_mac"); then
		echo "Invalid MAC address: expected 12 hex characters (e.g. aa:bb:cc:dd:ee:ff), got '$raw_mac'." >&2
		return 1
	fi

	(cd "$EASYRSA_DIR" && ./easyrsa --batch --days=3650 build-client-full "$client" nopass) || return 1

	new_client "$client"

	# Register client in the MAC-binding allowlist used by openvpn-mac-addr-check.py
	touch "$DB_FILE"
	ensure_trailing_newline "$DB_FILE"
	echo "$client=$mac" >> "$DB_FILE"

	# Move the generated .ovpn to OVPN_OUTPUT_DIR, owned by OVPN_OUTPUT_OWNER,
	# so it can be retrieved without needing root. Contains the client's
	# private key, so keep it owner-only readable (OVPN_OUTPUT_MODE).
	mkdir -p "$OVPN_OUTPUT_DIR"
	mv ~/"$client".ovpn "$OVPN_OUTPUT_DIR/$client.ovpn"
	chown "$OVPN_OUTPUT_OWNER" "$OVPN_OUTPUT_DIR/$client.ovpn"
	chmod "$OVPN_OUTPUT_MODE" "$OVPN_OUTPUT_DIR/$client.ovpn"

	echo "$client added. Configuration available in: $OVPN_OUTPUT_DIR/$client.ovpn"
	echo "$client registered in $DB_FILE with MAC $mac"
	return 0
}

do_revoke_client () {
	# Usage: do_revoke_client <name>
	local client="$1"
	if [[ -z "$client" ]]; then
		echo "Client name required." >&2
		return 1
	fi
	if [[ ! -e "$EASYRSA_DIR/pki/issued/$client.crt" ]]; then
		echo "$client: no such client." >&2
		return 1
	fi

	(cd "$EASYRSA_DIR" && ./easyrsa --batch revoke "$client" && ./easyrsa --batch --days=3650 gen-crl) || return 1
	rm -f "$OPENVPN_DIR/crl.pem"
	cp "$EASYRSA_DIR/pki/crl.pem" "$OPENVPN_DIR/crl.pem"
	# CRL is read with each client connection, while OpenVPN is dropped to nobody
	chown nobody:"$group_name" "$OPENVPN_DIR/crl.pem"

	# Remove client's entries from the MAC-binding allowlist
	if [[ -f "$DB_FILE" ]]; then
		sed -i "/^${client}=/d" "$DB_FILE"
		# sed -i preserves a missing final newline from the original file,
		# so re-check/fix it here too in case it was already missing.
		ensure_trailing_newline "$DB_FILE"
	fi

	echo "$client revoked!"
	echo "Removed $client's entries from $DB_FILE"
	return 0
}

do_show_ovpn () {
	# Usage: do_show_ovpn <name>
	# Prints an existing (valid) client's already-generated .ovpn config to
	# stdout, so a caller (e.g. the web admin app) can offer it for copy/
	# download/email without re-generating or touching any key material.
	local name="$1" ovpn_file
	if [[ -z "$name" ]]; then
		echo "Client name required." >&2
		return 1
	fi
	if [[ ! -e "$EASYRSA_DIR/pki/issued/$name.crt" ]]; then
		echo "$name: no such client (no valid certificate)." >&2
		return 1
	fi
	ovpn_file="$OVPN_OUTPUT_DIR/$name.ovpn"
	if [[ ! -f "$ovpn_file" ]]; then
		echo "$name: no .ovpn file found at $ovpn_file (it may have been moved or deleted after issuance)." >&2
		return 1
	fi
	cat "$ovpn_file"
	return 0
}

do_purge_revoked () {
	# Usage: do_purge_revoked <name>
	# Permanently deletes a *revoked* client's leftover PKI files (issued
	# cert, private key, CSR) and delivered .ovpn -- for cleaning up
	# certificates that will never be used again. Deliberately does NOT
	# remove the client's row from pki/index.txt: that row is what keeps it
	# on the CRL, and easy-rsa has no supported way to remove a single
	# index.txt entry without regenerating the whole PKI, so the audit
	# trail (who was revoked, when) stays intact even after a purge.
	local name="$1" is_revoked
	if [[ -z "$name" ]]; then
		echo "Client name required." >&2
		return 1
	fi
	is_revoked=$(tail -n +2 "$EASYRSA_DIR/pki/index.txt" 2>/dev/null | awk -F'\t' -v n="/CN=$name" '$1=="R" && $6==n {print "yes"; exit}')
	if [[ "$is_revoked" != "yes" ]]; then
		echo "$name: not a revoked client -- nothing to purge (use --revoke first)." >&2
		return 1
	fi
	rm -f "$EASYRSA_DIR/pki/issued/$name.crt" "$EASYRSA_DIR/pki/private/$name.key" "$EASYRSA_DIR/pki/reqs/$name.req" "$OVPN_OUTPUT_DIR/$name.ovpn"
	if [[ -f "$DB_FILE" ]]; then
		sed -i "/^${name}=/d" "$DB_FILE"
		ensure_trailing_newline "$DB_FILE"
	fi
	echo "$name: revoked client's leftover PKI/.ovpn files permanently deleted."
	return 0
}

do_restore_client () {
	# Usage: do_restore_client <name> <mac>
	# "Restoring" a revoked client is NOT un-revoking their old certificate
	# -- once a cert is on the CRL, easy-rsa (correctly, by PKI design) has
	# no way to reverse that; a revoked cert must stay revoked forever. What
	# this actually does is issue a brand-new certificate under the same
	# client name, after clearing out the old revoked cert's leftover files
	# so the name can be reused -- functionally "the person is back", but
	# cryptographically a fresh identity, not the old one reactivated.
	local name="$1" mac="$2" is_revoked
	if [[ -z "$name" ]]; then
		echo "Client name required." >&2
		return 1
	fi
	is_revoked=$(tail -n +2 "$EASYRSA_DIR/pki/index.txt" 2>/dev/null | awk -F'\t' -v n="/CN=$name" '$1=="R" && $6==n {print "yes"; exit}')
	if [[ "$is_revoked" != "yes" ]]; then
		echo "$name: not a revoked client -- nothing to restore." >&2
		return 1
	fi
	rm -f "$EASYRSA_DIR/pki/issued/$name.crt" "$EASYRSA_DIR/pki/private/$name.key" "$EASYRSA_DIR/pki/reqs/$name.req" "$OVPN_OUTPUT_DIR/$name.ovpn"
	do_add_client "$name" "$mac"
}

do_list_clients () {
	# Usage: do_list_clients [json]
	local as_json="${1:-}" names name first=1
	names=$(tail -n +2 "$EASYRSA_DIR/pki/index.txt" 2>/dev/null | grep "^V" | cut -d '=' -f 2)
	if [[ -z "$names" ]]; then
		if [[ "$as_json" == json ]]; then
			echo "[]"
		else
			echo "No valid clients found."
		fi
		return 0
	fi
	if [[ "$as_json" == json ]]; then
		printf '['
		while IFS= read -r name; do
			local in_db=false mac_count
			mac_count=$(grep -c "^${name}=" "$DB_FILE" 2>/dev/null || true)
			[[ -z "$mac_count" ]] && mac_count=0
			[[ "$mac_count" -gt 0 ]] && in_db=true
			[[ $first -eq 1 ]] && first=0 || printf ','
			printf '{"name":"%s","in_db":%s,"mac_count":%d}' "$(json_escape "$name")" "$in_db" "$mac_count"
		done <<< "$names"
		printf ']\n'
	else
		printf "%-20s %-6s %s\n" "NAME" "IN_DB" "MACS"
		while IFS= read -r name; do
			local mac_count
			mac_count=$(grep -c "^${name}=" "$DB_FILE" 2>/dev/null || true)
			[[ -z "$mac_count" ]] && mac_count=0
			if [[ "$mac_count" -gt 0 ]]; then
				printf "%-20s %-6s %d\n" "$name" "yes" "$mac_count"
			else
				printf "%-20s %-6s %d (cannot connect until added)\n" "$name" "no" "$mac_count"
			fi
		done <<< "$names"
	fi
	return 0
}

do_list_macs () {
	# Usage: do_list_macs <name> [json]
	# Shows every MAC address registered for a given client name --
	# openvpn_db.txt allows multiple "name=mac" lines per person for
	# multi-device users (e.g. a laptop and a phone), so this is genuinely
	# a one-to-many lookup, not just a single value.
	local name="$1" as_json="${2:-}" macs count
	if [[ -z "$name" ]]; then
		echo "Client name required." >&2
		return 1
	fi
	macs=$(grep "^${name}=" "$DB_FILE" 2>/dev/null | cut -d '=' -f 2-)
	if [[ -z "$macs" ]]; then
		count=0
	else
		count=$(wc -l <<< "$macs")
	fi

	if [[ "$as_json" == json ]]; then
		printf '{"name":"%s","count":%d,"macs":%s}\n' "$(json_escape "$name")" "$count" "$(json_string_array "$macs")"
	else
		if [[ "$count" -eq 0 ]]; then
			echo "No MAC addresses registered for '$name'."
		else
			echo "$count MAC address(es) registered for '$name':"
			sed 's/^/  - /' <<< "$macs"
		fi
	fi
	[[ "$count" -gt 0 ]]
}

do_add_mac () {
	# Usage: do_add_mac <name> <mac>
	# Registers an additional device MAC for an existing client, without
	# issuing a new certificate -- for the common multi-device case (same
	# person, a second laptop/phone). Requires a valid (non-revoked) cert to
	# already exist for the name, so this can't be used to sneak in a
	# registration for a client that was never actually issued.
	local name="$1" raw_mac="$2" mac
	if [[ -z "$name" ]]; then
		echo "Client name required." >&2
		return 1
	fi
	if [[ ! -e "$EASYRSA_DIR/pki/issued/$name.crt" ]]; then
		echo "$name: no such client (no valid certificate). Use --add to create a new client." >&2
		return 1
	fi
	if [[ -z "$raw_mac" ]]; then
		echo "A MAC address is required." >&2
		return 1
	fi
	if ! mac=$(normalize_mac "$raw_mac"); then
		echo "Invalid MAC address: expected 12 hex characters (e.g. aa:bb:cc:dd:ee:ff), got '$raw_mac'." >&2
		return 1
	fi
	if grep -qi "^${name}=${mac}$" "$DB_FILE" 2>/dev/null; then
		echo "$name is already registered with MAC $mac." >&2
		return 1
	fi
	touch "$DB_FILE"
	ensure_trailing_newline "$DB_FILE"
	echo "$name=$mac" >> "$DB_FILE"
	echo "Added MAC $mac for $name."
	return 0
}

do_remove_mac () {
	# Usage: do_remove_mac <name> <mac>
	# Removes one specific MAC registration for a client, leaving any other
	# MACs they have registered (and their certificate) untouched. Use
	# --revoke instead to remove a client entirely.
	local name="$1" raw_mac="$2" mac
	if [[ -z "$name" ]]; then
		echo "Client name required." >&2
		return 1
	fi
	if [[ -z "$raw_mac" ]]; then
		echo "A MAC address is required." >&2
		return 1
	fi
	if ! mac=$(normalize_mac "$raw_mac"); then
		echo "Invalid MAC address: expected 12 hex characters (e.g. aa:bb:cc:dd:ee:ff), got '$raw_mac'." >&2
		return 1
	fi
	if ! grep -qi "^${name}=${mac}$" "$DB_FILE" 2>/dev/null; then
		echo "$name has no registration for MAC $mac." >&2
		return 1
	fi
	sed -i "/^${name}=${mac}$/Id" "$DB_FILE"
	ensure_trailing_newline "$DB_FILE"
	echo "Removed MAC $mac for $name."
	return 0
}

format_asn1_time () {
	# easy-rsa's pki/index.txt dates are ASN.1-style "YYMMDDHHMMSSZ".
	# Reformats to "YYYY-MM-DD HH:MM:SS UTC" for readability; falls back to
	# printing the raw value unchanged if it doesn't match that shape.
	local t="$1"
	if [[ "$t" =~ ^([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})Z$ ]]; then
		echo "20${BASH_REMATCH[1]}-${BASH_REMATCH[2]}-${BASH_REMATCH[3]} ${BASH_REMATCH[4]}:${BASH_REMATCH[5]}:${BASH_REMATCH[6]} UTC"
	else
		echo "$t"
	fi
}

do_list_revoked () {
	# Usage: do_list_revoked [json]
	# Lists revoked clients: name, when revoked, and whether they still
	# have a (stale) entry in DB_FILE that should probably be cleaned up.
	local as_json="${1:-}" lines line name revoked_at first=1
	lines=$(tail -n +2 "$EASYRSA_DIR/pki/index.txt" 2>/dev/null | awk -F'\t' '$1=="R"{print $3"\t"$6}')
	if [[ -z "$lines" ]]; then
		if [[ "$as_json" == json ]]; then
			echo "[]"
		else
			echo "No revoked clients."
		fi
		return 0
	fi
	if [[ "$as_json" == json ]]; then
		printf '['
		while IFS=$'\t' read -r revoked_at name; do
			name="${name#/CN=}"
			local stale=false files_present=false
			grep -q "^${name}=" "$DB_FILE" 2>/dev/null && stale=true
			[[ -e "$EASYRSA_DIR/pki/issued/$name.crt" ]] && files_present=true
			[[ $first -eq 1 ]] && first=0 || printf ','
			printf '{"name":"%s","revoked_at":"%s","stale_db_entry":%s,"files_present":%s}' \
				"$(json_escape "$name")" "$(json_escape "$(format_asn1_time "$revoked_at")")" "$stale" "$files_present"
		done <<< "$lines"
		printf ']\n'
	else
		printf "%-20s %-24s %-16s %s\n" "NAME" "REVOKED_AT" "STALE_DB_ENTRY" "FILES_PRESENT"
		while IFS=$'\t' read -r revoked_at name; do
			name="${name#/CN=}"
			local stale_col files_col
			if grep -q "^${name}=" "$DB_FILE" 2>/dev/null; then
				stale_col="yes -- consider removing (see --check)"
			else
				stale_col="no"
			fi
			if [[ -e "$EASYRSA_DIR/pki/issued/$name.crt" ]]; then
				files_col="yes"
			else
				files_col="no (already purged)"
			fi
			printf "%-20s %-24s %-16s %s\n" "$name" "$(format_asn1_time "$revoked_at")" "$stale_col" "$files_col"
		done <<< "$lines"
	fi
	return 0
}

do_check_consistency () {
	# Usage: do_check_consistency [json]
	# Cross-checks PKI valid certs against DB_FILE entries in both
	# directions. Exit status: 0 = clean, 1 = at least one orphan found.
	local as_json="${1:-}" pki_names db_names orphan_pki orphan_db issues=0
	pki_names=$(tail -n +2 "$EASYRSA_DIR/pki/index.txt" 2>/dev/null | grep "^V" | cut -d '=' -f 2)
	db_names=$(cut -d '=' -f 1 "$DB_FILE" 2>/dev/null | sort -u)

	orphan_pki=$(comm -23 <(sort <<< "$pki_names") <(sort <<< "$db_names"))
	orphan_db=$(comm -13 <(sort <<< "$pki_names") <(sort <<< "$db_names"))

	[[ -n "$orphan_pki" ]] && issues=1
	[[ -n "$orphan_db" ]] && issues=1

	if [[ "$as_json" == json ]]; then
		printf '{"clean":%s,"orphan_pki":%s,"orphan_db":%s}\n' \
			"$([[ "$issues" -eq 0 ]] && echo true || echo false)" \
			"$(json_string_array "$orphan_pki")" \
			"$(json_string_array "$orphan_db")"
	else
		if [[ -n "$orphan_pki" ]]; then
			echo "Valid cert but no $DB_FILE entry (cannot connect until added):"
			sed 's/^/  - /' <<< "$orphan_pki"
		fi
		if [[ -n "$orphan_db" ]]; then
			echo "$DB_FILE entry with no matching valid cert (stale -- consider removing):"
			sed 's/^/  - /' <<< "$orphan_db"
		fi
		if [[ "$issues" -eq 0 ]]; then
			echo "OK -- every valid cert has a matching db entry and vice versa."
		fi
	fi
	return "$issues"
}

do_lint_db () {
	# Usage: do_lint_db [json]
	# Validates every openvpn_db.txt line matches "name=aa:bb:cc:dd:ee:ff"
	# and the file ends with a single trailing newline. Exit status:
	# 0 = clean, 1 = at least one problem found.
	local as_json="${1:-}" issues=0 lineno=0 line
	local -a problems=()

	if [[ ! -f "$DB_FILE" ]]; then
		if [[ "$as_json" == json ]]; then
			printf '{"error":"%s does not exist"}\n' "$(json_escape "$DB_FILE")"
		else
			echo "$DB_FILE does not exist."
		fi
		return 1
	fi

	while IFS= read -r line || [[ -n "$line" ]]; do
		lineno=$((lineno + 1))
		if [[ -z "$line" ]]; then
			problems+=("Line $lineno: blank line (harmless but unexpected).")
			continue
		fi
		if [[ ! "$line" =~ ^[A-Za-z0-9_.-]+=([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$ ]]; then
			problems+=("Line $lineno: malformed entry: '$line'")
			issues=1
		fi
	done < "$DB_FILE"

	local trailing_ok=true
	if [[ -s "$DB_FILE" ]] && [[ -n "$(tail -c1 "$DB_FILE")" ]]; then
		trailing_ok=false
		problems+=("$DB_FILE does not end with a trailing newline -- the next appended entry could get glued onto the last line.")
		issues=1
	fi

	if [[ "$as_json" == json ]]; then
		local first=1
		printf '{"clean":%s,"entries":%d,"trailing_newline_ok":%s,"issues":[' \
			"$([[ "$issues" -eq 0 ]] && echo true || echo false)" "$lineno" "$trailing_ok"
		for p in "${problems[@]}"; do
			[[ $first -eq 1 ]] && first=0 || printf ','
			printf '"%s"' "$(json_escape "$p")"
		done
		printf ']}\n'
	else
		for p in "${problems[@]}"; do
			echo "$p"
		done
		if [[ "$issues" -eq 0 ]]; then
			echo "OK -- $DB_FILE is well-formed ($lineno entries)."
		fi
	fi
	return "$issues"
}

print_usage () {
	cat <<-USAGE
	Usage: $0 [command]

	With no command, runs the interactive installer/menu.

	Commands:
	  --add NAME MAC   Add a new client non-interactively (MAC in any common
	                   separator style/case -- normalized automatically)
	  --revoke NAME    Revoke an existing client
	  --list           List valid clients and their MAC-db registration status
	  --list-revoked   List revoked clients, when revoked, and any stale db entries
	  --macs NAME      List every MAC address registered for one client
	  --add-mac NAME MAC     Register an additional device MAC for an existing client
	  --remove-mac NAME MAC  Remove one specific MAC registration (client keeps its cert)
	  --show-ovpn NAME       Print an existing client's .ovpn config to stdout
	  --purge-revoked NAME   Permanently delete a revoked client's leftover PKI/.ovpn files
	  --restore NAME MAC     Reissue a brand-new cert under a revoked client's name
	                         (NOT un-revoking the old cert -- see --help output below)
	  --check          Cross-check PKI valid certs against $DB_FILE for orphans
	  --lint-db        Validate $DB_FILE formatting and trailing-newline health
	  --help           Show this help

	--json can be combined with --list, --list-revoked, --macs, --check, or
	--lint-db to print structured JSON instead of a table (order doesn't
	matter, e.g. both "--list --json" and "--json --list" work). Not valid
	with any other command.

	Note on --restore: a revoked certificate cannot be un-revoked once its
	CRL entry exists (that's how PKI revocation is supposed to work).
	--restore instead purges the old revoked client's leftover files and
	issues a brand-new certificate under the same name -- the person is
	back, but cryptographically it's a fresh identity, not the old one
	reactivated.
	USAGE
}

# --- Non-interactive CLI dispatch --------------------------------------------

# --json can appear anywhere in the arguments ("--list --json" or
# "--json --list" both work) -- pull it out first, leaving the rest of the
# arguments (the actual command) to dispatch on as before.
json_flag=""
_cli_args=()
for _a in "$@"; do
	if [[ "$_a" == "--json" ]]; then
		json_flag=json
	else
		_cli_args+=("$_a")
	fi
done
set -- "${_cli_args[@]}"
unset _a _cli_args

case "${1:-}" in
	--add|--revoke|--list|--list-revoked|--macs|--add-mac|--remove-mac|--show-ovpn|--purge-revoked|--restore|--check|--lint-db)
		if [[ ! -e "$OPENVPN_DIR/server.conf" ]]; then
			echo "OpenVPN is not installed yet (no $OPENVPN_DIR/server.conf) -- run without arguments first to install." >&2
			exit 1
		fi
		;;
esac

if [[ -n "$json_flag" ]]; then
	case "${1:-}" in
		--list|--list-revoked|--macs|--check|--lint-db) ;;
		*)
			echo "--json option is not allowed with this command." >&2
			exit 1
			;;
	esac
fi

case "${1:-}" in
	--add)
		do_add_client "$2" "$3"
		exit $?
		;;
	--revoke)
		do_revoke_client "$2"
		exit $?
		;;
	--list)
		do_list_clients "$json_flag"
		exit $?
		;;
	--list-revoked)
		do_list_revoked "$json_flag"
		exit $?
		;;
	--macs)
		do_list_macs "$2" "$json_flag"
		exit $?
		;;
	--add-mac)
		do_add_mac "$2" "$3"
		exit $?
		;;
	--remove-mac)
		do_remove_mac "$2" "$3"
		exit $?
		;;
	--show-ovpn)
		do_show_ovpn "$2"
		exit $?
		;;
	--purge-revoked)
		do_purge_revoked "$2"
		exit $?
		;;
	--restore)
		do_restore_client "$2" "$3"
		exit $?
		;;
	--check)
		do_check_consistency "$json_flag"
		exit $?
		;;
	--lint-db)
		do_lint_db "$json_flag"
		exit $?
		;;
	--help|-h)
		print_usage
		exit 0
		;;
	"")
		: # no command given -- fall through to the interactive flow below
		;;
	*)
		echo "Unknown option: $1" >&2
		print_usage
		exit 1
		;;
esac

# --- Interactive flow (unchanged behavior, now using the config vars above) -

if [[ ! -e "$OPENVPN_DIR/server.conf" ]]; then
	# Detect some Debian minimal setups where neither wget nor curl are installed
	if ! hash wget 2>/dev/null && ! hash curl 2>/dev/null; then
		echo "Wget is required to use this installer."
		read -n1 -r -p "Press any key to install Wget and continue..."
		apt-get update
		apt-get install -y wget
	fi
	clear
	echo 'Welcome to this OpenVPN road warrior installer!'
	# If system has a single IPv4, it is selected automatically. Else, ask the user
	if [[ $(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}') -eq 1 ]]; then
		ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
	else
		number_of_ip=$(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}')
		echo
		echo "Which IPv4 address should be used?"
		ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | nl -s ') '
		read -p "IPv4 address [1]: " ip_number
		until [[ -z "$ip_number" || "$ip_number" =~ ^[0-9]+$ && "$ip_number" -le "$number_of_ip" ]]; do
			echo "$ip_number: invalid selection."
			read -p "IPv4 address [1]: " ip_number
		done
		[[ -z "$ip_number" ]] && ip_number="1"
		ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sed -n "$ip_number"p)
	fi
	# If $ip is a private IP address, the server must be behind NAT
	if echo "$ip" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
		echo
		echo "This server is behind NAT. What is the public IPv4 address or hostname?"
		# Get public IP and sanitize with grep
		get_public_ip=$(grep -m 1 -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' <<< "$(wget -T 10 -t 1 -4qO- "http://ip1.dynupdate.no-ip.com/" || curl -m 10 -4Ls "http://ip1.dynupdate.no-ip.com/")")
		read -p "Public IPv4 address / hostname [$get_public_ip]: " public_ip
		# If the checkip service is unavailable and user didn't provide input, ask again
		until [[ -n "$get_public_ip" || -n "$public_ip" ]]; do
			echo "Invalid input."
			read -p "Public IPv4 address / hostname: " public_ip
		done
		[[ -z "$public_ip" ]] && public_ip="$get_public_ip"
	fi
	# If system has a single IPv6, it is selected automatically
	if [[ $(ip -6 addr | grep -c 'inet6 [23]') -eq 1 ]]; then
		ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}')
	fi
	# If system has multiple IPv6, ask the user to select one
	if [[ $(ip -6 addr | grep -c 'inet6 [23]') -gt 1 ]]; then
		number_of_ip6=$(ip -6 addr | grep -c 'inet6 [23]')
		echo
		echo "Which IPv6 address should be used?"
		ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | nl -s ') '
		read -p "IPv6 address [1]: " ip6_number
		until [[ -z "$ip6_number" || "$ip6_number" =~ ^[0-9]+$ && "$ip6_number" -le "$number_of_ip6" ]]; do
			echo "$ip6_number: invalid selection."
			read -p "IPv6 address [1]: " ip6_number
		done
		[[ -z "$ip6_number" ]] && ip6_number="1"
		ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | sed -n "$ip6_number"p)
	fi
	echo
	echo "Which protocol should OpenVPN use?"
	echo "   1) UDP (recommended)"
	echo "   2) TCP"
	read -p "Protocol [1]: " protocol
	until [[ -z "$protocol" || "$protocol" =~ ^[12]$ ]]; do
		echo "$protocol: invalid selection."
		read -p "Protocol [1]: " protocol
	done
	case "$protocol" in
		1|"")
		protocol=udp
		;;
		2)
		protocol=tcp
		;;
	esac
	echo
	echo "What port should OpenVPN listen to?"
	read -p "Port [1194]: " port
	until [[ -z "$port" || "$port" =~ ^[0-9]+$ && "$port" -le 65535 ]]; do
		echo "$port: invalid port."
		read -p "Port [1194]: " port
	done
	[[ -z "$port" ]] && port="1194"
	echo
	echo "Select a DNS server for the clients:"
	echo "   1) Current system resolvers"
	echo "   2) Google"
	echo "   3) 1.1.1.1"
	echo "   4) OpenDNS"
	echo "   5) Quad9"
	echo "   6) AdGuard"
	read -p "DNS server [1]: " dns
	until [[ -z "$dns" || "$dns" =~ ^[1-6]$ ]]; do
		echo "$dns: invalid selection."
		read -p "DNS server [1]: " dns
	done
	echo
	echo "Enter a name for the first client:"
	read -p "Name [client]: " unsanitized_client
	# Allow a limited set of characters to avoid conflicts
	client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
	[[ -z "$client" ]] && client="client"
	echo
	echo "OpenVPN installation is ready to begin."
	# Install a firewall if firewalld or iptables are not already available
	if ! systemctl is-active --quiet firewalld.service && ! hash iptables 2>/dev/null; then
		if [[ "$os" == "centos" || "$os" == "fedora" ]]; then
			firewall="firewalld"
			# We don't want to silently enable firewalld, so we give a subtle warning
			# If the user continues, firewalld will be installed and enabled during setup
			echo "firewalld, which is required to manage routing tables, will also be installed."
		elif [[ "$os" == "debian" || "$os" == "ubuntu" ]]; then
			# iptables is way less invasive than firewalld so no warning is given
			firewall="iptables"
		fi
	fi
	read -n1 -r -p "Press any key to continue..."
	# If running inside a container, disable LimitNPROC to prevent conflicts
	if systemd-detect-virt -cq; then
		mkdir /etc/systemd/system/openvpn-server@server.service.d/ 2>/dev/null
		echo "[Service]
LimitNPROC=infinity" > /etc/systemd/system/openvpn-server@server.service.d/disable-limitnproc.conf
	fi
	if [[ "$os" = "debian" || "$os" = "ubuntu" ]]; then
		apt-get update
		apt-get install -y --no-install-recommends openvpn openssl ca-certificates $firewall
	elif [[ "$os" = "centos" ]]; then
		yum install -y epel-release
		yum install -y openvpn openssl ca-certificates tar $firewall
	else
		# Else, OS must be Fedora
		dnf install -y openvpn openssl ca-certificates tar $firewall
	fi
	# If firewalld was just installed, enable it
	if [[ "$firewall" == "firewalld" ]]; then
		systemctl enable --now firewalld.service
	fi
	# Get easy-rsa
	easy_rsa_url='https://github.com/OpenVPN/easy-rsa/releases/download/v3.1.7/EasyRSA-3.1.7.tgz'
	mkdir -p "$EASYRSA_DIR/"
	{ wget -qO- "$easy_rsa_url" 2>/dev/null || curl -sL "$easy_rsa_url" ; } | tar xz -C "$EASYRSA_DIR/" --strip-components 1
	chown -R root:root "$EASYRSA_DIR/"
	cd "$EASYRSA_DIR/"
	# Create the PKI, set up the CA and the server and client certificates
	./easyrsa --batch init-pki
	./easyrsa --batch build-ca nopass
	./easyrsa --batch --days=3650 build-server-full server nopass
	./easyrsa --batch --days=3650 build-client-full "$client" nopass
	./easyrsa --batch --days=3650 gen-crl
	# Move the stuff we need
	cp pki/ca.crt pki/private/ca.key pki/issued/server.crt pki/private/server.key pki/crl.pem "$OPENVPN_DIR"
	# CRL is read with each client connection, while OpenVPN is dropped to nobody
	chown nobody:"$group_name" "$OPENVPN_DIR/crl.pem"
	# Without +x in the directory, OpenVPN can't run a stat() on the CRL file
	chmod o+x "$OPENVPN_DIR/"
	# Generate key for tls-crypt
	openvpn --genkey --secret "$OPENVPN_DIR/tc.key"
	# Create the DH parameters file using the predefined ffdhe2048 group
	echo '-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz
+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a
87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7
YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi
7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD
ssbzSibBsu/6iGtCOGEoXJf//////////wIBAg==
-----END DH PARAMETERS-----' > "$OPENVPN_DIR/dh.pem"
	# Generate server.conf
	echo "local $ip
port $port
proto $protocol
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
auth SHA512
tls-crypt tc.key
topology subnet
server 10.8.0.0 255.255.255.0" > "$OPENVPN_DIR/server.conf"
	# IPv6
	if [[ -z "$ip6" ]]; then
		echo 'push "redirect-gateway def1 bypass-dhcp"' >> "$OPENVPN_DIR/server.conf"
	else
		echo 'server-ipv6 fddd:1194:1194:1194::/64' >> "$OPENVPN_DIR/server.conf"
		echo 'push "redirect-gateway def1 ipv6 bypass-dhcp"' >> "$OPENVPN_DIR/server.conf"
	fi
	echo 'ifconfig-pool-persist ipp.txt' >> "$OPENVPN_DIR/server.conf"
	# DNS
	case "$dns" in
		1|"")
			# Locate the proper resolv.conf
			# Needed for systems running systemd-resolved
			if grep '^nameserver' "/etc/resolv.conf" | grep -qv '127.0.0.53' ; then
				resolv_conf="/etc/resolv.conf"
			else
				resolv_conf="/run/systemd/resolve/resolv.conf"
			fi
			# Obtain the resolvers from resolv.conf and use them for OpenVPN
			grep -v '^#\|^;' "$resolv_conf" | grep '^nameserver' | grep -v '127.0.0.53' | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | while read line; do
				echo "push \"dhcp-option DNS $line\"" >> "$OPENVPN_DIR/server.conf"
			done
		;;
		2)
			echo 'push "dhcp-option DNS 8.8.8.8"' >> "$OPENVPN_DIR/server.conf"
			echo 'push "dhcp-option DNS 8.8.4.4"' >> "$OPENVPN_DIR/server.conf"
		;;
		3)
			echo 'push "dhcp-option DNS 1.1.1.1"' >> "$OPENVPN_DIR/server.conf"
			echo 'push "dhcp-option DNS 1.0.0.1"' >> "$OPENVPN_DIR/server.conf"
		;;
		4)
			echo 'push "dhcp-option DNS 208.67.222.222"' >> "$OPENVPN_DIR/server.conf"
			echo 'push "dhcp-option DNS 208.67.220.220"' >> "$OPENVPN_DIR/server.conf"
		;;
		5)
			echo 'push "dhcp-option DNS 9.9.9.9"' >> "$OPENVPN_DIR/server.conf"
			echo 'push "dhcp-option DNS 149.112.112.112"' >> "$OPENVPN_DIR/server.conf"
		;;
		6)
			echo 'push "dhcp-option DNS 94.140.14.14"' >> "$OPENVPN_DIR/server.conf"
			echo 'push "dhcp-option DNS 94.140.15.15"' >> "$OPENVPN_DIR/server.conf"
		;;
	esac
	echo 'push "block-outside-dns"' >> "$OPENVPN_DIR/server.conf"
	echo "keepalive 10 120
cipher AES-256-CBC
user nobody
group $group_name
persist-key
persist-tun
verb 3
crl-verify crl.pem" >> "$OPENVPN_DIR/server.conf"
	if [[ "$protocol" = "udp" ]]; then
		echo "explicit-exit-notify" >> "$OPENVPN_DIR/server.conf"
	fi
	# Enable net.ipv4.ip_forward for the system
	echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-openvpn-forward.conf
	# Enable without waiting for a reboot or service restart
	echo 1 > /proc/sys/net/ipv4/ip_forward
	if [[ -n "$ip6" ]]; then
		# Enable net.ipv6.conf.all.forwarding for the system
		echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.d/99-openvpn-forward.conf
		# Enable without waiting for a reboot or service restart
		echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
	fi
	if systemctl is-active --quiet firewalld.service; then
		# Using both permanent and not permanent rules to avoid a firewalld
		# reload.
		# We don't use --add-service=openvpn because that would only work with
		# the default port and protocol.
		firewall-cmd --add-port="$port"/"$protocol"
		firewall-cmd --zone=trusted --add-source=10.8.0.0/24
		firewall-cmd --permanent --add-port="$port"/"$protocol"
		firewall-cmd --permanent --zone=trusted --add-source=10.8.0.0/24
		# Set NAT for the VPN subnet
		firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip"
		firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip"
		if [[ -n "$ip6" ]]; then
			firewall-cmd --zone=trusted --add-source=fddd:1194:1194:1194::/64
			firewall-cmd --permanent --zone=trusted --add-source=fddd:1194:1194:1194::/64
			firewall-cmd --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
			firewall-cmd --permanent --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
		fi
	else
		# Create a service to set up persistent iptables rules
		iptables_path=$(command -v iptables)
		ip6tables_path=$(command -v ip6tables)
		# nf_tables is not available as standard in OVZ kernels. So use iptables-legacy
		# if we are in OVZ, with a nf_tables backend and iptables-legacy is available.
		if [[ $(systemd-detect-virt) == "openvz" ]] && readlink -f "$(command -v iptables)" | grep -q "nft" && hash iptables-legacy 2>/dev/null; then
			iptables_path=$(command -v iptables-legacy)
			ip6tables_path=$(command -v ip6tables-legacy)
		fi
		echo "[Unit]
Before=network.target
[Service]
Type=oneshot
ExecStart=$iptables_path -t nat -A POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $ip
ExecStart=$iptables_path -I INPUT -p $protocol --dport $port -j ACCEPT
ExecStart=$iptables_path -I FORWARD -s 10.8.0.0/24 -j ACCEPT
ExecStart=$iptables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$iptables_path -t nat -D POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $ip
ExecStop=$iptables_path -D INPUT -p $protocol --dport $port -j ACCEPT
ExecStop=$iptables_path -D FORWARD -s 10.8.0.0/24 -j ACCEPT
ExecStop=$iptables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" > /etc/systemd/system/openvpn-iptables.service
		if [[ -n "$ip6" ]]; then
			echo "ExecStart=$ip6tables_path -t nat -A POSTROUTING -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to $ip6
ExecStart=$ip6tables_path -I FORWARD -s fddd:1194:1194:1194::/64 -j ACCEPT
ExecStart=$ip6tables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$ip6tables_path -t nat -D POSTROUTING -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to $ip6
ExecStop=$ip6tables_path -D FORWARD -s fddd:1194:1194:1194::/64 -j ACCEPT
ExecStop=$ip6tables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" >> /etc/systemd/system/openvpn-iptables.service
		fi
		echo "RemainAfterExit=yes
[Install]
WantedBy=multi-user.target" >> /etc/systemd/system/openvpn-iptables.service
		systemctl enable --now openvpn-iptables.service
	fi
	# If SELinux is enabled and a custom port was selected, we need this
	if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$port" != 1194 ]]; then
		# Install semanage if not already present
		if ! hash semanage 2>/dev/null; then
			if [[ "$os_version" -eq 7 ]]; then
				# Centos 7
				yum install -y policycoreutils-python
			else
				# CentOS 8 or Fedora
				dnf install -y policycoreutils-python-utils
			fi
		fi
		semanage port -a -t openvpn_port_t -p "$protocol" "$port"
	fi
	# If the server is behind NAT, use the correct IP address
	[[ -n "$public_ip" ]] && ip="$public_ip"
	# client-common.txt is created so we have a template to add further users later
	echo "client
dev tun
proto $protocol
remote $ip $port
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA512
cipher AES-256-CBC
ignore-unknown-option block-outside-dns
push-peer-info
verb 3" > "$CLIENT_COMMON_FILE"
	# Enable and start the OpenVPN service
	systemctl enable --now "$SERVICE_NAME"
	# Generates the custom client.ovpn
	new_client "$client"
	echo
	echo "Finished!"
	echo
	echo "The client configuration is available in:" ~/"$client.ovpn"
	echo "New clients can be added by running this script again."
else
	clear
	echo "OpenVPN is already installed."
	echo
	echo "Select an option:"
	echo "   1) Add a new client"
	echo "   2) List existing clients"
	echo "   3) List revoked clients"
	echo "   4) List MAC addresses for a client"
	echo "   5) Add a MAC address for an existing client"
	echo "   6) Remove a MAC address from an existing client"
	echo "   7) Revoke an existing client"
	echo "   8) Remove OpenVPN"
	echo "   9) Show/print a client's .ovpn config"
	echo "  10) Permanently delete a revoked client's leftover files"
	echo "  11) Restore (reissue a new cert for) a revoked client"
	echo "  12) Exit"
	read -p "Option: " option
	until [[ "$option" =~ ^([1-9]|1[0-2])$ ]]; do
		echo "$option: invalid selection."
		read -p "Option: " option
	done
	case "$option" in
		1)
			echo
			echo "Provide a name for the client:"
			read -p "Name: " unsanitized_client
			client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
			while [[ -z "$client" || -e "$EASYRSA_DIR/pki/issued/$client.crt" ]]; do
				echo "$client: invalid name."
				read -p "Name: " unsanitized_client
				client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
			done
			echo
			echo "Enter the MAC address of the client's device (required for MAC-binding auth)."
			echo "Accepted separators: ':', '-', or none. Letters may be upper or lower case."
			while true; do
				read -p "MAC address: " raw_mac
				if mac=$(normalize_mac "$raw_mac"); then
					break
				else
					echo "Invalid MAC address: expected 12 hex characters (e.g. aa:bb:cc:dd:ee:ff)."
				fi
			done
			do_add_client "$client" "$mac"
			exit
		;;
		2)
			echo
			do_list_clients
			exit
		;;
		3)
			echo
			do_list_revoked
			exit
		;;
		4)
			echo
			echo "Provide the client name to look up:"
			read -p "Name: " macs_name
			do_list_macs "$macs_name"
			exit
		;;
		5)
			echo
			echo "Provide the name of the existing client to add a MAC address for:"
			read -p "Name: " addmac_name
			echo
			echo "Enter the additional device's MAC address."
			echo "Accepted separators: ':', '-', or none. Letters may be upper or lower case."
			while true; do
				read -p "MAC address: " raw_mac
				if mac=$(normalize_mac "$raw_mac"); then
					break
				else
					echo "Invalid MAC address: expected 12 hex characters (e.g. aa:bb:cc:dd:ee:ff)."
				fi
			done
			do_add_mac "$addmac_name" "$mac"
			exit
		;;
		6)
			echo
			echo "Provide the name of the existing client to remove a MAC address from:"
			read -p "Name: " removemac_name
			echo
			do_list_macs "$removemac_name"
			echo
			echo "Enter the MAC address to remove:"
			read -p "MAC address: " raw_mac
			if mac=$(normalize_mac "$raw_mac"); then
				do_remove_mac "$removemac_name" "$mac"
			else
				echo "Invalid MAC address: expected 12 hex characters (e.g. aa:bb:cc:dd:ee:ff)."
			fi
			exit
		;;
		7)
			# This option could be documented a bit better and maybe even be simplified
			# ...but what can I say, I want some sleep too
			number_of_clients=$(tail -n +2 "$EASYRSA_DIR/pki/index.txt" | grep -c "^V")
			if [[ "$number_of_clients" = 0 ]]; then
				echo
				echo "There are no existing clients!"
				exit
			fi
			echo
			echo "Select the client to revoke:"
			tail -n +2 "$EASYRSA_DIR/pki/index.txt" | grep "^V" | cut -d '=' -f 2 | nl -s ') '
			read -p "Client: " client_number
			until [[ "$client_number" =~ ^[0-9]+$ && "$client_number" -le "$number_of_clients" ]]; do
				echo "$client_number: invalid selection."
				read -p "Client: " client_number
			done
			client=$(tail -n +2 "$EASYRSA_DIR/pki/index.txt" | grep "^V" | cut -d '=' -f 2 | sed -n "$client_number"p)
			echo
			read -p "Confirm $client revocation? [y/N]: " revoke
			until [[ "$revoke" =~ ^[yYnN]*$ ]]; do
				echo "$revoke: invalid selection."
				read -p "Confirm $client revocation? [y/N]: " revoke
			done
			if [[ "$revoke" =~ ^[yY]$ ]]; then
				do_revoke_client "$client"
			else
				echo
				echo "$client revocation aborted!"
			fi
			exit
		;;
		8)
			echo
			read -p "Confirm OpenVPN removal? [y/N]: " remove
			until [[ "$remove" =~ ^[yYnN]*$ ]]; do
				echo "$remove: invalid selection."
				read -p "Confirm OpenVPN removal? [y/N]: " remove
			done
			if [[ "$remove" =~ ^[yY]$ ]]; then
				port=$(grep '^port ' "$OPENVPN_DIR/server.conf" | cut -d " " -f 2)
				protocol=$(grep '^proto ' "$OPENVPN_DIR/server.conf" | cut -d " " -f 2)
				if systemctl is-active --quiet firewalld.service; then
					ip=$(firewall-cmd --direct --get-rules ipv4 nat POSTROUTING | grep '\-s 10.8.0.0/24 '"'"'!'"'"' -d 10.8.0.0/24' | grep -oE '[^ ]+$')
					# Using both permanent and not permanent rules to avoid a firewalld reload.
					firewall-cmd --remove-port="$port"/"$protocol"
					firewall-cmd --zone=trusted --remove-source=10.8.0.0/24
					firewall-cmd --permanent --remove-port="$port"/"$protocol"
					firewall-cmd --permanent --zone=trusted --remove-source=10.8.0.0/24
					firewall-cmd --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip"
					firewall-cmd --permanent --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip"
					if grep -qs "server-ipv6" "$OPENVPN_DIR/server.conf"; then
						ip6=$(firewall-cmd --direct --get-rules ipv6 nat POSTROUTING | grep '\-s fddd:1194:1194:1194::/64 '"'"'!'"'"' -d fddd:1194:1194:1194::/64' | grep -oE '[^ ]+$')
						firewall-cmd --zone=trusted --remove-source=fddd:1194:1194:1194::/64
						firewall-cmd --permanent --zone=trusted --remove-source=fddd:1194:1194:1194::/64
						firewall-cmd --direct --remove-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
						firewall-cmd --permanent --direct --remove-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
					fi
				else
					systemctl disable --now openvpn-iptables.service
					rm -f /etc/systemd/system/openvpn-iptables.service
				fi
				if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$port" != 1194 ]]; then
					semanage port -d -t openvpn_port_t -p "$protocol" "$port"
				fi
				systemctl disable --now "$SERVICE_NAME"
				rm -f /etc/systemd/system/openvpn-server@server.service.d/disable-limitnproc.conf
				rm -f /etc/sysctl.d/99-openvpn-forward.conf
				if [[ "$os" = "debian" || "$os" = "ubuntu" ]]; then
					rm -rf "$OPENVPN_DIR"
					apt-get remove --purge -y openvpn
				else
					# Else, OS must be CentOS or Fedora
					yum remove -y openvpn
					rm -rf "$OPENVPN_DIR"
				fi
				echo
				echo "OpenVPN removed!"
			else
				echo
				echo "OpenVPN removal aborted!"
			fi
			exit
		;;
		9)
			echo
			echo "Provide the client name to show/print the .ovpn config for:"
			read -p "Name: " showovpn_name
			echo
			do_show_ovpn "$showovpn_name"
			exit
		;;
		10)
			echo
			do_list_revoked
			echo
			echo "Provide the name of the revoked client to permanently delete leftover files for:"
			read -p "Name: " purge_name
			echo
			read -p "Confirm permanent deletion of $purge_name's leftover PKI/.ovpn files? [y/N]: " purge_confirm
			until [[ "$purge_confirm" =~ ^[yYnN]*$ ]]; do
				echo "$purge_confirm: invalid selection."
				read -p "Confirm permanent deletion of $purge_name's leftover PKI/.ovpn files? [y/N]: " purge_confirm
			done
			if [[ "$purge_confirm" =~ ^[yY]$ ]]; then
				do_purge_revoked "$purge_name"
			else
				echo
				echo "Purge aborted!"
			fi
			exit
		;;
		11)
			echo
			echo "Restoring a revoked client does NOT un-revoke their old certificate"
			echo "(not possible once it's on the CRL) -- it purges the old leftover files"
			echo "and issues a brand-new certificate under the same name instead."
			echo
			do_list_revoked
			echo
			echo "Provide the name of the revoked client to restore:"
			read -p "Name: " restore_name
			echo
			echo "Enter the MAC address of the client's device (required for MAC-binding auth)."
			echo "Accepted separators: ':', '-', or none. Letters may be upper or lower case."
			while true; do
				read -p "MAC address: " raw_mac
				if mac=$(normalize_mac "$raw_mac"); then
					break
				else
					echo "Invalid MAC address: expected 12 hex characters (e.g. aa:bb:cc:dd:ee:ff)."
				fi
			done
			do_restore_client "$restore_name" "$mac"
			exit
		;;
		12)
			exit
		;;
	esac
fi
