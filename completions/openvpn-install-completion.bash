# Bash completion for openvpn-install.sh
#
# Enable it by sourcing this file, e.g. from ~/.bashrc:
#   source /path/to/openvpn-install-completion.bash
# or system-wide by copying it into /etc/bash_completion.d/.
#
# Only binds to the script's own name (openvpn-install.sh / ./openvpn-install.sh)
# -- NOT to bare `sudo` or `bash`, which would clobber tab-completion for
# every other command invoked that way. `sudo openvpn-install.sh ...` still
# completes correctly on any system with the standard `bash-completion`
# package installed (near-universal on Ubuntu/Debian/Fedora): its own sudo
# handler already looks up whatever completion is registered for the command
# name following `sudo` and reuses it -- that's the correct place for that
# logic to live, not here.

_openvpn_install_completions() {
	local cur prev opts
	COMPREPLY=()
	cur="${COMP_WORDS[COMP_CWORD]}"
	prev="${COMP_WORDS[COMP_CWORD-1]}"
	opts="--add --revoke --list --list-revoked --macs --add-mac --remove-mac --check --lint-db --json --help"

	# Best-effort dynamic client-name completion for any command that takes
	# an existing client's NAME as its first argument: only if the PKI index
	# happens to already be readable by the completing user. Never invokes
	# sudo or prompts a password just to tab-complete.
	case "$prev" in
		--revoke|--macs|--add-mac|--remove-mac)
			local index="/etc/openvpn/server/easy-rsa/pki/index.txt" names
			if [[ -r "$index" ]]; then
				names=$(tail -n +2 "$index" 2>/dev/null | awk -F'\t' '$1=="V"{print $6}' | sed 's#^/CN=##' | grep -v '^server$')
				COMPREPLY=( $(compgen -W "$names" -- "$cur") )
			fi
			return 0
			;;
	esac

	COMPREPLY=( $(compgen -W "$opts" -- "$cur") )
	return 0
}

complete -F _openvpn_install_completions openvpn-install.sh
complete -F _openvpn_install_completions ./openvpn-install.sh
