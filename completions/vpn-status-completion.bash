# Bash completion for vpn-status.py
#
# Enable it by sourcing this file, e.g. from ~/.bashrc:
#   source /path/to/vpn-status-completion.bash
# or system-wide by copying it into /etc/bash_completion.d/.
#
# Only binds to the script's own name (vpn-status.py / ./vpn-status.py) --
# NOT to bare `python3`/`python`, which would clobber tab-completion for
# every *other* Python script you run that way too. To get completion when
# invoking it as `python3 vpn-status.py ...`, either run it directly
# (it's executable and has a #!/usr/bin/env python3 shebang -- `./vpn-status.py
# --all-clients` works as-is), or add a shell alias/function named exactly
# `vpn-status.py` that wraps the python3 invocation, e.g. in ~/.bashrc:
#   vpn-status.py() { python3 /path/to/vpn-status.py "$@"; }
# Completion is looked up by the literal first word you type, so either
# form is matched the same way.

_vpn_status_completions() {
	local cur opts
	COMPREPLY=()
	cur="${COMP_WORDS[COMP_CWORD]}"
	opts="--all-clients --rejected-connections --json --help"
	COMPREPLY=( $(compgen -W "$opts" -- "$cur") )
	return 0
}

complete -F _vpn_status_completions vpn-status.py
complete -F _vpn_status_completions ./vpn-status.py
