"""Native Python OpenVPN service layer -- Phase 1 of the bash->Python migration
(see /home/hackx/.claude/plans/openvpn-bash-to-python-migration-lazy-neumann.md).

This package is developed and validated *alongside* openvpn-install.sh, which
remains untouched and authoritative in production. Nothing under
app/vpnadmin/ imports from here yet -- that wiring is Phase 2, gated on this
package's own parity tests passing against the bash script's documented
behavior.
"""
