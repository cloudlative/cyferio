"""Python port of openvpn-install.sh's do_* functions -- PKI/cert lifecycle,
client/MAC management, and (Phase 1, full scope) install/uninstall
orchestration. See exceptions.py for the error hierarchy every module here
raises, and each module's own docstring for which bash function(s) it
replaces.
"""
