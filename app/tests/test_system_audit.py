"""Tests for the System Audit module -- the run_audit() orchestrator
(scoring, first-run vs. subsequent-run new/resolved diffing, notification
fan-out) and the API routes' RBAC/serialization. Every test injects fake
Finding objects via monkeypatching the check modules' run() functions
rather than exercising the real host-filesystem-reading checks (which
have no meaningful host_root to read from in a test sandbox anyway) --
system_checks.py/ssh_checks.py/firewall_checks.py's actual file-parsing
logic is exercised by hand against a real filesystem during development,
not by this suite; what matters here is run_audit()'s own orchestration
logic, which is check-content-agnostic."""
import pytest

from vpnadmin import mailer, slack_notifications, system_audit
from vpnadmin.models import AuditNotification
from vpnadmin.system_audit import Finding, compute_score

from .conftest import login


def _mock_checks(monkeypatch, *, system=None, ssh=None, firewall=None):
    """Replaces each check module's run() with one returning a fixed
    Finding list (default: a single "passed" finding, so a run with no
    explicit findings still has SOME content, matching how a real check
    module always emits at least one row)."""
    from vpnadmin.system_audit import firewall_checks, ssh_checks, system_checks

    default = [Finding(check_id="x.passed", category="x", severity="passed", title="OK", description="OK")]
    monkeypatch.setattr(system_checks, "run", lambda host_root: system if system is not None else default)
    monkeypatch.setattr(ssh_checks, "run", lambda host_root: ssh if ssh is not None else [])
    monkeypatch.setattr(firewall_checks, "run", lambda host_root: firewall if firewall is not None else [])


def _mock_channels(monkeypatch):
    emails, slacks = [], []
    monkeypatch.setattr(mailer, "_send", lambda db, message: emails.append(message))
    monkeypatch.setattr(slack_notifications, "notify", lambda db, event_type, text: slacks.append((event_type, text)))
    return emails, slacks


class TestComputeScore:
    def test_no_findings_is_100(self):
        assert compute_score([]) == 100

    def test_passed_and_info_dont_affect_score(self):
        findings = [
            Finding(check_id="a", category="x", severity="passed", title="a", description="a"),
            Finding(check_id="b", category="x", severity="info", title="b", description="b"),
        ]
        assert compute_score(findings) == 100

    def test_severity_penalties(self):
        findings = [Finding(check_id="a", category="x", severity="critical", title="a", description="a")]
        assert compute_score(findings) == 75
        findings = [Finding(check_id="a", category="x", severity="high", title="a", description="a")]
        assert compute_score(findings) == 90

    def test_score_floors_at_zero(self):
        findings = [Finding(check_id=f"c{i}", category="x", severity="critical", title="c", description="c")
                    for i in range(10)]
        assert compute_score(findings) == 0

    def test_unknown_severity_rejected(self):
        import pytest
        with pytest.raises(ValueError):
            Finding(check_id="a", category="x", severity="urgent", title="a", description="a")


class TestRunAuditOrchestration:
    """Exercises run_audit() directly against db_session, not through the
    HTTP layer -- these are about the orchestration logic (scoring,
    persistence, history diffing), which is identical regardless of which
    route triggered it."""

    def test_first_run_nothing_is_flagged_new(self, db_session, monkeypatch):
        """Regression test: the very first audit run has no previous run to
        diff against, so nothing should be counted/flagged "new" -- fixed
        2026-08-22 after live testing showed every finding on a fresh
        deployment's first-ever run incorrectly counted as "new since the
        previous run" (there is no previous run)."""
        _mock_checks(monkeypatch, system=[
            Finding(check_id="s.one", category="system", severity="info", title="One", description="d"),
            Finding(check_id="s.two", category="system", severity="high", title="Two", description="d"),
        ])
        run = system_audit.run_audit(db_session, trigger="manual")
        assert run.status == "completed"
        assert run.new_findings_count == 0
        assert run.resolved_findings_count == 0
        assert all(f.status == "existing" for f in run.findings if f.severity != "passed")

    def test_second_run_new_finding_is_flagged(self, db_session, monkeypatch):
        _mock_checks(monkeypatch, system=[Finding(check_id="s.one", category="system", severity="info", title="One", description="d")])
        system_audit.run_audit(db_session, trigger="manual")

        _mock_checks(monkeypatch, system=[
            Finding(check_id="s.one", category="system", severity="info", title="One", description="d"),
            Finding(check_id="s.two", category="system", severity="critical", title="Two", description="d"),
        ])
        run2 = system_audit.run_audit(db_session, trigger="manual")
        assert run2.new_findings_count == 1
        new_finding = next(f for f in run2.findings if f.check_id == "s.two")
        assert new_finding.status == "new"
        existing_finding = next(f for f in run2.findings if f.check_id == "s.one")
        assert existing_finding.status == "existing"

    def test_resolved_finding_is_flagged(self, db_session, monkeypatch):
        _mock_checks(monkeypatch, system=[Finding(check_id="s.one", category="system", severity="high", title="One", description="d")])
        system_audit.run_audit(db_session, trigger="manual")

        _mock_checks(monkeypatch, system=[Finding(check_id="s.one", category="system", severity="passed", title="One", description="d")])
        run2 = system_audit.run_audit(db_session, trigger="manual")
        assert run2.resolved_findings_count == 1
        finding = next(f for f in run2.findings if f.check_id == "s.one")
        assert finding.status == "resolved"
        assert finding.severity == "passed"

    def test_score_and_counts_persisted_on_run(self, db_session, monkeypatch):
        _mock_checks(monkeypatch, system=[
            Finding(check_id="s.crit", category="system", severity="critical", title="C", description="d"),
            Finding(check_id="s.high", category="system", severity="high", title="H", description="d"),
        ])
        run = system_audit.run_audit(db_session, trigger="manual")
        assert run.score == 65  # 100 - 25 - 10
        assert run.critical_count == 1
        assert run.high_count == 1
        assert run.total_findings == 2

    def test_new_critical_notifies_every_admin(self, db_session, monkeypatch):
        from vpnadmin.auth import hash_password
        from vpnadmin.models import Role, User

        second_admin = User(username="second-admin", password_hash=hash_password("password123"), role=Role.admin)
        db_session.add(second_admin)
        db_session.commit()

        emails, slacks = _mock_channels(monkeypatch)
        _mock_checks(monkeypatch, system=[Finding(check_id="s.crit", category="system", severity="critical", title="C", description="d")])
        run = system_audit.run_audit(db_session, trigger="manual")

        notifs = db_session.query(AuditNotification).filter_by(run_id=run.id, reason="new_critical").all()
        # One per admin-role account that has view access (both "admin"
        # fixture users created by app_client + the second admin here) --
        # exact count depends on which fixture created which users, so
        # just assert it's broadcast (>1), not a hardcoded number tied to
        # fixture internals.
        assert len(notifs) >= 1
        assert any("Critical" in n.message for n in notifs)
        # Slack fires (admin_notification_email unset by default, so email
        # doesn't -- see mailer.send_admin_notification's own "not
        # configured" early return).
        assert any(evt == "audit_critical_finding" for evt, _ in slacks)

    def test_repeat_finding_does_not_renotify(self, db_session, monkeypatch):
        from vpnadmin.auth import hash_password
        from vpnadmin.models import Role, User

        db_session.add(User(username="an-admin", password_hash=hash_password("password123"), role=Role.admin))
        db_session.commit()

        _mock_channels(monkeypatch)
        _mock_checks(monkeypatch, system=[Finding(check_id="s.crit", category="system", severity="critical", title="C", description="d")])
        run1 = system_audit.run_audit(db_session, trigger="manual")
        run2 = system_audit.run_audit(db_session, trigger="manual")
        assert db_session.query(AuditNotification).filter_by(run_id=run1.id, reason="new_critical").count() >= 1
        assert db_session.query(AuditNotification).filter_by(run_id=run2.id, reason="new_critical").count() == 0

    def test_failed_check_module_becomes_info_finding_not_a_crash(self, db_session, monkeypatch):
        from vpnadmin.system_audit import system_checks

        def _boom(host_root):
            raise RuntimeError("simulated failure")
        monkeypatch.setattr(system_checks, "run", _boom)
        run = system_audit.run_audit(db_session, trigger="manual")
        assert run.status == "completed"
        assert any(f.severity == "info" and "could not fully run" in f.title for f in run.findings)


class TestSystemAuditApi:
    def test_no_runs_yet_returns_none(self, app_client, monkeypatch):
        _mock_checks(monkeypatch)
        login(app_client, "admin", "adminpass123")
        r = app_client.get("/api/system-audit/runs/latest")
        assert r.status_code == 200
        assert r.json()["run"] is None

    def test_run_now_and_fetch(self, app_client, monkeypatch):
        _mock_checks(monkeypatch, system=[Finding(check_id="s.one", category="system", severity="medium", title="M", description="d")])
        login(app_client, "admin", "adminpass123")
        r = app_client.post("/api/system-audit/run")
        assert r.status_code == 200
        run = r.json()["run"]
        assert run["status"] == "completed"
        assert run["medium_count"] == 1
        assert run["triggered_by"] == "admin"

        r2 = app_client.get("/api/system-audit/runs/latest")
        assert r2.json()["run"]["id"] == run["id"]

        r3 = app_client.get("/api/system-audit/runs")
        assert len(r3.json()["runs"]) == 1

    def test_export_csv(self, app_client, monkeypatch):
        _mock_checks(monkeypatch, system=[Finding(check_id="s.one", category="system", severity="low", title="L", description="d")])
        login(app_client, "admin", "adminpass123")
        run_id = app_client.post("/api/system-audit/run").json()["run"]["id"]
        r = app_client.get(f"/api/system-audit/runs/{run_id}/export.csv")
        assert r.status_code == 200
        body = r.json()
        assert "s.one" in body["csv"]
        assert body["count"] == 1

    def test_viewer_role_denied(self, app_client, monkeypatch):
        """system_audit is excluded from viewer's blanket "view everything"
        grant (permissions.py) -- same posture as db_reporting, given the
        sensitivity of what a finding's evidence can contain."""
        _mock_checks(monkeypatch)
        login(app_client, "viewer", "viewerpass123")
        r = app_client.get("/api/system-audit/runs/latest")
        assert r.status_code == 403
        r2 = app_client.post("/api/system-audit/run")
        assert r2.status_code == 403

    def test_unauthenticated_denied(self, app_client):
        r = app_client.get("/api/system-audit/runs/latest")
        assert r.status_code in (401, 403)

    def test_nonexistent_run_404s(self, app_client, monkeypatch):
        login(app_client, "admin", "adminpass123")
        r = app_client.get("/api/system-audit/runs/9999")
        assert r.status_code == 404


class TestFirewallLiveFindings:
    """Phase 2: live firewall state via the host-executor SSH channel
    (services/system/audit_probe.py's probe_firewall(), dispatched
    through openvpn_admin.py's audit-firewall action) -- see
    firewall_checks.py's _live_probe()/_live_findings(). These test
    _live_findings() directly against a fixed probe_firewall()-shaped
    dict, not the actual SSH round-trip (which needs a real host and
    real host-executor config -- exercised manually, see this feature's
    own commit message for the real-sandbox validation)."""

    def test_iptables_accept_policy_and_open_rules_flagged(self):
        from vpnadmin.system_audit.firewall_checks import _live_findings

        data = {
            "ufw": {"installed": False},
            "iptables": {
                "installed": True,
                "policies": {"INPUT": "ACCEPT", "FORWARD": "DROP", "OUTPUT": "ACCEPT"},
                "unrestricted_accept_rules": ["-A INPUT -p tcp --dport 53 -j ACCEPT"],
            },
            "firewalld": {"installed": False},
            "units": {},
        }
        findings = _live_findings(data)
        by_id = {f.check_id: f for f in findings}
        assert by_id["firewall.iptables_input_policy"].severity == "medium"
        assert by_id["firewall.iptables_unrestricted_rules"].severity == "medium"

    def test_iptables_deny_default_passes(self):
        from vpnadmin.system_audit.firewall_checks import _live_findings

        data = {
            "ufw": {"installed": True, "active": True, "status_output": "Status: active"},
            "iptables": {"installed": True, "policies": {"INPUT": "DROP"}, "unrestricted_accept_rules": []},
            "firewalld": {"installed": False},
            "units": {},
        }
        findings = _live_findings(data)
        by_id = {f.check_id: f for f in findings}
        assert by_id["firewall.iptables_input_policy"].severity == "passed"
        assert by_id["firewall.ufw_enabled"].severity == "passed"
        assert "firewall.iptables_unrestricted_rules" not in by_id

    def test_iptables_permission_error_not_reported_as_zero_rules(self):
        """Regression guard: a real error reading iptables state must
        never be silently indistinguishable from "confirmed zero rules"
        -- see audit_probe.py's probe_iptables() docstring."""
        from vpnadmin.system_audit.firewall_checks import _live_findings

        data = {
            "ufw": {"installed": False},
            "iptables": {"installed": None, "error": "Permission denied (you must be root)"},
            "firewalld": {"installed": False},
            "units": {},
        }
        findings = _live_findings(data)
        by_id = {f.check_id: f for f in findings}
        assert "firewall.iptables_readable" in by_id
        assert by_id["firewall.iptables_readable"].severity == "info"
        assert "firewall.iptables_input_policy" not in by_id

    def test_nothing_detected_is_a_high_finding(self):
        from vpnadmin.system_audit.firewall_checks import _live_findings

        data = {"ufw": {"installed": False}, "iptables": {"installed": False},
                "firewalld": {"installed": False}, "units": {}}
        findings = _live_findings(data)
        assert len(findings) == 1
        assert findings[0].severity == "high"
        assert "No firewall detected" in findings[0].title

    def test_run_falls_back_to_file_checks_when_live_probe_unavailable(self, monkeypatch, tmp_path):
        """_live_probe() returns None (host-executor not configured, the
        default in every test/dev environment) -- run() must fall back to
        the Phase 1 file-based checks, not raise or return nothing."""
        from vpnadmin.system_audit import firewall_checks

        monkeypatch.setattr(firewall_checks, "_live_probe", lambda: None)
        findings = firewall_checks.run(str(tmp_path))
        assert isinstance(findings, list)
        assert len(findings) > 0

    def test_audit_probe_module_never_raises_on_missing_binaries(self, monkeypatch):
        """probe_firewall() must degrade gracefully when none of ufw/
        iptables/nft/firewalld/systemctl exist on the host at all (e.g. a
        minimal container) -- every _try_run/_try_run_checked call catches
        CommandError itself, this just confirms the top-level function
        doesn't let anything slip through uncaught."""
        from services.system import audit_probe
        from services.system.process_manager import CommandError

        def _always_missing(args, timeout=10):
            raise CommandError(f"Command not found: {args[0]!r}")
        monkeypatch.setattr(audit_probe, "run", _always_missing)
        data = audit_probe.probe_firewall()
        assert data["ufw"] == {"installed": False}
        assert data["iptables"]["installed"] is None
        assert data["units"] == {}


class TestAuditRemediate:
    """Phase 3's ONLY automated-remediation action: chmod a file to its
    fixed canonical mode. See services/system/audit_remediate.py's module
    docstring for the full safety story -- these tests focus on the two
    properties that actually matter for a remediation action: it can
    NEVER touch a path outside its fixed allowlist, and it can NEVER be
    told what mode to apply (that's fixed per-path, not a parameter)."""

    def test_rejects_path_outside_allowlist(self):
        from services.openvpn.exceptions import ValidationError
        from services.system import audit_remediate

        with pytest.raises(ValidationError):
            audit_remediate.remediate_chmod("/etc/hosts")

    def test_rejects_nonexistent_file(self):
        from services.openvpn.exceptions import ValidationError
        from services.system import audit_remediate

        with pytest.raises(ValidationError):
            audit_remediate.remediate_chmod("/etc/shadow-does-not-exist-at-all")

    def test_fixes_an_allowlisted_target(self, tmp_path):
        """Uses a real temp file monkeypatched into the allowlist (never
        touches a real system path) -- confirms the actual chmod syscall,
        the before/after reporting, and the "target mode is fixed, not
        caller-supplied" behavior all work end-to-end."""
        from services.system import audit_remediate

        target = tmp_path / "fake-sshd-config"
        target.write_text("test")
        target.chmod(0o666)
        original_targets = dict(audit_remediate._CHMOD_TARGETS)
        try:
            audit_remediate._CHMOD_TARGETS[str(target)] = 0o644
            result = audit_remediate.remediate_chmod(str(target))
        finally:
            audit_remediate._CHMOD_TARGETS.clear()
            audit_remediate._CHMOD_TARGETS.update(original_targets)

        assert result["changed"] is True
        assert result["verified"] is True
        assert result["new_mode"] == "0o644"
        assert oct(target.stat().st_mode)[-3:] == "644"

    def test_idempotent_when_already_correct(self, tmp_path):
        from services.system import audit_remediate

        target = tmp_path / "already-fine"
        target.write_text("test")
        target.chmod(0o644)
        original_targets = dict(audit_remediate._CHMOD_TARGETS)
        try:
            audit_remediate._CHMOD_TARGETS[str(target)] = 0o644
            result = audit_remediate.remediate_chmod(str(target))
        finally:
            audit_remediate._CHMOD_TARGETS.clear()
            audit_remediate._CHMOD_TARGETS.update(original_targets)

        assert result["changed"] is False
        assert result["verified"] is True

    def test_host_key_regex_matches_expected_shape(self):
        from services.system import audit_remediate

        assert audit_remediate._target_mode_for("/etc/ssh/ssh_host_ed25519_key") == 0o600
        assert audit_remediate._target_mode_for("/etc/ssh/ssh_host_rsa_key") == 0o600
        from services.openvpn.exceptions import ValidationError
        with pytest.raises(ValidationError):
            # The PUBLIC key must never match -- it's meant to be
            # world-readable, chmod-ing it to 0600 would break nothing
            # security-wise but is still outside this action's intent.
            audit_remediate._target_mode_for("/etc/ssh/ssh_host_ed25519_key.pub")


class TestChecksEmitRemediationAction:
    """The two check functions that populate Finding.remediation_action --
    confirms the wiring from "a check found a bad permission" through to
    "the finding carries a machine-actionable fix", not just the human
    remediation text."""

    def test_permissions_check_sets_remediation_action(self, tmp_path):
        from vpnadmin.system_audit import system_checks

        etc = tmp_path / "etc"
        etc.mkdir()
        (etc / "shadow").write_text("x")
        (etc / "shadow").chmod(0o666)
        findings = system_checks._check_permissions(str(tmp_path))
        shadow_finding = next(f for f in findings if f.check_id == "system.permissions.etc_shadow")
        assert shadow_finding.remediation_action == {"type": "chmod", "path": "/etc/shadow"}

    def test_host_key_check_sets_remediation_action(self, tmp_path):
        from vpnadmin.system_audit import ssh_checks

        ssh_dir = tmp_path / "etc" / "ssh"
        ssh_dir.mkdir(parents=True)
        (ssh_dir / "ssh_host_ed25519_key").write_text("x")
        (ssh_dir / "ssh_host_ed25519_key").chmod(0o644)
        findings = ssh_checks._check_host_key_permissions(str(tmp_path))
        finding = next(f for f in findings if f.check_id == "ssh.host_key_permissions.ssh_host_ed25519_key")
        assert finding.remediation_action == {"type": "chmod", "path": "/etc/ssh/ssh_host_ed25519_key"}


class TestRemediateApi:
    def test_finding_without_remediation_action_400s(self, app_client, monkeypatch):
        _mock_checks(monkeypatch, system=[Finding(check_id="s.one", category="system", severity="medium", title="M", description="d")])
        login(app_client, "admin", "adminpass123")
        finding_id = app_client.post("/api/system-audit/run").json()["run"]["findings"][0]["id"]
        r = app_client.post(f"/api/system-audit/findings/{finding_id}/remediate")
        assert r.status_code == 400

    def test_nonexistent_finding_404s(self, app_client, monkeypatch):
        login(app_client, "admin", "adminpass123")
        r = app_client.post("/api/system-audit/findings/9999/remediate")
        assert r.status_code == 404

    def test_host_executor_not_configured_400s(self, app_client, monkeypatch):
        """Default test/dev environment has no HOST_SSH_TARGET/
        HOST_SSH_KEY_PATH set -- remediation must fail closed with a
        clear error, same as every other host-executor-backed endpoint."""
        finding = Finding(check_id="system.permissions.etc_shadow", category="system", severity="high",
                           title="T", description="d", remediation_action={"type": "chmod", "path": "/etc/shadow"})
        _mock_checks(monkeypatch, system=[finding])
        login(app_client, "admin", "adminpass123")
        finding_id = app_client.post("/api/system-audit/run").json()["run"]["findings"][0]["id"]
        r = app_client.post(f"/api/system-audit/findings/{finding_id}/remediate")
        assert r.status_code == 400
        assert "not configured" in r.json()["detail"]

    def test_viewer_role_denied(self, app_client, monkeypatch):
        finding = Finding(check_id="system.permissions.etc_shadow", category="system", severity="high",
                           title="T", description="d", remediation_action={"type": "chmod", "path": "/etc/shadow"})
        _mock_checks(monkeypatch, system=[finding])
        login(app_client, "admin", "adminpass123")
        finding_id = app_client.post("/api/system-audit/run").json()["run"]["findings"][0]["id"]

        login(app_client, "viewer", "viewerpass123")
        r = app_client.post(f"/api/system-audit/findings/{finding_id}/remediate")
        assert r.status_code == 403
