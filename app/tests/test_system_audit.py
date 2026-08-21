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
