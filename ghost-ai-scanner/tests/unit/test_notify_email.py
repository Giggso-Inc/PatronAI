# =============================================================
# FILE: tests/unit/test_notify_email.py
# PROJECT: PatronAI — Marauder Scan
# VERSION: 3.0.0
# UPDATED: 2026-09-02
# OWNER: Giggso Inc (Ravi Venugopal)
# PURPOSE: Tests for the unified notify.email module — now SMTP-backed.
#          Covers:
#            - ensure_verified() is a no-op stub (SMTP needs none)
#            - send() recipient normalisation + SMTP dispatch
#            - send_welcome / send_agent_otp / send_alert wrappers
#            - shim layers (manager_tab_actions.send_alert_email,
#              render_agent_package._send_email) still call through
# AUDIT LOG:
#   v2.0.0  2026-05-02  Initial — SES-backed.
#   v3.0.0  2026-09-02  Rewritten for SMTP backend (smtplib). Removed
#                       all SES / boto3 mocking.
# =============================================================

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))


def _mock_smtp():
    """Return a MagicMock that stands in for smtplib.SMTP context manager."""
    smtp = MagicMock()
    smtp.__enter__ = MagicMock(return_value=smtp)
    smtp.__exit__ = MagicMock(return_value=False)
    return smtp


# ── ensure_verified (no-op stub for SMTP) ─────────────────────


def test_ensure_verified_already_verified_skips_call(monkeypatch):
    """ensure_verified is a no-op — always returns already_verified."""
    from notify.email import ensure_verified
    r = ensure_verified("x@example.com", region="us-east-1")
    assert r["action"] == "already_verified"


def test_ensure_verified_unknown_triggers_verification(monkeypatch):
    """SMTP has no verification — stub returns already_verified regardless."""
    from notify.email import ensure_verified
    r = ensure_verified("x@example.com", region="us-east-1")
    assert r["action"] == "already_verified"


def test_ensure_verified_pending_resends(monkeypatch):
    from notify.email import ensure_verified
    r = ensure_verified("x@example.com")
    assert r["action"] == "already_verified"


def test_ensure_verified_invalid_short_circuits(monkeypatch):
    """Stub still returns a valid dict for bad input — no crash."""
    from notify.email import ensure_verified
    for bad in ("", "  ", "no-at", None):
        r = ensure_verified(bad or "")
        assert "action" in r


def test_ensure_verified_aws_error_does_not_raise(monkeypatch):
    """Stub never calls any network — no errors possible."""
    from notify.email import ensure_verified
    r = ensure_verified("x@example.com")
    assert r["action"] == "already_verified"


# ── send (SMTP) ────────────────────────────────────────────────


def test_send_str_recipient(monkeypatch):
    from notify.email import send
    smtp = _mock_smtp()
    monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("SMTP_USERNAME", "user@example.com")
    monkeypatch.setenv("SMTP_PASSWORD", "secret")
    monkeypatch.setenv("SMTP_FROM_EMAIL", "noreply@example.com")
    with patch("smtplib.SMTP", return_value=smtp):
        ok = send("x@example.com", "Subj", "Body")
    assert ok is True
    smtp.sendmail.assert_called_once()
    _, recipients, _ = smtp.sendmail.call_args.args
    assert recipients == ["x@example.com"]


def test_send_list_of_recipients(monkeypatch):
    from notify.email import send
    smtp = _mock_smtp()
    monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("SMTP_USERNAME", "user@example.com")
    monkeypatch.setenv("SMTP_PASSWORD", "secret")
    monkeypatch.setenv("SMTP_FROM_EMAIL", "noreply@example.com")
    with patch("smtplib.SMTP", return_value=smtp):
        ok = send(["a@x.com", "b@x.com"], "Subj", "Body")
    assert ok is True
    _, recipients, _ = smtp.sendmail.call_args.args
    assert recipients == ["a@x.com", "b@x.com"]


def test_send_skips_verification_when_disabled(monkeypatch):
    """auto_verify=False is accepted and ignored — SMTP has no verification."""
    from notify.email import send
    smtp = _mock_smtp()
    monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("SMTP_USERNAME", "user@example.com")
    monkeypatch.setenv("SMTP_PASSWORD", "secret")
    with patch("smtplib.SMTP", return_value=smtp):
        ok = send("x@example.com", "S", "B", auto_verify=False)
    assert ok is True


def test_send_failure_returns_false(monkeypatch):
    from notify.email import send
    monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("SMTP_USERNAME", "user@example.com")
    monkeypatch.setenv("SMTP_PASSWORD", "secret")
    with patch("smtplib.SMTP", side_effect=Exception("Connection refused")):
        assert send("x@example.com", "S", "B") is False


def test_send_no_recipients_returns_false(monkeypatch):
    from notify.email import send
    monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
    assert send([], "S", "B") is False
    assert send([""], "S", "B") is False


def test_send_falls_back_to_PATRONAI_FROM_EMAIL(monkeypatch):
    """SMTP_FROM_EMAIL replaces SES_SENDER_EMAIL as the canonical From."""
    from notify.email import send
    smtp = _mock_smtp()
    monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("SMTP_USERNAME", "alerts@example.com")
    monkeypatch.setenv("SMTP_PASSWORD", "secret")
    monkeypatch.delenv("SMTP_FROM_EMAIL", raising=False)
    with patch("smtplib.SMTP", return_value=smtp):
        ok = send("x@example.com", "S", "B")
    assert ok is True
    sender, _, _ = smtp.sendmail.call_args.args
    assert sender == "alerts@example.com"


# ── Convenience wrappers ───────────────────────────────────────


def test_send_welcome_calls_send_with_welcome_subject(monkeypatch):
    import notify.email as em
    captured = {}
    def _fake_send(recipient, subject, body, *, company="", auto_verify=True):
        captured.update(recipient=recipient, subject=subject, body=body,
                        auto_verify=auto_verify)
        return True
    monkeypatch.setattr(em, "send", _fake_send)
    em.send_welcome("alice@x.com", "Alice", "exec", "admin@x.com", "X")
    assert captured["recipient"] == "alice@x.com"
    assert "Welcome to PatronAI" in captured["subject"]
    assert "Alice" in captured["body"]
    assert "exec" in captured["body"]
    assert "admin@x.com" in captured["body"]


def test_send_agent_otp_includes_otp_and_url(monkeypatch):
    import notify.email as em
    captured = {}
    def _fake_send(recipient, subject, body, *, company="", auto_verify=True):
        captured.update(body=body, subject=subject)
        return True
    monkeypatch.setattr(em, "send", _fake_send)
    em.send_agent_otp("alice@x.com", "Alice", "621342",
                       "https://s3/installer.sh", "X")
    assert "PatronAI Agent" in captured["subject"]
    assert "621342" in captured["body"]
    assert "https://s3/installer.sh" in captured["body"]


def test_send_alert_bullets_each_event(monkeypatch):
    import notify.email as em
    captured = {}
    def _fake_send(recipient, subject, body, *, company="", auto_verify=True):
        captured.update(body=body, recipient=recipient)
        return True
    monkeypatch.setattr(em, "send", _fake_send)
    events = [
        {"severity": "CRITICAL", "provider": "openai", "owner": "alice@x.com",
         "timestamp": "2026-05-02T12:00:00+00:00"},
        {"severity": "HIGH", "provider": "claude", "owner": "bob@x.com",
         "timestamp": "2026-05-02T13:00:00+00:00"},
    ]
    em.send_alert("a@x.com,b@x.com", events)
    assert "2 event(s)" in captured["body"]
    assert "openai" in captured["body"] and "claude" in captured["body"]
    # Recipients comma-string was split.
    assert captured["recipient"] == ["a@x.com", "b@x.com"]


def test_send_alert_empty_events_returns_false():
    from notify.email import send_alert
    assert send_alert(["a@x.com"], []) is False


# ── Shims still delegate ───────────────────────────────────────


def test_manager_tab_actions_send_alert_email_delegates(monkeypatch):
    """The dashboard shim must call notify.email.send_alert and return
    its result without doing its own SES work."""
    sys.path.insert(0, str(REPO / "dashboard"))
    import notify.email as em
    seen = {}
    def _fake_send_alert(recipients, events):
        seen.update(recipients=recipients, events=events)
        return True
    monkeypatch.setattr(em, "send_alert", _fake_send_alert)
    from ui.manager_tab_actions import send_alert_email
    ok = send_alert_email([{"x": 1}], "a@x.com,b@x.com")
    assert ok is True
    assert seen["recipients"] == "a@x.com,b@x.com"
    assert seen["events"] == [{"x": 1}]


def test_render_agent_package_send_email_delegates(monkeypatch):
    sys.path.insert(0, str(REPO / "scripts"))
    import notify.email as em
    seen = {}
    def _fake_send_otp(recipient, name, otp, installer_url, company=""):
        seen.update(recipient=recipient, otp=otp, url=installer_url)
        return True
    monkeypatch.setattr(em, "send_agent_otp", _fake_send_otp)
    from render_agent_package import _send_email
    ok = _send_email("Alice", "alice@x.com", "621342",
                     "https://s3/installer.sh", "X")
    assert ok is True
    assert seen == {"recipient": "alice@x.com",
                    "otp": "621342",
                    "url": "https://s3/installer.sh"}
