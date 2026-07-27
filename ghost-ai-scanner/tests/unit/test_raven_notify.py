# =============================================================
# FILE: tests/unit/test_raven_notify.py
# VERSION: 1.0.0
# UPDATED: 2026-07-27
# OWNER: Giggso Inc
# PURPOSE: Unit tests for src/raven_notify.py — patron -> raven Phase 5
#          MCP-approval callback. Mocks urllib.request.urlopen (stdlib, no
#          real network), matching this module's own dependency-free design
#          — same style as raven's hub/tests/test_patron_sync.py.
# =============================================================

import io
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from jose import jwt as jose_jwt

import raven_notify

_ENV = {
    "RAVEN_HUB_BASE_URL": "http://raven.test",
    "RAVEN_JWT_SECRET": "test-secret",
}


def _set_env(monkeypatch):
    for k, v in _ENV.items():
        monkeypatch.setenv(k, v)


class _FakeResponse:
    def __init__(self, status=200):
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_missing_config_returns_error_without_any_network_call(monkeypatch):
    monkeypatch.delenv("RAVEN_HUB_BASE_URL", raising=False)
    monkeypatch.delenv("RAVEN_JWT_SECRET", raising=False)
    called = []
    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: called.append(1))

    result = raven_notify.notify_raven_mcp_approved(
        external_ref="g1", mcp_name="gmail", resolved_by="admin@acme.com",
    )

    assert result == {
        "ok": False,
        "error": "Raven callback is not configured (RAVEN_HUB_BASE_URL / RAVEN_JWT_SECRET).",
    }
    assert called == []


def test_posts_correct_path_and_body(monkeypatch):
    _set_env(monkeypatch)
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured["url"] = req.full_url
        captured["body"] = json.loads(req.data)
        captured["identity"] = req.get_header("X-patron-identity")
        return _FakeResponse(status=200)

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    result = raven_notify.notify_raven_mcp_approved(
        external_ref="group-123", mcp_name="gmail", resolved_by="admin@acme.com",
    )

    assert result == {"ok": True}
    assert captured["url"] == "http://raven.test/api/v1/patron-callbacks/mcp-approved"
    assert captured["body"] == {
        "external_ref": "group-123", "mcp_name": "gmail", "resolved_by": "admin@acme.com",
    }
    claims = jose_jwt.decode(captured["identity"], "test-secret", algorithms=["HS256"])
    assert claims["email"] == "admin@acme.com"
    assert claims["exp"] - claims["iat"] == 60


def test_http_error_reports_status_in_message(monkeypatch):
    _set_env(monkeypatch)

    def fake_urlopen(req, timeout=None):
        raise urllib.error.HTTPError(req.full_url, 404, "Not Found", hdrs=None, fp=io.BytesIO(b""))

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    result = raven_notify.notify_raven_mcp_approved(
        external_ref="unknown-group", mcp_name="gmail", resolved_by="admin@acme.com",
    )

    assert result == {"ok": False, "error": "Raven returned HTTP 404: Not Found"}


def test_non_2xx_response_without_raising_is_still_a_failure(monkeypatch):
    _set_env(monkeypatch)
    monkeypatch.setattr(urllib.request, "urlopen", lambda req, timeout=None: _FakeResponse(status=500))

    result = raven_notify.notify_raven_mcp_approved(
        external_ref="g1", mcp_name="gmail", resolved_by="admin@acme.com",
    )

    assert result == {"ok": False, "error": "Raven returned HTTP 500"}


def test_network_failure_never_raises(monkeypatch):
    _set_env(monkeypatch)

    def fake_urlopen(req, timeout=None):
        raise ConnectionError("connection refused")

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    result = raven_notify.notify_raven_mcp_approved(
        external_ref="g1", mcp_name="gmail", resolved_by="admin@acme.com",
    )

    assert result["ok"] is False
    assert "Could not reach Raven" in result["error"]
