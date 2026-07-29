"""Unit tests for notify.hub_alerts — PR review N1."""

from __future__ import annotations

import json
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from notify import hub_alerts


@pytest.fixture(autouse=True)
def clear_hub_env(monkeypatch):
    monkeypatch.delenv("RAVEN_HUB_URL", raising=False)
    monkeypatch.delenv("RAVEN_AGENT_KEY", raising=False)


@pytest.mark.parametrize("tool,outcome,expected", [
    ("filesystem-mcp", "UNKNOWN", "mcp"),
    ("api.openai.com", "DOMAIN_ALERT", "domain"),
    ("api.openai.com", "PERSONAL_KEY", "domain"),  # domain heuristic wins for dotted tool names
    ("unknown-tool", "CODE_ALERT", "shadow_ai"),
])
def test_infer_kind(tool, outcome, expected):
    assert hub_alerts._infer_kind(tool, outcome) == expected


def test_emit_denylisted_noop_without_url():
    with patch("urllib.request.urlopen") as urlopen:
        hub_alerts.emit_denylisted("giggso", "patron:1", "api.openai.com")
        urlopen.assert_not_called()


def test_emit_denylisted_sends_personal_key_outcome(monkeypatch):
    monkeypatch.setenv("RAVEN_HUB_URL", "http://hub.test")
    captured: dict = {}

    def fake_urlopen(req, timeout=8):
        captured["body"] = json.loads(req.data.decode())
        return MagicMock()

    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        hub_alerts.emit_denylisted(
            "giggso", "patron:10.0.0.1:openai.com:2026-07-29",
            "openai.com", outcome="PERSONAL_KEY", user="alice@corp.com",
        )

    assert captured["body"]["alert_code"] == "denylisted_ai_tool"
    assert captured["body"]["payload"]["outcome"] == "PERSONAL_KEY"


def test_emit_shadow_discovered_payload(monkeypatch):
    monkeypatch.setenv("RAVEN_HUB_URL", "http://hub.test")
    captured: dict = {}

    def fake_urlopen(req, timeout=8):
        captured["body"] = json.loads(req.data.decode())
        return MagicMock()

    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        hub_alerts.emit_shadow_discovered(
            "giggso", "patron:shadow:1", "unknown-ai-tool",
            outcome="UNKNOWN", user="bob", device="10.0.0.5",
        )

    assert captured["body"]["alert_code"] == "shadow_ai_discovered"
    assert captured["body"]["payload"]["resource_kind"] == "shadow_ai"
