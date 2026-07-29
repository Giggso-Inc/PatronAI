"""Hub emit path in alerter — PR review M1 regression test."""

from __future__ import annotations

import os
import sys
from datetime import date
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from alerter.alerter import Alerter


@pytest.fixture
def alerter():
    store = MagicMock()
    store.dedup.is_duplicate.return_value = False
    resolver = MagicMock()
    resolver.resolve.return_value = {
        "owner": "alice@corp.com",
        "email": "alice@corp.com",
        "hostname": "laptop-42",
    }
    settings = {
        "company": {"slug": "giggso"},
        "alerts": {"dedup_window_minutes": 60},
        "cloud": {"region": "us-east-1"},
    }
    return Alerter(store=store, identity_resolver=resolver, settings=settings)


def test_hub_emit_uses_upgraded_personal_key_outcome(alerter, monkeypatch):
    """After CloudTrail upgrade, Hub must receive PERSONAL_KEY not DOMAIN_ALERT."""
    monkeypatch.setenv("RAVEN_HUB_URL", "http://hub.test")
    event = {
        "src_ip": "10.0.0.5",
        "provider": "openai.com",
        "outcome": "DOMAIN_ALERT",
        "severity": "MEDIUM",
        "domain": "api.openai.com",
    }
    emitted: dict = {}

    def fake_denylisted(org, event_id, tool, **kwargs):
        emitted.update(kwargs)
        emitted["org"] = org
        emitted["event_id"] = event_id

    with patch("alerter.alerter.cloudtrail_check", return_value={"token_status": "personal_key"}), \
         patch("alerter.alerter.dispatch", return_value={}), \
         patch("notify.hub_alerts.emit_denylisted", side_effect=fake_denylisted), \
         patch("notify.hub_alerts.emit_shadow_discovered") as shadow:
        result = alerter._process_one(event)

    assert result == "fired"
    assert event["outcome"] == "PERSONAL_KEY"
    assert emitted.get("outcome") == "PERSONAL_KEY"
    shadow.assert_not_called()
