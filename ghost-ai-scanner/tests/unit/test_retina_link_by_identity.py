# =============================================================
# FILE: tests/unit/test_retina_link_by_identity.py
# PURPOSE: Regression guard for B-62 — unlinked agents (meta.json has no
#          raven_hub_token_id/secret) must attempt the identity-based
#          self-heal link on every cycle, and must NOT attempt it once
#          already linked.
# =============================================================

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT / "src"))

os.environ.setdefault("MARAUDER_SCAN_BUCKET", "test-bucket")
os.environ.setdefault("RAVEN_HUB_URL", "http://localhost:8000")
os.environ.setdefault("RAVEN_AGENT_KEY", "test-agent-key")
os.environ.setdefault("COMPANY_SLUG", "giggso")


def _store_with(meta=None, status=None):
    """Minimal fake store: _get returns canned JSON per-prefix, everything
    else is a no-op MagicMock."""
    import json as _json

    store = MagicMock()

    def _get(key):
        if key.endswith("/meta.json") and meta is not None:
            return _json.dumps(meta).encode()
        if key.endswith("/status.json") and status is not None:
            return _json.dumps(status).encode()
        return None

    store._get.side_effect = _get
    store._put.return_value = None
    return store


@pytest.fixture
def assembler_module():
    from retina.assembler import RetinaAssembler
    return RetinaAssembler


def test_unlinked_agent_attempts_identity_link(assembler_module):
    """No raven_hub_token_id/secret in meta.json -> _try_link_by_identity
    must fire with the agent's recipient_email + reported hostname."""
    meta = {"recipient_email": "dev@example.com"}
    status = {"device_id": "linuxbox"}
    store = _store_with(meta=meta, status=status)
    assembler = assembler_module(store)

    with patch("retina.assembler.request_hub_link_by_identity") as mock_link:
        mock_link.return_value = "linked"
        result = assembler._run_one("tok-1234")

    assert result == "skipped_no_token"
    mock_link.assert_called_once_with(
        patron_token="tok-1234",
        recipient_email="dev@example.com",
        host_hint="linuxbox",
    )


def test_linked_agent_does_not_attempt_identity_link(assembler_module):
    """Agent already has both fields -> the self-heal path must not fire
    (it has nothing to do, and must not add Hub traffic for healthy agents)."""
    meta = {
        "recipient_email":        "dev@example.com",
        "raven_hub_token_id":     "abc123",
        "raven_hub_token_secret": "secret123",
    }
    store = _store_with(meta=meta)
    assembler = assembler_module(store)

    # No scan yet -> _run_one returns "skipped" via the scan-missing branch,
    # not the token-missing branch; either way the identity link must never
    # be attempted once credentials are present.
    with patch("retina.assembler.request_hub_link_by_identity") as mock_link:
        assembler._run_one("tok-5678")

    mock_link.assert_not_called()


def test_unlinked_agent_without_email_skips_quietly(assembler_module):
    """No recipient_email on file -> nothing to match on; must not call out
    to the Hub with an empty identity."""
    meta = {}  # no recipient_email at all
    store = _store_with(meta=meta, status={"device_id": "linuxbox"})
    assembler = assembler_module(store)

    with patch("retina.assembler.request_hub_link_by_identity") as mock_link:
        assembler._run_one("tok-9999")

    mock_link.assert_not_called()


def test_unlinked_agent_without_hostname_skips_quietly(assembler_module):
    """No device_id in status.json (e.g. first cycle before first scan
    posts status) -> must not call out with an empty host_hint."""
    meta = {"recipient_email": "dev@example.com"}
    store = _store_with(meta=meta, status={})
    assembler = assembler_module(store)

    with patch("retina.assembler.request_hub_link_by_identity") as mock_link:
        assembler._run_one("tok-0000")

    mock_link.assert_not_called()


def test_request_hub_link_by_identity_posts_expected_payload():
    """hub_client.request_hub_link_by_identity must hit the Hub's identity
    endpoint with org/email/host/patron_token, and never raise."""
    from retina.hub_client import request_hub_link_by_identity

    captured = {}

    class _FakeResp:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self): return b'{"status": "linked"}'
        status = 200

    def _fake_urlopen(req, timeout=None):
        captured["url"] = req.full_url
        captured["headers"] = dict(req.header_items())
        return _FakeResp()

    with patch("urllib.request.urlopen", side_effect=_fake_urlopen):
        result = request_hub_link_by_identity(
            patron_token="tok-1234",
            recipient_email="dev@example.com",
            host_hint="linuxbox",
        )

    assert result == "linked"
    assert captured["url"].endswith("/api/v1/devices/patron-link-by-identity")
    assert any(k.lower() == "x-raven-agent" for k in captured["headers"])


def test_unlinked_agent_no_match_result_does_not_raise(assembler_module):
    """Hub responding 'no_match' (not yet enrolled on the Hub side either) is
    a normal, expected outcome -- must not raise or be treated differently
    from any other non-'linked' result. Documents that the self-heal simply
    retries next cycle with no further action taken here."""
    meta = {"recipient_email": "dev@example.com"}
    status = {"device_id": "linuxbox"}
    store = _store_with(meta=meta, status=status)
    assembler = assembler_module(store)

    with patch("retina.assembler.request_hub_link_by_identity") as mock_link:
        mock_link.return_value = "no_match"
        result = assembler._run_one("tok-1234")

    assert result == "skipped_no_token"
    mock_link.assert_called_once()


def test_request_hub_link_by_identity_never_raises_on_network_error():
    """Network failures must degrade to 'error', never propagate — this
    runs inside the retina cycle's best-effort path."""
    from retina.hub_client import request_hub_link_by_identity

    with patch("urllib.request.urlopen", side_effect=OSError("boom")):
        result = request_hub_link_by_identity(
            patron_token="tok-1234",
            recipient_email="dev@example.com",
            host_hint="linuxbox",
        )

    assert result == "error"
