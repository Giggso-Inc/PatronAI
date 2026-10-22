# =============================================================
# FILE: tests/unit/test_ravenhub_retina_link.py
# PURPOSE: Regression guard for the agent_store 500 bug (review finding M1,
#          PatronAI PR #63) — _get_store() read AgentStore from
#          request.app.state.agent_store, which startup never populates, so
#          every call to POST/GET/DELETE /ravenhub/retina/link/{token} 500'd
#          with "agent_store not initialised". Nothing caught this before.
#          Covers both the happy path (bucket configured, store mocked out
#          so no real S3 call happens) and the missing-config path (bucket
#          unset -> 503, matching api.py's own _get_store() for the same
#          condition).
# =============================================================

import os
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT / "src"))
sys.path.insert(0, str(_ROOT))

# api.py hard-fails at import time if API_KEY is unset (see test_api_auth.py,
# which established this same pattern first).
os.environ.setdefault("API_KEY", "test-key-for-test-ravenhub-retina-link")
os.environ.setdefault("MARAUDER_SCAN_BUCKET", "test-bucket")

import pytest
from fastapi.testclient import TestClient
from unittest.mock import MagicMock

import api as api_module
from routers import ravenhub_retina

_AUTH = {"Authorization": f"Bearer {os.environ['API_KEY']}"}
_TOKEN = "e560443d-61fd-4b20-a544-f31b4347e687"


class _FakeStore:
    """Mocked AgentStore — no real S3 call, so the test never touches
    network/credentials regardless of what MARAUDER_SCAN_BUCKET is."""

    def __init__(self):
        self._linked = {}

    def set_hub_token_id(self, patron_token, hub_token_id, hub_token_secret=""):
        self._linked[patron_token] = (hub_token_id, hub_token_secret)
        return True

    def get_hub_token_id(self, patron_token):
        return self._linked.get(patron_token, ("", ""))[0]

    def get_hub_token_secret(self, patron_token):
        return self._linked.get(patron_token, ("", ""))[1]


@pytest.fixture
def client():
    fake_store = _FakeStore()
    api_module.app.dependency_overrides[ravenhub_retina._get_store] = lambda: fake_store
    with TestClient(api_module.app) as c:
        yield c
    api_module.app.dependency_overrides.pop(ravenhub_retina._get_store, None)


def test_get_link_status_when_bucket_configured(client):
    """GET must return 200 with an unlinked status, not the old 500 from
    reading app.state.agent_store (which startup never populated)."""
    resp = client.get(f"/ravenhub/retina/link/{_TOKEN}", headers=_AUTH)
    assert resp.status_code == 200
    body = resp.json()
    assert body == {
        "patron_token": _TOKEN,
        "linked": False,
        "raven_hub_token_id": "",
        "raven_hub_token_secret_set": False,
    }


def test_post_link_then_get_shows_linked(client):
    """POST writes the Hub token into the store; a subsequent GET must
    reflect it — proves _get_store() returns the same store instance/data
    across requests, not a fresh unlinked one each time."""
    payload = {"raven_hub_token_id": "hub-tok-1", "raven_hub_token_secret": "hub-secret-1"}
    post_resp = client.post(f"/ravenhub/retina/link/{_TOKEN}", json=payload, headers=_AUTH)
    assert post_resp.status_code == 200
    assert post_resp.json()["status"] == "linked"

    get_resp = client.get(f"/ravenhub/retina/link/{_TOKEN}", headers=_AUTH)
    assert get_resp.status_code == 200
    body = get_resp.json()
    assert body["linked"] is True
    assert body["raven_hub_token_id"] == "hub-tok-1"
    assert body["raven_hub_token_secret_set"] is True


def test_delete_unlinks(client):
    """DELETE clears a previously-set Hub token id."""
    client.post(
        f"/ravenhub/retina/link/{_TOKEN}",
        json={"raven_hub_token_id": "hub-tok-1", "raven_hub_token_secret": "hub-secret-1"},
        headers=_AUTH,
    )
    del_resp = client.delete(f"/ravenhub/retina/link/{_TOKEN}", headers=_AUTH)
    assert del_resp.status_code == 200
    assert del_resp.json()["status"] == "unlinked"

    get_resp = client.get(f"/ravenhub/retina/link/{_TOKEN}", headers=_AUTH)
    assert get_resp.json()["linked"] is False


def test_get_link_status_503_when_bucket_not_configured(monkeypatch):
    """Without the dependency override, _get_store() runs for real and must
    503 (not 500) when MARAUDER_SCAN_BUCKET is unset -- this is the exact
    code path that used to 500 unconditionally before the fix."""
    monkeypatch.delenv("MARAUDER_SCAN_BUCKET", raising=False)
    with TestClient(api_module.app) as client:
        resp = client.get(f"/ravenhub/retina/link/{_TOKEN}", headers=_AUTH)
    assert resp.status_code == 503
    assert "MARAUDER_SCAN_BUCKET" in resp.json()["detail"]


def test_link_endpoints_require_auth(client):
    """No bearer token -> 401, same as every other /ravenhub route."""
    resp = client.get(f"/ravenhub/retina/link/{_TOKEN}")
    assert resp.status_code == 401


def test_invalid_patron_token_rejected(client):
    """_validate_token must 400 a non-UUID path param before it ever
    reaches the store (path-traversal guard)."""
    resp = client.get("/ravenhub/retina/link/not-a-uuid", headers=_AUTH)
    assert resp.status_code == 400
