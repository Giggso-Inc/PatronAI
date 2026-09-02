"""review-pr Giggso-Inc/PatronAI#35 C1: api.py's _get_store()/_blob_store()
were a second, unfixed copy of the exact cross-tenant bucket bug
routers/ravenhub.py's _blob_store already fixed. Both now delegate to the
same routers.ravenhub._org_bucket_for rather than duplicating the lookup --
these tests prove that delegation actually happens, not just that the
already-tested _org_bucket_for logic itself is correct."""
import os
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT / "src"))
sys.path.insert(0, str(_ROOT))

# api.py hard-fails at import time if API_KEY is unset (see test_api_auth.py,
# which established this same pattern first).
os.environ.setdefault("API_KEY", "test-key-for-test-api-org-scoped-store")

import api   # noqa: E402 - must follow the sys.path/env setup above


class _FakeAgentStore:
    def __init__(self, bucket, region="us-east-1"):
        self.bucket = bucket
        self.region = region


class _FakeBlobIndexStore:
    def __init__(self, bucket, region="us-east-1"):
        self.bucket = bucket
        self.region = region


def test_get_store_uses_org_bucket_when_resolvable(monkeypatch):
    monkeypatch.setattr(api, "AgentStore", _FakeAgentStore)
    monkeypatch.setattr(api, "_org_bucket_for", lambda email: "org-bucket-for-" + email)
    monkeypatch.setenv("MARAUDER_SCAN_BUCKET", "shared-fallback-bucket")

    store = api._get_store("someone@real-org.com")
    assert store.bucket == "org-bucket-for-someone@real-org.com"


def test_get_store_falls_back_to_env_var_when_unresolvable(monkeypatch):
    monkeypatch.setattr(api, "AgentStore", _FakeAgentStore)
    monkeypatch.setattr(api, "_org_bucket_for", lambda email: None)
    monkeypatch.setenv("MARAUDER_SCAN_BUCKET", "shared-fallback-bucket")

    store = api._get_store("stranger@nowhere.com")
    assert store.bucket == "shared-fallback-bucket"


def test_get_store_without_email_skips_org_lookup_entirely(monkeypatch):
    monkeypatch.setattr(api, "AgentStore", _FakeAgentStore)
    calls = []
    monkeypatch.setattr(api, "_org_bucket_for", lambda email: calls.append(email))
    monkeypatch.setenv("MARAUDER_SCAN_BUCKET", "shared-fallback-bucket")

    store = api._get_store()
    assert store.bucket == "shared-fallback-bucket"
    assert calls == []  # _org_bucket_for must not even be called with no email


def test_blob_store_uses_org_bucket_when_resolvable(monkeypatch):
    monkeypatch.setattr(api, "BlobIndexStore", _FakeBlobIndexStore)
    monkeypatch.setattr(api, "_org_bucket_for", lambda email: "org-bucket-for-" + email)
    monkeypatch.setenv("MARAUDER_SCAN_BUCKET", "shared-fallback-bucket")

    store = api._blob_store("someone@real-org.com")
    assert store.bucket == "org-bucket-for-someone@real-org.com"


def test_blob_store_falls_back_to_env_var_when_unresolvable(monkeypatch):
    monkeypatch.setattr(api, "BlobIndexStore", _FakeBlobIndexStore)
    monkeypatch.setattr(api, "_org_bucket_for", lambda email: None)
    monkeypatch.setenv("MARAUDER_SCAN_BUCKET", "shared-fallback-bucket")

    store = api._blob_store("stranger@nowhere.com")
    assert store.bucket == "shared-fallback-bucket"
