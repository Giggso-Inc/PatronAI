"""review-pr Giggso-Inc/PatronAI#35 C2: routers/ravenhub_settings.py's
_store() was a fourth unfixed copy of the exact cross-tenant bucket bug
routers/ravenhub.py's _blob_store already fixed -- a write here landing on
the wrong org's bucket would silently change another tenant's scan
settings. Now delegates to the same routers.ravenhub._org_bucket_for
rather than duplicating the lookup."""
import routers.ravenhub_settings as rs


class _FakeBlobIndexStore:
    def __init__(self, bucket, region="us-east-1"):
        self.bucket = bucket
        self.region = region


def test_store_uses_org_bucket_when_resolvable(monkeypatch):
    # _store() does `from blob_index_store import BlobIndexStore` INSIDE
    # the function body, so the source module's attribute is what must be
    # patched, not anything on `rs` itself.
    monkeypatch.setattr(
        "blob_index_store.BlobIndexStore", _FakeBlobIndexStore, raising=False)
    monkeypatch.setattr(rs, "_org_bucket_for", lambda email: "org-bucket-for-" + email)
    monkeypatch.setenv("MARAUDER_SCAN_BUCKET", "shared-fallback-bucket")

    store = rs._store("someone@real-org.com")
    assert store.bucket == "org-bucket-for-someone@real-org.com"


def test_store_falls_back_to_env_var_when_unresolvable(monkeypatch):
    monkeypatch.setattr(
        "blob_index_store.BlobIndexStore", _FakeBlobIndexStore, raising=False)
    monkeypatch.setattr(rs, "_org_bucket_for", lambda email: None)
    monkeypatch.setenv("MARAUDER_SCAN_BUCKET", "shared-fallback-bucket")

    store = rs._store("stranger@nowhere.com")
    assert store.bucket == "shared-fallback-bucket"


def test_store_without_email_skips_org_lookup_entirely(monkeypatch):
    monkeypatch.setattr(
        "blob_index_store.BlobIndexStore", _FakeBlobIndexStore, raising=False)
    calls = []
    monkeypatch.setattr(rs, "_org_bucket_for", lambda email: calls.append(email))
    monkeypatch.setenv("MARAUDER_SCAN_BUCKET", "shared-fallback-bucket")

    store = rs._store()
    assert store.bucket == "shared-fallback-bucket"
    assert calls == []
