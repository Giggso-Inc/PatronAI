"""review-pr Giggso-Inc/PatronAI#35 C2: routers/ravenhub_users.py's _store()
was a third, unfixed copy of the exact cross-tenant bucket bug
routers/ravenhub.py's _blob_store already fixed -- worse in kind here since
this is the user list/add/remove/grant-admin store, so an unscoped read
could operate on the wrong org's user roster. Now delegates to the same
routers.ravenhub._org_bucket_for rather than duplicating the lookup."""
import routers.ravenhub_users as ru


class _FakeUsersStore:
    def __init__(self, bucket, region="us-east-1"):
        self.bucket = bucket
        self.region = region


def test_store_uses_org_bucket_when_resolvable(monkeypatch):
    # _store() does `from store.users_store import UsersStore` INSIDE the
    # function body (evaluated at call time), so the source module's own
    # attribute is what must be patched -- not anything on `ru` itself.
    monkeypatch.setattr(
        "store.users_store.UsersStore", _FakeUsersStore, raising=False)
    monkeypatch.setattr(ru, "_org_bucket_for", lambda email: "org-bucket-for-" + email)
    monkeypatch.setenv("MARAUDER_SCAN_BUCKET", "shared-fallback-bucket")

    store = ru._store("someone@real-org.com")
    assert store.bucket == "org-bucket-for-someone@real-org.com"


def test_store_falls_back_to_env_var_when_unresolvable(monkeypatch):
    monkeypatch.setattr(
        "store.users_store.UsersStore", _FakeUsersStore, raising=False)
    monkeypatch.setattr(ru, "_org_bucket_for", lambda email: None)
    monkeypatch.setenv("MARAUDER_SCAN_BUCKET", "shared-fallback-bucket")

    store = ru._store("stranger@nowhere.com")
    assert store.bucket == "shared-fallback-bucket"


def test_store_without_email_skips_org_lookup_entirely(monkeypatch):
    monkeypatch.setattr(
        "store.users_store.UsersStore", _FakeUsersStore, raising=False)
    calls = []
    monkeypatch.setattr(ru, "_org_bucket_for", lambda email: calls.append(email))
    monkeypatch.setenv("MARAUDER_SCAN_BUCKET", "shared-fallback-bucket")

    store = ru._store()
    assert store.bucket == "shared-fallback-bucket"
    assert calls == []
