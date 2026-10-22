# =============================================================
# FILE: tests/unit/test_users_store.py
# PROJECT: PatronAI — Phase 1B
# VERSION: 1.0.0
# UPDATED: 2026-04-26
# OWNER: Giggso Inc (Ravi Venugopal)
# PURPOSE: Lock the users-store contract:
#          - First-run migration from env vars (admins → manager+admin;
#            allowlist → support)
#          - CRUD: upsert / remove / get
#          - Validation: bad role rejected; bad email rejected
#          - is_admin / role_of / is_authorised helpers
#          Mock-based; no real S3.
# AUDIT LOG:
#   v1.0.0  2026-04-26  Initial. Phase 1B.
# =============================================================

import json
import sys
import importlib.util
from pathlib import Path
from unittest.mock import MagicMock, patch

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

_UsersStoreCls = None


def _load_users_store_cls():
    """Import UsersStore without permanently poisoning sys.modules (PR #64 C1)."""
    global _UsersStoreCls
    if _UsersStoreCls is not None:
        return _UsersStoreCls

    # Prefer the real package when deps (polars) are available — CI path.
    try:
        from store.users_store import UsersStore as _Cls
        _UsersStoreCls = _Cls
        return _UsersStoreCls
    except ModuleNotFoundError:
        pass

    stub_keys = ("store", "store.base_store", "store.users_store")
    saved = {k: sys.modules[k] for k in stub_keys if k in sys.modules}
    try:
        pkg = type(sys)("store")
        pkg.__path__ = [str(REPO / "src" / "store")]
        sys.modules["store"] = pkg
        bs = type(sys)("store.base_store")

        class _Base:
            pass

        bs.BaseStore = _Base
        sys.modules["store.base_store"] = bs
        path = REPO / "src" / "store" / "users_store.py"
        spec = importlib.util.spec_from_file_location("store.users_store", path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules["store.users_store"] = mod
        assert spec.loader is not None
        spec.loader.exec_module(mod)
        _UsersStoreCls = mod.UsersStore
        return _UsersStoreCls
    finally:
        for k in stub_keys:
            if k in saved:
                sys.modules[k] = saved[k]
            else:
                sys.modules.pop(k, None)


def _make_store(initial_payload=None):
    """Build a UsersStore where _get returns initial_payload (None=missing)."""
    UsersStore = _load_users_store_cls()
    s = UsersStore.__new__(UsersStore)
    s.bucket = "test-bucket"
    s.region = "us-east-1"
    s.s3 = MagicMock()
    if initial_payload is None:
        s._get = MagicMock(return_value=b"")
    else:
        s._get = MagicMock(return_value=json.dumps(initial_payload).encode())
    s._put = MagicMock(return_value=True)
    return s


# ── First-run env-var migration ────────────────────────────────

def test_first_run_with_no_env_returns_empty():
    s = _make_store(None)
    with patch.dict("os.environ", {}, clear=True):
        assert s.read_all() == {}
    s._put.assert_not_called()


def test_first_run_migrates_admin_to_manager_admin():
    s = _make_store(None)
    with patch.dict("os.environ", {
        "ADMIN_EMAILS": "ravi@giggso.com",
        "ALLOWED_EMAILS": "",
    }, clear=True):
        users = s.read_all()
    assert "ravi@giggso.com" in users
    assert users["ravi@giggso.com"]["role"]     == "manager"
    assert users["ravi@giggso.com"]["is_admin"] is True
    s._put.assert_called_once()


def test_first_run_migrates_allowlist_to_support_no_admin():
    s = _make_store(None)
    with patch.dict("os.environ", {
        "ADMIN_EMAILS": "",
        "ALLOWED_EMAILS": "alice@x.com,bob@x.com",
    }, clear=True):
        users = s.read_all()
    assert users["alice@x.com"]["role"]     == "support"
    assert users["alice@x.com"]["is_admin"] is False
    assert users["bob@x.com"]["role"]       == "support"


def test_admin_overrides_allowlist_entry():
    """Same email in both lists — admin wins, role=manager + is_admin=true."""
    s = _make_store(None)
    with patch.dict("os.environ", {
        "ADMIN_EMAILS":   "ravi@giggso.com",
        "ALLOWED_EMAILS": "ravi@giggso.com",
    }, clear=True):
        users = s.read_all()
    assert users["ravi@giggso.com"]["role"]     == "manager"
    assert users["ravi@giggso.com"]["is_admin"] is True


def test_existing_users_json_skips_migration():
    """If users.json already exists, env vars are ignored."""
    s = _make_store({"alice@x.com": {"role": "exec", "is_admin": False,
                                      "added_at": "2026-04-26T00:00:00Z",
                                      "added_by": "admin"}})
    with patch.dict("os.environ", {
        "ADMIN_EMAILS": "ravi@giggso.com",
    }, clear=True):
        users = s.read_all()
    assert "ravi@giggso.com" not in users           # not migrated
    assert "alice@x.com"     in users
    s._put.assert_not_called()


# ── CRUD ───────────────────────────────────────────────────────

def test_upsert_adds_new_user():
    s = _make_store({})
    ok = s.upsert("alice@x.com", "manager", False, added_by="admin@x.com")
    assert ok is True
    body = json.loads(s._put.call_args[0][1])
    assert body["alice@x.com"]["role"]     == "manager"
    assert body["alice@x.com"]["is_admin"] is False
    assert body["alice@x.com"]["added_by"] == "admin@x.com"


def test_upsert_updates_existing_user_preserves_added_at():
    initial = {"alice@x.com": {"role": "support", "is_admin": False,
                                "added_at": "2025-01-01T00:00:00Z",
                                "added_by": "admin"}}
    s = _make_store(initial)
    s.upsert("alice@x.com", "exec", True)
    body = json.loads(s._put.call_args[0][1])
    assert body["alice@x.com"]["role"]     == "exec"
    assert body["alice@x.com"]["is_admin"] is True
    assert body["alice@x.com"]["added_at"] == "2025-01-01T00:00:00Z"  # preserved


def test_upsert_rejects_invalid_role():
    s = _make_store({})
    assert s.upsert("alice@x.com", "ceo", False) is False
    s._put.assert_not_called()


def test_upsert_rejects_invalid_email():
    s = _make_store({})
    assert s.upsert("not-an-email", "manager", False) is False
    assert s.upsert("",             "manager", False) is False
    s._put.assert_not_called()


def test_upsert_normalises_email_to_lowercase():
    s = _make_store({})
    s.upsert("Alice@X.COM", "manager", False)
    body = json.loads(s._put.call_args[0][1])
    assert "alice@x.com" in body
    assert "Alice@X.COM" not in body


def test_remove_deletes_user():
    s = _make_store({"alice@x.com": {"role": "manager", "is_admin": False,
                                      "added_at": "2026-04-26T00:00:00Z",
                                      "added_by": "admin"}})
    ok = s.remove("alice@x.com")
    assert ok is True
    body = json.loads(s._put.call_args[0][1])
    assert "alice@x.com" not in body


def test_remove_passes_removed_by_as_actor_email():
    s = _make_store({"alice@x.com": {"role": "manager", "is_admin": False,
                                      "added_at": "2026-04-26T00:00:00Z",
                                      "added_by": "admin"}})
    s.remove("alice@x.com", removed_by="Admin@Corp.com")
    kwargs = s._put.call_args.kwargs
    assert kwargs.get("actor_email") == "admin@corp.com"


def test_remove_missing_user_is_noop():
    s = _make_store({})
    assert s.remove("ghost@x.com") is True
    s._put.assert_not_called()


# ── Helpers ────────────────────────────────────────────────────

def test_is_authorised():
    s = _make_store({"alice@x.com": {"role": "manager", "is_admin": False}})
    assert s.is_authorised("alice@x.com")     is True
    assert s.is_authorised("ALICE@X.COM")     is True             # case-insensitive
    assert s.is_authorised("ghost@x.com")     is False
    assert s.is_authorised("")                is False


def test_role_of():
    s = _make_store({"alice@x.com": {"role": "exec", "is_admin": False}})
    assert s.role_of("alice@x.com") == "exec"
    assert s.role_of("ghost@x.com") == ""


def test_is_admin():
    s = _make_store({"alice@x.com": {"role": "manager", "is_admin": True},
                     "bob@x.com":   {"role": "exec",    "is_admin": False}})
    assert s.is_admin("alice@x.com") is True
    assert s.is_admin("bob@x.com")   is False
    assert s.is_admin("ghost@x.com") is False


def test_corrupt_users_json_returns_empty():
    s = _make_store(None)
    s._get = MagicMock(return_value=b"{this is not json")
    with patch.dict("os.environ", {}, clear=True):
        assert s.read_all() == {}
    s._put.assert_not_called()                                  # don't auto-recover
