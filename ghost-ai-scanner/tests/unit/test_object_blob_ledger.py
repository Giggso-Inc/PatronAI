"""object_blobs ledger — hash + actor + append-only user audit."""

from __future__ import annotations

import hashlib
import importlib.util
import sys
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from db import object_blob_ledger as ledger
from db.object_blob_ledger import (
    clear_object_actor,
    content_sha256,
    file_name_from_key,
    get_object_actor,
    object_actor,
    record_object_put,
    set_object_actor,
)


def test_content_sha256_and_file_name():
    assert content_sha256(b"hello") == hashlib.sha256(b"hello").hexdigest()
    assert file_name_from_key("ocsf/findings/2026/10/06/scan.json") == "scan.json"
    assert file_name_from_key("users/users.json") == "users.json"


def test_object_actor_restores_prior_context():
    clear_object_actor()
    uid = uuid.uuid4()
    set_object_actor(email="Alice@Example.com", user_id=uid)
    assert get_object_actor() == ("alice@example.com", uid)
    with object_actor(email="bob@ex.com"):
        assert get_object_actor()[0] == "bob@ex.com"
    assert get_object_actor() == ("alice@example.com", uid)
    clear_object_actor()
    assert get_object_actor() == (None, None)


class _Sess:
    """Session stub: upsert via execute(), audit via add()."""

    def __init__(self):
        self.audits = []
        self.upsert_stmts = []
        self.committed = False

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, stmt):
        self.upsert_stmts.append(stmt)
        return MagicMock()

    def add(self, row):
        self.audits.append(row)

    def commit(self):
        self.committed = True


def test_record_put_upserts_and_appends_audit():
    clear_object_actor()
    uid = uuid.uuid4()
    set_object_actor(email="writer@ex.com", user_id=uid)
    sess = _Sess()

    with patch("db.engine.get_session", return_value=sess):
        ledger._record_object_put_inner(
            bucket="bkt",
            key="chat/abcdef0123456789/admin/2026-10-06.jsonl",
            body=b'{"email":"ignored@ex.com","ok":true}',
            content_type="application/x-ndjson",
            storage_mode="s3",
            actor_email=None,
            actor_user_id=None,
        )

    assert len(sess.upsert_stmts) == 1
    assert len(sess.audits) == 1
    audit = sess.audits[0]
    assert audit.actor_email == "writer@ex.com"
    assert audit.actor_user_id == uid
    assert audit.subject_key_hash == "abcdef0123456789"
    assert audit.object_key.endswith("2026-10-06.jsonl")
    assert audit.content_hash == hashlib.sha256(
        b'{"email":"ignored@ex.com","ok":true}'
    ).hexdigest()
    assert sess.committed is True

    # Second put appends another audit; first audit row unchanged (append-only).
    first = sess.audits[0]
    first_hash = first.content_hash
    first_actor = first.actor_email
    set_object_actor(email="editor@ex.com")
    with patch("db.engine.get_session", return_value=sess):
        ledger._record_object_put_inner(
            bucket="bkt",
            key="chat/abcdef0123456789/admin/2026-10-06.jsonl",
            body=b"v2",
            content_type="application/x-ndjson",
            storage_mode="s3",
            actor_email=None,
            actor_user_id=None,
        )
    assert len(sess.audits) == 2
    assert sess.audits[0].content_hash == first_hash
    assert sess.audits[0].actor_email == first_actor
    assert sess.audits[1].actor_email == "editor@ex.com"
    assert sess.audits[1].content_hash == hashlib.sha256(b"v2").hexdigest()
    clear_object_actor()


def test_explicit_actor_email_overrides_context():
    clear_object_actor()
    set_object_actor(email="ctx@ex.com")
    sess = _Sess()
    with patch("db.engine.get_session", return_value=sess):
        ledger._record_object_put_inner(
            bucket="bkt",
            key="k.json",
            body=b"{}",
            content_type="application/json",
            storage_mode="s3",
            actor_email="Explicit@Ex.com",
            actor_user_id=None,
        )
    assert sess.audits[0].actor_email == "explicit@ex.com"
    clear_object_actor()


def test_body_email_not_trusted_as_actor():
    """M4: client JSON must not populate actor_email (spoofing)."""
    clear_object_actor()
    sess = _Sess()
    with patch("db.engine.get_session", return_value=sess):
        ledger._record_object_put_inner(
            bucket="bkt",
            key="config/HOOK_AGENTS/tok/meta.json",
            body=b'{"recipient_email":"spoofed@ex.com","token":"tok"}',
            content_type="application/json",
            storage_mode="s3",
            actor_email=None,
            actor_user_id=None,
        )
    assert sess.audits[0].actor_email is None
    assert len(sess.upsert_stmts) == 1


def test_nothing_resolves_actor_stays_null():
    clear_object_actor()
    sess = _Sess()
    with patch("db.engine.get_session", return_value=sess):
        ledger._record_object_put_inner(
            bucket="bkt",
            key="ocsf/findings/x.json",
            body=b"not-json",
            content_type="application/json",
            storage_mode="s3",
            actor_email=None,
            actor_user_id=None,
        )
    assert sess.audits[0].actor_email is None


def test_record_object_put_fail_open():
    clear_object_actor()
    with patch(
        "db.object_blob_ledger._record_object_put_inner",
        side_effect=RuntimeError("db down"),
    ):
        record_object_put(bucket="b", key="k.json", body=b"x")


def test_object_store_put_invokes_ledger():
    mod_path = ROOT / "src" / "store" / "object_store.py"
    spec = importlib.util.spec_from_file_location("object_store_ledger_ut2", mod_path)
    m = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(m)

    calls = []

    class Mem(m.ObjectStore):
        mode = "s3"

        def __init__(self):
            self.written = None

        def get(self, bucket, key):
            return b""

        def _put(self, bucket, key, body, content_type="application/json"):
            self.written = (bucket, key, body, content_type)

        def delete(self, bucket, key):
            pass

        def exists(self, bucket, key):
            return False

        def list_keys(self, bucket, prefix="", max_keys=5000):
            return []

    with patch.object(m, "_record_put", side_effect=lambda *a, **k: calls.append(a)):
        store = Mem()
        store.put("bucket", "k.json", b'{"a":1}')
    assert store.written[0] == "bucket"
    assert len(calls) == 1


def test_put_recording_client_positional_body():
    mod_path = ROOT / "src" / "store" / "object_store.py"
    spec = importlib.util.spec_from_file_location("object_store_ledger_ut3", mod_path)
    m = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(m)

    recorded = []

    class FakeClient:
        def put_object(self, *args, **kwargs):
            return {"ok": True}

    with patch.object(m, "_record_put", side_effect=lambda *a, **k: recorded.append(a)):
        wrap = m._PutRecordingClient(FakeClient(), mode="s3")
        wrap.put_object("bucket", "key.bin", b"secret-bytes")
    assert recorded
    assert recorded[0][2] == b"secret-bytes"


def test_base_store_put_inherits_context_actor_without_kwarg():
    """M2: ContextVar set (auth gate / Raven) is visible during BaseStore._put."""
    clear_object_actor()
    set_object_actor(email="dashboard@corp.com")
    seen = []

    class FakeBackend:
        def put(self, bucket, key, body, content_type="application/json"):
            seen.append(get_object_actor())

    # Exercise the same branch as BaseStore._put without importing store pkg.
    FakeBackend().put("b", "config/x.json", b"{}")
    assert seen == [("dashboard@corp.com", None)]
    clear_object_actor()


def test_settings_write_passes_email_written_by_as_actor():
    """Load settings_store.py directly; email written_by → actor_email kwarg."""
    # Stub .base_store so settings_store can import without polars/object_store.
    pkg = type(sys)("store")
    pkg.__path__ = [str(ROOT / "src" / "store")]
    sys.modules.setdefault("store", pkg)

    bs = type(sys)("store.base_store")

    class _Base:
        def _put(self, *a, **k):
            raise AssertionError("replace in test")

    bs.BaseStore = _Base
    sys.modules["store.base_store"] = bs

    mod_path = ROOT / "src" / "store" / "settings_store.py"
    spec = importlib.util.spec_from_file_location(
        "store.settings_store", mod_path,
        submodule_search_locations=[str(ROOT / "src" / "store")],
    )
    m = importlib.util.module_from_spec(spec)
    sys.modules["store.settings_store"] = m
    assert spec.loader is not None
    spec.loader.exec_module(m)

    store = m.SettingsStore.__new__(m.SettingsStore)
    store._put = MagicMock(return_value=True)
    store.write({"storage": {}}, written_by="Admin@Corp.com")
    assert store._put.call_args.kwargs.get("actor_email") == "admin@corp.com"
    store.write({"storage": {}}, written_by="streamlit")
    assert store._put.call_args.kwargs.get("actor_email") is None
