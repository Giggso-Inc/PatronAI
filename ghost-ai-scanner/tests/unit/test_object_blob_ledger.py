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


def test_object_actor_contextvar():
    clear_object_actor()
    uid = uuid.uuid4()
    set_object_actor(email="Alice@Example.com", user_id=uid)
    assert get_object_actor() == ("alice@example.com", uid)
    with object_actor(email="bob@ex.com"):
        assert get_object_actor()[0] == "bob@ex.com"
    clear_object_actor()


def test_record_put_upserts_and_appends_audit():
    clear_object_actor()
    uid = uuid.uuid4()
    set_object_actor(email="writer@ex.com", user_id=uid)

    existing = None
    captured = {"audits": []}

    class Sess:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def execute(self, stmt):
            res = MagicMock()
            res.scalar_one_or_none.return_value = existing
            return res

        def add(self, row):
            # ObjectBlob has content_hash; audit has actor_email
            if hasattr(row, "actor_email") or row.__class__.__name__ == "ObjectBlobAudit":
                captured["audits"].append(row)
            else:
                captured["blob"] = row

        def commit(self):
            captured["committed"] = True

    sess = Sess()
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

    blob = captured["blob"]
    assert blob.file_name == "2026-10-06.jsonl"
    assert blob.content_hash == hashlib.sha256(
        b'{"email":"ignored@ex.com","ok":true}'
    ).hexdigest()
    assert blob.created_by == "writer@ex.com"
    assert len(captured["audits"]) == 1
    audit = captured["audits"][0]
    assert audit.actor_email == "writer@ex.com"
    assert audit.subject_key_hash == "abcdef0123456789"
    assert audit.object_key.endswith("2026-10-06.jsonl")
    assert captured.get("committed") is True

    # Update path + new audit row
    existing = blob
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
    assert existing.content_hash == hashlib.sha256(b"v2").hexdigest()
    assert existing.updated_by == "editor@ex.com"
    assert existing.created_by == "writer@ex.com"
    assert len(captured["audits"]) == 2
    clear_object_actor()


def test_infer_email_from_json_body_when_no_actor():
    clear_object_actor()
    captured = {"audits": []}

    class Sess:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def execute(self, stmt):
            res = MagicMock()
            res.scalar_one_or_none.return_value = None
            return res

        def add(self, row):
            if hasattr(row, "actor_email") or "Audit" in row.__class__.__name__:
                captured["audits"].append(row)
            else:
                captured["blob"] = row

        def commit(self):
            pass

    with patch("db.engine.get_session", return_value=Sess()):
        ledger._record_object_put_inner(
            bucket="bkt",
            key="config/HOOK_AGENTS/tok/meta.json",
            body=b'{"recipient_email":"agent.owner@ex.com","token":"tok"}',
            content_type="application/json",
            storage_mode="s3",
            actor_email=None,
            actor_user_id=None,
        )
    assert captured["blob"].created_by == "agent.owner@ex.com"
    assert captured["audits"][0].actor_email == "agent.owner@ex.com"


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
