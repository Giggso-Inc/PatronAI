# =============================================================
# FILE: tests/unit/test_retina_assembler_blobstore.py
# PURPOSE: Regression guard — ensures RetinaAssembler works with
#          BlobIndexStore (the coordinator passed from threads.py).
#          Guards PR #58 (_get/_put on BlobIndexStore) and the
#          silent-crash fix in PR #60 (try/except in retina_loop).
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


def _mock_s3():
    """S3 store that returns NoSuchKey for every get — simulates empty bucket."""
    s3 = MagicMock()
    s3.get.side_effect = Exception("NoSuchKey: test-key")
    s3.put.return_value = None
    s3.exists.return_value = False
    s3.mode = "s3"
    return s3


@pytest.fixture(scope="module")
def store_and_assembler():
    # Patch at the usage site (base_store imports get_object_store at module
    # level, so we must patch the reference there, not the origin module).
    with patch("store.base_store.get_object_store", return_value=_mock_s3()):
        from blob_index_store import BlobIndexStore
        from retina import RetinaAssembler
        store = BlobIndexStore("test-bucket")
        assembler = RetinaAssembler(store)
        yield store, assembler


def test_blobindexstore_has_get_and_put(store_and_assembler):
    """PR #58: BlobIndexStore must expose _get/_put for RetinaAssembler."""
    store, _ = store_and_assembler
    assert hasattr(store, "_get"), "_get missing — PR #58 regression"
    assert hasattr(store, "_put"), "_put missing — PR #58 regression"


def test_retina_assembler_constructs_with_blobindexstore(store_and_assembler):
    """RetinaAssembler(BlobIndexStore) must not crash — this was the silent kill."""
    _, assembler = store_and_assembler
    assert assembler is not None


def test_run_all_with_empty_catalog_returns_zero_stats(store_and_assembler):
    """Empty S3 catalog → agents_checked=0, no crash, no Hub POST."""
    _, assembler = store_and_assembler
    stats = assembler.run_all()
    assert stats["agents_checked"] == 0
    assert stats["scans_posted"] == 0
    assert stats["errors"] == 0


def test_device_metadata_comes_from_heartbeat_not_server(store_and_assembler):
    """Root-cause guard: assembler must read per-agent heartbeat, NOT get_device_info().

    get_device_info() returns the server's own hostname/OS — wrong for every agent.
    _read_heartbeat(token) reads ocsf/agent/heartbeats/{token}/latest.json which
    heartbeat.sh uploads from each employee's own machine — correct per-agent source.
    """
    _, assembler = store_and_assembler
    # Confirm get_device_info is NOT imported at all in assembler
    import retina.assembler as asm_mod
    assert not hasattr(asm_mod, "get_device_info"), (
        "get_device_info must NOT be imported in assembler — it reads the server's "
        "own environment and is wrong for every agent. Use _read_heartbeat() instead."
    )
    # Confirm _read_heartbeat helper exists
    assert hasattr(assembler, "_read_heartbeat"), "_read_heartbeat helper missing"
    # Confirm it reads from the right S3 path
    import inspect
    src = inspect.getsource(assembler._read_heartbeat)
    assert "ocsf/agent/heartbeats" in src, (
        "_read_heartbeat must read from ocsf/agent/heartbeats/{token}/latest.json"
    )


def test_retina_loop_init_crash_is_caught(tmp_path):
    """PR #60: threads.retina_loop must log and return on init crash — not die silently."""
    import threading
    import logging
    import io

    log_output = io.StringIO()
    handler = logging.StreamHandler(log_output)
    handler.setLevel(logging.ERROR)
    logging.getLogger("marauder-scan.threads").addHandler(handler)

    # A broken store that raises on _get (simulates a bad import or construct)
    class _BrokenStore:
        def _get(self, key):
            raise RuntimeError("simulated init failure")
        def _put(self, key, body, content_type="application/json"):
            raise RuntimeError("simulated init failure")

    # Patch RetinaAssembler to raise during construction
    with patch("store.object_store.get_object_store", return_value=_mock_s3()):
        import importlib, src.threads as threads_mod  # noqa: E401

        stop = threading.Event()
        stop.set()  # stop immediately after init

        errors_before = log_output.tell()
        # Patch assembler to raise on construction
        with patch("retina.RetinaAssembler", side_effect=RuntimeError("boom")):
            t = threading.Thread(target=threads_mod.retina_loop, args=(_BrokenStore(), stop))
            t.start()
            t.join(timeout=5)
            assert not t.is_alive(), "retina_loop thread hung instead of returning"

        log_output.seek(errors_before)
        logged = log_output.read()
        assert "failed to initialise" in logged, f"Expected init crash logged, got: {logged!r}"
