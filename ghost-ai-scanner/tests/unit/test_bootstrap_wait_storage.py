"""Bootstrap-wait: Patron must start without MARAUDER_SCAN_BUCKET."""

from __future__ import annotations

import importlib.util
import json
import logging
import os
import sys
import types
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parents[2] / "src"
_OBJ_PATH = _SRC / "store" / "object_store.py"
_BOOT_PATH = _SRC / "bootstrap.py"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _install_store_stub(monkeypatch, osm):
    store_pkg = types.ModuleType("store")
    store_pkg.object_store = osm
    monkeypatch.setitem(sys.modules, "store", store_pkg)
    monkeypatch.setitem(sys.modules, "store.object_store", osm)


@pytest.fixture
def osm(monkeypatch, tmp_path):
    for key in (
        "MARAUDER_SCAN_BUCKET",
        "OBJECT_BUCKET",
        "PATRONAI_BUCKET",
        "PATRON_STORAGE_CONFIG_PATH",
        "STORAGE_MODE",
    ):
        monkeypatch.delenv(key, raising=False)
    cfg = tmp_path / "patron_storage.json"
    monkeypatch.setenv("PATRON_STORAGE_CONFIG_PATH", str(cfg))
    mod = _load("object_store_bootstrap_ut", _OBJ_PATH)
    mod._persisted_loaded = False
    mod._store = None
    yield mod
    mod._persisted_loaded = False
    mod._store = None


def test_validate_env_returns_false_without_bucket(monkeypatch, osm):
    _install_store_stub(monkeypatch, osm)
    boot = _load("bootstrap_wait_ut", _BOOT_PATH)
    monkeypatch.setattr(boot, "BUCKET", "")
    assert boot.validate_env() is False


def test_validate_env_true_when_bucket_set(monkeypatch, osm):
    _install_store_stub(monkeypatch, osm)
    boot = _load("bootstrap_wait_ut2", _BOOT_PATH)
    monkeypatch.setenv("MARAUDER_SCAN_BUCKET", "demo-bucket")
    monkeypatch.setattr(boot, "BUCKET", "demo-bucket")
    assert boot.validate_env() is True


def test_storage_is_configured_reads_disk(osm):
    cfg = Path(os.environ["PATRON_STORAGE_CONFIG_PATH"])
    assert osm.storage_is_configured() is False

    cfg.write_text(
        json.dumps({"storage_mode": "s3", "storage": {"s3_bucket": "from-hub"}}),
        encoding="utf-8",
    )
    assert osm.storage_is_configured() is True
    assert osm.reload_persisted_storage_config() is True
    assert os.environ.get("MARAUDER_SCAN_BUCKET") == "from-hub"


def test_seed_config_files_skips_without_bucket(monkeypatch, osm, caplog):
    _install_store_stub(monkeypatch, osm)
    boot = _load("bootstrap_wait_ut3", _BOOT_PATH)
    monkeypatch.setattr(boot, "BUCKET", "")
    with caplog.at_level(logging.WARNING):
        boot.seed_config_files(store=None)
    assert any("seed_config_files skipped" in r.message for r in caplog.records)
