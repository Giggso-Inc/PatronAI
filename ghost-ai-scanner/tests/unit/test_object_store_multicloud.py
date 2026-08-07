"""Patron multi-cloud object store — persist, facade list, mode."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path

import pytest


def _load_mod():
    mod_path = Path(__file__).resolve().parents[2] / "src" / "store" / "object_store.py"
    spec = importlib.util.spec_from_file_location("object_store_ut", mod_path)
    m = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(m)
    return m


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch, tmp_path):
    for key in (
        "STORAGE_MODE",
        "AWS_ENDPOINT_URL",
        "AZURE_STORAGE_CONNECTION_STRING",
        "AZURE_STORAGE_ACCOUNT",
        "GCP_SERVICE_ACCOUNT_JSON",
        "PATRON_STORAGE_CONFIG_PATH",
        "MARAUDER_SCAN_BUCKET",
        "OBJECT_BUCKET",
    ):
        monkeypatch.delenv(key, raising=False)
    path = tmp_path / "patron_storage.json"
    monkeypatch.setenv("PATRON_STORAGE_CONFIG_PATH", str(path))
    yield


def test_storage_mode_explicit_azure(monkeypatch):
    monkeypatch.setenv("STORAGE_MODE", "azure")
    m = _load_mod()
    assert m.storage_mode() == "azure"


def test_apply_and_persist_reload(monkeypatch):
    m = _load_mod()
    m._store = None
    m._persisted_loaded = False
    m.apply_storage_config_from_provision(
        "azure",
        {
            "azure_account_name": "acct",
            "azure_account_key": "key",
            "azure_container_name": "cont",
        },
    )
    path = Path(os.environ["PATRON_STORAGE_CONFIG_PATH"])
    assert path.is_file()
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["storage_mode"] == "azure"
    assert data["storage"]["azure_container_name"] == "cont"
    assert os.environ.get("STORAGE_MODE") == "azure"
    assert os.environ.get("MARAUDER_SCAN_BUCKET") == "cont"

    for key in (
        "STORAGE_MODE",
        "AZURE_STORAGE_ACCOUNT",
        "AZURE_STORAGE_KEY",
        "MARAUDER_SCAN_BUCKET",
        "OBJECT_BUCKET",
    ):
        monkeypatch.delenv(key, raising=False)
    m._store = None
    m._persisted_loaded = False
    assert m.load_persisted_storage_config() is True
    assert os.environ.get("STORAGE_MODE") == "azure"
    assert os.environ.get("AZURE_STORAGE_ACCOUNT") == "acct"
    assert os.environ.get("MARAUDER_SCAN_BUCKET") == "cont"


def test_facade_put_get_list():
    m = _load_mod()

    class Mem(m.ObjectStore):
        mode = "azure"

        def __init__(self):
            self.data = {}

        def get(self, bucket, key):
            return self.data[(bucket, key)]

        def put(self, bucket, key, body, content_type="application/json"):
            self.data[(bucket, key)] = body

        def delete(self, bucket, key):
            self.data.pop((bucket, key), None)

        def exists(self, bucket, key):
            return (bucket, key) in self.data

        def list_keys(self, bucket, prefix="", max_keys=5000):
            out = []
            for (b, k), v in self.data.items():
                if b == bucket and k.startswith(prefix or ""):
                    out.append({"Key": k, "LastModified": None, "Size": len(v)})
            return out[:max_keys]

    fac = m.ObjectStoreS3Facade(Mem())
    fac.put_object(Bucket="b", Key="chat/a.json", Body=b"hi")
    assert fac.get_object(Bucket="b", Key="chat/a.json")["Body"].read() == b"hi"
    listed = fac.list_objects_v2(Bucket="b", Prefix="chat/")
    assert listed["KeyCount"] == 1
    pages = list(fac.get_paginator("list_objects_v2").paginate(Bucket="b", Prefix="chat/"))
    assert pages[0]["Contents"][0]["Key"] == "chat/a.json"
