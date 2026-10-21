"""OciObjectStore tests against a mocked oci.object_storage.ObjectStorageClient.

Follows test_object_store_multicloud.py's pattern of loading object_store.py
by file path (the module isn't part of an installed package here). The real
`oci` package may not be installed in every test environment, so a fake
module tree is injected into sys.modules before the module under test runs
its (deferred, per-method) `import oci`.
"""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

import pytest


class _FakeServiceError(Exception):
    def __init__(self, status: int):
        super().__init__(f"status={status}")
        self.status = status


def _install_fake_oci_module(monkeypatch, client: MagicMock):
    fake_oci = types.ModuleType("oci")
    fake_oci.exceptions = types.SimpleNamespace(ServiceError=_FakeServiceError)

    fake_object_storage = types.ModuleType("oci.object_storage")
    fake_object_storage.ObjectStorageClient = MagicMock(return_value=client)

    fake_models = types.ModuleType("oci.object_storage.models")
    fake_models.CreatePreauthenticatedRequestDetails = MagicMock(
        side_effect=lambda **kwargs: types.SimpleNamespace(**kwargs)
    )
    fake_object_storage.models = fake_models
    fake_oci.object_storage = fake_object_storage

    monkeypatch.setitem(sys.modules, "oci", fake_oci)
    monkeypatch.setitem(sys.modules, "oci.object_storage", fake_object_storage)
    monkeypatch.setitem(sys.modules, "oci.object_storage.models", fake_models)


def _load_mod():
    mod_path = Path(__file__).resolve().parents[2] / "src" / "store" / "object_store.py"
    spec = importlib.util.spec_from_file_location("object_store_ut_oci", mod_path)
    m = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(m)
    return m


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for key in (
        "STORAGE_MODE", "OCI_USER_OCID", "OCI_TENANCY_OCID", "OCI_REGION",
        "OCI_FINGERPRINT", "OCI_PRIVATE_KEY", "OCI_NAMESPACE", "OCI_COMPARTMENT_ID",
    ):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("OCI_USER_OCID", "ocid1.user.oc1..aaa")
    monkeypatch.setenv("OCI_TENANCY_OCID", "ocid1.tenancy.oc1..bbb")
    monkeypatch.setenv("OCI_REGION", "us-ashburn-1")
    monkeypatch.setenv("OCI_FINGERPRINT", "aa:bb:cc")
    monkeypatch.setenv("OCI_PRIVATE_KEY", "-----BEGIN PRIVATE KEY-----\\nabc\\n-----END PRIVATE KEY-----")
    monkeypatch.setenv("OCI_NAMESPACE", "mynamespace")
    monkeypatch.setenv("OCI_COMPARTMENT_ID", "ocid1.compartment.oc1..ccc")


@pytest.fixture
def oci_client(monkeypatch):
    client = MagicMock()
    client.base_client.endpoint = "https://objectstorage.us-ashburn-1.oraclecloud.com"
    _install_fake_oci_module(monkeypatch, client)
    return client


def test_private_key_literal_newlines_unescaped(oci_client):
    mod = _load_mod()
    mod.OciObjectStore()
    object_storage = sys.modules["oci.object_storage"]
    config = object_storage.ObjectStorageClient.call_args[0][0]
    assert "\\n" not in config["key_content"]
    assert "\n" in config["key_content"]


def test_get_put_delete(oci_client):
    mod = _load_mod()
    store = mod.OciObjectStore()

    oci_client.get_object.return_value.data.content = b"hello"
    assert store.get("bkt", "key") == b"hello"
    oci_client.get_object.assert_called_once_with("mynamespace", "bkt", "key")

    store.put("bkt", "key", b"hello", content_type="text/plain")
    oci_client.put_object.assert_called_once_with(
        "mynamespace", "bkt", "key", b"hello", content_type="text/plain"
    )

    store.delete("bkt", "key")
    oci_client.delete_object.assert_called_once_with("mynamespace", "bkt", "key")


def test_exists_true(oci_client):
    mod = _load_mod()
    store = mod.OciObjectStore()
    oci_client.head_object.return_value = object()
    assert store.exists("bkt", "key") is True


def test_exists_false_on_404(oci_client):
    mod = _load_mod()
    store = mod.OciObjectStore()
    oci_client.head_object.side_effect = _FakeServiceError(404)
    assert store.exists("bkt", "key") is False


def test_exists_reraises_non_404(oci_client):
    mod = _load_mod()
    store = mod.OciObjectStore()
    oci_client.head_object.side_effect = _FakeServiceError(403)
    with pytest.raises(_FakeServiceError):
        store.exists("bkt", "key")


def test_list_keys_paginates(oci_client):
    mod = _load_mod()
    store = mod.OciObjectStore()

    page1 = MagicMock()
    page1.data.objects = [types.SimpleNamespace(name="a.json", size=10, time_modified=None)]
    page1.data.next_start_with = "a.json"
    page2 = MagicMock()
    page2.data.objects = [types.SimpleNamespace(name="b.json", size=20, time_modified=None)]
    page2.data.next_start_with = None
    oci_client.list_objects.side_effect = [page1, page2]

    keys = store.list_keys("bkt", prefix="p/")
    assert [k["Key"] for k in keys] == ["a.json", "b.json"]
    assert oci_client.list_objects.call_count == 2


def test_presign_get_uses_client_endpoint_not_hardcoded_host(oci_client):
    mod = _load_mod()
    store = mod.OciObjectStore()
    oci_client.base_client.endpoint = "https://objectstorage.us-gov-ashburn-1.oraclecloud.com"
    oci_client.create_preauthenticated_request.return_value.data.access_uri = "/p/xyz/n/ns/b/bkt/o/key"

    url = store.generate_presigned_url("get_object", {"Bucket": "bkt", "Key": "key"}, ExpiresIn=120)

    assert url == "https://objectstorage.us-gov-ashburn-1.oraclecloud.com/p/xyz/n/ns/b/bkt/o/key"


def test_presign_put_uses_object_write_access_type(oci_client):
    mod = _load_mod()
    store = mod.OciObjectStore()
    oci_client.create_preauthenticated_request.return_value.data.access_uri = "/p/xyz/n/ns/b/bkt/o/key"

    store.generate_presigned_url("put_object", {"Bucket": "bkt", "Key": "key"})

    details = oci_client.create_preauthenticated_request.call_args[0][2]
    assert details.access_type == "ObjectWrite"


def test_env_int_falls_back_on_bad_value(monkeypatch):
    mod = _load_mod()
    monkeypatch.setenv("S3_CONNECT_TIMEOUT_SECS", "not-a-number")
    assert mod._env_int("S3_CONNECT_TIMEOUT_SECS", 5) == 5


def test_env_int_parses_good_value(monkeypatch):
    mod = _load_mod()
    monkeypatch.setenv("S3_CONNECT_TIMEOUT_SECS", "30")
    assert mod._env_int("S3_CONNECT_TIMEOUT_SECS", 5) == 30
