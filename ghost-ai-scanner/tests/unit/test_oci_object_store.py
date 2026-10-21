"""OciObjectStore tests - boto3 against OCI's S3-Compatibility API.

Follows test_object_store_multicloud.py's pattern of loading object_store.py
by file path. OciObjectStore uses boto3 + a Customer Secret Key (access
key/secret key), not the native `oci` SDK, so these tests mock
boto3.client("s3") exactly the way an S3ObjectStore test would.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError


def _load_mod():
    mod_path = Path(__file__).resolve().parents[2] / "src" / "store" / "object_store.py"
    spec = importlib.util.spec_from_file_location("object_store_ut_oci", mod_path)
    m = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(m)
    return m


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for key in ("STORAGE_MODE", "OCI_ACCESS_KEY_ID", "OCI_SECRET_ACCESS_KEY", "OCI_REGION", "OCI_NAMESPACE"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("OCI_ACCESS_KEY_ID", "AKIAEXAMPLE")
    monkeypatch.setenv("OCI_SECRET_ACCESS_KEY", "secretexample")
    monkeypatch.setenv("OCI_REGION", "us-ashburn-1")
    monkeypatch.setenv("OCI_NAMESPACE", "mynamespace")


@pytest.fixture
def boto_client():
    return MagicMock()


def _make_store(mod, boto_client):
    with patch("boto3.client", return_value=boto_client) as mock_boto:
        store = mod.OciObjectStore()
    return store, mock_boto


def test_endpoint_uses_s3_compat_url(boto_client):
    mod = _load_mod()
    _, mock_boto = _make_store(mod, boto_client)
    kwargs = mock_boto.call_args.kwargs
    assert kwargs["endpoint_url"] == "https://mynamespace.compat.objectstorage.us-ashburn-1.oraclecloud.com"
    assert kwargs["aws_access_key_id"] == "AKIAEXAMPLE"
    assert kwargs["aws_secret_access_key"] == "secretexample"


def test_missing_credentials_raises(monkeypatch):
    mod = _load_mod()
    monkeypatch.delenv("OCI_ACCESS_KEY_ID", raising=False)
    with pytest.raises(ValueError):
        mod.OciObjectStore()


def test_get_put_delete(boto_client):
    mod = _load_mod()
    store, _ = _make_store(mod, boto_client)

    boto_client.get_object.return_value = {"Body": MagicMock(read=MagicMock(return_value=b"hello"))}
    assert store.get("bkt", "key") == b"hello"
    boto_client.get_object.assert_called_once_with(Bucket="bkt", Key="key")

    store.put("bkt", "key", b"hello", content_type="application/json")
    boto_client.put_object.assert_called_once_with(
        Bucket="bkt", Key="key", Body=b"hello", ContentType="application/json"
    )

    store.delete("bkt", "key")
    boto_client.delete_object.assert_called_once_with(Bucket="bkt", Key="key")


def test_exists_true(boto_client):
    mod = _load_mod()
    store, _ = _make_store(mod, boto_client)
    boto_client.head_object.return_value = {}
    assert store.exists("bkt", "key") is True


def test_exists_false_on_error(boto_client):
    mod = _load_mod()
    store, _ = _make_store(mod, boto_client)
    boto_client.head_object.side_effect = ClientError(
        {"Error": {"Code": "404"}}, "HeadObject"
    )
    assert store.exists("bkt", "key") is False


def test_boto3_s3_client_returns_raw_client_for_oci(boto_client, monkeypatch):
    """Architecture fix from PR #71 review: OciObjectStore IS a real boto3
    client now (OCI S3-Compat API), so boto3_s3_client() must return it
    directly, not wrap it in ObjectStoreS3Facade."""
    mod = _load_mod()
    monkeypatch.setenv("STORAGE_MODE", "oci")
    with patch("boto3.client", return_value=boto_client):
        mod._store = None
        client = mod.boto3_s3_client()
    assert client is boto_client


def test_presign_is_pure_boto3_sigv4_no_api_call(boto_client):
    mod = _load_mod()
    store, _ = _make_store(mod, boto_client)
    boto_client.generate_presigned_url.return_value = "https://mynamespace.compat.objectstorage.us-ashburn-1.oraclecloud.com/bkt/key?sig=abc"

    url = store.client.generate_presigned_url("get_object", Params={"Bucket": "bkt", "Key": "key"}, ExpiresIn=120)

    assert url.startswith("https://mynamespace.compat.objectstorage.us-ashburn-1.oraclecloud.com")
    boto_client.generate_presigned_url.assert_called_once()
