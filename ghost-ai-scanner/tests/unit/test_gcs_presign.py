"""GCS presign — V4 signed URLs through ObjectStoreS3Facade.

Signs with a throwaway service-account key, so google-cloud-storage's real
V4 signer runs locally with no network call.
"""

from __future__ import annotations

import json
import os
import sys
from urllib.parse import parse_qs, urlparse

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from store import object_store

BUCKET = "gsd-test-evidence"
CLIENT_EMAIL = "patron-test@test-proj.iam.gserviceaccount.com"


def _service_account_json() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    return json.dumps({
        "type": "service_account",
        "project_id": "test-proj",
        "private_key_id": "test-key-id",
        "private_key": pem,
        "client_email": CLIENT_EMAIL,
        "client_id": "1",
        "token_uri": "https://oauth2.googleapis.com/token",
    })


@pytest.fixture
def gcs_env(monkeypatch, tmp_path):
    monkeypatch.setenv("STORAGE_MODE", "gcp")
    monkeypatch.setenv("GCP_SERVICE_ACCOUNT_JSON", _service_account_json())
    monkeypatch.setenv("GCP_PROJECT_ID", "test-proj")
    monkeypatch.setenv("MARAUDER_SCAN_BUCKET", BUCKET)
    monkeypatch.setenv("PATRON_STORAGE_CONFIG_PATH", str(tmp_path / "patron_storage.json"))
    monkeypatch.setattr(object_store, "_store", None)
    monkeypatch.setattr(object_store, "_persisted_loaded", True)
    yield


def _query(url: str) -> dict[str, str]:
    return {k: v[0] for k, v in parse_qs(urlparse(url).query).items()}


def test_get_object_is_v4_signed_get(gcs_env):
    store = object_store.GcsObjectStore()
    url = store.generate_presigned_url(
        "get_object", {"Bucket": BUCKET, "Key": "config/HOOK_AGENTS/tok/meta.json"}, 172800,
    )
    assert url.startswith(f"https://storage.googleapis.com/{BUCKET}/config/HOOK_AGENTS/tok/meta.json?")
    q = _query(url)
    assert q["X-Goog-Algorithm"] == "GOOG4-RSA-SHA256"
    assert q["X-Goog-Credential"].startswith(CLIENT_EMAIL + "/")
    assert q["X-Goog-Expires"] == "172800"
    assert q["X-Goog-SignedHeaders"] == "host"


def test_put_object_binds_content_type_at_seven_day_max(gcs_env):
    store = object_store.GcsObjectStore()
    url = store.generate_presigned_url(
        "put_object",
        {"Bucket": BUCKET, "Key": "ocsf/agent/heartbeats/tok/latest.json", "ContentType": "application/json"},
        604800,
    )
    q = _query(url)
    assert q["X-Goog-SignedHeaders"] == "content-type;host"
    assert q["X-Goog-Expires"] == "604800"


def test_unsupported_operation_raises(gcs_env):
    store = object_store.GcsObjectStore()
    with pytest.raises(NotImplementedError):
        store.generate_presigned_url("delete_object", {"Bucket": BUCKET, "Key": "k"}, 60)


def test_facade_delegates_to_gcs(gcs_env):
    facade = object_store.ObjectStoreS3Facade(object_store.GcsObjectStore())
    url = facade.generate_presigned_url(
        "get_object", Params={"Bucket": BUCKET, "Key": "k.txt"}, ExpiresIn=3600,
    )
    assert _query(url)["X-Goog-Algorithm"] == "GOOG4-RSA-SHA256"


def test_agent_store_presigned_urls_on_gcs(gcs_env):
    """The /agent/provision path that returned 502 on GCP VMs."""
    from store.agent_store import AgentStore

    store = AgentStore(BUCKET)
    assert isinstance(store.s3, object_store.ObjectStoreS3Facade)
    urls = store.get_presigned_urls("tok", "linux")
    assert set(urls) == {
        "installer_url", "meta_url", "status_put_url", "heartbeat_put_url",
        "scan_put_url", "authorized_get_url", "urls_refresh_url",
    }
    for name, url in urls.items():
        assert url.startswith(f"https://storage.googleapis.com/{BUCKET}/"), name
    assert _query(urls["status_put_url"])["X-Goog-SignedHeaders"] == "content-type;host"
    assert _query(urls["installer_url"])["X-Goog-SignedHeaders"] == "host"
