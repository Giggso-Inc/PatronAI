# =============================================================
# Multi-cloud object store backends for PatronAI finds/writes.
# STORAGE_MODE=local|s3|azure|gcp|oci — Azure/GCS from bootstrap provision
# or env (AZURE_*, GCP_*). S3/MinIO via AWS_* + optional endpoint.
# OCI via OCI_* (API-key auth, not access-key/secret).
# =============================================================

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

_log = logging.getLogger("marauder-scan.object_store")

def _config_path_candidates() -> tuple[str, ...]:
    return (
        (os.environ.get("PATRON_STORAGE_CONFIG_PATH") or "").strip(),
        "/data/patron_storage.json",
        str(Path.home() / ".patron" / "storage.json"),
        str(Path(__file__).resolve().parents[2] / ".patron_storage.json"),
    )


def _config_path() -> Optional[Path]:
    explicit = (os.environ.get("PATRON_STORAGE_CONFIG_PATH") or "").strip()
    if explicit:
        return Path(explicit)
    for p in _config_path_candidates():
        if not p:
            continue
        path = Path(p)
        if path.exists() or path.parent.exists() or path.parent == Path("."):
            return path
    last = [x for x in _config_path_candidates() if x]
    return Path(last[-1]) if last else None


def storage_mode() -> str:
    mode = (os.environ.get("STORAGE_MODE") or "").strip().lower()
    if mode in ("local", "minio", "s3", "azure", "gcp", "oci"):
        return "local" if mode == "minio" else mode
    if (os.environ.get("AWS_ENDPOINT_URL") or os.environ.get("LOCAL_STORAGE_ENDPOINT") or "").strip():
        return "local"
    if (os.environ.get("AZURE_STORAGE_CONNECTION_STRING") or os.environ.get("AZURE_STORAGE_ACCOUNT") or "").strip():
        return "azure"
    if (os.environ.get("GCP_SERVICE_ACCOUNT_JSON") or os.environ.get("GOOGLE_APPLICATION_CREDENTIALS") or "").strip():
        if not os.environ.get("AWS_ACCESS_KEY_ID"):
            return "gcp"
    if (os.environ.get("OCI_NAMESPACE") or "").strip():
        if not os.environ.get("AWS_ACCESS_KEY_ID"):
            return "oci"
    return "s3"


def default_bucket() -> str:
    return (
        os.environ.get("MARAUDER_SCAN_BUCKET")
        or os.environ.get("OBJECT_BUCKET")
        or os.environ.get("PATRONAI_BUCKET")
        or ""
    ).strip()


def storage_config_present_on_disk() -> bool:
    """True if Hub Bootstrap has written a storage config file with a bucket/mode."""
    for p in _config_path_candidates():
        if not p:
            continue
        path = Path(p)
        if not path.is_file():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        storage = data.get("storage") or {}
        if (
            storage.get("s3_bucket")
            or storage.get("azure_container_name")
            or storage.get("gcp_bucket")
            or storage.get("oci_bucket")
            or storage.get("local_path")
        ):
            return True
        mode = (data.get("storage_mode") or "").strip().lower()
        if mode == "local":
            return True
    return False


def storage_is_configured() -> bool:
    """True when env or persisted Hub Bootstrap config has an object-store target."""
    if default_bucket():
        return True
    return storage_config_present_on_disk()


class ObjectStore:
    mode: str = "s3"

    def get(self, bucket: str, key: str) -> bytes:
        raise NotImplementedError

    def put(self, bucket: str, key: str, body: bytes, content_type: str = "application/json") -> None:
        raise NotImplementedError

    def delete(self, bucket: str, key: str) -> None:
        raise NotImplementedError

    def exists(self, bucket: str, key: str) -> bool:
        raise NotImplementedError

    def list_keys(
        self,
        bucket: str,
        prefix: str = "",
        max_keys: int = 5000,
    ) -> list[dict[str, Any]]:
        """Return [{"Key", "LastModified", "Size"}, ...] under prefix."""
        raise NotImplementedError

    def dual_get(self, bucket: str, key: str, backup_bucket: str = "") -> bytes:
        data = self.get(bucket, key) if self.exists(bucket, key) else b""
        if data:
            return data
        backup = (backup_bucket or os.environ.get("LOCAL_BACKUP_BUCKET") or "").strip()
        if backup and backup != bucket and self.exists(backup, key):
            try:
                return self.get(backup, key)
            except Exception as e:
                _log.debug("dual_get backup miss: %s", e)
        return b""


class S3ObjectStore(ObjectStore):
    mode = "s3"

    def __init__(self):
        import boto3
        from botocore.config import Config

        endpoint = (
            os.environ.get("AWS_ENDPOINT_URL")
            or os.environ.get("LOCAL_STORAGE_ENDPOINT")
            or ""
        ).strip()
        mode = storage_mode()
        path = bool(endpoint) or mode == "local"
        cfg = Config(
            signature_version="s3v4",
            s3={"addressing_style": "path" if path else "virtual"},
            request_checksum_calculation="when_required",
            response_checksum_validation="when_required",
            retries={"max_attempts": 3, "mode": "standard"},
            # Env-tunable: large scan uploads/list pages may need more headroom
            # than the small per-agent meta/status reads this was sized for.
            connect_timeout=int(os.environ.get("S3_CONNECT_TIMEOUT_SECS", "5")),
            read_timeout=int(os.environ.get("S3_READ_TIMEOUT_SECS", "10")),
        )
        kwargs: dict[str, Any] = {
            "region_name": os.environ.get("AWS_DEFAULT_REGION") or os.environ.get("AWS_REGION") or "us-east-1",
            "config": cfg,
        }
        if endpoint:
            kwargs["endpoint_url"] = endpoint
        access = os.environ.get("LOCAL_STORAGE_ACCESS_KEY") or os.environ.get("AWS_ACCESS_KEY_ID")
        secret = os.environ.get("LOCAL_STORAGE_SECRET_KEY") or os.environ.get("AWS_SECRET_ACCESS_KEY")
        if access:
            kwargs["aws_access_key_id"] = access
        if secret:
            kwargs["aws_secret_access_key"] = secret
        self.client = boto3.client("s3", **kwargs)
        self.mode = "local" if path or mode == "local" else "s3"

    def get(self, bucket: str, key: str) -> bytes:
        return self.client.get_object(Bucket=bucket, Key=key)["Body"].read()

    def put(self, bucket: str, key: str, body: bytes, content_type: str = "application/json") -> None:
        self.client.put_object(Bucket=bucket, Key=key, Body=body, ContentType=content_type)

    def delete(self, bucket: str, key: str) -> None:
        self.client.delete_object(Bucket=bucket, Key=key)

    def exists(self, bucket: str, key: str) -> bool:
        try:
            self.client.head_object(Bucket=bucket, Key=key)
            return True
        except Exception:
            return False

    def list_keys(
        self,
        bucket: str,
        prefix: str = "",
        max_keys: int = 5000,
    ) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        paginator = self.client.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket, Prefix=prefix or ""):
            for obj in page.get("Contents", []) or []:
                out.append({
                    "Key": obj["Key"],
                    "LastModified": obj.get("LastModified"),
                    "Size": obj.get("Size", 0),
                })
                if len(out) >= max_keys:
                    return out
        return out


class AzureObjectStore(ObjectStore):
    mode = "azure"

    def __init__(self):
        from azure.storage.blob import BlobServiceClient

        conn = (os.environ.get("AZURE_STORAGE_CONNECTION_STRING") or "").strip()
        account = (os.environ.get("AZURE_STORAGE_ACCOUNT") or "").strip()
        key = (os.environ.get("AZURE_STORAGE_KEY") or "").strip()
        sas = (os.environ.get("AZURE_STORAGE_SAS_TOKEN") or "").strip()
        if conn:
            self.service = BlobServiceClient.from_connection_string(conn)
        elif account and key:
            self.service = BlobServiceClient(
                account_url=f"https://{account}.blob.core.windows.net",
                credential=key,
            )
        elif account and sas:
            token = sas if sas.startswith("?") else f"?{sas}"
            self.service = BlobServiceClient(
                account_url=f"https://{account}.blob.core.windows.net{token}",
            )
        else:
            raise ValueError("Azure storage env not configured (connection string or account+key)")

    def get(self, bucket: str, key: str) -> bytes:
        return self.service.get_blob_client(container=bucket, blob=key).download_blob().readall()

    def put(self, bucket: str, key: str, body: bytes, content_type: str = "application/json") -> None:
        self.service.get_blob_client(container=bucket, blob=key).upload_blob(body, overwrite=True)

    def delete(self, bucket: str, key: str) -> None:
        self.service.get_blob_client(container=bucket, blob=key).delete_blob()

    def exists(self, bucket: str, key: str) -> bool:
        return bool(self.service.get_blob_client(container=bucket, blob=key).exists())

    def list_keys(
        self,
        bucket: str,
        prefix: str = "",
        max_keys: int = 5000,
    ) -> list[dict[str, Any]]:
        container = self.service.get_container_client(bucket)
        out: list[dict[str, Any]] = []
        for blob in container.list_blobs(name_starts_with=prefix or None):
            out.append({
                "Key": blob.name,
                "LastModified": blob.last_modified,
                "Size": getattr(blob, "size", 0) or 0,
            })
            if len(out) >= max_keys:
                break
        return out


class GcsObjectStore(ObjectStore):
    mode = "gcp"

    def __init__(self):
        from google.cloud import storage
        from google.oauth2 import service_account

        raw = (os.environ.get("GCP_SERVICE_ACCOUNT_JSON") or "").strip()
        project = (os.environ.get("GCP_PROJECT_ID") or "").strip() or None
        if raw:
            info = json.loads(raw)
            creds = service_account.Credentials.from_service_account_info(info)
            self.client = storage.Client(
                project=project or info.get("project_id"),
                credentials=creds,
            )
        else:
            self.client = storage.Client(project=project)

    def get(self, bucket: str, key: str) -> bytes:
        return self.client.bucket(bucket).blob(key).download_as_bytes()

    def put(self, bucket: str, key: str, body: bytes, content_type: str = "application/json") -> None:
        self.client.bucket(bucket).blob(key).upload_from_string(body, content_type=content_type)

    def delete(self, bucket: str, key: str) -> None:
        self.client.bucket(bucket).blob(key).delete()

    def exists(self, bucket: str, key: str) -> bool:
        return self.client.bucket(bucket).blob(key).exists()

    def list_keys(
        self,
        bucket: str,
        prefix: str = "",
        max_keys: int = 5000,
    ) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for blob in self.client.list_blobs(bucket, prefix=prefix or None, max_results=max_keys):
            out.append({
                "Key": blob.name,
                "LastModified": blob.updated,
                "Size": blob.size or 0,
            })
            if len(out) >= max_keys:
                break
        return out


class OciObjectStore(ObjectStore):
    """OCI Object Storage backend.

    Auth is API-key based (user/tenancy OCID + fingerprint + PEM key), not an
    access-key/secret pair, and every call needs the account's namespace.
    Unlike Azure/GCS here, OCI DOES support presigning (via Pre-Authenticated
    Requests), so this class also exposes generate_presigned_url() with the
    same (operation, Params, ExpiresIn) shape boto3's S3 client uses —
    get_object_store()/boto3_s3_client() return this object directly for
    oci mode, so existing call sites (e.g. agent_store.py's
    self.s3.generate_presigned_url(...)) work unmodified.
    """

    mode = "oci"

    def __init__(self):
        import oci

        config = {
            "user": (os.environ.get("OCI_USER_OCID") or "").strip(),
            "tenancy": (os.environ.get("OCI_TENANCY_OCID") or "").strip(),
            "region": (os.environ.get("OCI_REGION") or "").strip(),
            "fingerprint": (os.environ.get("OCI_FINGERPRINT") or "").strip(),
            "key_content": (os.environ.get("OCI_PRIVATE_KEY") or "").strip(),
        }
        self.namespace = (os.environ.get("OCI_NAMESPACE") or "").strip()
        self.compartment_id = (os.environ.get("OCI_COMPARTMENT_ID") or "").strip()
        if not self.namespace:
            raise ValueError("OCI storage requires OCI_NAMESPACE")
        self.client = oci.object_storage.ObjectStorageClient(config)

    def get(self, bucket: str, key: str) -> bytes:
        return self.client.get_object(self.namespace, bucket, key).data.content

    def put(self, bucket: str, key: str, body: bytes, content_type: str = "application/json") -> None:
        self.client.put_object(self.namespace, bucket, key, body, content_type=content_type)

    def delete(self, bucket: str, key: str) -> None:
        self.client.delete_object(self.namespace, bucket, key)

    def exists(self, bucket: str, key: str) -> bool:
        try:
            self.client.head_object(self.namespace, bucket, key)
            return True
        except Exception:
            return False

    def list_keys(
        self,
        bucket: str,
        prefix: str = "",
        max_keys: int = 5000,
    ) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        start: Optional[str] = None
        while True:
            resp = self.client.list_objects(
                self.namespace, bucket, prefix=prefix or None, start=start,
                fields="name,size,timeModified",
            )
            for obj in resp.data.objects or []:
                out.append({
                    "Key": obj.name,
                    "LastModified": getattr(obj, "time_modified", None),
                    "Size": getattr(obj, "size", 0) or 0,
                })
                if len(out) >= max_keys:
                    return out
            start = getattr(resp.data, "next_start_with", None)
            if not start:
                break
        return out

    def generate_presigned_url(self, operation: str, Params: dict, ExpiresIn: int = 3600) -> str:
        """boto3-shaped presign via OCI Pre-Authenticated Request (PAR).

        Each call makes one real OCI API call (unlike SigV4's pure local
        crypto) — OCI has no client-side URL-signing primitive.
        """
        import oci

        bucket = Params["Bucket"]
        key = Params["Key"]
        access_type = "ObjectWrite" if operation == "put_object" else "ObjectRead"
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=ExpiresIn)
        details = oci.object_storage.models.CreatePreauthenticatedRequestDetails(
            name=f"patron-presign-{key}",
            access_type=access_type,
            time_expires=expires_at,
            object_name=key,
        )
        par = self.client.create_preauthenticated_request(self.namespace, bucket, details)
        region = (os.environ.get("OCI_REGION") or "").strip()
        host = f"https://objectstorage.{region}.oraclecloud.com"
        return f"{host}{par.data.access_uri}"


# ── boto3-shaped facade (Azure/GCS + shared call sites) ──────────


class _NoSuchKey(Exception):
    """Mimics botocore NoSuchKey for call sites that catch it."""


class _Body:
    def __init__(self, data: bytes):
        self._data = data if isinstance(data, (bytes, bytearray)) else bytes(data or b"")

    def read(self, *args, **kwargs) -> bytes:
        return self._data


class _ListPaginator:
    def __init__(self, store: ObjectStore):
        self._store = store

    def paginate(self, Bucket: str, Prefix: str = "", **kwargs):
        keys = self._store.list_keys(Bucket, prefix=Prefix or "", max_keys=10_000)
        page_size = 1000
        if not keys:
            yield {"Contents": []}
            return
        for i in range(0, len(keys), page_size):
            yield {"Contents": keys[i:i + page_size]}


class ObjectStoreS3Facade:
    """Minimal boto3 S3 client surface over any ObjectStore backend."""

    def __init__(self, store: ObjectStore):
        self._store = store
        self.exceptions = type("Exc", (), {"NoSuchKey": _NoSuchKey})()

    def get_object(self, Bucket: str, Key: str, **kwargs) -> dict:
        try:
            data = self._store.get(Bucket, Key)
        except Exception as exc:
            # Map miss to NoSuchKey when possible
            msg = str(exc).lower()
            if "not found" in msg or "nosuchkey" in msg or "404" in msg or "blobnotfound" in msg:
                raise _NoSuchKey(str(exc)) from exc
            if not self._store.exists(Bucket, Key):
                raise _NoSuchKey(str(exc)) from exc
            raise
        return {"Body": _Body(data), "ContentType": "application/octet-stream"}

    def put_object(
        self,
        Bucket: str,
        Key: str,
        Body: Any = b"",
        ContentType: str = "application/octet-stream",
        **kwargs,
    ) -> dict:
        if hasattr(Body, "read"):
            Body = Body.read()
        if isinstance(Body, str):
            Body = Body.encode("utf-8")
        self._store.put(Bucket, Key, bytes(Body or b""), content_type=ContentType or "application/octet-stream")
        return {}

    def head_object(self, Bucket: str, Key: str, **kwargs) -> dict:
        if not self._store.exists(Bucket, Key):
            raise _NoSuchKey(f"Not found: {Key}")
        return {}

    def delete_object(self, Bucket: str, Key: str, **kwargs) -> dict:
        try:
            self._store.delete(Bucket, Key)
        except Exception:
            pass
        return {}

    def delete_objects(self, Bucket: str, Delete: Optional[dict] = None, **kwargs) -> dict:
        for obj in (Delete or {}).get("Objects") or []:
            key = obj.get("Key")
            if key:
                self.delete_object(Bucket=Bucket, Key=key)
        return {}

    def list_objects_v2(self, Bucket: str, Prefix: str = "", **kwargs) -> dict:
        keys = self._store.list_keys(Bucket, prefix=Prefix or "")
        return {"Contents": keys, "KeyCount": len(keys)}

    def get_paginator(self, name: str):
        if name != "list_objects_v2":
            raise NotImplementedError(f"paginator {name}")
        return _ListPaginator(self._store)

    def upload_file(self, Filename: str, Bucket: str, Key: str, ExtraArgs: Optional[dict] = None, **kwargs) -> None:
        ctype = (ExtraArgs or {}).get("ContentType", "application/octet-stream")
        with open(Filename, "rb") as fh:
            self.put_object(Bucket=Bucket, Key=Key, Body=fh.read(), ContentType=ctype)

    def generate_presigned_url(self, operation_name: str, Params: Optional[dict] = None, ExpiresIn: int = 3600, **kwargs) -> str:
        """Delegate to the backing store's own presign when it has one (OCI,
        via Pre-Authenticated Requests). Azure/GCS backends have no presign
        implementation here, same gap as before this method existed —
        callers already treat any exception as "presign unavailable"."""
        impl = getattr(self._store, "generate_presigned_url", None)
        if impl is None:
            raise NotImplementedError(f"presign not supported for mode={self._store.mode}")
        return impl(operation_name, Params or {}, ExpiresIn)

    def get_bucket_lifecycle_configuration(self, Bucket: str, **kwargs) -> dict:
        raise _client_error("NoSuchLifecycleConfiguration")

    def put_bucket_lifecycle_configuration(self, Bucket: str, LifecycleConfiguration=None, **kwargs) -> dict:
        _log.info("lifecycle config skipped for storage mode=%s", self._store.mode)
        return {}


def _client_error(code: str):
    try:
        from botocore.exceptions import ClientError
        return ClientError({"Error": {"Code": code, "Message": code}}, "op")
    except Exception:
        return _NoSuchKey(code)


_store: Optional[ObjectStore] = None
_persisted_loaded = False


def persist_storage_config(storage_mode_val: str, storage: dict[str, Any]) -> Optional[str]:
    """Write Hub provision storage to disk so restarts keep Azure/GCS/S3 mode."""
    path = _config_path()
    if path is None:
        return None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "storage_mode": (storage_mode_val or "s3").strip().lower(),
            "storage": dict(storage or {}),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        path.write_text(json.dumps(payload), encoding="utf-8")
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        _log.info("Persisted storage config → %s", path)
        return str(path)
    except Exception as exc:
        _log.warning("Could not persist storage config: %s", exc)
        return None


def load_persisted_storage_config() -> bool:
    """Load disk storage config into env if present. Returns True if applied."""
    global _persisted_loaded
    if _persisted_loaded:
        return False
    _persisted_loaded = True
    # Explicit process env wins — only fill gaps from disk
    for p in _config_path_candidates():
        if not p:
            continue
        path = Path(p)
        if not path.is_file():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            _log.warning("Bad storage config %s: %s", path, exc)
            continue
        mode = (data.get("storage_mode") or "").strip()
        storage = data.get("storage") or {}
        if mode and not (os.environ.get("STORAGE_MODE") or "").strip():
            os.environ["STORAGE_MODE"] = mode
        # Apply only keys not already forced in env
        _apply_storage_dict(storage, force=False)
        _log.info("Loaded persisted storage config from %s (mode=%s)", path, mode or storage_mode())
        return True
    return False


def reload_persisted_storage_config() -> bool:
    """Force re-read of disk storage config (bootstrap-wait loop)."""
    global _persisted_loaded, _store
    _persisted_loaded = False
    _store = None
    return load_persisted_storage_config()


def _apply_storage_dict(storage: dict[str, Any], *, force: bool = True) -> None:
    """Map provision/storage secrets into env."""
    if not storage:
        return

    def _set(key: str, value: str) -> None:
        if not value:
            return
        if force or not (os.environ.get(key) or "").strip():
            os.environ[key] = value

    _set("AWS_ENDPOINT_URL", storage.get("s3_endpoint_url") or "")
    _set("AWS_ACCESS_KEY_ID", storage.get("s3_access_key_id") or "")
    _set("AWS_SECRET_ACCESS_KEY", storage.get("s3_secret_access_key") or "")
    if storage.get("s3_region"):
        _set("AWS_DEFAULT_REGION", storage["s3_region"])
        _set("AWS_REGION", storage["s3_region"])
    if storage.get("s3_bucket"):
        _set("MARAUDER_SCAN_BUCKET", storage["s3_bucket"])
        _set("OBJECT_BUCKET", storage["s3_bucket"])
    _set("AZURE_STORAGE_CONNECTION_STRING", storage.get("azure_connection_string") or "")
    _set("AZURE_STORAGE_ACCOUNT", storage.get("azure_account_name") or "")
    _set("AZURE_STORAGE_KEY", storage.get("azure_account_key") or "")
    _set("AZURE_STORAGE_SAS_TOKEN", storage.get("azure_sas_token") or "")
    if storage.get("azure_container_name"):
        _set("MARAUDER_SCAN_BUCKET", storage["azure_container_name"])
        _set("OBJECT_BUCKET", storage["azure_container_name"])
    _set("GCP_SERVICE_ACCOUNT_JSON", storage.get("gcp_service_account_json") or "")
    _set("GCP_PROJECT_ID", storage.get("gcp_project_id") or "")
    if storage.get("gcp_bucket"):
        _set("MARAUDER_SCAN_BUCKET", storage["gcp_bucket"])
        _set("OBJECT_BUCKET", storage["gcp_bucket"])
    _set("OCI_USER_OCID", storage.get("oci_user_ocid") or "")
    _set("OCI_TENANCY_OCID", storage.get("oci_tenancy_ocid") or "")
    _set("OCI_REGION", storage.get("oci_region") or "")
    _set("OCI_FINGERPRINT", storage.get("oci_fingerprint") or "")
    _set("OCI_PRIVATE_KEY", storage.get("oci_private_key") or "")
    _set("OCI_NAMESPACE", storage.get("oci_namespace") or "")
    _set("OCI_COMPARTMENT_ID", storage.get("oci_compartment_id") or "")
    if storage.get("oci_bucket"):
        _set("MARAUDER_SCAN_BUCKET", storage["oci_bucket"])
        _set("OBJECT_BUCKET", storage["oci_bucket"])


def get_object_store(force: bool = False) -> ObjectStore:
    global _store
    load_persisted_storage_config()
    if _store is None or force:
        mode = storage_mode()
        if mode == "azure":
            _store = AzureObjectStore()
        elif mode == "gcp":
            _store = GcsObjectStore()
        elif mode == "oci":
            _store = OciObjectStore()
        else:
            _store = S3ObjectStore()
            _store.mode = mode
        _log.info("Patron object store mode=%s", _store.mode)
    return _store


def boto3_s3_client(region_name: Optional[str] = None):
    """Return a boto3 S3 client (s3/local) or multi-cloud facade (azure/gcp).

    Prefer this over bare ``boto3.client("s3")`` so Azure/GCS wizard choice
    reaches chat, rollups, ingestor, and seed paths.
    """
    store = get_object_store()
    if isinstance(store, S3ObjectStore) and getattr(store, "client", None) is not None:
        return store.client
    return ObjectStoreS3Facade(store)


def apply_storage_config_from_provision(storage_mode_val: str, storage: dict[str, Any]) -> None:
    """Apply Hub bootstrap storage payload into process env, persist, reset client."""
    global _store, _persisted_loaded
    mode = (storage_mode_val or "s3").strip().lower()
    if mode:
        os.environ["STORAGE_MODE"] = mode
    _apply_storage_dict(storage or {}, force=True)
    persist_storage_config(mode, storage or {})
    _store = None
    _persisted_loaded = True  # already applied; don't re-read partial on next get
    _log.info("Applied provision storage_mode=%s", mode)
