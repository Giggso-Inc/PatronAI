# =============================================================
# FILE: src/store/base_store.py
# VERSION: 1.3.0
# UPDATED: 2026-08-05
# PURPOSE: Shared base class for all store modules — multi-cloud
#          (S3/MinIO, Azure Blob, GCS) via object_store backends.
# =============================================================

import os
import logging

from .object_store import S3ObjectStore, get_object_store, storage_mode

log = logging.getLogger("marauder-scan.store")


def is_s3_compatible_local() -> bool:
    """True for MinIO / LocalStack — S3 Select may be unavailable."""
    return storage_mode() in ("local",)


class BaseStore:
    """
    Parent class for all store modules.
    Bucket/container name + multi-cloud ObjectStore backend.
    """

    def __init__(self, bucket: str, region: str = "us-east-1"):
        self.bucket = (
            bucket
            or os.environ.get("MARAUDER_SCAN_BUCKET")
            or os.environ.get("OBJECT_BUCKET")
            or ""
        )
        self.region = region
        self._store = get_object_store()
        self.local_mode = self._store.mode in ("local",) or is_s3_compatible_local()
        # Only expose raw boto3 client for S3/MinIO. Azure/GCS use a facade
        # when callers need put/get via boto3-shaped APIs (never a GCS Client).
        if isinstance(self._store, S3ObjectStore):
            self.s3 = self._store.client
        else:
            from .object_store import ObjectStoreS3Facade
            self.s3 = ObjectStoreS3Facade(self._store)

    def _get(self, key: str) -> bytes:
        """Fetch raw bytes. Returns empty bytes if key not found."""
        try:
            return self._store.get(self.bucket, key)
        except Exception as e:
            msg = str(e).lower()
            if any(t in msg for t in ("nosuchkey", "not found", "404", "blobnotfound", "404")):
                return b""
            log.error(f"object get failed [{key}]: {e}")
            return b""

    def _put(self, key: str, body: bytes, content_type: str = "application/json") -> bool:
        """Write bytes. Returns True on success."""
        try:
            self._store.put(self.bucket, key, body, content_type=content_type)
            return True
        except Exception as e:
            log.error(f"object put failed [{key}]: {e}")
            return False

    def _exists(self, key: str) -> bool:
        try:
            return self._store.exists(self.bucket, key)
        except Exception:
            return False

    def dual_get(self, key: str, backup_bucket: str = "") -> bytes:
        """Primary then optional backup bucket."""
        try:
            return self._store.dual_get(self.bucket, key, backup_bucket=backup_bucket)
        except Exception as e:
            log.debug("dual_get failed [%s]: %s", key, e)
            return b""
