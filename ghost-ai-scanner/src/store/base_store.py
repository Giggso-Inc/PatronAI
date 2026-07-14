# =============================================================
# FILE: src/store/base_store.py
# VERSION: 1.1.0
# UPDATED: 2026-05-01
# PURPOSE: Shared base class for all store modules.
#          Initialises boto3 S3 client and bucket reference once.
#          Every store inherits this — no repeated setup code.
# OWNER: Ravi Venugopal, Giggso Inc
# DEPENDS: boto3
# AUDIT LOG:
#   v1.0.0  2026-04-18  Initial.
#   v1.1.0  2026-05-01  Force SigV4 (signature_version='s3v4') on every
#                       store's S3 client. boto3 may default to deprecated
#                       SigV2 in some configs; SigV2 only works for
#                       us-east-1 buckets, fails under SSE-KMS, and is
#                       being phased out by AWS. Fixes presigned-URL
#                       SignatureDoesNotMatch errors on agent DMG/EXE
#                       downloads.
# =============================================================

import os
import logging
import boto3
from botocore.config import Config

log = logging.getLogger("marauder-scan.store")

# A custom endpoint (AWS_ENDPOINT_URL) means we are talking to LocalStack /
# another S3-compatible mock in dev, not real AWS. botocore auto-detects this
# env var; we mirror that detection here to pick safe per-environment defaults.
_CUSTOM_ENDPOINT = os.environ.get("AWS_ENDPOINT_URL", "").strip()


def _build_s3_config() -> Config:
    """Shared S3 client config. SigV4 everywhere so presigned URLs sign
    correctly (see audit log v1.1.0).

    Production (real AWS): virtual-hosted addressing + botocore's default
    flexible checksums.

    Dev (AWS_ENDPOINT_URL set → LocalStack): path-style addressing is
    REQUIRED — bucket-as-subdomain (marauder-scan-demo.localhost) does not
    resolve against localhost. Checksum calculation is forced to
    "when_required" because LocalStack 3.4's S3 provider cannot parse the
    CRC32/CRC64NVME trailers botocore >=1.36 attaches by default and dies with
    "'NoneType' object has no attribute 'to_bytes'".
    """
    if _CUSTOM_ENDPOINT:
        return Config(
            signature_version="s3v4",
            s3={"addressing_style": "path"},
            request_checksum_calculation="when_required",
            response_checksum_validation="when_required",
            retries={"max_attempts": 3, "mode": "standard"},
        )
    return Config(
        signature_version="s3v4",
        s3={"addressing_style": "virtual"},
        retries={"max_attempts": 3, "mode": "standard"},
    )


# All S3 clients share this config so presigned URLs are SigV4-signed.
_S3_CLIENT_CONFIG = _build_s3_config()


class BaseStore:
    """
    Parent class for all store modules.
    Holds the S3 client and bucket name.
    Inherit this — get S3 for free.
    """

    def __init__(self, bucket: str, region: str = "us-east-1"):
        # Single S3 client shared across all methods in the subclass.
        # SigV4 forced via _S3_CLIENT_CONFIG (see module docstring).
        self.bucket = bucket
        self.s3 = boto3.client("s3", region_name=region,
                                config=_S3_CLIENT_CONFIG)
        self.region = region

    def _get(self, key: str) -> bytes:
        """Fetch raw bytes from S3. Returns empty bytes if key not found."""
        try:
            resp = self.s3.get_object(Bucket=self.bucket, Key=key)
            return resp["Body"].read()
        except self.s3.exceptions.NoSuchKey:
            return b""
        except Exception as e:
            log.error(f"S3 get failed [{key}]: {e}")
            return b""

    def _put(self, key: str, body: bytes, content_type: str = "application/json") -> bool:
        """Write bytes to S3. Returns True on success."""
        try:
            self.s3.put_object(
                Bucket=self.bucket,
                Key=key,
                Body=body,
                ContentType=content_type,
            )
            return True
        except Exception as e:
            log.error(f"S3 put failed [{key}]: {e}")
            return False

    def _exists(self, key: str) -> bool:
        """Check if a key exists in S3 without downloading it."""
        try:
            self.s3.head_object(Bucket=self.bucket, Key=key)
            return True
        except Exception:
            return False
