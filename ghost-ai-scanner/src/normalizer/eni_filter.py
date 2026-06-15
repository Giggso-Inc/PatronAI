# =============================================================
# FILE: src/normalizer/eni_filter.py
# VERSION: 2.0.0
# UPDATED: 2026-06-11
# OWNER: Giggso Inc
# PURPOSE: OCI VNIC denylist filter for VCN Flow Log normalisation.
#          OCI migration: replaced AWS ENI metadata (EC2 API) with
#          OCI VNIC metadata (OCI Core API).
#          Loads VNIC type patterns from config/eni_denylist.yaml.
#          Cache miss = fail open (never drop unclassified flows).
#          Filter counts logged as vnic_filtered_total{reason=...}
# DEPENDS: pyyaml, boto3 (for S3 cache read), oci SDK (optional)
# AUDIT LOG:
#   v1.0.0  2026-04-19  Initial (AWS ENI filter)
#   v1.0.1  2026-04-19  Fix: load_eni_cache stored full JSON obj
#   v2.0.0  2026-06-11  OCI migration — replaced EC2 ENI metadata
#                       with OCI VNIC metadata. Cache still stored
#                       in OCI Object Storage (S3-compat). Filter
#                       logic unchanged — same 5 rule types mapped
#                       to OCI VNIC equivalents.
# =============================================================

import json
import logging
import os
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Optional

import boto3
import yaml

log = logging.getLogger("marauder-scan.normalizer.vnic_filter")

_vnic_cache:       dict               = {}
_cache_loaded_at:  Optional[datetime] = None
_CACHE_TTL_HOURS   = 6
_CACHE_S3_KEY      = "cache/vnic_metadata.json"  # OCI Object Storage key

# Prometheus-compatible filter counter
eni_filtered_total: Counter = Counter()  # name kept for backwards compat


def load_eni_patterns(path: str) -> dict:
    """
    Load VNIC denylist rules from YAML file.
    Returns dict keyed by rule name.
    Returns empty dict on failure — caller treats as pass-through (fail open).
    """
    try:
        with open(path, "r") as fh:
            data = yaml.safe_load(fh)
        rules = data.get("rules", {})
        log.info(f"VNIC denylist loaded: {len(rules)} rules from {path}")
        return rules
    except Exception as e:
        log.error(f"Failed to load VNIC denylist [{path}]: {e}")
        return {}


def load_eni_cache(bucket: str, region: str = "us-chicago-1") -> None:
    """
    Pull cache/vnic_metadata.json from OCI Object Storage into module-level cache.
    Uses boto3 S3-compat with S3_ENDPOINT_URL for OCI Object Storage.
    Called at startup and every _CACHE_TTL_HOURS hours.
    Fails silently — stale or missing cache means fail-open filtering.
    """
    global _vnic_cache, _cache_loaded_at
    try:
        endpoint = os.environ.get("S3_ENDPOINT_URL", "")
        s3_kwargs = {"region_name": region}
        if endpoint:
            s3_kwargs["endpoint_url"] = endpoint
        s3   = boto3.client("s3", **s3_kwargs)
        resp = s3.get_object(Bucket=bucket, Key=_CACHE_S3_KEY)
        data = json.loads(resp["Body"].read().decode("utf-8"))
        _vnic_cache      = data.get("vnics", data.get("enis", {}))  # support both key names
        _cache_loaded_at = datetime.now(timezone.utc)
        log.info(f"VNIC metadata cache loaded: {len(_vnic_cache)} VNICs from oci://{bucket}/{_CACHE_S3_KEY}")
    except Exception as e:
        log.warning(f"VNIC cache load failed — fail-open mode active: {e}")


def cache_is_stale() -> bool:
    """Return True if cache has never loaded or is older than TTL."""
    if _cache_loaded_at is None:
        return True
    return datetime.now(timezone.utc) - _cache_loaded_at > timedelta(hours=_CACHE_TTL_HOURS)


def enrich_with_metadata(vnic_id: str) -> dict:
    """
    Look up VNIC ID in module-level cache.
    Returns metadata dict on hit, empty dict on miss (fail open).
    """
    return _vnic_cache.get(vnic_id, {})


def is_denied_eni(eni_meta: dict, patterns: dict, account_id: str = "") -> tuple:
    """
    Check VNIC metadata against denylist rule types.
    Returns (True, reason_str) if denied, (False, "") if allowed.
    Empty eni_meta (cache miss) → always returns (False, "") — fail open.
    Increments eni_filtered_total[reason] counter on every denial.

    OCI VNIC equivalents to AWS ENI types:
      efs     → OCI File Storage mount target VNIC
      nat     → OCI NAT Gateway VNIC
      vpce    → OCI Service Gateway VNIC
      elb     → OCI Load Balancer VNIC
      lambda  → OCI Functions VNIC
    """
    if not eni_meta:
        return False, ""

    desc       = eni_meta.get("Description", "") or eni_meta.get("display_name", "")
    iface_type = eni_meta.get("InterfaceType", "") or eni_meta.get("vnic_type", "")
    req_id     = eni_meta.get("RequesterId", "") or eni_meta.get("requester_id", "")
    owner_id   = eni_meta.get("OwnerId", "") or eni_meta.get("owner_id", "")
    req_managed = eni_meta.get("RequesterManaged", False) or eni_meta.get("is_managed", False)

    # Rule 1: File Storage (OCI equivalent of EFS)
    efs = patterns.get("efs", {})
    if desc.startswith(efs.get("description_prefix", "\x00")) or \
            req_id == efs.get("requester_id", ""):
        eni_filtered_total["efs"] += 1
        return True, "efs"

    # Rule 2: NAT Gateway VNIC
    if iface_type == patterns.get("nat", {}).get("interface_type", "\x00"):
        eni_filtered_total["nat"] += 1
        return True, "nat"

    # Rule 3: Service Gateway (OCI equivalent of VPC Endpoint)
    if iface_type == patterns.get("vpce", {}).get("interface_type", "\x00"):
        eni_filtered_total["vpce"] += 1
        return True, "vpce"

    # Rule 4: Load Balancer VNIC
    if desc.startswith(patterns.get("elb", {}).get("description_prefix", "\x00")):
        eni_filtered_total["elb"] += 1
        return True, "elb"

    # Rule 5: OCI Functions VNIC (equivalent of Lambda)
    if desc.startswith(patterns.get("lambda", {}).get("description_prefix", "\x00")):
        eni_filtered_total["lambda"] += 1
        return True, "lambda"

    # Drop any OCI-managed VNIC not owned by this tenancy
    if req_managed and account_id and owner_id != account_id:
        eni_filtered_total["managed_foreign"] += 1
        return True, "managed_foreign"

    return False, ""
