#!/usr/bin/env python3
# =============================================================
# FILE: scripts/refresh_vnic_cache.py
# VERSION: 1.0.0
# UPDATED: 2026-06-11
# OWNER: Giggso Inc
# PURPOSE: Fetch all VNIC metadata from OCI Compute and write to
#          oci://{BUCKET}/cache/vnic_metadata.json (OCI Object Storage).
#          Called inline by flow_log.py every 6h (cache TTL).
#          Also runnable standalone for manual refresh:
#            python scripts/refresh_vnic_cache.py
#          Requires: MARAUDER_SCAN_BUCKET + S3_ENDPOINT_URL env vars.
#          OCI migration: replaces refresh_eni_cache.py (EC2 → OCI VNIC)
# AUDIT LOG:
#   v1.0.0  2026-06-11  Initial — OCI VNIC paginated fetch, S3-compat write
# =============================================================

import json
import logging
import os
import sys
from datetime import datetime, timezone

import boto3

log = logging.getLogger("marauder-scan.refresh_vnic_cache")
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s")

BUCKET       = os.environ.get("MARAUDER_SCAN_BUCKET", "")
REGION       = os.environ.get("AWS_REGION", "us-chicago-1")  # boto3 var holds OCI region
S3_ENDPOINT  = os.environ.get("S3_ENDPOINT_URL", "")
COMPARTMENT  = os.environ.get("OCI_COMPARTMENT_ID", "")
CACHE_KEY    = "cache/vnic_metadata.json"

_KEEP_FIELDS = {
    "NetworkInterfaceId", "Description", "InterfaceType",
    "RequesterManaged", "RequesterId", "OwnerId", "Status",
}


def fetch_vnic_metadata() -> dict:
    """
    Fetch all VNIC metadata from OCI Compute via OCI SDK.
    Falls back to empty dict if OCI SDK not installed.
    Returns dict keyed by VNIC ID with metadata fields.
    """
    results: dict = {}

    try:
        import oci  # type: ignore
        config = oci.config.from_file()
        config["region"] = REGION

        compute = oci.core.ComputeClient(config)
        network = oci.core.VirtualNetworkClient(config)

        compartment_id = COMPARTMENT or config.get("tenancy", "")
        if not compartment_id:
            log.error("OCI_COMPARTMENT_ID not set — cannot fetch VNIC metadata")
            return {}

        # Paginate through all VNIC attachments
        vnic_attachments = oci.pagination.list_call_get_all_results(
            compute.list_vnic_attachments,
            compartment_id=compartment_id,
        ).data

        for attachment in vnic_attachments:
            if attachment.lifecycle_state != "ATTACHED":
                continue
            try:
                vnic = network.get_vnic(attachment.vnic_id).data
                vnic_id = vnic.id
                # Normalize to ENI-compatible field names for filter compatibility
                results[vnic_id] = {
                    "NetworkInterfaceId": vnic_id,
                    "Description":        vnic.display_name or "",
                    "InterfaceType":      _map_vnic_type(vnic),
                    "RequesterManaged":   not vnic.is_primary if hasattr(vnic, "is_primary") else False,
                    "RequesterId":        "",
                    "OwnerId":            compartment_id,
                    "Status":             vnic.lifecycle_state,
                    "private_ip":         vnic.private_ip or "",
                }
            except Exception as e:
                log.debug(f"VNIC fetch error: {e}")

        log.info(f"Fetched metadata for {len(results)} VNICs")

    except ImportError:
        log.warning("OCI SDK not installed — generating empty VNIC cache")
    except Exception as e:
        log.error(f"OCI VNIC fetch failed: {e}")

    return results


def _map_vnic_type(vnic) -> str:
    """Map OCI VNIC characteristics to ENI-compatible interface types."""
    name = (getattr(vnic, "display_name", "") or "").lower()
    if "nat" in name:
        return "nat_gateway"
    if "service" in name or "sgw" in name:
        return "vpc_endpoint"   # OCI Service Gateway
    if "lb" in name or "load" in name:
        return "load_balancer"
    return "interface"


def write_cache(data: dict) -> bool:
    """Write VNIC metadata to OCI Object Storage via S3-compat endpoint."""
    payload = {
        "_meta": {
            "fetched_at":  datetime.now(timezone.utc).isoformat(),
            "compartment": COMPARTMENT,
            "vnic_count":  len(data),
            "region":      REGION,
        },
        "vnics": data,
        "enis":  data,  # backwards compat key for eni_filter.py
    }
    try:
        s3_kwargs = {"region_name": REGION}
        if S3_ENDPOINT:
            s3_kwargs["endpoint_url"] = S3_ENDPOINT
        s3 = boto3.client("s3", **s3_kwargs)
        s3.put_object(
            Bucket=BUCKET,
            Key=CACHE_KEY,
            Body=json.dumps(payload, indent=2).encode("utf-8"),
            ContentType="application/json",
        )
        log.info(f"VNIC cache written → oci://{BUCKET}/{CACHE_KEY} ({len(data)} VNICs)")
        return True
    except Exception as e:
        log.error(f"Object Storage write failed [{CACHE_KEY}]: {e}")
        return False


def run() -> bool:
    if not BUCKET:
        log.error("MARAUDER_SCAN_BUCKET not set — cannot write cache")
        return False
    vnic_data = fetch_vnic_metadata()
    return write_cache(vnic_data)


if __name__ == "__main__":
    ok = run()
    sys.exit(0 if ok else 1)
