# =============================================================
# FILE: src/identity_resolver/source_oci_vnic.py
# VERSION: 1.0.0
# UPDATED: 2026-06-11
# OWNER: Ravi Venugopal, Giggso Inc
# PURPOSE: Resolve source IP to owner via OCI VNIC metadata.
#          OCI equivalent of source_ec2.py.
#          Looks up private IP in OCI Compute instance VNICs.
#          Requires OCI_COMPARTMENT_ID env var.
# DEPENDS: oci (OCI Python SDK) — optional, gracefully skipped if absent
# AUDIT LOG:
#   v1.0.0  2026-06-11  Initial — OCI VNIC resolver (replaces source_ec2.py)
# =============================================================

import logging
import os
from typing import Optional
from .sources import make_identity

log = logging.getLogger("marauder-scan.identity_resolver.oci_vnic")

_OCI_REGION       = os.environ.get("AWS_REGION", "us-chicago-1")  # boto3 var holds OCI region
_OCI_COMPARTMENT  = os.environ.get("OCI_COMPARTMENT_ID", "")


def resolve(ip: str, region: str = "") -> Optional[dict]:
    """
    Look up private IP in OCI Compute VNIC attachments.
    Returns identity dict if Owner tag found, else None.
    """
    region = region or _OCI_REGION

    try:
        import oci  # type: ignore
        config = oci.config.from_file()
        config["region"] = region

        compute = oci.core.ComputeClient(config)
        network = oci.core.VirtualNetworkClient(config)

        compartment_id = _OCI_COMPARTMENT or config.get("tenancy", "")
        if not compartment_id:
            log.debug("OCI_COMPARTMENT_ID not set — skipping VNIC lookup")
            return None

        # List all VNIC attachments in compartment
        vnic_attachments = oci.pagination.list_call_get_all_results(
            compute.list_vnic_attachments,
            compartment_id=compartment_id,
        ).data

        for attachment in vnic_attachments:
            if attachment.lifecycle_state != "ATTACHED":
                continue
            try:
                vnic = network.get_vnic(attachment.vnic_id).data
                if vnic.private_ip == ip:
                    # Get instance tags for owner resolution
                    instance = compute.get_instance(attachment.instance_id).data
                    tags  = instance.freeform_tags or {}
                    owner = tags.get("Owner") or tags.get("employee_id", "")
                    if not owner:
                        continue
                    return make_identity(
                        ip=ip,
                        source="oci_vnic",
                        owner=owner,
                        department=tags.get("Department", ""),
                        email=tags.get("Email", ""),
                        asset_type=instance.shape or "oci_compute",
                    )
            except Exception as e:
                log.debug(f"VNIC lookup error for attachment {attachment.id}: {e}")
                continue

    except ImportError:
        log.debug("OCI SDK not installed — VNIC lookup skipped")
    except Exception as e:
        log.debug(f"OCI VNIC lookup failed for {ip}: {e}")

    return None
