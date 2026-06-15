# =============================================================
# FILE: src/identity_resolver/source_ec2.py
# VERSION: 2.0.0
# UPDATED: 2026-06-11
# OWNER: Ravi Venugopal, Giggso Inc
# PURPOSE: OCI migration shim — delegates to source_oci_vnic.py.
#          File kept to avoid import errors in existing callers.
#          On OCI, EC2 instance tags are replaced by OCI VNIC
#          freeform tags (Owner, Department, Email).
# AUDIT LOG:
#   v1.0.0  2026-04-18  Initial (AWS EC2 describe_instances)
#   v2.0.0  2026-06-11  OCI migration — delegates to source_oci_vnic.py
# =============================================================

import logging
from typing import Optional
from .source_oci_vnic import resolve as _oci_resolve

log = logging.getLogger("marauder-scan.identity_resolver.ec2")


def resolve(ip: str, region: str = "us-chicago-1") -> Optional[dict]:
    """
    Resolve IP to identity via OCI VNIC tags.
    Delegates to source_oci_vnic.resolve() — kept for backwards compat.
    """
    return _oci_resolve(ip, region)
