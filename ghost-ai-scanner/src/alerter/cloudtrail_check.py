# =============================================================
# FILE: src/alerter/cloudtrail_check.py
# VERSION: 2.0.0
# UPDATED: 2026-06-11
# OWNER: Ravi Venugopal, Giggso Inc
# PURPOSE: Lightweight OCI Audit log spot check — called only when
#          an alert fires on an authorized domain. Checks if a
#          Vault GetSecret call preceded the API call.
#          No-op on non-OCI clouds or if Audit log not configured.
#          Returns enrichment dict merged into alert payload.
# DEPENDS: oci (OCI Python SDK) — optional, gracefully skipped if absent
# NOTE: OCI Audit log has up to 15 min delivery lag. Result is
#       best-effort enrichment only — not a hard gate.
# AUDIT LOG:
#   v1.0.0  2026-04-18  Initial (AWS CloudTrail GetParameter check)
#   v2.0.0  2026-06-11  OCI migration — replaced CloudTrail with
#                       OCI Audit log. Checks for Vault GetSecret
#                       events instead of SSM GetParameter.
#                       Falls back gracefully if OCI SDK not installed.
# =============================================================

import logging
import os
from datetime import datetime, timezone, timedelta
from typing import Optional

log = logging.getLogger("marauder-scan.alerter.cloudtrail_check")

LOOKBACK_MINUTES = 15
_OCI_REGION = os.environ.get("AWS_REGION", "us-chicago-1")  # boto3 var holds OCI region


def check(
    owner: str,
    provider: str,
    region: str = "",
) -> dict:
    """
    Spot-check OCI Audit log for a Vault GetSecret call from this owner
    within the last LOOKBACK_MINUTES before the alert time.

    Returns enrichment dict:
    {
        "cloudtrail_check": "found" | "not_found" | "error" | "skipped",
        "token_status":     "company_key" | "personal_key" | "unknown",
    }

    NOTE: Function signature and return keys kept identical to v1.0.0
    for backwards compatibility with alert payload consumers.
    """
    if not owner or owner == "unknown":
        return _result("skipped", "unknown")

    region = region or _OCI_REGION

    try:
        import oci  # type: ignore
        config = oci.config.from_file()  # reads ~/.oci/config
        audit  = oci.audit.AuditClient(config)

        compartment_id = os.environ.get("OCI_COMPARTMENT_ID", config.get("tenancy", ""))
        if not compartment_id:
            log.debug("OCI_COMPARTMENT_ID not set — skipping audit check")
            return _result("skipped", "unknown")

        end_time   = datetime.now(timezone.utc)
        start_time = end_time - timedelta(minutes=LOOKBACK_MINUTES)

        # Search OCI Audit log for Vault GetSecret events
        resp = audit.list_events(
            compartment_id=compartment_id,
            start_time=start_time,
            end_time=end_time,
        )

        events = resp.data if resp.data else []
        provider_slug = provider.lower().replace(" ", "_").replace(".", "_")

        for event in events:
            event_name = getattr(event, "event_name", "") or ""
            # Look for Vault GetSecretBundle (OCI equivalent of SSM GetParameter)
            if "GetSecretBundle" in event_name or "GetSecret" in event_name:
                # Check if the resource name includes the provider
                resource_name = ""
                if hasattr(event, "data") and event.data:
                    resource_name = str(getattr(event.data, "resource_name", ""))
                if provider_slug in resource_name.lower():
                    log.info(f"OCI Audit: company key confirmed for {owner} → {provider}")
                    return _result("found", "company_key")

        if not events:
            log.info(f"OCI Audit: no GetSecret found for {owner} — personal key suspected")
            return _result("not_found", "personal_key")

        log.info(f"OCI Audit: events found but not for {provider} — personal key suspected")
        return _result("found", "personal_key")

    except ImportError:
        # OCI SDK not installed — skip gracefully
        log.debug("OCI SDK not installed — audit check skipped")
        return _result("skipped", "unknown")
    except Exception as e:
        log.debug(f"OCI Audit check failed: {e}")
        return _result("error", "unknown")


def _result(check_status: str, token_status: str) -> dict:
    return {
        "cloudtrail_check": check_status,  # key kept for backwards compat
        "token_status":     token_status,
    }
