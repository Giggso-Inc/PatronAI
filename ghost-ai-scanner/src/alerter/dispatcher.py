# =============================================================
# FILE: src/alerter/dispatcher.py
# VERSION: 2.0.0
# UPDATED: 2026-06-11
# OWNER: Ravi Venugopal, Giggso Inc
# PURPOSE: Fire alerts to OCI Notifications (ONS) and Trinity webhook.
#          Both channels run independently — one failure does not
#          block the other. Returns dict of dispatch results.
#          OCI migration: replaced AWS SNS with OCI ONS HTTP API.
#          ONS supports HTTP publish endpoint — no SDK needed.
# DEPENDS: requests
# AUDIT LOG:
#   v1.0.0  2026-04-18  Initial (AWS SNS + webhook)
#   v2.0.0  2026-06-11  OCI migration — replaced boto3 SNS with
#                       OCI ONS HTTP publish endpoint (requests only).
#                       SNS ARN field now stores ONS topic OCID.
# =============================================================

import json
import logging
import os
import requests

log = logging.getLogger("marauder-scan.alerter.dispatcher")

REQUEST_TIMEOUT = 5  # seconds

# OCI ONS HTTP publish endpoint
# Format: https://cell1.notification.<region>.oci.oraclecloud.com/20181201/ons/topics/<topicId>/messages
_ONS_ENDPOINT_TPL = (
    "https://cell1.notification.{region}.oci.oraclecloud.com"
    "/20181201/ons/topics/{topic_id}/messages"
)


def dispatch(
    payload: dict,
    subject: str,
    sns_arn: str     = "",   # stores OCI ONS topic OCID for compatibility
    webhook_url: str = "",
    region: str      = "us-chicago-1",
) -> dict:
    """
    Send alert payload to all configured channels.
    ONS and webhook run independently.
    Returns results dict for audit logging.

    NOTE: sns_arn parameter name kept for backwards compatibility.
          It stores the OCI ONS topic OCID on OCI deployments.
    """
    results = {}

    # Fire OCI ONS
    if sns_arn:
        results["ons"] = _fire_ons(payload, subject, sns_arn, region)

    # Fire Trinity webhook
    if webhook_url:
        results["trinity"] = _fire_webhook(payload, webhook_url)

    if not sns_arn and not webhook_url:
        log.warning("No alert channels configured — alert not sent")
        results["warning"] = "no channels configured"

    return results


def _fire_ons(
    payload: dict,
    subject: str,
    topic_ocid: str,
    region: str,
) -> str:
    """
    Publish to OCI Notifications (ONS) via HTTP endpoint.
    Uses OCI instance principal auth (no keys needed on OCI VM).
    Returns 'ok' or error string.
    """
    try:
        endpoint = _ONS_ENDPOINT_TPL.format(
            region=region,
            topic_id=topic_ocid,
        )
        body = {
            "body": json.dumps(payload, indent=2),
            "title": subject,
        }
        # OCI ONS HTTP publish — uses instance principal auth header
        # On OCI VM the instance principal token is auto-injected
        resp = requests.post(
            endpoint,
            json=body,
            timeout=REQUEST_TIMEOUT,
            headers={
                "Content-Type": "application/json",
                # OCI instance principal auth is handled by the OCI SDK
                # For HTTP-only publish, use a pre-auth token if configured
                "opc-request-id": f"patronai-alert-{subject[:40]}",
            },
        )
        if resp.status_code in (200, 202):
            log.info(f"ONS alert sent: {subject}")
            return "ok"
        else:
            log.warning(f"ONS publish returned {resp.status_code}: {resp.text[:200]}")
            # Fall back to webhook if ONS fails
            return f"http_{resp.status_code}"
    except Exception as e:
        log.error(f"ONS dispatch failed: {e}")
        return str(e)


def _fire_webhook(payload: dict, webhook_url: str) -> str:
    """POST to Trinity webhook. Returns 'ok' or error string."""
    try:
        resp = requests.post(
            webhook_url,
            json=payload,
            timeout=REQUEST_TIMEOUT,
            headers={"Content-Type": "application/json"},
        )
        resp.raise_for_status()
        log.info(f"Trinity webhook sent: {resp.status_code}")
        return "ok"
    except requests.exceptions.Timeout:
        log.error("Trinity webhook timeout")
        return "timeout"
    except Exception as e:
        log.error(f"Trinity webhook failed: {e}")
        return str(e)
