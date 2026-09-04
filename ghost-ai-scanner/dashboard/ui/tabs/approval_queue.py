# =============================================================
# FILE: dashboard/ui/tabs/approval_queue.py
# VERSION: 1.0.0
# UPDATED: 2026-09-04
# OWNER: Giggso Inc (Ravi Venugopal)
# PURPOSE: Approval Queue — surfaces greylist findings from the last
#          7 days for admin review. Admin can promote a domain to the
#          whitelist (authorized_custom.csv), demote to blacklist
#          (unauthorized_custom.csv), or keep monitoring.
#          Admin-only. No auto-promotion. S3 pattern follows
#          discovered_panel.py.
# DEPENDS: streamlit, boto3 (via object_store), store.object_store
# AUDIT LOG:
#   v1.0.0  2026-09-04  Initial. Three-tier list — greylist approval flow.
# =============================================================

import json
import logging
import os
from collections import Counter
from datetime import datetime, timedelta, timezone

import pandas as pd
import streamlit as st

from store.object_store import boto3_s3_client
from .. import audit as _audit

log    = logging.getLogger("patronai.ui.approval_queue")
BUCKET = os.environ.get("MARAUDER_SCAN_BUCKET", "")

ALLOW_CUSTOM_KEY = "config/authorized_custom.csv"
DENY_CUSTOM_KEY  = "config/unauthorized_custom.csv"
DISMISSED_KEY    = "config/greylist_dismissed.txt"


def render(is_admin: bool, email: str = "") -> None:
    """Greylist Approval Queue — admin review page."""
    st.markdown("**🟡 Greylist — Approval Queue**")
    st.caption(
        "Domains observed in the last 7 days that matched your greylist. "
        "Ranked by hit count. Promote to Whitelist (no more alerts) or "
        "Blacklist (always blocked). Keep Monitoring leaves them in the queue."
    )
    if not is_admin:
        st.info("Admin access required to manage the approval queue.")
        return

    rows = _aggregate_greylist()
    dismissed = _load_dismissed()
    rows = [r for r in rows if r["domain"] not in dismissed]

    if not rows:
        st.success("✅ No pending greylist domains in the last 7 days.")
        return

    df = pd.DataFrame(rows)
    st.dataframe(df, use_container_width=True, hide_index=True)

    options = [r["domain"] for r in rows]
    picked = st.multiselect("Select domain(s) to act on", options,
                            key="aq::picked")
    c1, c2, c3, _ = st.columns([1, 1, 1, 3])
    if c1.button("✅ Approve → Whitelist", type="primary",
                 key="aq::approve") and picked:
        _promote_to_whitelist(picked, email)
        st.rerun()
    if c2.button("🚫 Deny → Blacklist", key="aq::deny") and picked:
        _demote_to_blacklist(picked, email)
        st.rerun()
    if c3.button("👁 Keep monitoring", key="aq::keep") and picked:
        _persist_dismissed(dismissed | set(picked), email)
        st.rerun()


def _aggregate_greylist() -> list:
    """Walk last-7-days findings; return greylist hits ranked by count."""
    s3 = boto3_s3_client()
    counters: Counter = Counter()
    last_seen: dict   = {}
    sample_dev: dict  = {}
    peak_rate: dict   = {}
    owner_map: dict   = {}
    today = datetime.now(timezone.utc).date()
    paginator = s3.get_paginator("list_objects_v2")
    for offset in range(7):
        d = today - timedelta(days=offset)
        prefix = f"ocsf/findings/{d.year}/{d.month:02d}/{d.day:02d}/"
        try:
            for page in paginator.paginate(Bucket=BUCKET, Prefix=prefix):
                for obj in page.get("Contents", []):
                    _ingest(s3, obj["Key"], counters, last_seen,
                            sample_dev, peak_rate, owner_map)
        except Exception as exc:
            log.debug("findings list %s failed: %s", prefix, exc)
    return [
        {"domain": dom, "hits": cnt,
         "peak_calls/10m": round(peak_rate.get(dom, 0), 1),
         "owner": owner_map.get(dom, ""),
         "last_seen": last_seen.get(dom, ""),
         "sample_device": sample_dev.get(dom, "")}
        for dom, cnt in counters.most_common(100)
    ]


def _ingest(s3, key: str, counters: Counter, last_seen: dict,
            sample_dev: dict, peak_rate: dict, owner_map: dict) -> None:
    try:
        body = s3.get_object(Bucket=BUCKET, Key=key)["Body"].read()
        payload = json.loads(body)
    except Exception:
        return
    if payload.get("outcome") != "GREYLIST":
        return
    domain = (payload.get("dst_domain") or payload.get("domain") or "").lower().strip()
    if not domain:
        return
    counters[domain] += 1
    ts = payload.get("timestamp") or payload.get("time", "")
    if ts and (domain not in last_seen or ts > last_seen[domain]):
        last_seen[domain] = ts
    sample_dev.setdefault(domain, payload.get("device_id", "")
                          or payload.get("src_ip", ""))
    owner_map.setdefault(domain, payload.get("owner", "")
                         or payload.get("email", ""))
    rate = payload.get("calls_per_10_min") or 0
    if rate and rate > peak_rate.get(domain, 0):
        peak_rate[domain] = rate


def _load_dismissed() -> set:
    try:
        s3 = boto3_s3_client()
        body = s3.get_object(Bucket=BUCKET, Key=DISMISSED_KEY)["Body"].read().decode()
        return {ln.strip() for ln in body.splitlines()
                if ln.strip() and not ln.startswith("#")}
    except Exception:
        return set()


def _persist_dismissed(domains: set, email: str) -> None:
    body = "# Dismissed from greylist approval queue\n" + "\n".join(sorted(domains)) + "\n"
    try:
        boto3_s3_client().put_object(
            Bucket=BUCKET, Key=DISMISSED_KEY,
            Body=body.encode(), ContentType="text/plain",
        )
        _audit.write(email, "greylist.dismissed", "", str(len(domains)))
        st.info(f"Kept {len(domains)} domain(s) in monitoring — hidden from queue for now.")
    except Exception as exc:
        log.error("greylist dismissed save failed: %s", exc)
        st.error(f"Save failed: {exc}")


def _promote_to_whitelist(domains: list, email: str) -> None:
    s3 = boto3_s3_client()
    try:
        existing = s3.get_object(Bucket=BUCKET, Key=ALLOW_CUSTOM_KEY)["Body"].read().decode()
    except Exception:
        existing = "name,domain_pattern,notes\n"
    if not existing.endswith("\n"):
        existing += "\n"
    for d in domains:
        existing += f"Approved {d},*{d}*,Promoted from greylist approval queue\n"
    try:
        s3.put_object(Bucket=BUCKET, Key=ALLOW_CUSTOM_KEY,
                      Body=existing.encode(), ContentType="text/csv")
        _audit.write(email, "greylist.approved", "", ", ".join(domains))
        st.success(f"✅ Approved {len(domains)} domain(s) → added to Whitelist.")
    except Exception as exc:
        log.error("whitelist promote failed: %s", exc)
        st.error(f"Promote failed: {exc}")


def _demote_to_blacklist(domains: list, email: str) -> None:
    s3 = boto3_s3_client()
    try:
        existing = s3.get_object(Bucket=BUCKET, Key=DENY_CUSTOM_KEY)["Body"].read().decode()
    except Exception:
        existing = "name,category,domain,port,severity,notes\n"
    if not existing.endswith("\n"):
        existing += "\n"
    for d in domains:
        existing += f"Denied {d},Greylist Denied,{d},443,HIGH,Denied from greylist approval queue\n"
    try:
        s3.put_object(Bucket=BUCKET, Key=DENY_CUSTOM_KEY,
                      Body=existing.encode(), ContentType="text/csv")
        _audit.write(email, "greylist.denied", "", ", ".join(domains))
        st.success(f"🚫 Denied {len(domains)} domain(s) → added to Blacklist.")
    except Exception as exc:
        log.error("blacklist demote failed: %s", exc)
        st.error(f"Deny failed: {exc}")
