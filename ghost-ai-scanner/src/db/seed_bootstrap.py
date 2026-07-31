# =============================================================
# FILE: src/db/seed_bootstrap.py
# VERSION: 1.0.0
# UPDATED: 2026-07-31
# OWNER: Giggso Inc
# PURPOSE: Process-startup S3 -> policy-DB seed (moved out of the lazy,
#          per-Streamlit-session trigger in dashboard/ui/policy_context_
#          loader.py). Called once by main.py on every service/container
#          restart, so the policy DB is populated before any dashboard
#          session ever renders — not on whichever browser tab happens to
#          load first. No Streamlit dependency; pure boto3 + db.seeding.
#          policy_context_loader.py keeps a thin, session-gated fallback
#          call to the same function for standalone Streamlit-only dev
#          runs (RB_local-setup.md Mode A/B) that don't go through main.py.
# DEPENDS: boto3, db.engine, db.seeding
# =============================================================

import csv
import io
import json
import logging
import os

log = logging.getLogger("marauder-scan.db.seed_bootstrap")

_ALLOW       = ("config/authorized.csv", ["name", "domain_pattern", "notes"])
_ALLOW_CODE  = ("config/authorized_code.csv", ["name", "type", "pattern", "dept_scope", "notes"])
_DENY_CUSTOM = ("config/unauthorized_custom.csv", ["name", "category", "domain", "port", "severity", "notes"])
_DENY_CODE   = ("config/unauthorized_code_custom.csv", ["name", "type", "pattern", "severity", "notes"])


def _s3_csv_rows(key: str, cols: list) -> list:
    """Read a CSV from S3 into a list of dict rows. Empty list on any miss —
    seeding must never crash the boot sequence over a missing/absent file."""
    try:
        import boto3
        bucket = os.environ.get("MARAUDER_SCAN_BUCKET", "")
        region = os.environ.get("AWS_REGION", "us-east-1")
        raw = boto3.client("s3", region_name=region).get_object(
            Bucket=bucket, Key=key)["Body"].read().decode()
        body = "\n".join(ln for ln in raw.splitlines() if not ln.strip().startswith("#"))
        return list(csv.DictReader(io.StringIO(body))) if body.strip() else []
    except Exception as exc:
        log.debug("seed read %s skipped: %s", key, exc)
        return []


def _s3_users_json() -> dict:
    try:
        import boto3
        bucket = os.environ.get("MARAUDER_SCAN_BUCKET", "")
        region = os.environ.get("AWS_REGION", "us-east-1")
        body = boto3.client("s3", region_name=region).get_object(
            Bucket=bucket, Key="users/users.json")["Body"].read().decode()
        return json.loads(body)
    except Exception:
        return {}


def seed_policy_db_from_s3() -> dict | None:
    """Run the policy-DB seed once for this org, sourcing S3's allow/deny
    CSVs + users.json (the starter DENY content itself is read locally by
    db.seeding._starter_deny_rows(), not from S3 — ADR_2026-07-31).
    No-op (returns None) when DATABASE_URL isn't set. Best-effort: logs and
    returns None on failure rather than blocking startup."""
    if not os.environ.get("DATABASE_URL"):
        return None
    try:
        from db.engine import get_session, run_migrations
        from db.seeding import seed_all
        run_migrations()
        with get_session() as s:
            result = seed_all(
                s,
                org_slug=os.environ.get("COMPANY_SLUG", "dev"),
                org_name=os.environ.get("COMPANY_NAME", "PatronAI"),
                bucket=os.environ.get("MARAUDER_SCAN_BUCKET", ""),
                users_map=_s3_users_json(),
                allow_rows=_s3_csv_rows(*_ALLOW), allow_code_rows=_s3_csv_rows(*_ALLOW_CODE),
                deny_rows=_s3_csv_rows(*_DENY_CUSTOM), deny_code_rows=_s3_csv_rows(*_DENY_CODE),
            )
        log.info("[startup] policy DB seeded: %s", result)
        return result
    except Exception as exc:
        log.warning("[startup] policy DB seed skipped/failed: %s", exc)
        return None
