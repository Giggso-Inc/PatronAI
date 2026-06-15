#!/usr/bin/env bash
# =============================================================
# FILE: scripts/setup_hook_agents.sh
# VERSION: 2.0.0
# UPDATED: 2026-06-11
# OWNER: Giggso Inc
# PURPOSE: One-time post-deploy provisioning for agent delivery on OCI.
#          Creates config/HOOK_AGENTS/ prefix in OCI Object Storage.
#          Validates OCI Object Storage write permissions.
#          Verifies OCI Email Delivery SMTP credentials.
#          OCI migration: replaced AWS IAM/SES/S3 CLI with
#          OCI CLI + boto3 S3-compat + smtplib check.
# USAGE: bash scripts/setup_hook_agents.sh
# REQUIRES: MARAUDER_SCAN_BUCKET + S3_ENDPOINT_URL + AWS_REGION env vars
# AUDIT LOG:
#   v1.0.0  2026-04-19  Initial (AWS IAM/SES/S3)
#   v1.1.0  2026-04-19  S3 prefix agents/ → config/HOOK_AGENTS/
#   v1.2.0  2026-04-19  Auto-detect EC2 instance role
#   v1.3.0  2026-04-20  IAM Access Analyzer validate-policy
#   v2.0.0  2026-06-11  OCI migration — replaced AWS CLI with
#                       OCI CLI + boto3 S3-compat. Removed IAM/SES.
#                       Added OCI Email Delivery SMTP check.
# =============================================================
set -euo pipefail

BUCKET="${MARAUDER_SCAN_BUCKET:-}"
REGION="${AWS_REGION:-us-chicago-1}"
S3_ENDPOINT="${S3_ENDPOINT_URL:-}"

[ -n "$BUCKET" ] || { echo "ERROR: MARAUDER_SCAN_BUCKET is not set." >&2; exit 1; }
[ -n "$S3_ENDPOINT" ] || { echo "ERROR: S3_ENDPOINT_URL is not set." >&2; exit 1; }

echo "PatronAI — Agent Delivery Setup (OCI)"
echo "Bucket    : $BUCKET"
echo "Region    : $REGION"
echo "Endpoint  : $S3_ENDPOINT"
echo ""

# ── Check OCI Object Storage access ──────────────────────────
echo "Checking OCI Object Storage access..."
python3 -c "
import boto3, os
try:
    s3 = boto3.client('s3',
        endpoint_url='${S3_ENDPOINT}',
        region_name='${REGION}')
    s3.head_bucket(Bucket='${BUCKET}')
    print('  OCI Object Storage accessible.')
except Exception as e:
    print(f'  ERROR: {e}')
    exit(1)
" || { echo "ERROR: Cannot access oci://$BUCKET/" >&2; exit 1; }

# ── Establish config/HOOK_AGENTS/ prefix ─────────────────────
HOOK_PREFIX="config/HOOK_AGENTS"
echo ""
echo "Establishing oci://$BUCKET/$HOOK_PREFIX/ prefix..."
python3 -c "
import boto3
s3 = boto3.client('s3',
    endpoint_url='${S3_ENDPOINT}',
    region_name='${REGION}')
s3.put_object(Bucket='${BUCKET}', Key='${HOOK_PREFIX}/.keep', Body=b'')
print('  Prefix marker created.')
"

# ── Bootstrap catalog if missing ─────────────────────────────
CATALOG_KEY="$HOOK_PREFIX/catalog.json"
echo "Checking catalog at oci://$BUCKET/$CATALOG_KEY..."
python3 -c "
import boto3, json
s3 = boto3.client('s3',
    endpoint_url='${S3_ENDPOINT}',
    region_name='${REGION}')
try:
    s3.head_object(Bucket='${BUCKET}', Key='${CATALOG_KEY}')
    print('  Catalog already exists.')
except Exception:
    s3.put_object(
        Bucket='${BUCKET}',
        Key='${CATALOG_KEY}',
        Body=json.dumps([]).encode(),
        ContentType='application/json')
    print('  Catalog created.')
"

# ── Validate HOOK_AGENTS write permission ─────────────────────
echo ""
echo "Validating config/HOOK_AGENTS write permissions..."
python3 -c "
import boto3
s3 = boto3.client('s3',
    endpoint_url='${S3_ENDPOINT}',
    region_name='${REGION}')
try:
    s3.put_object(Bucket='${BUCKET}', Key='${HOOK_PREFIX}/.iam-test', Body=b'test')
    s3.delete_object(Bucket='${BUCKET}', Key='${HOOK_PREFIX}/.iam-test')
    print('  HOOK_AGENTS write permission verified.')
except Exception as e:
    print(f'  ERROR: Cannot write to ${HOOK_PREFIX}/ — {e}')
    exit(1)
"

# ── Verify OCI Email Delivery SMTP credentials ────────────────
echo ""
echo "Checking OCI Email Delivery SMTP credentials..."
SMTP_USER="${OCI_EMAIL_SMTP_USER:-}"
SMTP_PASS="${OCI_EMAIL_SMTP_PASSWORD:-}"
if [ -n "$SMTP_USER" ] && [ -n "$SMTP_PASS" ]; then
    python3 -c "
import smtplib
try:
    smtp_host = 'smtp.email.${REGION}.oci.oraclecloud.com'
    with smtplib.SMTP(smtp_host, 587) as smtp:
        smtp.ehlo()
        smtp.starttls()
        smtp.login('${SMTP_USER}', '${SMTP_PASS}')
    print('  OCI Email Delivery SMTP credentials valid.')
except smtplib.SMTPAuthenticationError:
    print('  WARNING: SMTP auth failed — check OCI_EMAIL_SMTP_USER and OCI_EMAIL_SMTP_PASSWORD')
except Exception as e:
    print(f'  WARNING: SMTP check failed — {e}')
"
else
    echo "  OCI_EMAIL_SMTP_USER / OCI_EMAIL_SMTP_PASSWORD not set — email delivery will be disabled."
    echo "  Generate SMTP credentials: OCI Console → Email Delivery → SMTP Credentials"
fi

echo ""
echo "Setup complete. Agent delivery system ready."
echo "Open the PatronAI dashboard → Settings → Deploy Agents to generate packages."
