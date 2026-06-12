#!/usr/bin/env bash
# =============================================================
# FILE: scripts/setup.sh
# VERSION: 2.1.0
# UPDATED: 2026-06-11
# OWNER: Giggso Inc
# PURPOSE: OCI setup — validates OCI CLI, bucket, credentials,
#          seeds S3-compat config files, generates .env.
#          Run once on the OCI VM before docker compose up.
#          Replaces AWS setup.sh for OCI deployments.
# USAGE:   bash scripts/setup.sh
# REQUIRES: OCI CLI configured, docker, docker-compose
# AUDIT LOG:
#   v1.0.0  2026-04-19  Initial (AWS).
#   v2.0.0  2026-06-11  OCI migration — replaced AWS CLI calls
#   v2.1.0  2026-06-11  Region default updated ap-mumbai-1 → us-chicago-1.
#                       with OCI CLI + S3-compat endpoint.
# =============================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'

ok()   { echo -e "${GREEN}✓${NC} $1"; }
err()  { echo -e "${RED}✗${NC} $1" >&2; exit 1; }
warn() { echo -e "${YELLOW}!${NC} $1"; }
info() { echo -e "${BLUE}→${NC} $1"; }
ask()  { echo -e "\n${BOLD}$1${NC}"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

clear
echo -e "${BOLD}"
echo "=================================================="
echo "  PatronAI — OCI Setup"
echo "  Giggso Inc  |  v2.0.0"
echo "=================================================="
echo -e "${NC}"
echo "This script will:"
echo "  • Validate OCI credentials and Object Storage bucket"
echo "  • Seed config files to OCI Object Storage"
echo "  • Verify .env is present and correct"
echo "  • Verify Docker is running"
echo ""

# ── STEP 1 — Verify .env ──────────────────────────────────────
info "Checking .env..."
[[ -f "$REPO_DIR/.env" ]] || err ".env not found — run prereqs_oci.sh from your Mac first"
ok ".env found"

# Load key vars from .env
source <(grep -E "^(PATRONAI_BUCKET|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_REGION|S3_ENDPOINT_URL|COMPANY_SLUG)" \
  "$REPO_DIR/.env" | sed 's/ *= */=/')

[[ -z "${PATRONAI_BUCKET:-}" ]] && err "PATRONAI_BUCKET not set in .env"
[[ -z "${S3_ENDPOINT_URL:-}" ]] && err "S3_ENDPOINT_URL not set in .env — required for OCI Object Storage"
ok "Key env vars present"

# ── STEP 2 — Verify OCI Object Storage access ─────────────────
info "Verifying OCI Object Storage access via S3-compat endpoint..."
python3 -c "
import boto3, os, sys
try:
    s3 = boto3.client('s3',
        endpoint_url=os.environ.get('S3_ENDPOINT_URL') or '${S3_ENDPOINT_URL}',
        aws_access_key_id='${AWS_ACCESS_KEY_ID}',
        aws_secret_access_key='${AWS_SECRET_ACCESS_KEY}',
        region_name='${AWS_REGION:-us-chicago-1}')
    s3.head_bucket(Bucket='${PATRONAI_BUCKET}')
    print('OK')
except Exception as e:
    print('FAIL', str(e))
    sys.exit(1)
" && ok "OCI Object Storage accessible: ${PATRONAI_BUCKET}" \
  || err "Cannot access OCI bucket — check S3_ENDPOINT_URL, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY in .env"

# ── STEP 3 — Seed config files ────────────────────────────────
info "Seeding config files to OCI Object Storage..."
python3 -c "
import boto3, os, pathlib
s3 = boto3.client('s3',
    endpoint_url='${S3_ENDPOINT_URL}',
    aws_access_key_id='${AWS_ACCESS_KEY_ID}',
    aws_secret_access_key='${AWS_SECRET_ACCESS_KEY}',
    region_name='${AWS_REGION:-us-chicago-1}')
config_dir = pathlib.Path('${REPO_DIR}/config')
files = ['settings.json','authorized.csv','unauthorized.csv',
         'authorized_code.csv','unauthorized_code.csv']
for f in files:
    p = config_dir / f
    if p.exists():
        key = f'config/{f}'
        try:
            s3.head_object(Bucket='${PATRONAI_BUCKET}', Key=key)
            print(f'  exists: {key}')
        except:
            s3.upload_file(str(p), '${PATRONAI_BUCKET}', key)
            print(f'  seeded: {key}')
"
ok "Config files seeded"

# ── STEP 4 — Verify Docker ────────────────────────────────────
info "Checking Docker..."
command -v docker &>/dev/null || err "Docker not found — install Docker first"
docker info &>/dev/null || err "Docker daemon not running — sudo systemctl start docker"
ok "Docker running"

command -v docker-compose &>/dev/null || \
  docker compose version &>/dev/null || \
  err "Docker Compose not found"
ok "Docker Compose found"

# ── DONE ──────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}"
echo "=================================================="
echo "  Setup complete!"
echo "=================================================="
echo -e "${NC}"
echo "  Bucket    : ${PATRONAI_BUCKET}"
echo "  Endpoint  : ${S3_ENDPOINT_URL}"
echo "  Company   : ${COMPANY_SLUG:-not set}"
echo ""
echo "Next step:"
echo "  bash scripts/start.sh"
echo ""
echo -e "${BOLD}Giggso Inc x TrinityOps.ai x AIRTaaS${NC}"
