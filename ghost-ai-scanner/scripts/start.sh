#!/usr/bin/env bash
# =============================================================
# FILE: scripts/start.sh
# VERSION: 2.1.0
# UPDATED: 2026-06-11
# OWNER: Giggso Inc
# PURPOSE: Safe wrapper around `docker compose up` for OCI.
#          Purges stale shell-exported env vars that could shadow
#          the on-disk .env, brings the stack down cleanly, then
#          starts fresh. Verifies OCI Object Storage access via
#          S3-compat endpoint instead of AWS STS.
# USAGE:   bash scripts/start.sh           # safe restart (default)
#          bash scripts/start.sh --no-build # skip image rebuild
# AUDIT LOG:
#   v1.0.0  2026-05-02  Initial (AWS STS credential check).
#   v2.0.0  2026-06-11  OCI migration — replaced AWS STS check
#   v2.1.0  2026-06-11  Region default updated ap-mumbai-1 → us-chicago-1.
#                       Added boto3 variable name comment.
#                       with OCI Object Storage S3-compat check.
# =============================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'
ok()   { echo -e "${GREEN}✓${NC} $1"; }
warn() { echo -e "${YELLOW}!${NC} $1"; }
err()  { echo -e "${RED}✗${NC} $1" >&2; exit 1; }
info() { echo -e "${BLUE}→${NC} $1"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_DIR="${COMPOSE_DIR:-$(cd "$SCRIPT_DIR/.." && pwd)}"
cd "$COMPOSE_DIR"

[[ -f docker-compose.yml ]] || err "docker-compose.yml not found in $COMPOSE_DIR"
[[ -f .env ]]               || err ".env not found in $COMPOSE_DIR — run scripts/setup.sh first"

# ── Step 1 — purge stale exported env vars ────────────────────
info "Purging stale shell-exported env vars (boto3 variable names — store OCI credentials)..."
unset \
    AWS_ACCESS_KEY_ID \
    AWS_SECRET_ACCESS_KEY \
    AWS_SESSION_TOKEN \
    AWS_REGION \
    AWS_DEFAULT_REGION \
    S3_ENDPOINT_URL \
    GF_SECURITY_ADMIN_USER \
    GF_SECURITY_ADMIN_PASSWORD \
    COMPANY_NAME \
    COMPANY_SLUG \
    ALLOWED_EMAILS \
    ADMIN_EMAILS \
    SUPPORT_EMAILS \
    ALERT_RECIPIENTS \
    ALERT_SNS_ARN \
    PATRONAI_FROM_EMAIL \
    PUBLIC_HOST \
    GRAFANA_URL \
    LLM_PROVIDER LLM_BASE_URL LLM_API_KEY LLM_MODEL LLM_MODEL_REPO \
    LLM_READ_TIMEOUT_S LLM_MAX_TOKENS \
    ROLLUP_HOURLY_OFFSET_MINUTES ROLLUP_INITIAL_BACKFILL_DAYS \
    CHAT_HISTORY_RETENTION_DAYS DOCS_REFRESH_INTERVAL_S \
    TRINITY_WEBHOOK_URL LOGANALYZER_WEBHOOK_URL \
    SCAN_INTERVAL_SECS DEDUP_WINDOW_MINUTES \
    CROWDSTRIKE_ENABLED CLOUD_PROVIDER \
    PATRONAI_BUCKET MARAUDER_SCAN_BUCKET 2>/dev/null || true
ok "Stale env vars purged"

# ── Step 2 — clear compose project state ─────────────────────
info "Stopping any running stack..."
docker compose down --remove-orphans 2>&1 | sed 's/^/  /'

# ── Step 3 — start fresh ─────────────────────────────────────
BUILD_FLAG="--build"
if [[ "${1:-}" == "--no-build" ]]; then
    BUILD_FLAG=""
    warn "--no-build: reusing existing image"
fi
info "Starting stack: docker compose up -d $BUILD_FLAG"
docker compose up -d $BUILD_FLAG 2>&1 | sed 's/^/  /'

# ── Step 3b — pre-fetch the LLM model ────────────────────────
if [ -x "$SCRIPT_DIR/prefetch_model.sh" ]; then
    info "Ensuring chat LLM model is present..."
    bash "$SCRIPT_DIR/prefetch_model.sh" || \
        warn "Model prefetch returned non-zero — chat may take ~3-5 min to be available."
fi

# ── Step 4 — verify OCI Object Storage access ─────────────────
info "Waiting 10s for container to come up..."
sleep 10

info "Verifying OCI Object Storage access inside the container..."
OCI_CHECK=$(docker exec patronai python3 -c "
import boto3, os
try:
    endpoint = os.environ.get('S3_ENDPOINT_URL', '')
    bucket   = os.environ.get('PATRONAI_BUCKET') or os.environ.get('MARAUDER_SCAN_BUCKET', '')
    s3 = boto3.client('s3',
        endpoint_url=endpoint if endpoint else None,
        region_name=os.environ.get('AWS_REGION', 'us-chicago-1'))
    s3.head_bucket(Bucket=bucket)
    print('OK bucket=' + bucket)
except Exception as e:
    print('FAIL', type(e).__name__, str(e)[:200])
" 2>&1 || echo "FAIL (docker exec failed: container not ready?)")

case "$OCI_CHECK" in
    "OK "*)
        ok "OCI Object Storage check passed: ${OCI_CHECK:3}"
        ;;
    *"NoSuchBucket"*)
        warn "OCI check: $OCI_CHECK"
        warn "→ Bucket not found. Check PATRONAI_BUCKET and S3_ENDPOINT_URL in .env"
        ;;
    *"InvalidAccessKeyId"*|*"SignatureDoesNotMatch"*)
        warn "OCI check: $OCI_CHECK"
        warn "→ Invalid Customer Secret Key. Re-generate in OCI Console → Profile → Customer Secret Keys"
        warn "  Then update AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY in .env"
        warn "  Re-run: bash scripts/start.sh"
        ;;
    *)
        warn "OCI check did not pass (container may still be starting):"
        warn "  $OCI_CHECK"
        warn "Check logs: docker logs -f patronai"
        ;;
esac

echo ""
ok "Done. Tail logs with: docker logs -f patronai"
