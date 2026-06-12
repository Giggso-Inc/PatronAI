#!/usr/bin/env bash
# =============================================================
# FILE: prereqs_oci.sh
# VERSION: 1.1.0
# UPDATED: 2026-06-11
# OWNER: Giggso Inc
# PURPOSE: Create all OCI resources needed by PatronAI.
#          At every step lists existing resources — user chooses
#          to reuse or create new. Generates .env, agent config,
#          grafana datasource. Optionally SCPs all generated
#          files to the OCI VM.
#          Mirrors prereqs.sh — OCI edition.
# USAGE:   bash prereqs_oci.sh   (run from patronai/)
# RUN ON:  Your Mac or Linux — not on the OCI VM
# BEFORE:  Run deploy_to_oci.sh first to get code onto OCI VM
# AFTER:   SSH into OCI VM and run bash scripts/start.sh
# AUDIT LOG:
#   v1.0.0  2026-06-11  Initial — OCI port of prereqs.sh
#   v1.1.0  2026-06-11  Region default updated ap-mumbai-1 → us-chicago-1.
#                       CLOUD_PROVIDER default changed aws → oci.
#                       Added boto3 variable name comments in .env output.
# =============================================================

set -euo pipefail

# ── Colours ───────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'

ok()      { echo -e "${GREEN}✓${NC} $1"; }
err()     { echo -e "${RED}✗${NC} $1" >&2; exit 1; }
warn()    { echo -e "${YELLOW}!${NC} $1"; }
info()    { echo -e "${BLUE}→${NC} $1"; }
ask()     { echo -e "\n${BOLD}$1${NC}"; }
divider() { echo -e "\n${BOLD}──────────────────────────────────────────────${NC}"; }
section() { echo -e "\n${BOLD}${BLUE}══════════════════════════════════════════════";
            echo -e "  $1";
            echo -e "══════════════════════════════════════════════${NC}"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -d "$SCRIPT_DIR/ghost-ai-scanner" ]]; then
  REPO_DIR="$SCRIPT_DIR/ghost-ai-scanner"
elif [[ -f "$SCRIPT_DIR/main.py" || -d "$SCRIPT_DIR/config" ]]; then
  REPO_DIR="$SCRIPT_DIR"
else
  err "Cannot find project root. Run from patronai/ (Mac) or ghost-ai-scanner/ (OCI VM)."
fi

OCI_VM_HOST=""; OCI_VM_KEY=""; OCI_VM_USER=""; OCI_VM_REMOTE_DIR=""
OCI_SECRET_KEY_ID=""; OCI_SECRET_KEY_SECRET=""
ONS_TOPIC_ID=""

# ══════════════════════════════════════════════════════════════
# BANNER
# ══════════════════════════════════════════════════════════════
clear
echo -e "${BOLD}"
echo "=================================================="
echo "  PatronAI — OCI Prerequisites Setup"
echo "  Giggso Inc  |  v1.0.0"
echo "=================================================="
echo -e "${NC}"
echo "Run this on your Mac AFTER deploy_to_oci.sh."
echo ""
echo "This script will:"
echo "  • Create OCI Object Storage bucket (S3-compatible)"
echo "  • Generate Customer Secret Keys (replaces IAM user)"
echo "  • Create OCI Notifications topic (replaces SNS)"
echo "  • Generate .env, agent config, grafana datasource"
echo "  • Optionally SCP all generated files to your OCI VM"
echo ""

# ══════════════════════════════════════════════════════════════
# STEP 1 — OCI CREDENTIALS
# ══════════════════════════════════════════════════════════════
section "STEP 1 — OCI Credentials"

command -v oci &>/dev/null || err "OCI CLI not found. Install: https://docs.oracle.com/en-us/iaas/Content/API/SDKDocs/cliinstall.htm"

info "Checking OCI CLI configuration..."
OCI_TENANCY_ID=$(oci iam tenancy get --query 'data.id' --raw-output 2>/dev/null) \
  || err "OCI CLI not configured. Run: oci setup config"
OCI_TENANCY_NAME=$(oci iam tenancy get --query 'data.name' --raw-output 2>/dev/null)
ok "OCI CLI valid — Tenancy: $OCI_TENANCY_NAME"

ask "OCI Region [us-chicago-1]:"
read -r OCI_REGION
OCI_REGION="${OCI_REGION:-us-chicago-1}"

ask "OCI Compartment OCID:"
read -r OCI_COMPARTMENT_ID
[[ -z "$OCI_COMPARTMENT_ID" ]] && err "Cannot be empty"

# Get namespace for S3-compat endpoint
OCI_NAMESPACE=$(oci os ns get --query 'data' --raw-output 2>/dev/null) \
  || err "Cannot get OCI Object Storage namespace"
ok "Object Storage namespace: $OCI_NAMESPACE"
ok "Region: $OCI_REGION"

# S3-compatible endpoint
S3_ENDPOINT="https://${OCI_NAMESPACE}.compat.objectstorage.${OCI_REGION}.oraclecloud.com"
ok "S3-compat endpoint: $S3_ENDPOINT"

# ══════════════════════════════════════════════════════════════
# STEP 2 — COMPANY CONFIGURATION
# ══════════════════════════════════════════════════════════════
section "STEP 2 — Company Configuration"

ask "Company name (display name, e.g. Acme Corp):"
read -r COMPANY_NAME
[[ -z "$COMPANY_NAME" ]] && err "Cannot be empty"

ask "Company slug (lowercase-no-spaces, e.g. acme):"
read -r COMPANY_SLUG
COMPANY_SLUG=$(echo "$COMPANY_SLUG" | tr '[:upper:]' '[:lower:]' | tr ' ' '-')
[[ -z "$COMPANY_SLUG" ]] && err "Cannot be empty"

ask "Allowed emails for Streamlit UI (comma-separated):"
read -r ALLOWED_EMAILS
[[ -z "$ALLOWED_EMAILS" ]] && err "At least one email required"

ask "Admin emails — can edit settings (comma-separated):"
read -r ADMIN_EMAILS
[[ -z "$ADMIN_EMAILS" ]] && err "At least one admin email required"

ask "Alert email for notifications:"
read -r ALERT_EMAIL
ALERT_EMAIL="${ALERT_EMAIL//[$'\t\r\n']/}"
ALERT_EMAIL="${ALERT_EMAIL// /}"
[[ -z "$ALERT_EMAIL" ]] && err "Cannot be empty"

ask "Trinity webhook URL [optional — Enter to skip]:"
read -r TRINITY_WEBHOOK_URL
TRINITY_WEBHOOK_URL="${TRINITY_WEBHOOK_URL:-}"

ask "LogAnalyzer webhook URL [optional — Enter to skip]:"
read -r LOGANALYZER_WEBHOOK_URL
LOGANALYZER_WEBHOOK_URL="${LOGANALYZER_WEBHOOK_URL:-}"

ask "Scan interval seconds [300]:"
read -r SCAN_INTERVAL_SECS
SCAN_INTERVAL_SECS="${SCAN_INTERVAL_SECS:-300}"

ask "Dedup window minutes [60]:"
read -r DEDUP_WINDOW_MINUTES
DEDUP_WINDOW_MINUTES="${DEDUP_WINDOW_MINUTES:-60}"

ask "Grafana admin password [change-me-before-demo]:"
read -r -s GF_ADMIN_PASSWORD
GF_ADMIN_PASSWORD="${GF_ADMIN_PASSWORD:-change-me-before-demo}"
echo ""

# ══════════════════════════════════════════════════════════════
# STEP 3 — OCI OBJECT STORAGE BUCKET
# ══════════════════════════════════════════════════════════════
section "STEP 3 — OCI Object Storage Bucket"
DEFAULT_BUCKET="patronai-scan-${COMPANY_SLUG}"

info "Listing existing OCI Object Storage buckets..."
EXISTING_BUCKETS=()
while IFS= read -r bname; do
  [[ -n "$bname" ]] && EXISTING_BUCKETS+=("$bname")
done < <(oci os bucket list \
  --compartment-id "$OCI_COMPARTMENT_ID" \
  --namespace "$OCI_NAMESPACE" \
  --region "$OCI_REGION" \
  --query 'data[*].name' \
  --raw-output 2>/dev/null | tr ',' '\n' | tr -d '[]" ' | grep -v "^$" || true)

OCI_BUCKET=""; BUCKET_CREATE=true
if [[ ${#EXISTING_BUCKETS[@]} -gt 0 ]]; then
  echo ""
  echo "  Existing buckets:"
  for i in "${!EXISTING_BUCKETS[@]}"; do
    echo "  [$((i+1))]  ${EXISTING_BUCKETS[$i]}"
  done
  CREATE_IDX=$(( ${#EXISTING_BUCKETS[@]} + 1 ))
  CUSTOM_IDX=$(( ${#EXISTING_BUCKETS[@]} + 2 ))
  echo "  [$CREATE_IDX]  Create: $DEFAULT_BUCKET"
  echo "  [$CUSTOM_IDX]  Create with custom name"
  ask "Choice [$CREATE_IDX]:"
  read -r C; C="${C:-$CREATE_IDX}"
  if [[ "$C" == "$CUSTOM_IDX" ]]; then
    ask "Bucket name:"; read -r OCI_BUCKET; BUCKET_CREATE=true
  elif [[ "$C" == "$CREATE_IDX" ]]; then
    OCI_BUCKET="$DEFAULT_BUCKET"; BUCKET_CREATE=true
  else
    OCI_BUCKET="${EXISTING_BUCKETS[$(( C - 1 ))]}"; BUCKET_CREATE=false
    ok "Reusing: $OCI_BUCKET"
  fi
else
  warn "No existing buckets found."
  echo "  [1]  Create: $DEFAULT_BUCKET"
  echo "  [2]  Create with custom name"
  ask "Choice [1]:"
  read -r C; C="${C:-1}"
  [[ "$C" == "2" ]] && { ask "Bucket name:"; read -r OCI_BUCKET; } || OCI_BUCKET="$DEFAULT_BUCKET"
  BUCKET_CREATE=true
fi

if [[ "$BUCKET_CREATE" == true ]]; then
  info "Creating bucket: $OCI_BUCKET"
  oci os bucket create \
    --compartment-id "$OCI_COMPARTMENT_ID" \
    --namespace "$OCI_NAMESPACE" \
    --name "$OCI_BUCKET" \
    --region "$OCI_REGION" \
    --versioning Enabled \
    --public-access-type NoPublicAccess >/dev/null 2>/dev/null \
    && ok "Bucket created: $OCI_BUCKET" \
    || warn "Bucket may already exist — continuing"
  ok "Bucket ready: $OCI_BUCKET (versioning enabled, private)"
fi

# Seed config files
divider
echo -e "${BOLD}  Seed config files to OCI Object Storage${NC}"
echo "  [1]  Seed from local repo → oci://${OCI_BUCKET}/config/"
echo "  [2]  Skip (already in bucket)"
ask "Choice [1]:"
read -r C; C="${C:-1}"
if [[ "$C" == "1" ]]; then
  for f in settings.json authorized.csv unauthorized.csv; do
    if [[ -f "$REPO_DIR/config/$f" ]]; then
      oci os object put \
        --namespace "$OCI_NAMESPACE" \
        --bucket-name "$OCI_BUCKET" \
        --name "config/$f" \
        --file "$REPO_DIR/config/$f" \
        --region "$OCI_REGION" \
        --force >/dev/null 2>/dev/null \
        && ok "Seeded: config/$f" \
        || warn "Failed to seed: $f"
    fi
  done
  ok "Config files seeded to OCI Object Storage"
else
  warn "Seeding skipped"
fi

# ══════════════════════════════════════════════════════════════
# STEP 4 — CUSTOMER SECRET KEYS (replaces IAM user)
# ══════════════════════════════════════════════════════════════
section "STEP 4 — Customer Secret Keys (S3-compatible access)"

echo ""
echo "  Customer Secret Keys allow S3-compatible access to OCI Object Storage."
echo "  They are tied to your OCI user and scoped to Object Storage only."
echo ""

# Get current user OCID
OCI_USER_ID=$(oci iam user list \
  --compartment-id "$OCI_TENANCY_ID" \
  --region "$OCI_REGION" \
  --query 'data[0].id' \
  --raw-output 2>/dev/null || true)

info "Listing existing Customer Secret Keys..."
EXISTING_KEYS=$(oci iam customer-secret-key list \
  --user-id "$OCI_USER_ID" \
  --region "$OCI_REGION" \
  --query 'data[*].[id,"display-name","time-created"]' \
  --output table 2>/dev/null || echo "none")

echo "$EXISTING_KEYS"
echo ""
echo "  [1]  Generate new Customer Secret Key (recommended)"
echo "  [2]  Enter existing key manually"
ask "Choice [1]:"
read -r C; C="${C:-1}"

if [[ "$C" == "1" ]]; then
  KEY_DISPLAY_NAME="patronai-scanner-$(date +%Y%m%d)"
  KEY_OUT=$(oci iam customer-secret-key create \
    --user-id "$OCI_USER_ID" \
    --display-name "$KEY_DISPLAY_NAME" \
    --region "$OCI_REGION" 2>/dev/null)
  OCI_SECRET_KEY_ID=$(echo "$KEY_OUT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['data']['id'])")
  OCI_SECRET_KEY_SECRET=$(echo "$KEY_OUT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['data']['key'])")
  ok "Customer Secret Key generated — ID: $OCI_SECRET_KEY_ID"
  warn "Secret key shown only ONCE — it will be saved to .env automatically"
elif [[ "$C" == "2" ]]; then
  ask "Customer Secret Key ID:"; read -r OCI_SECRET_KEY_ID
  ask "Customer Secret Key (secret):"; read -r -s OCI_SECRET_KEY_SECRET; echo ""
  ok "Using manually entered credentials"
fi

# ══════════════════════════════════════════════════════════════
# STEP 5 — OCI NOTIFICATIONS (replaces SNS)
# ══════════════════════════════════════════════════════════════
section "STEP 5 — OCI Notifications Topic (replaces SNS)"

echo ""
echo "  [1]  Create OCI Notifications topic for email alerts"
echo "  [2]  Use webhook only (Trinity/LogAnalyzer — no ONS needed)"
echo "  [3]  Skip alerts"
ask "Choice [1]:"
read -r C; C="${C:-1}"

if [[ "$C" == "1" ]]; then
  DEFAULT_TOPIC="patronai-alerts-${COMPANY_SLUG}"
  info "Creating ONS topic: $DEFAULT_TOPIC"
  TOPIC_OUT=$(oci ons topic create \
    --compartment-id "$OCI_COMPARTMENT_ID" \
    --name "$DEFAULT_TOPIC" \
    --region "$OCI_REGION" 2>/dev/null || echo "")
  if [[ -n "$TOPIC_OUT" ]]; then
    ONS_TOPIC_ID=$(echo "$TOPIC_OUT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['data']['topic-id'])" 2>/dev/null || echo "")
    ok "ONS topic created: $ONS_TOPIC_ID"
    # Subscribe email
    if [[ -n "$ONS_TOPIC_ID" ]]; then
      oci ons subscription create \
        --compartment-id "$OCI_COMPARTMENT_ID" \
        --topic-id "$ONS_TOPIC_ID" \
        --protocol EMAIL \
        --subscription-endpoint "$ALERT_EMAIL" \
        --region "$OCI_REGION" >/dev/null 2>/dev/null \
        && ok "Email subscription sent to $ALERT_EMAIL — confirm via email" \
        || warn "Subscription failed — add manually in OCI Console"
    fi
  else
    warn "ONS topic creation failed — alerts will use webhook only"
    ONS_TOPIC_ID=""
  fi
elif [[ "$C" == "2" ]]; then
  warn "Using webhook only — ensure TRINITY_WEBHOOK_URL or LOGANALYZER_WEBHOOK_URL is set"
  ONS_TOPIC_ID=""
else
  warn "Alerts skipped"
  ONS_TOPIC_ID=""
fi

# ══════════════════════════════════════════════════════════════
# STEP 6 — VCN FLOW LOGS (replaces VPC Flow Logs)
# ══════════════════════════════════════════════════════════════
section "STEP 6 — VCN Flow Logs"

echo ""
echo "  [1]  Enable VCN Flow Logs → OCI Object Storage"
echo "  [2]  Skip"
ask "Choice [2]:"
read -r C; C="${C:-2}"

if [[ "$C" == "1" ]]; then
  info "Listing VCNs in compartment..."
  oci network vcn list \
    --compartment-id "$OCI_COMPARTMENT_ID" \
    --region "$OCI_REGION" \
    --query 'data[*].[id,"display-name"]' \
    --output table 2>/dev/null || warn "No VCNs found"
  ask "VCN OCID to enable flow logs on (Enter to skip):"
  read -r VCN_OCID
  if [[ -n "$VCN_OCID" ]]; then
    warn "VCN Flow Logs require a Log Group in OCI Logging service."
    warn "Enable manually: OCI Console → Logging → Log Groups → Create"
    warn "Then: Logging → Logs → Create Log → choose VCN Flow Log"
  fi
else
  warn "VCN Flow Logs skipped"
fi

# ══════════════════════════════════════════════════════════════
# STEP 7 — GENERATE CONFIG FILES
# ══════════════════════════════════════════════════════════════
section "STEP 7 — Generate Config Files"

# ── .env ──────────────────────────────────────────────────────
divider
echo -e "${BOLD}  .env${NC}"
echo "  [1]  Generate .env (overwrites if exists)"
echo "  [2]  Skip"
ask "Choice [1]:"
read -r C; C="${C:-1}"
if [[ "$C" == "1" ]]; then
  cat > "$REPO_DIR/.env" <<EOF
# Generated by prereqs_oci.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ)
# DO NOT COMMIT TO GIT

# ── OCI Object Storage (S3-compatible) ───────────────────────
# NOTE: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION are
# boto3 variable names — required by the Python S3 SDK.
# They store OCI Customer Secret Key values, not AWS credentials.
PATRONAI_BUCKET=${OCI_BUCKET}
AWS_REGION=${OCI_REGION}
AWS_ACCESS_KEY_ID=${OCI_SECRET_KEY_ID}
AWS_SECRET_ACCESS_KEY=${OCI_SECRET_KEY_SECRET}
# OCI S3-compatible endpoint — required for boto3 to reach OCI Object Storage
S3_ENDPOINT_URL=${S3_ENDPOINT}

# ── Company ───────────────────────────────────────────────────
COMPANY_NAME=${COMPANY_NAME}
COMPANY_SLUG=${COMPANY_SLUG}

# ── Auth ──────────────────────────────────────────────────────
ALLOWED_EMAILS=${ALLOWED_EMAILS}
ADMIN_EMAILS=${ADMIN_EMAILS}

# ── Alerts ────────────────────────────────────────────────────
ALERT_SNS_ARN=${ONS_TOPIC_ID}
TRINITY_WEBHOOK_URL=${TRINITY_WEBHOOK_URL}
LOGANALYZER_WEBHOOK_URL=${LOGANALYZER_WEBHOOK_URL}

# ── Scan ──────────────────────────────────────────────────────
SCAN_INTERVAL_SECS=${SCAN_INTERVAL_SECS}
DEDUP_WINDOW_MINUTES=${DEDUP_WINDOW_MINUTES}
CROWDSTRIKE_ENABLED=false
CLOUD_PROVIDER=oci

# ── Grafana ───────────────────────────────────────────────────
GF_SECURITY_ADMIN_PASSWORD=${GF_ADMIN_PASSWORD}
GF_SECURITY_ADMIN_USER=admin
GF_AUTH_ANONYMOUS_ENABLED=false

# ── Ports ─────────────────────────────────────────────────────
STREAMLIT_PORT=8501
GRAFANA_PORT=3000
EOF
  chmod 600 "$REPO_DIR/.env"
  ok ".env → $REPO_DIR/.env  (chmod 600)"
else
  warn ".env skipped"
fi

# ── agent/config.json ─────────────────────────────────────────
divider
echo -e "${BOLD}  agent/config.json${NC}"
echo "  [1]  Generate"
echo "  [2]  Skip"
ask "Choice [1]:"
read -r C; C="${C:-1}"
if [[ "$C" == "1" ]]; then
  mkdir -p "$REPO_DIR/agent"
  cat > "$REPO_DIR/agent/config.json" <<EOF
{
  "bucket":           "${OCI_BUCKET}",
  "region":           "${OCI_REGION}",
  "prefix":           "ocsf/agent/",
  "interval_seconds": 60,
  "company":          "${COMPANY_SLUG}",
  "s3_endpoint_url":  "${S3_ENDPOINT}"
}
EOF
  ok "agent/config.json → $REPO_DIR/agent/config.json"
else
  warn "agent/config.json skipped"
fi

# ── Grafana datasource ────────────────────────────────────────
divider
echo -e "${BOLD}  grafana/datasources/oci.json${NC}"
echo "  [1]  Generate"
echo "  [2]  Skip"
ask "Choice [1]:"
read -r C; C="${C:-1}"
if [[ "$C" == "1" ]]; then
  mkdir -p "$REPO_DIR/grafana/datasources"
  cat > "$REPO_DIR/grafana/datasources/oci.json" <<EOF
{
  "apiVersion": 1,
  "datasources": [{
    "name":      "PatronAI-OCI",
    "type":      "marcusolsson-json-datasource",
    "access":    "proxy",
    "url":       "${S3_ENDPOINT}/${OCI_BUCKET}",
    "isDefault": true,
    "jsonData":  {
      "bucket":       "${OCI_BUCKET}",
      "region":       "${OCI_REGION}",
      "endpoint":     "${S3_ENDPOINT}"
    }
  }]
}
EOF
  ok "grafana/datasources/oci.json generated"
else
  warn "Grafana datasource skipped"
fi

# ══════════════════════════════════════════════════════════════
# STEP 8 — SCP GENERATED FILES TO OCI VM
# ══════════════════════════════════════════════════════════════
section "STEP 8 — Deploy Generated Files to OCI VM"

echo "  [1]  SCP generated files to OCI VM now"
echo "  [2]  Skip — I'll copy manually"
ask "Choice [1]:"
read -r C; C="${C:-1}"

if [[ "$C" == "1" ]]; then
  ask "OCI VM public IP or hostname:"
  read -r OCI_VM_HOST
  [[ -z "$OCI_VM_HOST" ]] && err "Cannot be empty"

  ask "Path to SSH private key (.key or .pem):"
  read -r OCI_VM_KEY
  OCI_VM_KEY="${OCI_VM_KEY/#\~/$HOME}"
  [[ ! -f "$OCI_VM_KEY" ]] && err "Key not found: $OCI_VM_KEY"
  chmod 400 "$OCI_VM_KEY" 2>/dev/null || true

  ask "SSH username [opc]:"
  read -r OCI_VM_USER
  OCI_VM_USER="${OCI_VM_USER:-opc}"

  ask "Remote project directory [/home/${OCI_VM_USER}/ghost-ai-scanner]:"
  read -r OCI_VM_REMOTE_DIR
  OCI_VM_REMOTE_DIR="${OCI_VM_REMOTE_DIR:-/home/${OCI_VM_USER}/ghost-ai-scanner}"

  info "Testing SSH..."
  ssh -i "$OCI_VM_KEY" -o StrictHostKeyChecking=no -o ConnectTimeout=10 \
    "${OCI_VM_USER}@${OCI_VM_HOST}" "echo ok" &>/dev/null \
    && ok "SSH OK" \
    || err "SSH failed — check key, username, port 22"

  for FILE in ".env" "agent/config.json" "grafana/datasources/oci.json"; do
    LOCAL="$REPO_DIR/$FILE"
    if [[ -f "$LOCAL" ]]; then
      ssh -i "$OCI_VM_KEY" -o StrictHostKeyChecking=no \
        "${OCI_VM_USER}@${OCI_VM_HOST}" \
        "mkdir -p '${OCI_VM_REMOTE_DIR}/$(dirname "$FILE")'" 2>/dev/null || true
      scp -i "$OCI_VM_KEY" -o StrictHostKeyChecking=no \
        "$LOCAL" "${OCI_VM_USER}@${OCI_VM_HOST}:${OCI_VM_REMOTE_DIR}/${FILE}"
      ok "Pushed: $FILE"
    fi
  done
  ssh -i "$OCI_VM_KEY" -o StrictHostKeyChecking=no \
    "${OCI_VM_USER}@${OCI_VM_HOST}" \
    "chmod 600 '${OCI_VM_REMOTE_DIR}/.env'" 2>/dev/null || true
  ok "Remote .env chmod 600"
else
  warn "SCP skipped — copy files manually:"
  warn "  scp -i your-key.pem .env ${OCI_VM_USER:-opc}@<OCI_IP>:<remote-dir>/"
fi

# ══════════════════════════════════════════════════════════════
# DONE
# ══════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}${GREEN}"
echo "=================================================="
echo "  OCI Prerequisites complete!"
echo "=================================================="
echo -e "${NC}"
echo "  OCI Bucket   : $OCI_BUCKET"
echo "  S3 Endpoint  : $S3_ENDPOINT"
echo "  Secret Key ID: $OCI_SECRET_KEY_ID"
[[ -n "$ONS_TOPIC_ID" ]] && echo "  ONS Topic    : $ONS_TOPIC_ID"
[[ -n "$OCI_VM_HOST" ]] && echo "  OCI VM       : ${OCI_VM_USER}@${OCI_VM_HOST}"
echo ""
echo "Next steps:"
echo ""
echo "  1. Confirm ONS subscription email: $ALERT_EMAIL"
echo ""
echo "  2. Migrate data from source (AWS → OCI):"
echo "     bash ghost-ai-scanner/scripts/migrate_data.sh"
echo ""
[[ -n "$OCI_VM_HOST" ]] && echo "  3. SSH into OCI VM:"
[[ -n "$OCI_VM_HOST" ]] && echo "     ssh -i $OCI_VM_KEY ${OCI_VM_USER}@${OCI_VM_HOST}"
echo ""
echo "  4. Start the scanner:"
echo "     cd ${OCI_VM_REMOTE_DIR:-/home/opc/ghost-ai-scanner} && bash scripts/start.sh"
echo ""
echo "  5. Open dashboards:"
echo "     PatronAI : https://${OCI_VM_HOST:-<oci-ip>}/"
echo "     Grafana  : https://${OCI_VM_HOST:-<oci-ip>}/grafana/"
echo ""
echo -e "${YELLOW}IMPORTANT:${NC} .env contains OCI credentials — never commit to git."
echo ""
echo -e "${RED}${BOLD}⚠  SECURITY — ACTION REQUIRED BEFORE PRODUCTION  ⚠${NC}"
echo -e "${RED}   OCI Security List is currently open to 0.0.0.0/0.${NC}"
echo -e "${RED}   Lock each port to your office/VPN IP before go-live:${NC}"
echo ""
echo "   OCI Console → Networking → VCN → Security Lists → Ingress Rules"
echo "   Change Source from 0.0.0.0/0 to <your-ip>/32"
echo ""
echo "   Ports to restrict:"
echo "     22   SSH        → your admin IP only"
echo "     80   HTTP       → your office/VPN CIDR"
echo "     443  HTTPS      → your office/VPN CIDR"
echo ""
echo -e "${RED}${BOLD}────────────────────────────────────────────────────${NC}"
echo ""
echo -e "${BOLD}Giggso Inc x TrinityOps.ai x AIRTaaS${NC}"
