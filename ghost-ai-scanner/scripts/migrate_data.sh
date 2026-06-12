#!/usr/bin/env bash
# =============================================================
# FILE: ghost-ai-scanner/scripts/migrate_data.sh
# VERSION: 1.1.0
# UPDATED: 2026-06-11
# OWNER: Giggso Inc
# PURPOSE: Migrate all PatronAI data from AWS to OCI.
#          Handles three data sources:
#            1. S3 bucket → OCI Object Storage (via rclone)
#            2. Grafana Docker volume → OCI VM
#            3. LLM model volume — skipped (auto re-downloads)
#          Run AFTER deploy_to_oci.sh and prereqs_oci.sh.
# USAGE:   bash ghost-ai-scanner/scripts/migrate_data.sh
# RUN ON:  Your Mac or Linux — not on AWS EC2 or OCI VM
# REQUIRES: rclone, ssh, scp
# AUDIT LOG:
#   v1.0.0  2026-06-11  Initial
#   v1.1.0  2026-06-11  Removed hardcoded AWS EC2 IP.
#                       OCI region default updated to us-chicago-1.
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
section() { echo -e "\n${BOLD}${BLUE}══════════════════════════════════════════════";
            echo -e "  $1";
            echo -e "══════════════════════════════════════════════${NC}"; }

# ══════════════════════════════════════════════════════════════
# BANNER
# ══════════════════════════════════════════════════════════════
clear
echo -e "${BOLD}"
echo "=================================================="
echo "  PatronAI — AWS → OCI Data Migration"
echo "  Giggso Inc  |  v1.0.0"
echo "=================================================="
echo -e "${NC}"
echo "This script migrates:"
echo "  1. S3 bucket → OCI Object Storage (all scan data)"
echo "  2. Grafana Docker volume → OCI VM (dashboards)"
echo "  3. LLM model volume — SKIPPED (auto re-downloads on OCI)"
echo ""
warn "Run AFTER deploy_to_oci.sh and prereqs_oci.sh."
warn "PatronAI containers on OCI must be STOPPED during migration."
echo ""

# ══════════════════════════════════════════════════════════════
# STEP 1 — COLLECT CONNECTION DETAILS
# ══════════════════════════════════════════════════════════════
section "STEP 1 — Connection Details"

# ── AWS EC2 ───────────────────────────────────────────────────
echo -e "${BOLD}  AWS EC2 (source)${NC}"
ask "AWS EC2 public IP:"
read -r AWS_EC2_IP
AWS_EC2_IP="${AWS_EC2_IP:-}"

ask "AWS EC2 SSH key path (.pem):"
read -r AWS_EC2_KEY
AWS_EC2_KEY="${AWS_EC2_KEY/#\~/$HOME}"
[[ ! -f "$AWS_EC2_KEY" ]] && err "Key not found: $AWS_EC2_KEY"
chmod 400 "$AWS_EC2_KEY" 2>/dev/null || true

ask "AWS EC2 SSH username [ec2-user]:"
read -r AWS_EC2_USER
AWS_EC2_USER="${AWS_EC2_USER:-ec2-user}"

info "Testing AWS EC2 SSH..."
ssh -i "$AWS_EC2_KEY" -o StrictHostKeyChecking=no -o ConnectTimeout=15 \
  "${AWS_EC2_USER}@${AWS_EC2_IP}" "echo ok" &>/dev/null \
  && ok "AWS EC2 SSH OK" \
  || err "Cannot reach AWS EC2 — check key and IP"

# ── OCI VM ────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}  OCI VM (destination)${NC}"
ask "OCI VM public IP:"
read -r OCI_VM_IP
[[ -z "$OCI_VM_IP" ]] && err "OCI VM IP cannot be empty"

ask "OCI VM SSH key path (.key or .pem):"
read -r OCI_VM_KEY
OCI_VM_KEY="${OCI_VM_KEY/#\~/$HOME}"
[[ ! -f "$OCI_VM_KEY" ]] && err "Key not found: $OCI_VM_KEY"
chmod 400 "$OCI_VM_KEY" 2>/dev/null || true

ask "OCI VM SSH username [opc]:"
read -r OCI_VM_USER
OCI_VM_USER="${OCI_VM_USER:-opc}"

info "Testing OCI VM SSH..."
ssh -i "$OCI_VM_KEY" -o StrictHostKeyChecking=no -o ConnectTimeout=15 \
  "${OCI_VM_USER}@${OCI_VM_IP}" "echo ok" &>/dev/null \
  && ok "OCI VM SSH OK" \
  || err "Cannot reach OCI VM — check key and IP"

# ── S3 / OCI bucket names ─────────────────────────────────────
echo ""
echo -e "${BOLD}  Bucket Names${NC}"
ask "AWS S3 bucket name [patronai-scan-bucket]:"
read -r AWS_BUCKET
AWS_BUCKET="${AWS_BUCKET:-patronai-scan-bucket}"

ask "OCI Object Storage bucket name:"
read -r OCI_BUCKET
[[ -z "$OCI_BUCKET" ]] && err "OCI bucket name cannot be empty"

ask "OCI namespace (from prereqs_oci.sh output):"
read -r OCI_NAMESPACE
[[ -z "$OCI_NAMESPACE" ]] && err "OCI namespace cannot be empty"

ask "OCI region [us-chicago-1]:"
read -r OCI_REGION
OCI_REGION="${OCI_REGION:-us-chicago-1}"

OCI_S3_ENDPOINT="https://${OCI_NAMESPACE}.compat.objectstorage.${OCI_REGION}.oraclecloud.com"

# ── Temp directory on this machine ────────────────────────────
TMPDIR_LOCAL="/tmp/patronai-migration-$$"
mkdir -p "$TMPDIR_LOCAL"
ok "Local temp dir: $TMPDIR_LOCAL"

# ══════════════════════════════════════════════════════════════
# STEP 2 — S3 BUCKET → OCI OBJECT STORAGE
# ══════════════════════════════════════════════════════════════
section "STEP 2 — S3 Bucket → OCI Object Storage"

echo ""
echo "  [1]  Migrate S3 bucket now (uses rclone)"
echo "  [2]  Skip (bucket already migrated)"
ask "Choice [1]:"
read -r C; C="${C:-1}"

if [[ "$C" == "1" ]]; then
  command -v rclone &>/dev/null || err "rclone not found. Install: curl https://rclone.org/install.sh | sudo bash"

  info "Configuring rclone remotes..."

  # Configure AWS source
  echo ""
  echo -e "${BOLD}  AWS S3 credentials (for rclone source)${NC}"
  ask "AWS Access Key ID:"
  read -r AWS_ACCESS_KEY_ID
  ask "AWS Secret Access Key:"
  read -r -s AWS_SECRET_ACCESS_KEY; echo ""
  ask "AWS Region [us-east-1]:"
  read -r AWS_REGION_SRC
  AWS_REGION_SRC="${AWS_REGION_SRC:-us-east-1}"

  # Configure OCI destination
  echo ""
  echo -e "${BOLD}  OCI Object Storage credentials (for rclone destination)${NC}"
  ask "OCI Customer Secret Key ID:"
  read -r OCI_SECRET_KEY_ID
  ask "OCI Customer Secret Key (secret):"
  read -r -s OCI_SECRET_KEY_SECRET; echo ""

  # Write rclone config
  RCLONE_CONFIG="$TMPDIR_LOCAL/rclone.conf"
  cat > "$RCLONE_CONFIG" <<EOF
[aws-src]
type = s3
provider = AWS
access_key_id = ${AWS_ACCESS_KEY_ID}
secret_access_key = ${AWS_SECRET_ACCESS_KEY}
region = ${AWS_REGION_SRC}
acl = private

[oci-dst]
type = s3
provider = Other
access_key_id = ${OCI_SECRET_KEY_ID}
secret_access_key = ${OCI_SECRET_KEY_SECRET}
endpoint = ${OCI_S3_ENDPOINT}
acl = private
EOF
  chmod 600 "$RCLONE_CONFIG"
  ok "rclone config written"

  # Verify source bucket exists
  info "Verifying source bucket: s3://$AWS_BUCKET"
  rclone --config "$RCLONE_CONFIG" lsd "aws-src:$AWS_BUCKET" >/dev/null 2>/dev/null \
    && ok "Source bucket accessible" \
    || err "Cannot access s3://$AWS_BUCKET — check AWS credentials"

  # Count objects
  OBJ_COUNT=$(rclone --config "$RCLONE_CONFIG" size "aws-src:$AWS_BUCKET" 2>/dev/null | grep "Total objects" || echo "unknown")
  info "Source: $OBJ_COUNT"

  # Sync
  info "Starting rclone sync: s3://$AWS_BUCKET → oci://$OCI_BUCKET"
  info "This may take several minutes depending on data size..."
  rclone sync \
    "aws-src:$AWS_BUCKET" \
    "oci-dst:$OCI_BUCKET" \
    --config "$RCLONE_CONFIG" \
    --progress \
    --transfers 10 \
    --checkers 20 \
    --s3-upload-concurrency 10 \
    && ok "S3 → OCI Object Storage sync complete" \
    || err "rclone sync failed — check credentials and network"

  # Verify destination
  DST_COUNT=$(rclone --config "$RCLONE_CONFIG" size "oci-dst:$OCI_BUCKET" 2>/dev/null | grep "Total objects" || echo "unknown")
  ok "Destination: $DST_COUNT"

  # Clean up rclone config (contains credentials)
  rm -f "$RCLONE_CONFIG"
  ok "rclone config cleaned up"
else
  warn "S3 migration skipped"
fi

# ══════════════════════════════════════════════════════════════
# STEP 3 — GRAFANA VOLUME MIGRATION
# ══════════════════════════════════════════════════════════════
section "STEP 3 — Grafana Docker Volume Migration"

echo ""
echo "  [1]  Migrate grafana-data volume (dashboards, datasources, users)"
echo "  [2]  Skip (fresh Grafana install on OCI)"
ask "Choice [1]:"
read -r C; C="${C:-1}"

if [[ "$C" == "1" ]]; then
  GRAFANA_VOLUME="ghost-ai-scanner_grafana-data"

  # Check volume exists on AWS EC2
  info "Checking grafana volume on AWS EC2..."
  VOL_CHECK=$(ssh -i "$AWS_EC2_KEY" -o StrictHostKeyChecking=no \
    "${AWS_EC2_USER}@${AWS_EC2_IP}" \
    "docker volume ls -q | grep '$GRAFANA_VOLUME' || echo MISSING" 2>/dev/null)

  if [[ "$VOL_CHECK" == "MISSING" ]]; then
    err "Volume '$GRAFANA_VOLUME' not found on AWS EC2 — check volume name with: docker volume ls"
  fi
  ok "Volume found: $GRAFANA_VOLUME"

  # Get volume size
  VOL_SIZE=$(ssh -i "$AWS_EC2_KEY" -o StrictHostKeyChecking=no \
    "${AWS_EC2_USER}@${AWS_EC2_IP}" \
    "docker run --rm -v ${GRAFANA_VOLUME}:/data alpine du -sh /data 2>/dev/null | cut -f1" 2>/dev/null || echo "unknown")
  info "Volume size: $VOL_SIZE"

  # Export volume on AWS EC2
  info "Exporting grafana-data volume on AWS EC2..."
  ssh -i "$AWS_EC2_KEY" -o StrictHostKeyChecking=no \
    "${AWS_EC2_USER}@${AWS_EC2_IP}" "
    mkdir -p /tmp/patronai-migration
    docker run --rm \
      -v ${GRAFANA_VOLUME}:/data \
      -v /tmp/patronai-migration:/backup \
      alpine tar czf /backup/grafana-data.tar.gz -C /data .
    ls -lh /tmp/patronai-migration/grafana-data.tar.gz
  " && ok "Volume exported to AWS EC2:/tmp/patronai-migration/grafana-data.tar.gz" \
    || err "Volume export failed"

  # Copy from AWS EC2 to this machine
  info "Downloading grafana backup from AWS EC2 to local machine..."
  scp -i "$AWS_EC2_KEY" -o StrictHostKeyChecking=no \
    "${AWS_EC2_USER}@${AWS_EC2_IP}:/tmp/patronai-migration/grafana-data.tar.gz" \
    "$TMPDIR_LOCAL/grafana-data.tar.gz" \
    && ok "Downloaded: $TMPDIR_LOCAL/grafana-data.tar.gz" \
    || err "SCP from AWS EC2 failed"

  BACKUP_SIZE=$(du -sh "$TMPDIR_LOCAL/grafana-data.tar.gz" | cut -f1)
  info "Backup size: $BACKUP_SIZE"

  # Copy from this machine to OCI VM
  info "Uploading grafana backup to OCI VM..."
  ssh -i "$OCI_VM_KEY" -o StrictHostKeyChecking=no \
    "${OCI_VM_USER}@${OCI_VM_IP}" "mkdir -p /tmp/patronai-migration"
  scp -i "$OCI_VM_KEY" -o StrictHostKeyChecking=no \
    "$TMPDIR_LOCAL/grafana-data.tar.gz" \
    "${OCI_VM_USER}@${OCI_VM_IP}:/tmp/patronai-migration/grafana-data.tar.gz" \
    && ok "Uploaded to OCI VM" \
    || err "SCP to OCI VM failed"

  # Create volume and import on OCI VM
  info "Creating and importing grafana-data volume on OCI VM..."
  ssh -i "$OCI_VM_KEY" -o StrictHostKeyChecking=no \
    "${OCI_VM_USER}@${OCI_VM_IP}" "
    docker volume create ${GRAFANA_VOLUME} 2>/dev/null || true
    docker run --rm \
      -v ${GRAFANA_VOLUME}:/data \
      -v /tmp/patronai-migration:/backup \
      alpine tar xzf /backup/grafana-data.tar.gz -C /data
    echo 'Volume contents:'
    docker run --rm \
      -v ${GRAFANA_VOLUME}:/data \
      alpine ls -la /data
  " && ok "Grafana volume imported on OCI VM" \
    || err "Volume import failed on OCI VM"

  # Cleanup temp files
  ssh -i "$AWS_EC2_KEY" -o StrictHostKeyChecking=no \
    "${AWS_EC2_USER}@${AWS_EC2_IP}" \
    "rm -rf /tmp/patronai-migration" 2>/dev/null || true
  ssh -i "$OCI_VM_KEY" -o StrictHostKeyChecking=no \
    "${OCI_VM_USER}@${OCI_VM_IP}" \
    "rm -rf /tmp/patronai-migration" 2>/dev/null || true
  rm -rf "$TMPDIR_LOCAL"
  ok "Temp files cleaned up"

else
  warn "Grafana volume migration skipped — Grafana will start fresh on OCI"
fi

# ══════════════════════════════════════════════════════════════
# STEP 4 — LLM MODEL VOLUME (skip)
# ══════════════════════════════════════════════════════════════
section "STEP 4 — LLM Model Volume"

echo ""
ok "Skipping ghost-ai-scanner_patronai-models volume"
info "The LLM model (~750MB) auto-downloads on first docker compose up on OCI VM."
info "No migration needed — PatronAI handles this automatically."

# ══════════════════════════════════════════════════════════════
# DONE
# ══════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}${GREEN}"
echo "=================================================="
echo "  Data Migration Complete!"
echo "=================================================="
echo -e "${NC}"
echo "  S3 → OCI Object Storage : done"
echo "  Grafana volume           : done"
echo "  LLM model volume         : skipped (auto-downloads)"
echo ""
echo "Next steps:"
echo ""
echo "  1. SSH into OCI VM:"
echo "     ssh -i $OCI_VM_KEY ${OCI_VM_USER}@${OCI_VM_IP}"
echo ""
echo "  2. Start PatronAI:"
echo "     cd /home/${OCI_VM_USER}/ghost-ai-scanner"
echo "     bash scripts/start.sh"
echo ""
echo "  3. Verify containers healthy:"
echo "     docker ps -a"
echo ""
echo "  4. Test via OCI IP before DNS switch:"
echo "     curl -k https://${OCI_VM_IP}/"
echo "     curl -k https://${OCI_VM_IP}/grafana/"
echo ""
echo "  5. When verified — switch DNS:"
echo "     patronai.giggso.com A → ${OCI_VM_IP}"
echo ""
echo -e "${BOLD}Giggso Inc x TrinityOps.ai x AIRTaaS${NC}"
