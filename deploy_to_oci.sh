#!/usr/bin/env bash
# =============================================================
# FILE: deploy_to_oci.sh
# VERSION: 1.1.0
# UPDATED: 2026-06-11
# OWNER: Giggso Inc
# PURPOSE: List OCI Compute instances, pick one, SCP the full
#          codebase from this Mac/Linux to the chosen OCI VM,
#          then open an SSH session so you land inside the
#          project directory.
#          Mirrors deploy_to_ec2.sh — OCI edition.
# USAGE:   bash deploy_to_oci.sh
# REQUIRES: OCI CLI configured (~/.oci/config), SSH key, port 22
# RUN ON:  Your Mac or Linux — not on the OCI VM
# BEFORE:  Run prereqs_oci.sh after this to set up OCI resources
# AFTER:   SSH into OCI VM and run bash scripts/start.sh
# AUDIT LOG:
#   v1.0.0  2026-06-11  Initial — OCI port of deploy_to_ec2.sh
#   v1.1.0  2026-06-11  Region default updated ap-mumbai-1 → us-chicago-1.
# =============================================================

set -euo pipefail

# ── Colours ───────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'

ok()   { echo -e "${GREEN}✓${NC} $1"; }
err()  { echo -e "${RED}✗${NC} $1" >&2; exit 1; }
warn() { echo -e "${YELLOW}!${NC} $1"; }
info() { echo -e "${BLUE}→${NC} $1"; }
ask()  { echo -e "\n${BOLD}$1${NC}"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/ghost-ai-scanner" && pwd 2>/dev/null || echo "$SCRIPT_DIR")"

# ══════════════════════════════════════════════════════════════
# BANNER
# ══════════════════════════════════════════════════════════════
clear
echo -e "${BOLD}"
echo "=================================================="
echo "  PatronAI — Deploy Codebase to OCI Compute VM"
echo "  Giggso Inc  |  v1.0.0"
echo "=================================================="
echo -e "${NC}"
echo "Source: $REPO_DIR"
echo "Steps:  credentials → pick OCI VM → SSH details → SCP → SSH in"
echo ""

# ══════════════════════════════════════════════════════════════
# STEP 1 — OCI CLI CHECK
# ══════════════════════════════════════════════════════════════
echo -e "${BOLD}──────────────────────────────────────────────${NC}"
echo -e "${BOLD}STEP 1 — OCI CLI Credentials${NC}"
echo -e "${BOLD}──────────────────────────────────────────────${NC}"

command -v oci &>/dev/null || err "OCI CLI not found. Install: https://docs.oracle.com/en-us/iaas/Content/API/SDKDocs/cliinstall.htm"

# Verify OCI CLI config works
info "Verifying OCI CLI configuration (~/.oci/config)..."
OCI_TENANCY=$(oci iam tenancy get --query 'data.name' --raw-output 2>/dev/null) \
  || err "OCI CLI not configured. Run: oci setup config"
ok "OCI CLI valid — Tenancy: $OCI_TENANCY"

# Get compartment OCID
ask "OCI Compartment OCID (find in OCI Console → Identity → Compartments):"
read -r OCI_COMPARTMENT_ID
[[ -z "$OCI_COMPARTMENT_ID" ]] && err "Compartment OCID cannot be empty"

ask "OCI Region [us-chicago-1]:"
read -r OCI_REGION
OCI_REGION="${OCI_REGION:-us-chicago-1}"
ok "Region: $OCI_REGION   Compartment: $OCI_COMPARTMENT_ID"

# ══════════════════════════════════════════════════════════════
# STEP 2 — PICK AN OCI COMPUTE INSTANCE
# ══════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}──────────────────────────────────────────────${NC}"
echo -e "${BOLD}STEP 2 — Pick OCI Compute Instance${NC}"
echo -e "${BOLD}──────────────────────────────────────────────${NC}"
info "Fetching OCI Compute instances in $OCI_REGION..."
echo ""

OCI_IDS=()
OCI_NAMES=()
OCI_PUB_IPS=()
OCI_PRIV_IPS=()
OCI_STATES=()
OCI_SHAPES=()

# Pull all instances
while IFS=$'\t' read -r id name state shape; do
  [[ -z "$id" ]] && continue
  OCI_IDS+=("$id")
  OCI_NAMES+=("${name:-(no name)}")
  OCI_STATES+=("$state")
  OCI_SHAPES+=("$shape")
  # Get public IP for this instance
  PUB_IP=$(oci compute instance list-vnics \
    --instance-id "$id" \
    --compartment-id "$OCI_COMPARTMENT_ID" \
    --region "$OCI_REGION" \
    --query 'data[0]."public-ip"' \
    --raw-output 2>/dev/null || echo "—")
  PRIV_IP=$(oci compute instance list-vnics \
    --instance-id "$id" \
    --compartment-id "$OCI_COMPARTMENT_ID" \
    --region "$OCI_REGION" \
    --query 'data[0]."private-ip"' \
    --raw-output 2>/dev/null || echo "—")
  OCI_PUB_IPS+=("${PUB_IP:-—}")
  OCI_PRIV_IPS+=("${PRIV_IP:-—}")
done < <(oci compute instance list \
  --compartment-id "$OCI_COMPARTMENT_ID" \
  --region "$OCI_REGION" \
  --lifecycle-state RUNNING \
  --query 'data[*].[id,"display-name","lifecycle-state",shape]' \
  --output table 2>/dev/null \
  | grep -v "^\+" | grep -v "^\|.*display" | grep "^\|" \
  | awk -F'|' '{print $2"\t"$3"\t"$4"\t"$5}' \
  | sed 's/ //g' \
  | grep -v "^$" || true)

OCI_HOST=""
if [[ ${#OCI_IDS[@]} -eq 0 ]]; then
  warn "No running OCI Compute instances found."
  echo ""
  echo "  [1]  Enter host IP or hostname manually"
  echo "  [2]  Exit and create an OCI Compute instance first"
  ask "Choice [1]:"
  read -r C; C="${C:-1}"
  [[ "$C" == "2" ]] && { echo "Exiting."; exit 0; }
  ask "OCI VM public IP or hostname:"
  read -r OCI_HOST
  [[ -z "$OCI_HOST" ]] && err "Host cannot be empty"
else
  printf "  %-4s %-22s %-20s %-18s %-10s %s\n" \
    "No." "Instance ID (short)" "Name" "Public IP" "State" "Shape"
  printf "  %-4s %-22s %-20s %-18s %-10s %s\n" \
    "---" "-------------------" "----" "---------" "-----" "-----"
  for i in "${!OCI_IDS[@]}"; do
    SHORT_ID="${OCI_IDS[$i]:(-8)}"
    printf "  [%s]  %-20s %-20s %-18s %-10s %s\n" \
      "$((i+1))" "...${SHORT_ID}" "${OCI_NAMES[$i]}" \
      "${OCI_PUB_IPS[$i]}" "${OCI_STATES[$i]}" "${OCI_SHAPES[$i]}"
  done
  echo ""
  echo "  [$(( ${#OCI_IDS[@]} + 1 ))]  Enter IP manually"
  ask "Which OCI VM to deploy to? [1]:"
  read -r OCI_PICK
  OCI_PICK="${OCI_PICK:-1}"

  if [[ "$OCI_PICK" == "$(( ${#OCI_IDS[@]} + 1 ))" ]]; then
    ask "OCI VM public IP or hostname:"
    read -r OCI_HOST
    [[ -z "$OCI_HOST" ]] && err "Host cannot be empty"
  else
    IDX=$(( OCI_PICK - 1 ))
    if [[ "${OCI_PUB_IPS[$IDX]}" != "—" ]]; then
      OCI_HOST="${OCI_PUB_IPS[$IDX]}"
    else
      OCI_HOST="${OCI_PRIV_IPS[$IDX]}"
      warn "No public IP — using private IP $OCI_HOST (requires VPN or bastion)"
    fi
    ok "Target: ${OCI_IDS[$IDX]}  (${OCI_NAMES[$IDX]})  →  $OCI_HOST"
  fi
fi

# ══════════════════════════════════════════════════════════════
# STEP 3 — SSH CONNECTION DETAILS
# ══════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}──────────────────────────────────────────────${NC}"
echo -e "${BOLD}STEP 3 — SSH Connection Details${NC}"
echo -e "${BOLD}──────────────────────────────────────────────${NC}"

ask "Path to SSH private key (.key or .pem file):"
read -r OCI_KEY
OCI_KEY="${OCI_KEY/#\~/$HOME}"
[[ ! -f "$OCI_KEY" ]] && err "Key file not found: $OCI_KEY"
chmod 400 "$OCI_KEY" 2>/dev/null || true

ask "SSH username [opc]  (Oracle Linux/Ubuntu → opc  |  Ubuntu custom → ubuntu):"
read -r OCI_USER
OCI_USER="${OCI_USER:-opc}"

DEFAULT_REMOTE="/home/${OCI_USER}/ghost-ai-scanner"
ask "Remote directory on OCI VM [$DEFAULT_REMOTE]:"
read -r OCI_REMOTE_DIR
OCI_REMOTE_DIR="${OCI_REMOTE_DIR:-$DEFAULT_REMOTE}"

info "Testing SSH connection to ${OCI_USER}@${OCI_HOST}..."
ssh -i "$OCI_KEY" \
  -o StrictHostKeyChecking=no \
  -o ConnectTimeout=15 \
  "${OCI_USER}@${OCI_HOST}" "echo ok" &>/dev/null \
  && ok "SSH connection successful" \
  || err "SSH connection failed. Check: key path, username, security list port 22 open."

# ══════════════════════════════════════════════════════════════
# STEP 4 — INSTALL DOCKER ON OCI VM (if needed)
# ══════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}──────────────────────────────────────────────${NC}"
echo -e "${BOLD}STEP 4 — Docker Setup on OCI VM${NC}"
echo -e "${BOLD}──────────────────────────────────────────────${NC}"

DOCKER_CHECK=$(ssh -i "$OCI_KEY" -o StrictHostKeyChecking=no \
  "${OCI_USER}@${OCI_HOST}" \
  "command -v docker &>/dev/null && docker --version || echo MISSING" 2>/dev/null)

if [[ "$DOCKER_CHECK" == MISSING ]]; then
  warn "Docker not found on OCI VM."
  ask "Install Docker + Docker Compose now? (y/N):"
  read -r INSTALL_DOCKER
  if [[ "$INSTALL_DOCKER" =~ ^[yY]$ ]]; then
    info "Installing Docker on OCI VM..."
    ssh -i "$OCI_KEY" -o StrictHostKeyChecking=no \
      "${OCI_USER}@${OCI_HOST}" "
      sudo yum install -y yum-utils 2>/dev/null || sudo apt-get update -y 2>/dev/null || true
      curl -fsSL https://get.docker.com | sudo sh
      sudo usermod -aG docker ${OCI_USER}
      sudo systemctl enable --now docker
      sudo curl -L \"https://github.com/docker/compose/releases/latest/download/docker-compose-\$(uname -s)-\$(uname -m)\" \
        -o /usr/local/bin/docker-compose
      sudo chmod +x /usr/local/bin/docker-compose
      docker --version
      docker-compose --version
    " && ok "Docker installed successfully" \
      || err "Docker install failed — check OCI VM internet access"
  else
    warn "Skipping Docker install — install manually before running docker compose"
  fi
else
  ok "Docker found: $DOCKER_CHECK"
fi

# ══════════════════════════════════════════════════════════════
# STEP 5 — SCP CODEBASE
# ══════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}──────────────────────────────────────────────${NC}"
echo -e "${BOLD}STEP 5 — Transfer Codebase${NC}"
echo -e "${BOLD}──────────────────────────────────────────────${NC}"
echo ""
echo "  From : $REPO_DIR"
echo "  To   : ${OCI_USER}@${OCI_HOST}:${OCI_REMOTE_DIR}"
echo ""

FILE_COUNT=$(find "$REPO_DIR" \
  -not -path "*/.git/*" \
  -not -name ".DS_Store" \
  -not -name "*.pyc" \
  -not -path "*/__pycache__/*" \
  -type f | wc -l | tr -d ' ')
echo "  Files to transfer: ~$FILE_COUNT (excluding .git, __pycache__, .DS_Store)"
echo ""
ask "Proceed with transfer? (y/N):"
read -r SCP_CONFIRM
[[ ! "$SCP_CONFIRM" =~ ^[yY]$ ]] && { warn "Transfer cancelled."; exit 0; }

info "Creating remote directory..."
ssh -i "$OCI_KEY" -o StrictHostKeyChecking=no \
  "${OCI_USER}@${OCI_HOST}" "mkdir -p '${OCI_REMOTE_DIR}'"

info "Transferring files..."
rsync -avz --progress \
  --exclude ".git" \
  --exclude "__pycache__" \
  --exclude "*.pyc" \
  --exclude ".DS_Store" \
  --exclude "*.egg-info" \
  --exclude ".env" \
  -e "ssh -i '${OCI_KEY}' -o StrictHostKeyChecking=no" \
  "$REPO_DIR/" \
  "${OCI_USER}@${OCI_HOST}:${OCI_REMOTE_DIR}/" \
  2>/dev/null \
|| {
  warn "rsync not found — falling back to scp (no progress bar)"
  scp -i "$OCI_KEY" \
    -o StrictHostKeyChecking=no \
    -r "$REPO_DIR/." \
    "${OCI_USER}@${OCI_HOST}:${OCI_REMOTE_DIR}/"
}

ok "Codebase transferred to ${OCI_HOST}:${OCI_REMOTE_DIR}"

# ══════════════════════════════════════════════════════════════
# STEP 6 — VERIFY TRANSFER
# ══════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}──────────────────────────────────────────────${NC}"
echo -e "${BOLD}STEP 6 — Verify Transfer${NC}"
echo -e "${BOLD}──────────────────────────────────────────────${NC}"
info "Checking remote file count..."
REMOTE_COUNT=$(ssh -i "$OCI_KEY" -o StrictHostKeyChecking=no \
  "${OCI_USER}@${OCI_HOST}" \
  "find '${OCI_REMOTE_DIR}' -type f | wc -l" 2>/dev/null | tr -d ' ')
ok "Remote file count: $REMOTE_COUNT"

info "Remote directory listing:"
ssh -i "$OCI_KEY" -o StrictHostKeyChecking=no \
  "${OCI_USER}@${OCI_HOST}" \
  "ls -la '${OCI_REMOTE_DIR}/'" 2>/dev/null

# ══════════════════════════════════════════════════════════════
# STEP 7 — MCP SERVER SETUP
# ══════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}──────────────────────────────────────────────${NC}"
echo -e "${BOLD}STEP 7 — MCP Server Setup${NC}"
echo -e "${BOLD}──────────────────────────────────────────────${NC}"

MCP_SCRIPT="${OCI_REMOTE_DIR}/scripts/patronai_mcp_server.py"

info "Installing Python dependencies (includes fastmcp)..."
ssh -i "$OCI_KEY" -o StrictHostKeyChecking=no \
  "${OCI_USER}@${OCI_HOST}" \
  "cd '${OCI_REMOTE_DIR}' && pip install -q -r requirements.txt 2>&1 | tail -5" \
  && ok "Dependencies installed" \
  || warn "pip install had warnings — check manually"

info "Making MCP server script executable..."
ssh -i "$OCI_KEY" -o StrictHostKeyChecking=no \
  "${OCI_USER}@${OCI_HOST}" \
  "chmod +x '${MCP_SCRIPT}'" \
  && ok "Script is executable: $MCP_SCRIPT"

info "Smoke-testing MCP server import..."
MCP_SMOKE=$(ssh -i "$OCI_KEY" -o StrictHostKeyChecking=no \
  "${OCI_USER}@${OCI_HOST}" \
  "cd '${OCI_REMOTE_DIR}' && \
   python -c \"
import sys
sys.path.insert(0, 'src')
from fastmcp import FastMCP
from chat.tools import get_summary_stats
from chat.tools_schema import TOOLS_SCHEMA
print('OK tools=%d' % len(TOOLS_SCHEMA))
\" 2>&1" || echo "FAIL")

if [[ "$MCP_SMOKE" == OK* ]]; then
  ok "MCP smoke test passed — $MCP_SMOKE"
else
  warn "MCP smoke test output: $MCP_SMOKE"
  warn "MCP server may need manual check — continuing deploy"
fi

# Print ready-to-paste Claude Desktop config
OCI_KEY_ABS=$(realpath "$OCI_KEY" 2>/dev/null || echo "$OCI_KEY")
echo ""
echo -e "${BOLD}${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}  PatronAI MCP — Claude Desktop Config${NC}"
echo -e "${BOLD}${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "  Add to: ~/.config/claude/claude_desktop_config.json"
echo "  (macOS: ~/Library/Application Support/Claude/claude_desktop_config.json)"
echo ""
echo '  "mcpServers": {'
echo '    "patronai": {'
echo '      "command": "ssh",'
echo '      "args": ['
echo "        \"-i\", \"${OCI_KEY_ABS}\","
echo '        "-o", "StrictHostKeyChecking=yes",'
echo "        \"${OCI_USER}@${OCI_HOST}\","
echo "        \"python ${MCP_SCRIPT}\""
echo '      ]'
echo '    }'
echo '  }'
echo ""
echo -e "${YELLOW}  Security: SSH stdio only. Access = SSH key to OCI VM.${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

# ══════════════════════════════════════════════════════════════
# STEP 8 — LLM SETUP
# ══════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}──────────────────────────────────────────────${NC}"
echo -e "${BOLD}STEP 8 — LLM Setup (Chat Widget)${NC}"
echo -e "${BOLD}──────────────────────────────────────────────${NC}"

LLM_DETECT=$(ssh -i "$OCI_KEY" -o StrictHostKeyChecking=no \
  "${OCI_USER}@${OCI_HOST}" \
  'if command -v llama-server &>/dev/null; then echo "llama";
   elif command -v ollama &>/dev/null; then echo "ollama";
   else echo "none"; fi' 2>/dev/null)

LLM_BASE_URL_VAL="http://localhost:8080"
LLM_MODEL_VAL=""

if [[ "$LLM_DETECT" == "ollama" ]]; then
  ok "Ollama found on OCI VM"
  LLM_BASE_URL_VAL="http://localhost:11434"
  ask "Ollama model to use [lfm2:1b]  (alternatives: qwen3:8b, llama3.2):"
  read -r OLLAMA_MODEL
  OLLAMA_MODEL="${OLLAMA_MODEL:-lfm2:1b}"
  LLM_MODEL_VAL="$OLLAMA_MODEL"
  info "Pulling model $OLLAMA_MODEL..."
  ssh -i "$OCI_KEY" -o StrictHostKeyChecking=no \
    "${OCI_USER}@${OCI_HOST}" \
    "ollama pull '${OLLAMA_MODEL}'" \
    && ok "Model ready: $OLLAMA_MODEL" \
    || warn "ollama pull had issues — check OCI VM connectivity"
  ssh -i "$OCI_KEY" -o StrictHostKeyChecking=no \
    "${OCI_USER}@${OCI_HOST}" \
    "sudo systemctl enable --now ollama 2>/dev/null || \
     pgrep -f 'ollama serve' >/dev/null || \
     nohup ollama serve >> /tmp/ollama.log 2>&1 &"
  ok "Ollama service running"

elif [[ "$LLM_DETECT" == "none" ]]; then
  warn "No LLM runtime found on OCI VM."
  ask "Install Ollama now? (recommended) (y/N):"
  read -r INSTALL_OLLAMA
  if [[ "$INSTALL_OLLAMA" =~ ^[yY]$ ]]; then
    info "Installing Ollama on OCI VM..."
    ssh -i "$OCI_KEY" -o StrictHostKeyChecking=no \
      "${OCI_USER}@${OCI_HOST}" \
      "curl -fsSL https://ollama.ai/install.sh | sh" \
      && ok "Ollama installed" \
      || err "Ollama install failed — check OCI VM internet access"
    ask "Model to pull [lfm2:1b]  (~750 MB; or qwen3:8b ~5.2 GB):"
    read -r OLLAMA_MODEL
    OLLAMA_MODEL="${OLLAMA_MODEL:-lfm2:1b}"
    LLM_MODEL_VAL="$OLLAMA_MODEL"
    LLM_BASE_URL_VAL="http://localhost:11434"
    LLM_DETECT="ollama"
    info "Pulling $OLLAMA_MODEL..."
    ssh -i "$OCI_KEY" -o StrictHostKeyChecking=no \
      "${OCI_USER}@${OCI_HOST}" \
      "ollama pull '${OLLAMA_MODEL}'" \
      && ok "Model ready: $OLLAMA_MODEL"
    ssh -i "$OCI_KEY" -o StrictHostKeyChecking=no \
      "${OCI_USER}@${OCI_HOST}" \
      "sudo systemctl enable --now ollama 2>/dev/null || \
       nohup ollama serve >> /tmp/ollama.log 2>&1 &"
  else
    warn "Skipping LLM setup — chat widget will show 'LLM server unreachable'."
  fi
else
  ok "llama-server found on OCI VM (port 8080)"
fi

# ══════════════════════════════════════════════════════════════
# DONE + SSH IN
# ══════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}${GREEN}"
echo "=================================================="
echo "  Deploy complete!"
echo "=================================================="
echo -e "${NC}"
echo "  OCI VM:    ${OCI_USER}@${OCI_HOST}"
echo "  Directory: ${OCI_REMOTE_DIR}"
echo "  MCP:       Ready — paste config above into Claude Desktop"
echo "  LLM:       ${LLM_BASE_URL_VAL} (${LLM_DETECT})"
echo ""
echo "Next steps:"
echo "  1. Run prereqs_oci.sh to set up OCI resources and .env"
echo "  2. Run ghost-ai-scanner/scripts/migrate_data.sh to migrate data from AWS"
echo "  3. bash scripts/start.sh"
echo ""
ask "Open SSH session to OCI VM now? (y/N):"
read -r SSH_NOW
if [[ "$SSH_NOW" =~ ^[yY]$ ]]; then
  echo ""
  ok "Connecting to ${OCI_USER}@${OCI_HOST} — landing in ${OCI_REMOTE_DIR}"
  echo ""
  ssh -i "$OCI_KEY" \
    -o StrictHostKeyChecking=no \
    -t \
    "${OCI_USER}@${OCI_HOST}" \
    "cd '${OCI_REMOTE_DIR}' && exec \$SHELL -l"
else
  echo ""
  echo "To connect manually:"
  echo "  ssh -i $OCI_KEY ${OCI_USER}@${OCI_HOST}"
  echo "  cd ${OCI_REMOTE_DIR}"
fi
echo ""
echo -e "${BOLD}Giggso Inc x TrinityOps.ai x AIRTaaS${NC}"
