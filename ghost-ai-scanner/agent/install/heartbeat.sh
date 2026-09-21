#!/usr/bin/env bash
# Step 0 heartbeat: refresh URLs → emit identity-bound payload → log outcome.
AGENT_DIR="$HOME/.patronai"
LOG="$AGENT_DIR/agent.log"
[ -f "$AGENT_DIR/config.json" ] || exit 0

# 1. Refresh URLs daily — best-effort. If urls.json reachable, overwrite local copies.
REFRESH_URL=$(cat "$AGENT_DIR/urls_refresh_url" 2>/dev/null || echo "")
if [ -n "$REFRESH_URL" ]; then
  BUNDLE=$(curl -fsSL --max-time 10 "$REFRESH_URL" 2>/dev/null || echo "")
  if [ -z "$BUNDLE" ]; then
    # urls_refresh_url is itself a presigned URL with the same 7-day TTL
    # and nothing re-pushes a fresh one to this laptop — the 2026-06 fleet
    # heartbeat outage RCA. Fall back to the server's token-authenticated
    # refresh endpoint (no API key needed).
    TOKEN=$(python3 -c "import json;print(json.load(open('$AGENT_DIR/config.json'))['token'])" 2>/dev/null)
    if [ -n "$TOKEN" ]; then
      # Feed the URL to curl via -K/stdin rather than the command line — a
      # token embedded directly in argv is visible to any other local user
      # via `ps` / `/proc/<pid>/cmdline` for the process's lifetime
      # (PR#10 review, M1). `printf` here is bash's builtin, not an exec'd
      # process, so the token is never a separate process's argv.
      BUNDLE=$(printf 'url = "https://patronai.giggso.com/agent/url-refresh/%s"\n' "$TOKEN" \
               | curl -fsSL --max-time 10 -K - 2>/dev/null || echo "")
    fi
  fi
  if [ -n "$BUNDLE" ]; then
    python3 - <<PYREFRESH 2>/dev/null
import json, os
b = json.loads("""$BUNDLE""")
for k, fname in (("heartbeat_put_url","heartbeat_url"),
                 ("scan_put_url","scan_url"),
                 ("authorized_get_url","authorized_url")):
    if b.get(k):
        open(os.path.expanduser("~/.patronai/" + fname), "w").write(b[k])
# apply_update.sh (hourly cron/launchd job) picks this up - never applied
# inline here, so a scheduled apply_update run can never read this same
# heartbeat.sh half-replaced out from under this very process.
if b.get("update_available"):
    pending = {k: b.get(k, "") for k in
               ("latest_agent_version", "update_bundle_url", "update_bundle_sha256")}
    json.dump(pending, open(os.path.expanduser("~/.patronai/pending_update.json"), "w"))
PYREFRESH
  fi
fi

# 2. Emit heartbeat with full identity binding.
[ -f "$AGENT_DIR/heartbeat_url" ] || exit 0
HB_URL=$(cat "$AGENT_DIR/heartbeat_url")
export PATRONAI_TOKEN="$(python3 -c "import json;print(json.load(open('$AGENT_DIR/config.json'))['token'])" 2>/dev/null)"
export PATRONAI_COMPANY="$(python3 -c "import json;print(json.load(open('$AGENT_DIR/config.json'))['company'])" 2>/dev/null)"
PAYLOAD=$(python3 - <<PYHB
import json, os, platform, socket, uuid
from datetime import datetime, timezone
cfg = json.load(open(os.path.expanduser("~/.patronai/config.json")))
try:
    ips = sorted({ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")})
except Exception:
    ips = []
# Read from agent_version.txt rather than a literal baked into this script -
# apply_update.sh bumps that file in place, so every heartbeat after a
# successful update reports the new version with no change to heartbeat.sh.
try:
    agent_version = open(os.path.expanduser("~/.patronai/agent_version.txt")).read().strip() or "unknown"
except Exception:
    agent_version = "unknown"
print(json.dumps({
    "event_type":   "HEARTBEAT",
    "status":       "installed",
    "device_id":    platform.node(),
    "device_uuid":  cfg.get("device_uuid",""),
    "mac_primary":  cfg.get("mac_primary",""),
    "ip_set":       ips,
    "email":        cfg.get("email",""),
    "token":        cfg.get("token",""),
    "company":      cfg.get("company",""),
    "os_name":      platform.system(),
    "os_version":   platform.release(),
    "agent_version":agent_version,
    "timestamp":    datetime.now(timezone.utc).isoformat(),
}))
PYHB
)
HTTP=$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 \
       -X PUT "$HB_URL" -H 'Content-Type: application/json' -d "$PAYLOAD")
TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)
echo "{\"ts\":\"$TS\",\"type\":\"heartbeat\",\"http_status\":$HTTP}" >> "$LOG"

# 4. Hook coverage backstop (Step 0.1) — every 5 min, ensure every git
# repo under $HOME (depth 6) has our chain-installed pre-commit hook.
# Catches repos cloned before the agent was installed and any rare
# miss by the init.templateDir path. Idempotent via the chain
# library — pre-existing Raven/husky/user hooks are preserved as
# pre-commit.pre-patronai and called from our chain script.
HOOK_SCRIPT="$AGENT_DIR/pre_commit_hook.sh"
HOOK_CHAIN_LIB="$AGENT_DIR/hook_chain.sh"
[ -f "$HOOK_SCRIPT" ] || exit 0
[ -f "$HOOK_CHAIN_LIB" ] || exit 0
# shellcheck disable=SC1090
source "$HOOK_CHAIN_LIB"
ADDED=0
MARKER="PatronAI managed pre-commit chain"
while IFS= read -r -d '' GIT_DIR; do
    HP="$GIT_DIR/hooks/pre-commit"
    # Skip the noisy majority: chain already present. Otherwise let
    # the library decide whether to preserve, replace, or install.
    if [ -f "$HP" ] && grep -q "$MARKER" "$HP" 2>/dev/null; then
        continue
    fi
    if pa_install_chain_hook "$GIT_DIR/hooks"; then
        ADDED=$((ADDED + 1))
    fi
done < <(find "$HOME" -maxdepth 6 -name ".git" -type d -print0 2>/dev/null)
[ "$ADDED" -gt 0 ] && \
    echo "{\"ts\":\"$TS\",\"type\":\"hook_backstop\",\"added\":$ADDED}" >> "$LOG"
