#!/usr/bin/env bash
# PatronAI agent self-update — Mac/Linux.
#
# Runs hourly via cron/launchd (PatronAI-Update), separate from the 5-min
# heartbeat that notices an update: doing the file swap inline in heartbeat
# would risk a scheduled heartbeat run reading a half-replaced heartbeat.sh
# out from under itself. This script only ever touches the generic script
# bodies (heartbeat/scan/hook_chain/pre_commit_hook/diagnose) plus
# agent_version.txt — it never touches config.json, the *_url files, or
# authorized_domains, so the device's identity/enrollment is untouched by
# an update no matter how it turns out.
#
# heartbeat.sh's own "1. Refresh URLs" step is what writes pending_update.json
# when the backend's urls.json bundle carries a newer version — see that file.
AGENT_DIR="$HOME/.patronai"
CONFIG="$AGENT_DIR/config.json"
PENDING="$AGENT_DIR/pending_update.json"
VERSION_FILE="$AGENT_DIR/agent_version.txt"
LOCK_FILE="$AGENT_DIR/update.lock"
ATTEMPT_FILE="$AGENT_DIR/last_update_attempt.json"
LOG="$AGENT_DIR/agent.log"

[ -f "$CONFIG" ]  || exit 0
[ -f "$PENDING" ] || exit 0

_ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }
_log() {
  # $1=type, rest are already-escaped "key":value fragments
  local type="$1"; shift
  local extra=""
  for kv in "$@"; do extra="$extra,$kv"; done
  echo "{\"ts\":\"$(_ts)\",\"type\":\"$type\"$extra}" >> "$LOG"
}

# --- Lock: crash-safety, not multi-machine coordination ----------------------
# A stale lock (>2h old) is from a killed/crashed prior run, not one still in
# progress — this task only ever runs one instance per machine on an hourly
# trigger, so 2h is generous headroom, not a tight race window.
if [ -f "$LOCK_FILE" ]; then
  STARTED=$(python3 -c "import json; print(json.load(open('$LOCK_FILE')).get('started_at', 0))" 2>/dev/null || echo 0)
  AGE_H=$(python3 -c "import time; print((time.time() - float('$STARTED' or 0)) / 3600)" 2>/dev/null || echo 999)
  if awk "BEGIN{exit !($AGE_H < 2)}"; then exit 0; fi
fi
python3 -c "import json,time; json.dump({'pid': $$, 'started_at': time.time()}, open('$LOCK_FILE','w'))" 2>/dev/null

cleanup_lock() { rm -f "$LOCK_FILE"; }
trap cleanup_lock EXIT

TARGET_VERSION=$(python3 -c "import json; print(json.load(open('$PENDING')).get('latest_agent_version',''))" 2>/dev/null)
BUNDLE_URL=$(python3 -c "import json; print(json.load(open('$PENDING')).get('update_bundle_url',''))" 2>/dev/null)
BUNDLE_SHA256=$(python3 -c "import json; print(json.load(open('$PENDING')).get('update_bundle_sha256',''))" 2>/dev/null)
[ -z "$TARGET_VERSION" ] && exit 0
[ -z "$BUNDLE_URL" ] && exit 0

CURRENT_VERSION=""
[ -f "$VERSION_FILE" ] && CURRENT_VERSION=$(cat "$VERSION_FILE" | tr -d '[:space:]')
if [ "$CURRENT_VERSION" = "$TARGET_VERSION" ]; then
  rm -f "$PENDING"
  exit 0
fi

# --- Cooldown: don't retry the same target more than once per 24h ------------
if [ -f "$ATTEMPT_FILE" ]; then
  SAME_AND_RECENT=$(python3 -c "
import json, time
try:
    d = json.load(open('$ATTEMPT_FILE'))
    print(1 if d.get('target') == '$TARGET_VERSION' and (time.time() - d.get('at', 0)) < 86400 else 0)
except Exception:
    print(0)
" 2>/dev/null)
  [ "$SAME_AND_RECENT" = "1" ] && exit 0
fi

# --- Fetch --------------------------------------------------------------
TMP_ZIP="$(mktemp "${TMPDIR:-/tmp}/patronai-update-XXXXXX.zip")"
if ! curl -fsSL --max-time 60 "$BUNDLE_URL" -o "$TMP_ZIP"; then
  _log "update_failed" "\"reason\":\"download_failed\"" "\"target\":\"$TARGET_VERSION\""
  rm -f "$TMP_ZIP"
  exit 0
fi

# --- Validate: checksum, then a well-formed zip --------------------------
if [ -n "$BUNDLE_SHA256" ]; then
  ACTUAL_SHA=$(shasum -a 256 "$TMP_ZIP" 2>/dev/null | awk '{print $1}')
  [ -z "$ACTUAL_SHA" ] && ACTUAL_SHA=$(sha256sum "$TMP_ZIP" 2>/dev/null | awk '{print $1}')
  if [ "$(echo "$ACTUAL_SHA" | tr 'A-Z' 'a-z')" != "$(echo "$BUNDLE_SHA256" | tr 'A-Z' 'a-z')" ]; then
    _log "update_failed" "\"reason\":\"checksum_mismatch\"" "\"target\":\"$TARGET_VERSION\""
    rm -f "$TMP_ZIP"
    exit 0
  fi
fi

EXTRACT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/patronai-update-extract-XXXXXX")"
if ! unzip -tq "$TMP_ZIP" >/dev/null 2>&1 || ! unzip -q "$TMP_ZIP" -d "$EXTRACT_DIR" >/dev/null 2>&1; then
  _log "update_failed" "\"reason\":\"bad_zip\"" "\"target\":\"$TARGET_VERSION\""
  rm -f "$TMP_ZIP"; rm -rf "$EXTRACT_DIR"
  exit 0
fi

UPDATABLE_FILES="heartbeat.sh scan.sh hook_chain.sh pre_commit_hook.sh diagnose.sh"

# --- Syntax-check every incoming script BEFORE wiring any of them in ---------
# A corrupt/truncated download that still passes zip validation (e.g. a
# bundle built from a broken source tree) must not become the file cron
# invokes next.
SYNTAX_OK=1
for f in $UPDATABLE_FILES; do
  if [ -f "$EXTRACT_DIR/$f" ]; then
    bash -n "$EXTRACT_DIR/$f" 2>/dev/null || SYNTAX_OK=0
  fi
done
if [ "$SYNTAX_OK" != "1" ]; then
  _log "update_failed" "\"reason\":\"syntax_check_failed\"" "\"target\":\"$TARGET_VERSION\""
  rm -f "$TMP_ZIP"; rm -rf "$EXTRACT_DIR"
  exit 0
fi

# --- Backup: file-level, not a directory swap. config.json/*_url files/
# authorized_domains/agent.log/first_run.flag/git-template are never touched,
# so nothing about this device's identity or enrollment can be affected by a
# bad update or a rollback.
BACKUP_DIR="$AGENT_DIR/_backup_${CURRENT_VERSION}_$(date +%s)"
mkdir -p "$BACKUP_DIR"
for f in $UPDATABLE_FILES agent_version.txt; do
  [ -f "$AGENT_DIR/$f" ] && cp "$AGENT_DIR/$f" "$BACKUP_DIR/$f"
done

# --- Apply --------------------------------------------------------------
for f in $UPDATABLE_FILES; do
  if [ -f "$EXTRACT_DIR/$f" ]; then
    cp "$EXTRACT_DIR/$f" "$AGENT_DIR/$f"
    chmod +x "$AGENT_DIR/$f"
  fi
done
echo "$TARGET_VERSION" > "$VERSION_FILE"

# --- Smoke-test: run the NEW heartbeat once, check the log line it appends ---
bash "$AGENT_DIR/heartbeat.sh" || true
sleep 2
SMOKE_OK=0
LAST_LINE=$(grep '"type":"heartbeat"' "$LOG" 2>/dev/null | tail -n 1)
if echo "$LAST_LINE" | grep -qE '"http_status":(2[0-9][0-9])'; then
  SMOKE_OK=1
fi

if [ "$SMOKE_OK" = "1" ]; then
  _log "update_success" "\"from\":\"$CURRENT_VERSION\"" "\"to\":\"$TARGET_VERSION\""
  rm -f "$PENDING"
  # Prune backups older than 14 days — best-effort, never fails the update.
  find "$AGENT_DIR" -maxdepth 1 -type d -name "_backup_*" -mtime +14 -exec rm -rf {} \; 2>/dev/null || true
else
  _log "update_rolled_back" "\"from\":\"$CURRENT_VERSION\"" "\"to\":\"$TARGET_VERSION\""
  for f in $UPDATABLE_FILES agent_version.txt; do
    [ -f "$BACKUP_DIR/$f" ] && cp "$BACKUP_DIR/$f" "$AGENT_DIR/$f"
  done
fi

python3 -c "import json,time; json.dump({'target': '$TARGET_VERSION', 'at': time.time()}, open('$ATTEMPT_FILE','w'))" 2>/dev/null
rm -f "$TMP_ZIP"
rm -rf "$EXTRACT_DIR"
