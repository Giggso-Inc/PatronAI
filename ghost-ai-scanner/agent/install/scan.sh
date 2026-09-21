#!/usr/bin/env bash
# PatronAI endpoint scan — multi-surface
AGENT_DIR="$HOME/.patronai"
[ -f "$AGENT_DIR/config.json" ] || exit 0
[ -f "$AGENT_DIR/scan_url" ]    || exit 0
SCAN_URL=$(cat "$AGENT_DIR/scan_url")
[ -z "$SCAN_URL" ] && exit 0
PATRONAI_TOKEN=$(python3 -c "import json; print(json.load(open('$AGENT_DIR/config.json'))['token'])" 2>/dev/null)
PATRONAI_COMPANY=$(python3 -c "import json; print(json.load(open('$AGENT_DIR/config.json'))['company'])" 2>/dev/null)
export PATRONAI_TOKEN PATRONAI_COMPANY

# Refresh live authorised list from S3 (presigned GET; admin can edit
# without reinstalling). Falls back to baked-in list on expiry.
AUTH_URL=$(cat "$AGENT_DIR/authorized_url" 2>/dev/null || echo "")
if [ -n "$AUTH_URL" ]; then
  LIVE=$(curl -fsSL --max-time 10 "$AUTH_URL" 2>/dev/null || echo "")
  [ -n "$LIVE" ] && echo "$LIVE" > "$AGENT_DIR/authorized_domains"
fi

python3 << 'PYEOF'
{{INLINE_SCAN_PYTHON}}
PYEOF
