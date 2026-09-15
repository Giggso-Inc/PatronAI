#!/usr/bin/env bash
AGENT_DIR="$HOME/.patronai"
CONFIG="$AGENT_DIR/config.json"
[ -f "$CONFIG" ] || exit 0
BUCKET=$(python3 -c "import json; print(json.load(open('$CONFIG'))['bucket'])" 2>/dev/null)
REGION=$(python3 -c "import json; print(json.load(open('$CONFIG'))['region'])" 2>/dev/null)
COMPANY=$(python3 -c "import json; print(json.load(open('$CONFIG'))['company'])" 2>/dev/null)
[ -z "$BUCKET" ] && exit 0
AI_SIGNALS="langchain|langgraph|llama_index|haystack|autogen|crewai|openai|anthropic|pydantic_ai|smolagents|MCPServer|sk-proj-|sk-ant-|hf_[a-zA-Z0-9]"
DIFF=$(git diff --cached --unified=3 2>/dev/null || echo "")
[ -z "$DIFF" ] && exit 0
echo "$DIFF" | grep -qiE "$AI_SIGNALS" || exit 0
DEVICE_ID=$(hostname)
TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
REPO=$(git rev-parse --show-toplevel 2>/dev/null | xargs basename)
BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null)
PAYLOAD=$(python3 -c "
import json,sys
print(json.dumps({'event_type':'GIT_DIFF_SIGNAL','source':'patronai_git_hook',
  'device_id':'${DEVICE_ID}','company':'${COMPANY}','repo':'${REPO}',
  'branch':'${BRANCH}','timestamp':'${TIMESTAMP}','diff_snippet':sys.argv[1]}))" \
  "$(echo "$DIFF" | head -c 5120)" 2>/dev/null)
aws s3 cp - "s3://${BUCKET}/ocsf/agent/git-diffs/${DEVICE_ID}-${TIMESTAMP}.json" \
  --region "$REGION" --content-type "application/json" --quiet <<< "$PAYLOAD" 2>/dev/null &
exit 0
