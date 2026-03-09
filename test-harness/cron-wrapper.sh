#!/bin/bash
# Wrapper for cron execution - outputs markdown summary for agent

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
BASELINE_FILE="$SCRIPT_DIR/.error-baseline"
SCHEMA_FILE="$SCRIPT_DIR/openclaw-schema.json"

# Sync schema from upstream OpenClaw (weekly or if missing)
SCHEMA_AGE_DAYS=7
if [ ! -f "$SCHEMA_FILE" ] || [ $(find "$SCHEMA_FILE" -mtime +$SCHEMA_AGE_DAYS 2>/dev/null | wc -l) -gt 0 ]; then
  echo "📥 Syncing schema from upstream OpenClaw..."
  bash "$SCRIPT_DIR/sync-schema.sh" 2>/dev/null || echo "⚠️ Schema sync failed, using cached"
  echo ""
fi

# Run validation
RESULT=$(node "$SCRIPT_DIR/validate-config-blocks.js" "$REPO_DIR/guide.md" --json 2>&1)
ERRORS=$(echo "$RESULT" | jq -r '.summary.totalErrors // 0')

# Get baseline
BASELINE=0
if [ -f "$BASELINE_FILE" ]; then
  BASELINE=$(cat "$BASELINE_FILE")
fi

# Calculate delta
DELTA=$((ERRORS - BASELINE))

# Output for agent
echo "## Secure-My-Claw Validator Results"
echo ""
echo "| Metric | Value |"
echo "|--------|-------|"
echo "| Current Errors | $ERRORS |"
echo "| Baseline | $BASELINE |"
echo "| Delta | $DELTA |"
echo ""

if [ "$DELTA" -gt 0 ]; then
  echo "⚠️ **ALERT:** Errors increased by $DELTA since last baseline!"
  echo ""
  echo "New errors:"
  echo "$RESULT" | jq -r '.errors[-'$DELTA':][] | "- Line \(.line): \(.message)"' 2>/dev/null || echo "(Could not parse new errors)"
elif [ "$DELTA" -lt 0 ]; then
  echo "✅ **Progress:** Errors decreased by ${DELTA#-}!"
else
  echo "ℹ️ No change in error count."
fi

# Update baseline if errors decreased or first run
if [ "$ERRORS" -lt "$BASELINE" ] || [ ! -f "$BASELINE_FILE" ]; then
  echo "$ERRORS" > "$BASELINE_FILE"
  echo ""
  echo "(Baseline updated to $ERRORS)"
fi
