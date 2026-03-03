#!/bin/bash
# Full test cycle for secure-my-claw guide
# Usage: ./test-guide.sh [--docker] [--notify]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
USE_DOCKER=false
NOTIFY=false
DISCORD_WEBHOOK="${SECURE_MY_CLAW_WEBHOOK:-}"

# Parse args
for arg in "$@"; do
  case $arg in
    --docker) USE_DOCKER=true ;;
    --notify) NOTIFY=true ;;
  esac
done

echo "🧪 Secure-My-Claw Guide Validator"
echo "================================="
echo "Time: $(date)"
echo "Mode: $([ "$USE_DOCKER" = true ] && echo "Docker (isolated)" || echo "Local")"
echo ""

# Run validation
if [ "$USE_DOCKER" = true ]; then
  echo "🐳 Building Docker image..."
  docker build -t secure-my-claw-test "$SCRIPT_DIR" -f "$SCRIPT_DIR/Dockerfile" --quiet

  echo "🔍 Running validation in container..."
  RESULT=$(docker run --rm \
    -v "$REPO_DIR/guide.md:/home/testuser/test-harness/guide.md:ro" \
    secure-my-claw-test \
    node /home/testuser/test-harness/validate-config-blocks.js /home/testuser/test-harness/guide.md --json 2>&1) || true
else
  echo "🔍 Running local validation..."
  RESULT=$(node "$SCRIPT_DIR/validate-config-blocks.js" "$REPO_DIR/guide.md" --json 2>&1) || true
fi

# Parse results
ERRORS=$(echo "$RESULT" | jq -r '.summary.totalErrors // 0')
WARNINGS=$(echo "$RESULT" | jq -r '.summary.totalWarnings // 0')

echo ""
echo "Results:"
echo "  ❌ Errors: $ERRORS"
echo "  ⚠️  Warnings: $WARNINGS"

# Determine status
if [ "$ERRORS" -eq 0 ] && [ "$WARNINGS" -eq 0 ]; then
  STATUS="✅ PASS"
  EXIT_CODE=0
elif [ "$ERRORS" -eq 0 ]; then
  STATUS="⚠️ WARN"
  EXIT_CODE=0
else
  STATUS="❌ FAIL"
  EXIT_CODE=1
fi

echo ""
echo "Status: $STATUS"

# Send Discord notification if requested
if [ "$NOTIFY" = true ] && [ -n "$DISCORD_WEBHOOK" ]; then
  echo ""
  echo "📢 Sending Discord notification..."
  
  # Build message
  MSG="**Secure-My-Claw Daily Validation**\n\n"
  MSG+="Status: $STATUS\n"
  MSG+="Errors: $ERRORS | Warnings: $WARNINGS\n"
  MSG+="Time: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  
  if [ "$ERRORS" -gt 0 ]; then
    MSG+="\n\n**Top Errors:**\n"
    MSG+=$(echo "$RESULT" | jq -r '.errors[:5][] | "• Line \(.line): \(.message)"' | head -5)
  fi

  curl -s -X POST "$DISCORD_WEBHOOK" \
    -H "Content-Type: application/json" \
    -d "{\"content\": \"$MSG\"}" > /dev/null
fi

# Write report
REPORT_FILE="$SCRIPT_DIR/last-run.json"
cat > "$REPORT_FILE" << EOF
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "status": "$STATUS",
  "errors": $ERRORS,
  "warnings": $WARNINGS,
  "mode": "$([ "$USE_DOCKER" = true ] && echo "docker" || echo "local")",
  "details": $RESULT
}
EOF

echo ""
echo "📊 Full report: $REPORT_FILE"

exit $EXIT_CODE
