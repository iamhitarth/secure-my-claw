#!/bin/bash
# Test harness for secure-my-claw guide
# Runs in Docker, validates all code blocks work

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GUIDE_PATH="${1:-$SCRIPT_DIR/../guide.md}"
REPORT_FILE="${2:-$SCRIPT_DIR/test-report.json}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "🧪 Secure-My-Claw Test Harness"
echo "================================"
echo "Guide: $GUIDE_PATH"
echo ""

# Extract blocks
echo "📝 Extracting code blocks..."
BLOCKS=$(node "$SCRIPT_DIR/extract-blocks.js" "$GUIDE_PATH" --testable)
TOTAL=$(echo "$BLOCKS" | jq 'length')
echo "   Found $TOTAL testable blocks"
echo ""

# Initialize counters
PASSED=0
FAILED=0
SKIPPED=0
FAILURES=()

# Test each block
echo "🔍 Running tests..."
echo ""

echo "$BLOCKS" | jq -c '.[]' | while read -r block; do
  TYPE=$(echo "$block" | jq -r '.testType')
  CODE=$(echo "$block" | jq -r '.code')
  LINE=$(echo "$block" | jq -r '.line')
  CONTEXT=$(echo "$block" | jq -r '.context')
  
  case "$TYPE" in
    json-parse)
      # Test if JSON/JSON5 parses
      echo -n "  Line $LINE [$CONTEXT] - JSON parse: "
      
      # Try parsing with node (supports JSON5-ish)
      if echo "$CODE" | node -e "
        const input = require('fs').readFileSync('/dev/stdin', 'utf8');
        try {
          // Try JSON first
          JSON.parse(input);
          process.exit(0);
        } catch {
          // Try as JS object literal (JSON5-like)
          try {
            eval('(' + input + ')');
            process.exit(0);
          } catch (e) {
            console.error(e.message);
            process.exit(1);
          }
        }
      " 2>/dev/null; then
        echo -e "${GREEN}PASS${NC}"
        ((PASSED++)) || true
      else
        echo -e "${RED}FAIL${NC}"
        ((FAILED++)) || true
        FAILURES+=("Line $LINE: JSON parse failed in '$CONTEXT'")
      fi
      ;;
      
    yaml-parse)
      echo -n "  Line $LINE [$CONTEXT] - YAML parse: "
      # YAML blocks in the guide are actually wrong (should be JSON5)
      # This will fail as expected
      if command -v python3 &>/dev/null; then
        if echo "$CODE" | python3 -c "import sys, yaml; yaml.safe_load(sys.stdin)" 2>/dev/null; then
          echo -e "${GREEN}PASS${NC}"
          ((PASSED++)) || true
        else
          echo -e "${RED}FAIL${NC} (expected - guide uses YAML but OpenClaw uses JSON5)"
          ((FAILED++)) || true
          FAILURES+=("Line $LINE: YAML block in '$CONTEXT' - should be JSON5")
        fi
      else
        echo -e "${YELLOW}SKIP${NC} (no python3)"
        ((SKIPPED++)) || true
      fi
      ;;
      
    bash-run|bash-check)
      echo -n "  Line $LINE [$CONTEXT] - Bash syntax: "
      # Just check syntax, don't actually run (could be destructive)
      if bash -n <(echo "$CODE") 2>/dev/null; then
        echo -e "${GREEN}PASS${NC} (syntax)"
        ((PASSED++)) || true
      else
        echo -e "${RED}FAIL${NC} (syntax error)"
        ((FAILED++)) || true
        FAILURES+=("Line $LINE: Bash syntax error in '$CONTEXT'")
      fi
      ;;
      
    *)
      echo "  Line $LINE [$CONTEXT] - ${YELLOW}SKIP${NC} ($TYPE)"
      ((SKIPPED++)) || true
      ;;
  esac
done

echo ""
echo "================================"
echo "Results: $PASSED passed, $FAILED failed, $SKIPPED skipped"

if [ ${#FAILURES[@]} -gt 0 ]; then
  echo ""
  echo -e "${RED}Failures:${NC}"
  for f in "${FAILURES[@]}"; do
    echo "  ❌ $f"
  done
fi

# Write JSON report
cat > "$REPORT_FILE" << EOF
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "guide": "$GUIDE_PATH",
  "total": $TOTAL,
  "passed": $PASSED,
  "failed": $FAILED,
  "skipped": $SKIPPED,
  "failures": $(printf '%s\n' "${FAILURES[@]:-}" | jq -R . | jq -s .)
}
EOF

echo ""
echo "📊 Report written to: $REPORT_FILE"

# Exit with failure if any tests failed
[ "$FAILED" -eq 0 ]
