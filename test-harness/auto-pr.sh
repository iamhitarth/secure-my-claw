#!/bin/bash
# Auto-create PR when validation finds fixable issues
# Called by cron-wrapper.sh when errors are detected

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
BRANCH_PREFIX="auto-fix"
DATE=$(date +%Y-%m-%d)
BRANCH_NAME="${BRANCH_PREFIX}/${DATE}"

cd "$REPO_DIR"

# Check if we're on main
CURRENT_BRANCH=$(git branch --show-current)
if [ "$CURRENT_BRANCH" != "main" ]; then
  echo "⚠️ Not on main branch, skipping auto-PR"
  exit 0
fi

# Check for uncommitted changes
if ! git diff --quiet; then
  echo "⚠️ Uncommitted changes detected, skipping auto-PR"
  exit 0
fi

# Pull latest
git pull --rebase origin main 2>/dev/null || true

# Run validation and capture errors
RESULT=$(node "$SCRIPT_DIR/validate-config-blocks.js" "$REPO_DIR/guide.md" --json 2>&1) || true
ERRORS=$(echo "$RESULT" | jq -r '.summary.totalErrors // 0')

if [ "$ERRORS" -eq 0 ]; then
  echo "✅ No errors to fix"
  exit 0
fi

# Check if branch already exists
if git show-ref --verify --quiet "refs/heads/$BRANCH_NAME"; then
  echo "⚠️ Branch $BRANCH_NAME already exists, skipping"
  exit 0
fi

# Check if PR already exists
EXISTING_PR=$(gh pr list --head "$BRANCH_NAME" --json number --jq '.[0].number' 2>/dev/null || echo "")
if [ -n "$EXISTING_PR" ]; then
  echo "⚠️ PR #$EXISTING_PR already exists for $BRANCH_NAME"
  exit 0
fi

echo "🔧 Creating fix branch: $BRANCH_NAME"
git checkout -b "$BRANCH_NAME"

# Attempt auto-fixes
FIXES_MADE=0

# Fix 1: Replace config.yaml references with openclaw.json
if grep -q "config\.yaml" "$REPO_DIR/guide.md"; then
  sed -i '' 's/config\.yaml/openclaw.json/g' "$REPO_DIR/guide.md"
  FIXES_MADE=$((FIXES_MADE + 1))
  echo "  ✓ Fixed config.yaml → openclaw.json references"
fi

# Fix 2: Update minimum version if schema shows newer
SCHEMA_VERSION=$(jq -r '.upstreamVersion // "unknown"' "$SCRIPT_DIR/openclaw-schema.json" 2>/dev/null || echo "unknown")
if [ "$SCHEMA_VERSION" != "unknown" ]; then
  CURRENT_MIN=$(grep -oE "Minimum Safe Version: [0-9.]+" "$REPO_DIR/guide.md" | grep -oE "[0-9.]+" || echo "")
  if [ -n "$CURRENT_MIN" ] && [ "$SCHEMA_VERSION" \> "$CURRENT_MIN" ]; then
    # Don't auto-update version - flag for manual review instead
    echo "  ⚠️ Upstream version $SCHEMA_VERSION > guide minimum $CURRENT_MIN (needs manual review)"
  fi
fi

# Check if any fixes were made
if [ "$FIXES_MADE" -eq 0 ]; then
  echo "⚠️ No auto-fixable issues found (manual intervention needed)"
  git checkout main
  git branch -D "$BRANCH_NAME"
  exit 0
fi

# Re-run validation
NEW_ERRORS=$(node "$SCRIPT_DIR/validate-config-blocks.js" "$REPO_DIR/guide.md" --json 2>&1 | jq -r '.summary.totalErrors // 0')
FIXED=$((ERRORS - NEW_ERRORS))

if [ "$FIXED" -le 0 ]; then
  echo "⚠️ Fixes didn't reduce errors, aborting"
  git checkout -- "$REPO_DIR/guide.md"
  git checkout main
  git branch -D "$BRANCH_NAME"
  exit 0
fi

# Commit and push
git add "$REPO_DIR/guide.md"
git commit -m "Auto-fix: $FIXED validation errors

Fixed by automated validation cron:
- Errors before: $ERRORS
- Errors after: $NEW_ERRORS
- Fixed: $FIXED

Run: $DATE"

git push -u origin "$BRANCH_NAME"

# Create PR
PR_BODY="## Automated Fix

The daily validation cron detected fixable issues in the security guide.

### Changes
- **Errors before:** $ERRORS
- **Errors after:** $NEW_ERRORS  
- **Fixed:** $FIXED

### Fixes Applied
$(git log -1 --pretty=%B | tail -n +3)

### Validation
\`\`\`
$(./test-harness/cron-wrapper.sh 2>&1 || true)
\`\`\`

---
*Created automatically by [Secure-My-Claw Validator](test-harness/README.md)*"

PR_URL=$(gh pr create \
  --title "Auto-fix: $FIXED validation errors ($DATE)" \
  --body "$PR_BODY" \
  --base main \
  --head "$BRANCH_NAME")

echo "✅ Created PR: $PR_URL"

# Switch back to main
git checkout main

echo ""
echo "PR_URL=$PR_URL"
echo "FIXED=$FIXED"
echo "REMAINING=$NEW_ERRORS"
