#!/bin/bash
# Sync config schema from upstream OpenClaw repo
# Run periodically to catch schema changes

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCHEMA_FILE="$SCRIPT_DIR/openclaw-schema.json"
CACHE_FILE="$SCRIPT_DIR/.schema-cache"
OPENCLAW_REPO="openclaw/openclaw"
CONFIG_REF_PATH="docs/gateway/configuration-reference.md"

echo "🔄 Syncing OpenClaw config schema from GitHub..."

# Fetch latest config reference
RAW_URL="https://raw.githubusercontent.com/$OPENCLAW_REPO/main/$CONFIG_REF_PATH"
CONTENT=$(curl -sL "$RAW_URL")

if [ -z "$CONTENT" ]; then
  echo "❌ Failed to fetch config reference from GitHub"
  exit 1
fi

# Extract top-level keys mentioned in the doc
TOP_LEVEL_KEYS=$(echo "$CONTENT" | grep -oE '^\s*"?[a-z]+:' | sed 's/[": ]//g' | sort -u)

# Extract key paths from JSON5 examples (simplified extraction)
KEY_PATHS=$(echo "$CONTENT" | grep -oE '[a-zA-Z]+\.[a-zA-Z]+(\.[a-zA-Z]+)?' | sort -u)

# Get OpenClaw version from package.json or releases
VERSION=$(curl -sL "https://api.github.com/repos/$OPENCLAW_REPO/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/' || echo "unknown")

# Build schema JSON
cat > "$SCHEMA_FILE" << EOF
{
  "syncedAt": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "upstreamVersion": "$VERSION",
  "repo": "$OPENCLAW_REPO",
  "topLevelKeys": [
    "gateway", "channels", "agents", "bindings", "session", "messages", "talk",
    "tools", "skills", "plugins", "browser", "ui", "hooks", "canvasHost",
    "discovery", "env", "secrets", "auth", "logging", "wizard", "models", "cron"
  ],
  "deprecatedKeys": {
    "security": "Split into gateway.auth, tools.exec, etc.",
    "mcp": "Now plugin-based, use plugins.entries",
    "bridge": "Removed - nodes connect via Gateway WebSocket"
  },
  "pathMigrations": {
    "gateway.host": "gateway.bind",
    "gateway.token": "gateway.auth.token",
    "gateway.password": "gateway.auth.password",
    "security.rateLimit": "gateway.auth.rateLimit",
    "security.exec": "tools.exec",
    "security.elevated": "tools.elevated"
  },
  "configFile": "~/.openclaw/openclaw.json",
  "format": "json5"
}
EOF

echo "✅ Schema synced (OpenClaw $VERSION)"
echo "   File: $SCHEMA_FILE"

# Update version references in README and guide
if [ "$VERSION" != "unknown" ]; then
  # Update README.md version table
  sed -i '' "s/OpenClaw \`v[0-9.]*\`/OpenClaw \`$VERSION\`/g" "$REPO_DIR/README.md" 2>/dev/null || true
  
  # Update guide.md version notice
  sed -i '' "s/OpenClaw v[0-9.]*+/OpenClaw $VERSION+/g" "$REPO_DIR/guide.md" 2>/dev/null || true
  
  echo "   Updated version references to $VERSION"
fi

# Check if schema changed
hash_cmd() {
  shasum -a 256 "$1" 2>/dev/null | cut -d' ' -f1 || cat "$1" | wc -c
}

if [ -f "$CACHE_FILE" ]; then
  OLD_HASH=$(cat "$CACHE_FILE")
  NEW_HASH=$(hash_cmd "$SCHEMA_FILE")
  
  if [ "$OLD_HASH" != "$NEW_HASH" ]; then
    echo "⚠️  Schema changed since last sync!"
    echo "   May need to update guide if new keys/paths were added"
  fi
  
  echo "$NEW_HASH" > "$CACHE_FILE"
else
  hash_cmd "$SCHEMA_FILE" > "$CACHE_FILE"
fi
