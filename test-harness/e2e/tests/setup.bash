# Bats test helpers for Secure-My-Claw E2E

# Load bats helpers
load '/usr/local/lib/bats-support/load'
load '/usr/local/lib/bats-assert/load'

# Discord API helpers
E2E_CHANNEL_ID="1482488306401939641"
DISCORD_API="https://discord.com/api/v10"

discord_post() {
    local message="$1"
    curl -s -X POST "$DISCORD_API/channels/$E2E_CHANNEL_ID/messages" \
        -H "Authorization: Bot $E2E_DISCORD_BOT_TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"content\": \"$message\"}"
}

discord_delete() {
    local message_id="$1"
    curl -s -X DELETE "$DISCORD_API/channels/$E2E_CHANNEL_ID/messages/$message_id" \
        -H "Authorization: Bot $E2E_DISCORD_BOT_TOKEN"
}

discord_get_last() {
    curl -s "$DISCORD_API/channels/$E2E_CHANNEL_ID/messages?limit=1" \
        -H "Authorization: Bot $E2E_DISCORD_BOT_TOKEN"
}

# OpenClaw config helpers
OPENCLAW_CONFIG_DIR="$HOME/.openclaw"
OPENCLAW_CONFIG="$OPENCLAW_CONFIG_DIR/openclaw.json"

setup_openclaw_config() {
    mkdir -p "$OPENCLAW_CONFIG_DIR"
}

cleanup_openclaw_config() {
    rm -rf "$OPENCLAW_CONFIG_DIR"
}

# Gemini API helper
gemini_test_call() {
    curl -s "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=$GEMINI_API_KEY" \
        -H "Content-Type: application/json" \
        -d '{"contents":[{"parts":[{"text":"Reply with exactly: E2E_OK"}]}]}'
}
