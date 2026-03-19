#!/usr/bin/env bats
# Test: Discord channel integration

load 'setup'

setup() {
    # Ensure clean state
    setup_openclaw_config
}

teardown() {
    # Clean up any test messages
    :
}

@test "Discord bot token is set" {
    assert [ -n "$E2E_DISCORD_BOT_TOKEN" ]
}

@test "Discord bot can post to e2e-test channel" {
    result=$(discord_post "🧪 Bats E2E test - $(date +%s)")
    message_id=$(echo "$result" | jq -r '.id')
    
    assert [ "$message_id" != "null" ]
    assert [ -n "$message_id" ]
    
    # Cleanup
    discord_delete "$message_id"
}

@test "Discord bot can read messages from e2e-test channel" {
    # Post a unique message
    unique="E2E_READ_TEST_$(date +%s)"
    result=$(discord_post "$unique")
    message_id=$(echo "$result" | jq -r '.id')
    
    # Wait a moment for Discord
    sleep 1
    
    # Read it back
    last=$(discord_get_last)
    last_content=$(echo "$last" | jq -r '.[0].content')
    
    assert_equal "$last_content" "$unique"
    
    # Cleanup
    discord_delete "$message_id"
}

@test "Discord bot can delete messages (cleanup capability)" {
    # Post
    result=$(discord_post "🗑️ Delete test - $(date +%s)")
    message_id=$(echo "$result" | jq -r '.id')
    
    # Delete
    discord_delete "$message_id"
    
    # Verify deleted (should get 404 or empty)
    sleep 1
    check=$(curl -s "$DISCORD_API/channels/$E2E_CHANNEL_ID/messages/$message_id" \
        -H "Authorization: Bot $E2E_DISCORD_BOT_TOKEN")
    
    # Message should not exist or return error
    code=$(echo "$check" | jq -r '.code // empty')
    assert [ "$code" = "10008" ] || [ -z "$(echo "$check" | jq -r '.id // empty')" ]
}

@test "OpenClaw Discord config block is valid JSON5" {
    # Create a minimal Discord config as shown in the guide
    cat > "$OPENCLAW_CONFIG" << 'EOF'
{
  "channels": {
    "discord": {
      "token": "${E2E_DISCORD_BOT_TOKEN}",
      "allowlist": ["1482488306401939641"]
    }
  }
}
EOF
    
    # Validate JSON
    run jq '.' "$OPENCLAW_CONFIG"
    assert_success
}
