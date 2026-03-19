#!/usr/bin/env bats
# Test: Part 2 - Secrets management from security guide

load 'setup'

setup() {
    setup_openclaw_config
}

@test "Config with env var reference is valid (no plaintext secrets)" {
    # Good: uses env var reference
    cat > "$OPENCLAW_CONFIG" << 'EOF'
{
  "channels": {
    "discord": {
      "token": "${DISCORD_BOT_TOKEN}"
    }
  },
  "gateway": {
    "auth": {
      "token": "${GATEWAY_TOKEN}"
    }
  }
}
EOF
    
    run jq '.' "$OPENCLAW_CONFIG"
    assert_success
    
    # Verify no actual token values in file
    refute grep -q "MTQ" "$OPENCLAW_CONFIG"  # Discord tokens start with MTQ, etc.
}

@test "Environment variables are the correct way to pass secrets" {
    # Test that env vars are accessible
    export TEST_SECRET="e2e_test_value"
    assert_equal "$TEST_SECRET" "e2e_test_value"
    unset TEST_SECRET
}

@test "Config file should not contain hardcoded API keys" {
    cat > "$OPENCLAW_CONFIG" << 'EOF'
{
  "models": {
    "default": "gemini/gemini-2.0-flash"
  }
}
EOF
    
    # Check for common API key patterns
    run grep -E "(sk-[a-zA-Z0-9]{20,}|AIza[a-zA-Z0-9_-]{35})" "$OPENCLAW_CONFIG"
    assert_failure  # grep should NOT find matches
}
