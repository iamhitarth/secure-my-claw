#!/usr/bin/env bats
# Test: Gemini API integration

load 'setup'

@test "Gemini API key is set" {
    assert [ -n "$GEMINI_API_KEY" ]
}

@test "Gemini API responds to test call" {
    result=$(gemini_test_call)
    
    # Check we got a response (not an error)
    error=$(echo "$result" | jq -r '.error.message // empty')
    assert [ -z "$error" ] || fail "Gemini API error: $error"
    
    # Check we got content back
    text=$(echo "$result" | jq -r '.candidates[0].content.parts[0].text // empty')
    assert [ -n "$text" ]
}

@test "OpenClaw Gemini config block is valid" {
    setup_openclaw_config
    
    # Create config with Gemini as shown in guide
    cat > "$OPENCLAW_CONFIG" << 'EOF'
{
  "gateway": {
    "bind": "127.0.0.1:3000"
  },
  "models": {
    "default": "gemini/gemini-2.0-flash"
  }
}
EOF
    
    run jq '.' "$OPENCLAW_CONFIG"
    assert_success
}
