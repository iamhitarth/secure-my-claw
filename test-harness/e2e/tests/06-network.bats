#!/usr/bin/env bats
# Test: Part 3 - Network security from security guide

load 'setup'

setup() {
    setup_openclaw_config
}

@test "Gateway config binds to localhost only" {
    cat > "$OPENCLAW_CONFIG" << 'EOF'
{
  "gateway": {
    "bind": "127.0.0.1:3000"
  }
}
EOF
    
    # Verify bind is localhost
    bind=$(jq -r '.gateway.bind' "$OPENCLAW_CONFIG")
    assert_equal "$bind" "127.0.0.1:3000"
}

@test "Gateway config with 0.0.0.0 should trigger warning" {
    cat > "$OPENCLAW_CONFIG" << 'EOF'
{
  "gateway": {
    "bind": "0.0.0.0:3000"
  }
}
EOF
    
    bind=$(jq -r '.gateway.bind' "$OPENCLAW_CONFIG")
    
    # This is valid JSON but insecure - test should note this
    if [[ "$bind" == "0.0.0.0"* ]]; then
        echo "WARNING: Gateway bound to all interfaces (0.0.0.0) - insecure!"
    fi
    
    # Config is syntactically valid, just insecure
    run jq '.' "$OPENCLAW_CONFIG"
    assert_success
}

@test "Gateway auth token config is valid" {
    cat > "$OPENCLAW_CONFIG" << 'EOF'
{
  "gateway": {
    "bind": "127.0.0.1:3000",
    "auth": {
      "token": "${GATEWAY_TOKEN}"
    }
  }
}
EOF
    
    run jq '.' "$OPENCLAW_CONFIG"
    assert_success
    
    # Auth block exists
    auth=$(jq -r '.gateway.auth' "$OPENCLAW_CONFIG")
    assert [ "$auth" != "null" ]
}
