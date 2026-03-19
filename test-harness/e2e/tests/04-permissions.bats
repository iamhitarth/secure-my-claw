#!/usr/bin/env bats
# Test: Part 1 - File permissions from security guide

load 'setup'

setup() {
    setup_openclaw_config
}

@test "Config directory permissions can be set to 700" {
    chmod 700 "$OPENCLAW_CONFIG_DIR"
    
    perms=$(stat -c %a "$OPENCLAW_CONFIG_DIR" 2>/dev/null || stat -f %Lp "$OPENCLAW_CONFIG_DIR")
    assert_equal "$perms" "700"
}

@test "Config file permissions can be set to 600" {
    touch "$OPENCLAW_CONFIG"
    chmod 600 "$OPENCLAW_CONFIG"
    
    perms=$(stat -c %a "$OPENCLAW_CONFIG" 2>/dev/null || stat -f %Lp "$OPENCLAW_CONFIG")
    assert_equal "$perms" "600"
}

@test "Running as non-root user" {
    run whoami
    assert_success
    refute_output "root"
}

@test "User is not in sudoers without password (test user exception)" {
    # This is informational - test user has NOPASSWD for testing
    # Real deployments should NOT have NOPASSWD
    skip "Test user has NOPASSWD for automation - skip in E2E"
}
