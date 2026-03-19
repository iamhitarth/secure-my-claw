#!/usr/bin/env bats
# Test: OpenClaw installation and basic setup

load 'setup'

@test "OpenClaw is installed" {
    run openclaw --version
    assert_success
    # Output format: "OpenClaw 2026.3.13 (hash)"
    assert_output --regexp 'OpenClaw [0-9]+\.[0-9]+\.[0-9]+'
}

@test "OpenClaw version is at minimum safe version (2026.2.25)" {
    raw=$(openclaw --version)
    # Extract version number from "OpenClaw 2026.3.13 (hash)"
    version=$(echo "$raw" | sed -E 's/OpenClaw ([0-9]+\.[0-9]+\.[0-9]+).*/\1/')
    
    # Extract major.minor.patch
    IFS='.' read -r major minor patch <<< "$version"
    
    # 2026.2.25 or higher
    if [ "$major" -gt 2026 ]; then
        return 0
    elif [ "$major" -eq 2026 ] && [ "$minor" -gt 2 ]; then
        return 0
    elif [ "$major" -eq 2026 ] && [ "$minor" -eq 2 ] && [ "$patch" -ge 25 ]; then
        return 0
    else
        fail "Version $version is below minimum safe version 2026.2.25"
    fi
}

@test "OpenClaw config directory can be created" {
    setup_openclaw_config
    assert [ -d "$OPENCLAW_CONFIG_DIR" ]
}

@test "OpenClaw help command works" {
    run openclaw --help
    assert_success
    assert_output --partial "openclaw"
}
