#!/bin/bash
# Secure-My-Claw E2E Test Runner
# Runs inside Docker container

set -e

echo "================================================"
echo "  Secure-My-Claw E2E Test Suite"
echo "  $(date)"
echo "================================================"
echo ""

# Check required env vars
if [ -z "$E2E_DISCORD_BOT_TOKEN" ]; then
    echo "ERROR: E2E_DISCORD_BOT_TOKEN not set"
    exit 1
fi

if [ -z "$GEMINI_API_KEY" ]; then
    echo "ERROR: GEMINI_API_KEY not set"
    exit 1
fi

# Verify OpenClaw installed
echo "Checking OpenClaw installation..."
OPENCLAW_VERSION=$(openclaw --version 2>/dev/null || echo "not installed")
echo "  OpenClaw version: $OPENCLAW_VERSION"

if [ "$OPENCLAW_VERSION" = "not installed" ]; then
    echo "ERROR: OpenClaw not installed"
    exit 1
fi

echo ""

# Run Bats tests
echo "Running E2E tests..."
echo ""

bats --tap /home/testuser/tests/*.bats

echo ""
echo "================================================"
echo "  E2E Tests Complete"
echo "================================================"
