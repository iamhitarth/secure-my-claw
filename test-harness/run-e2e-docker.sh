#!/bin/bash
# Run E2E tests in Docker
# Usage: ./run-e2e-docker.sh [--notify]

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
E2E_DIR="$SCRIPT_DIR/e2e"

# Load env vars
if [ -f "$SCRIPT_DIR/.env" ]; then
    export $(grep -v '^#' "$SCRIPT_DIR/.env" | xargs)
fi

# Aggressive OrbStack recovery function
# OrbStack can get stuck after macOS sleep/wake cycles (known issue: GitHub #1933, #2003)
recover_orbstack() {
    echo "Force-killing OrbStack processes..."
    pkill -9 -f "OrbStack" 2>/dev/null || true
    pkill -9 -f "com.orbstack" 2>/dev/null || true
    sleep 3
    
    echo "Starting OrbStack fresh..."
    open -a OrbStack
    
    # Wait up to 90 seconds for Docker to become available
    for i in {1..18}; do
        sleep 5
        if docker info >/dev/null 2>&1; then
            echo "OrbStack recovered after $((i*5))s"
            return 0
        fi
        echo "Waiting for Docker... ($((i*5))s)"
    done
    return 1
}

# Check if Docker is available
if ! docker info >/dev/null 2>&1; then
    echo "Docker not responding, attempting to start OrbStack..."
    open -a OrbStack 2>/dev/null || true
    
    # Wait up to 30 seconds for soft start
    for i in {1..6}; do
        sleep 5
        if docker info >/dev/null 2>&1; then
            echo "OrbStack started successfully"
            break
        fi
        echo "Waiting for Docker... ($((i*5))s)"
    done
    
    # If still not responding, try aggressive recovery
    if ! docker info >/dev/null 2>&1; then
        echo "Soft start failed, attempting aggressive recovery..."
        if ! recover_orbstack; then
            echo "ERROR: Docker is not available after recovery attempts."
            echo "OrbStack may be in a bad state. Manual intervention required."
            exit 1
        fi
    fi
fi

# Verify Docker is actually responsive (not just socket exists)
if ! timeout 10 docker ps >/dev/null 2>&1; then
    echo "Docker socket exists but commands hang. Attempting recovery..."
    if ! recover_orbstack; then
        echo "ERROR: Docker is unresponsive. Manual intervention required."
        exit 1
    fi
fi

# Also check ~/.zshrc for GEMINI_API_KEY
if [ -z "$GEMINI_API_KEY" ]; then
    GEMINI_API_KEY=$(grep GEMINI_API_KEY ~/.zshrc 2>/dev/null | sed 's/.*="\([^"]*\)".*/\1/' | head -1)
    export GEMINI_API_KEY
fi

# Validate required env vars
if [ -z "$E2E_DISCORD_BOT_TOKEN" ]; then
    echo "ERROR: E2E_DISCORD_BOT_TOKEN not set"
    echo "Add it to $SCRIPT_DIR/.env"
    exit 1
fi

if [ -z "$GEMINI_API_KEY" ]; then
    echo "ERROR: GEMINI_API_KEY not set"
    exit 1
fi

echo "Building E2E test container..."
cd "$E2E_DIR"
docker compose build --quiet

echo "Running E2E tests..."
echo ""

# Run and capture output
OUTPUT=$(docker compose run --rm e2e-test 2>&1) || EXIT_CODE=$?
EXIT_CODE=${EXIT_CODE:-0}

echo "$OUTPUT"

# Notify Discord if requested
if [ "$1" = "--notify" ] || [ "$NOTIFY" = "true" ]; then
    WEBHOOK="${SECURE_MY_CLAW_WEBHOOK:-}"
    CHANNEL_ID="1482488306401939641"
    
    if [ $EXIT_CODE -eq 0 ]; then
        STATUS="✅ **E2E Tests Passed**"
    else
        STATUS="❌ **E2E Tests Failed**"
    fi
    
    # Post to Discord via bot
    curl -s -X POST "https://discord.com/api/v10/channels/$CHANNEL_ID/messages" \
        -H "Authorization: Bot $E2E_DISCORD_BOT_TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"content\": \"$STATUS\n\nRun at: $(date)\nExit code: $EXIT_CODE\"}" > /dev/null
fi

# Cleanup
docker compose down --volumes --remove-orphans 2>/dev/null || true

exit $EXIT_CODE
