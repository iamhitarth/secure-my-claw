#!/bin/bash
# Run E2E tests in Docker
# Usage: ./run-e2e-docker.sh [--notify]

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
E2E_DIR="$SCRIPT_DIR/e2e"
LOG_DIR="$HOME/.openclaw/logs"
mkdir -p "$LOG_DIR"
DIAG_FILE="$LOG_DIR/e2e-orbstack-$(date +%Y%m%d-%H%M%S).log"

# Mirror all stdout/stderr to a per-run log so we can inspect failures later.
exec > >(tee -a "$DIAG_FILE") 2>&1

echo "OrbStack/E2E diagnostic log: $DIAG_FILE"

# Load env vars
if [ -f "$SCRIPT_DIR/.env" ]; then
    export $(grep -v '^#' "$SCRIPT_DIR/.env" | xargs)
fi

run_diag_cmd() {
    local label="$1"
    shift
    echo
    echo "---- $label ----"
    "$@" 2>&1 || true
}

run_diag_shell() {
    local label="$1"
    local cmd="$2"
    echo
    echo "---- $label ----"
    bash -lc "$cmd" 2>&1 || true
}

collect_orbstack_diag() {
    local stage="$1"
    echo
    echo "=== OrbStack diagnostics: $stage ==="
    run_diag_shell "date / uptime" 'date; uptime'
    run_diag_cmd "orb version" orb version
    run_diag_cmd "orb status" timeout 10 orb status
    run_diag_cmd "docker context ls" timeout 10 docker context ls
    run_diag_cmd "docker version" timeout 10 docker version
    run_diag_cmd "docker info" timeout 10 docker info
    run_diag_shell "processes" "ps aux | egrep 'OrbStack|orbstack|docker' | grep -v egrep"
    run_diag_shell "launchd gateway env" "launchctl print gui/$UID/ai.openclaw.gateway 2>/dev/null | sed -n '/EnvironmentVariables/,/\<\/dict\>/p'"
    run_diag_shell "OrbStack logs" 'ls -la ~/Library/Logs/OrbStack 2>/dev/null; tail -100 ~/Library/Logs/OrbStack/*.log 2>/dev/null'
    run_diag_shell "gateway log" 'tail -100 ~/.openclaw/logs/gateway.log 2>/dev/null'
    run_diag_shell "docker desktop / OrbStack app state" "osascript -e 'tell application \"System Events\" to (name of every process)' 2>/dev/null | tr ',' '\n' | grep -i -E 'orbstack|docker'"
}

# Aggressive OrbStack recovery function
# OrbStack can get stuck after macOS sleep/wake cycles (known issue: GitHub #1933, #2003)
recover_orbstack() {
    echo "Force-killing OrbStack processes..."
    pkill -9 -f "OrbStack" 2>/dev/null || true
    pkill -9 -f "com.orbstack" 2>/dev/null || true
    sleep 3
    
    echo "Starting OrbStack fresh..."
    open -gj -a OrbStack 2>/dev/null || true
    
    # Wait up to 90 seconds for Docker to become available
    for i in {1..18}; do
        sleep 5
        if docker info >/dev/null 2>&1; then
            echo "OrbStack recovered after $((i*5))s"
            return 0
        fi
        echo "Waiting for Docker... ($((i*5))s)"
    done

    collect_orbstack_diag "recovery timeout"
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
        collect_orbstack_diag "soft-start timeout"
        if ! recover_orbstack; then
            echo "ERROR: Docker is not available after recovery attempts."
            echo "OrbStack may be in a bad state. Manual intervention required."
            collect_orbstack_diag "final failure after recovery"
            exit 1
        fi
    fi
fi

# Verify Docker is actually responsive (not just socket exists)
if ! timeout 10 docker ps >/dev/null 2>&1; then
    echo "Docker socket exists but commands hang. Attempting recovery..."
    collect_orbstack_diag "docker ps hang"
    if ! recover_orbstack; then
        echo "ERROR: Docker is unresponsive. Manual intervention required."
        collect_orbstack_diag "final failure after hang"
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
