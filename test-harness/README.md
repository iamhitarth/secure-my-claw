# Secure-My-Claw Test Harness

Self-validating documentation system for the OpenClaw security guide.

## What It Does

```
┌─────────────────────────────────────────────────────────────┐
│                    Daily Validation (4am NZT)               │
├─────────────────────────────────────────────────────────────┤
│  1. Sync schema from openclaw/openclaw (weekly refresh)     │
│  2. Extract all code blocks from guide.md                   │
│  3. Validate config blocks against current OpenClaw schema  │
│  4. Compare error count to baseline                         │
│  5. Report to Discord thread if delta != 0                  │
└─────────────────────────────────────────────────────────────┘
```

## Files

| File | Purpose |
|------|---------|
| `validate-config-blocks.js` | Core validator - checks JSON5/YAML blocks against schema |
| `extract-blocks.js` | Extracts code blocks from markdown |
| `sync-schema.sh` | Fetches latest config schema from GitHub |
| `cron-wrapper.sh` | Entry point for cron - outputs markdown summary |
| `test-guide.sh` | Manual test runner with Docker support |
| `openclaw-schema.json` | Cached schema from upstream |
| `.error-baseline` | Last known error count (currently: 0) |
| `.schema-cache` | Hash to detect schema changes |

## Manual Usage

```bash
# Quick validation
node validate-config-blocks.js ../guide.md

# Full test with report
./test-guide.sh

# Sync schema from upstream
./sync-schema.sh

# Run exactly what cron runs
./cron-wrapper.sh
```

## Cron Job Details

**Name:** `Secure-My-Claw Validator`  
**Schedule:** `0 4 * * *` (4am NZT daily)  
**Agent:** Uses `claude-haiku-4-5` for cost efficiency  
**Delivery:** Discord thread `1473562889645195316`

### Cron Behavior

| Condition | Action |
|-----------|--------|
| Errors increased | 🚨 Alert Discord with new errors |
| Errors decreased | 🎉 Celebrate progress |
| No change, 0 errors | Reply `HEARTBEAT_OK` (silent) |
| No change, >0 errors | Reply `HEARTBEAT_OK` (silent) |
| Schema changed upstream | ⚠️ Flag for review |

## What Gets Validated

1. **Config format** - Must be JSON5, not YAML
2. **File references** - Must reference `openclaw.json`, not `config.yaml`
3. **Top-level keys** - Must exist in current OpenClaw schema
4. **Key paths** - Must use current paths (e.g., `gateway.bind` not `gateway.host`)
5. **Deprecated keys** - Flags use of removed config options

## Fixing Errors

When errors are found:

1. Run `node validate-config-blocks.js ../guide.md` to see details
2. Fix the config block in `guide.md`
3. Re-run validator to confirm fix
4. Commit changes
5. Update `.error-baseline` if needed: `echo "0" > .error-baseline`

## Adding New Validations

Edit `validate-config-blocks.js`:

- `VALID_TOP_LEVEL_KEYS` - Add new top-level config keys
- `DEPRECATED_KEYS` - Add removed keys with migration notes
- `PATH_MIGRATIONS` - Add old→new path mappings

## Schema Sync

The `sync-schema.sh` script:
1. Fetches `docs/gateway/configuration-reference.md` from `openclaw/openclaw`
2. Extracts config structure into `openclaw-schema.json`
3. Alerts if schema changed since last sync

**Refresh frequency:** Weekly (or when `openclaw-schema.json` is missing)

## Upstream Tracking

Currently tracking: **OpenClaw v2026.3.8**

When OpenClaw releases new versions with config changes:
1. Cron detects schema change
2. Review new/changed keys
3. Update guide if needed
4. Update validator if new keys added
