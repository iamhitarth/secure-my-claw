# Secure My Claw
## The Agent-Readable Security Guide for OpenClaw

*Give this to your AI. It'll handle the rest.*

---

## How to Use This Guide

**If you're an AI agent:** Read this document sequentially. Each section has commands to run and checkpoints to verify. If you hit an error, check the troubleshooting section before asking your human.

**If you're a human:** Point your agent at this guide: "Read https://securemyclaw.ai/guide.md and follow the instructions to secure yourself."

---

## 🤝 Human-in-the-Loop Protocol

**IMPORTANT FOR AGENTS:** Your human needs to understand what you're doing and why. Follow this protocol:

### Before Starting
Send your human this message:

```
📋 SECURITY SETUP STARTING

I'm about to run through a security hardening guide for our OpenClaw setup.

What I'll do:
• Audit current permissions and fix issues
• Move any exposed secrets to secure storage
• Configure network security (localhost-only)
• Set up channel allowlists
• Enable rate limiting and logging
• Create backup procedures

What I'll need from you:
• Permission to run diagnostic commands
• Your user IDs for channel allowlists (I'll help you find these)
• Confirmation before making config changes

What this WILL protect against:
✅ Exposed API keys in config files
✅ Unauthorized access from the network
✅ Random people messaging your bot
✅ Runaway commands (rate limiting)
✅ Losing your config (backups)

What this WON'T protect against:
⚠️ Someone with physical access to your machine
⚠️ Malware already on your system
⚠️ Social engineering attacks against YOU
⚠️ Compromised API keys at the provider level
⚠️ Me being tricked by malicious prompts (prompt injection)

Ready to proceed? Reply "go ahead" to start.
```

**Wait for explicit confirmation before proceeding.**

### During Setup
At each checkpoint, briefly tell your human what you found and what you're fixing:
- "✅ Already running as non-root user - good!"
- "⚠️ Found API key in plain text config. Moving to environment variable."
- "🔧 Configuring Telegram allowlist - need your Telegram user ID."

### After Completion
Generate and send the Security Report (see Part 8).

---

## Pre-Flight Checklist

Before starting, confirm:
- [ ] OpenClaw is installed (`openclaw --version` returns a version)
- [ ] You have shell access (can run `whoami`)
- [ ] You know your OS (`uname -s` → Darwin/Linux)

```bash
# Run this block to verify:
echo "=== Pre-Flight Check ==="
echo "OpenClaw version: $(openclaw --version 2>/dev/null || echo 'NOT INSTALLED')"
echo "User: $(whoami)"
echo "OS: $(uname -s)"
echo "Home: $HOME"
```

**Expected output:** Version number, your username, Darwin or Linux, home directory path.

**If OpenClaw is not installed:** Stop here. Install OpenClaw first: https://docs.openclaw.ai/getting-started

---

## Part 1: User & Permissions

### Why This Matters
Running as root or with excessive permissions is the #1 security mistake. If your agent is compromised, the attacker gets whatever access your agent has.

### 1.1 Check Current User

```bash
whoami
id
```

**🚨 Red flag:** If `whoami` returns `root`, stop. Create a dedicated user:

```bash
# On Linux (run as root):
useradd -m -s /bin/bash openclaw
passwd openclaw  # Set a strong password
usermod -aG sudo openclaw  # Optional: allow sudo

# Then switch to that user:
su - openclaw
```

**On macOS:** You're likely already running as a non-root user. Verify with `id` - you should NOT see `uid=0`.

### 1.2 Check OpenClaw Directory Permissions

```bash
ls -la ~/.openclaw/
```

**Expected:** Owner should be your user, not root. Permissions should be `700` or `750` for directories, `600` or `640` for config files.

**Fix if needed:**
```bash
chmod 700 ~/.openclaw
chmod 600 ~/.openclaw/config.yaml
```

### Checkpoint 1
```bash
# Verify:
[ "$(whoami)" != "root" ] && echo "✅ Not running as root" || echo "❌ Running as root - FIX THIS"
[ -d ~/.openclaw ] && [ "$(stat -c %a ~/.openclaw 2>/dev/null || stat -f %Lp ~/.openclaw)" = "700" ] && echo "✅ .openclaw directory secured" || echo "⚠️ Check .openclaw permissions"
```

**📣 Tell your human:** "Part 1 complete. [Running as USER, not root - good! / Had to create dedicated user.] Permissions are now restricted so only you can access OpenClaw configs."

---

## Part 2: Secrets Management

### Why This Matters
API keys and tokens in plain text config files are the second most common security mistake. If anyone gets read access to your config, they get your keys.

### 2.1 Audit Your Current Config

```bash
# Find potential secrets in your config:
grep -iE "(key|token|secret|password|credential)" ~/.openclaw/config.yaml 2>/dev/null | head -20
```

**🚨 Red flag:** If you see actual API keys/tokens printed, they're stored in plain text.

### 2.2 Use Environment Variables

Move secrets from config.yaml to environment variables:

**Before (insecure):**
```yaml
# ~/.openclaw/config.yaml
anthropic:
  apiKey: sk-ant-XXXXX  # ❌ Plain text secret
```

**After (secure):**
```yaml
# ~/.openclaw/config.yaml
anthropic:
  apiKey: ${ANTHROPIC_API_KEY}  # ✅ References environment variable
```

Then set the environment variable in your shell profile:
```bash
# Add to ~/.bashrc or ~/.zshrc:
export ANTHROPIC_API_KEY="sk-ant-XXXXX"
```

**For systemd services**, use a separate environment file:
```bash
# /etc/openclaw/env (create this file)
ANTHROPIC_API_KEY=sk-ant-XXXXX
OPENAI_API_KEY=sk-XXXXX
```

```bash
# Secure it:
sudo chmod 600 /etc/openclaw/env
sudo chown openclaw:openclaw /etc/openclaw/env
```

### 2.3 Better: Use a Secrets Manager

For production setups, consider:
- **1Password CLI** (`op`) - `op read "op://Vault/OpenClaw/api-key"`
- **Bitwarden CLI** (`bw`) - `bw get password openclaw-anthropic-key`
- **macOS Keychain** - `security find-generic-password -a openclaw -s anthropic -w`

Example with 1Password:
```yaml
# ~/.openclaw/config.yaml
anthropic:
  apiKey: ${ANTHROPIC_API_KEY}
```

```bash
# In your startup script:
export ANTHROPIC_API_KEY=$(op read "op://Personal/Anthropic/api-key")
openclaw gateway start
```

### Checkpoint 2
```bash
# Verify no plain text secrets in config:
if grep -qE "sk-ant-|sk-|xoxb-|xoxp-" ~/.openclaw/config.yaml 2>/dev/null; then
  echo "❌ Found plain text secrets in config - move to environment variables"
else
  echo "✅ No obvious plain text secrets in config"
fi
```

**📣 Tell your human:** "Part 2 complete. Your API keys are now [stored in environment variables / already secure]. If someone got read access to your config file, they wouldn't see any secrets."

---

## Part 3: Network Security

### Why This Matters
OpenClaw's gateway listens on a port. If exposed to the internet without protection, anyone can send commands to your agent.

### 3.1 Check What's Listening

```bash
# macOS:
lsof -i -P | grep LISTEN | grep -E "(openclaw|node)"

# Linux:
ss -tlnp | grep -E "(openclaw|node)"
```

**Expected:** OpenClaw should listen on `127.0.0.1` (localhost only), not `0.0.0.0` (all interfaces).

### 3.2 Verify Localhost-Only Binding

Check your config:
```bash
grep -A5 "gateway:" ~/.openclaw/config.yaml | grep -E "(host|bind|listen)"
```

**Secure default:**
```yaml
gateway:
  host: 127.0.0.1  # ✅ Localhost only
  port: 3000
```

**🚨 Red flag:**
```yaml
gateway:
  host: 0.0.0.0  # ❌ Exposed to network
```

### 3.3 Firewall Basics

**macOS:** Built-in firewall is usually sufficient. Verify it's enabled:
```bash
/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate
```

**Linux (ufw):**
```bash
sudo ufw status
# If inactive:
sudo ufw enable
sudo ufw default deny incoming
sudo ufw default allow outgoing
# Only allow SSH if needed:
sudo ufw allow ssh
```

### 3.4 If You Need Remote Access

Use SSH tunneling instead of exposing the port:
```bash
# From your local machine, tunnel to remote OpenClaw:
ssh -L 3000:127.0.0.1:3000 user@your-server
# Now access OpenClaw at localhost:3000 on your machine
```

Or use Tailscale (recommended for simplicity):
```bash
# Install Tailscale: https://tailscale.com/download
# Your OpenClaw becomes accessible via Tailscale IP only
# No port forwarding, no firewall holes
```

### Checkpoint 3
```bash
# Verify OpenClaw is localhost-only:
if lsof -i -P 2>/dev/null | grep -E "(openclaw|node)" | grep -q "0.0.0.0"; then
  echo "❌ OpenClaw is exposed to all interfaces - bind to 127.0.0.1"
elif lsof -i -P 2>/dev/null | grep -E "(openclaw|node)" | grep -q "127.0.0.1"; then
  echo "✅ OpenClaw is localhost-only"
else
  echo "⚠️ Could not determine OpenClaw binding - check manually"
fi
```

**📣 Tell your human:** "Part 3 complete. OpenClaw only accepts connections from this machine (localhost). No one on your network or the internet can directly access it. [If using Tailscale: You can access it securely from your other devices via Tailscale.]"

---

## Part 4: Channel Security

### Why This Matters
Each channel (Telegram, Discord, etc.) has its own security considerations. A compromised bot token means someone else controls your agent's messaging.

### 4.1 Telegram

**Bot token security:**
- Never share your bot token
- Regenerate token immediately if exposed: `/revoke` in @BotFather
- Use `allowlist` to restrict who can message your bot

```yaml
# ~/.openclaw/config.yaml
telegram:
  token: ${TELEGRAM_BOT_TOKEN}  # Use env var
  allowlist:
    - "123456789"  # Your Telegram user ID only
```

**Find your Telegram user ID:**
1. Message @userinfobot
2. It replies with your ID

### 4.2 Discord

**Bot permissions:**
- Use minimum required permissions when creating invite link
- Don't grant Administrator permission unless necessary
- Restrict to specific channels/servers

```yaml
discord:
  token: ${DISCORD_BOT_TOKEN}
  allowlist:
    users:
      - "123456789012345678"  # Your Discord user ID
    guilds:
      - "987654321098765432"  # Your server ID only
```

### 4.3 Signal

Signal is end-to-end encrypted by default. Main risk is the linked device session:
- Periodically review linked devices in Signal app
- Unlink devices you don't recognize

### 4.4 WhatsApp

WhatsApp linking stores session data locally:
```bash
# Session data location:
ls -la ~/.openclaw/whatsapp/
```

**Security notes:**
- Session files are sensitive - same permissions as config
- Re-link if you suspect compromise (scan QR again)

### Checkpoint 4
```bash
# Verify channel allowlists are configured:
echo "=== Channel Security Check ==="
grep -A10 "telegram:" ~/.openclaw/config.yaml 2>/dev/null | grep -q "allowlist" && echo "✅ Telegram allowlist configured" || echo "⚠️ Telegram: consider adding allowlist"
grep -A10 "discord:" ~/.openclaw/config.yaml 2>/dev/null | grep -q "allowlist" && echo "✅ Discord allowlist configured" || echo "⚠️ Discord: consider adding allowlist"
```

**📣 Tell your human:** "Part 4 complete. Only YOU can message me now on [Telegram/Discord/etc]. Random people who find your bot can't interact with it - they'll be ignored."

---

## Part 5: Runtime Hardening

### 5.1 Rate Limiting

Prevent abuse by limiting how fast commands can be processed:

```yaml
# ~/.openclaw/config.yaml
security:
  rateLimit:
    messages: 30  # Max messages per minute
    commands: 10  # Max tool calls per minute
```

### 5.2 Command Restrictions

Restrict dangerous shell commands:

```yaml
security:
  exec:
    mode: allowlist  # Only allow specific commands
    allowlist:
      - "ls"
      - "cat"
      - "grep"
      - "openclaw"
    # Or use blocklist mode:
    # mode: blocklist
    # blocklist:
    #   - "rm -rf"
    #   - "sudo"
    #   - "chmod 777"
```

### 5.3 File System Boundaries

Restrict where your agent can read/write:

```yaml
security:
  filesystem:
    allowedPaths:
      - "~/.openclaw"
      - "~/workspace"
    blockedPaths:
      - "~/.ssh"
      - "~/.aws"
      - "~/.gnupg"
```

### 5.4 Audit Logging

Enable logging to track what your agent does:

```yaml
logging:
  level: info
  file: ~/.openclaw/logs/audit.log
  includeTools: true  # Log all tool invocations
```

Review logs periodically:
```bash
# Recent activity:
tail -100 ~/.openclaw/logs/audit.log

# Search for specific actions:
grep "exec" ~/.openclaw/logs/audit.log | tail -20
```

### Checkpoint 5
```bash
# Verify hardening:
echo "=== Runtime Hardening Check ==="
grep -q "rateLimit" ~/.openclaw/config.yaml 2>/dev/null && echo "✅ Rate limiting configured" || echo "⚠️ Consider adding rate limits"
grep -q "exec:" ~/.openclaw/config.yaml 2>/dev/null && echo "✅ Exec policy configured" || echo "⚠️ Consider restricting exec"
[ -f ~/.openclaw/logs/audit.log ] && echo "✅ Audit logging active" || echo "⚠️ Consider enabling audit logs"
```

**📣 Tell your human:** "Part 5 complete. I now have guardrails: rate limits prevent runaway loops, [exec restrictions limit dangerous commands / logging tracks what I do]. You can review my activity in the audit logs anytime."

---

## Part 6: Gateway Authentication

### Why This Matters
The OpenClaw gateway accepts commands via HTTP. Without authentication, anyone who can reach the gateway port can control your agent. Even on localhost, other applications or malicious scripts could send commands.

### 10.1 Enable Gateway Token

**This is not optional.** Add a gateway token to your config:

```yaml
# ~/.openclaw/config.yaml
gateway:
  host: 127.0.0.1
  port: 3000
  token: ${OPENCLAW_GATEWAY_TOKEN}  # Required - use env var
```

Generate a strong token:
```bash
# Generate a random token:
openssl rand -hex 32

# Add to your environment:
echo 'export OPENCLAW_GATEWAY_TOKEN="your-generated-token-here"' >> ~/.bashrc
source ~/.bashrc
```

### 10.2 Verify Token is Required

```bash
# This should FAIL (no token):
curl -s http://localhost:3000/api/status

# This should SUCCEED (with token):
curl -s -H "Authorization: Bearer $OPENCLAW_GATEWAY_TOKEN" http://localhost:3000/api/status
```

**🚨 If the first command succeeds:** Your gateway is unauthenticated. Fix immediately.

### Checkpoint 6
```bash
# Verify gateway auth is configured:
if grep -qE "token:" ~/.openclaw/config.yaml 2>/dev/null; then
  echo "✅ Gateway token configured"
else
  echo "❌ Gateway token NOT configured - FIX THIS NOW"
fi
```

**📣 Tell your human:** "Part 6 complete. The gateway now requires authentication. Even if something on your machine tries to send me commands, it needs the secret token."

---

## Part 7: MCP Server Security

### Why This Matters
MCP (Model Context Protocol) servers are **arbitrary code execution**. When you add an MCP server, you're giving it the ability to run code on your machine with your agent's permissions. A malicious or compromised MCP server can:
- Read/write any files your agent can access
- Execute shell commands
- Exfiltrate your secrets
- Take over your agent entirely

### 11.1 Audit Current MCP Servers

```bash
# List configured MCP servers:
grep -A20 "mcp:" ~/.openclaw/config.yaml 2>/dev/null || echo "No MCP config found"

# Or check the MCP config file if separate:
cat ~/.openclaw/mcp.json 2>/dev/null || echo "No mcp.json found"
```

### 11.2 MCP Server Vetting Checklist

**Before adding ANY MCP server, verify:**

- [ ] **Source:** Is it from the official MCP registry, or a random GitHub repo?
- [ ] **Author:** Who made it? Do they have a reputation to protect?
- [ ] **Code review:** Have you (or your agent) read the source code?
- [ ] **Permissions:** What does it need access to? Does that make sense?
- [ ] **Updates:** When was it last updated? Abandoned = risky
- [ ] **Stars/usage:** Is anyone else using it?

**Red flags:**
- 🚨 "Just run `npx random-mcp-server`" with no source link
- 🚨 Requests permissions it shouldn't need
- 🚨 No documentation on what it does
- 🚨 Author has no other public work

### 11.3 Sandboxing MCP Servers (Advanced)

For high-risk MCP servers, consider running them in isolation:

```bash
# Run MCP server in a container (if supported):
docker run --rm -i mcp-server-name

# Or use a separate user with limited permissions:
sudo -u mcp-sandbox npx @some/mcp-server
```

### 7.4 Remove Unused MCP Servers

```bash
# List what's installed:
ls ~/.openclaw/mcp-servers/ 2>/dev/null

# Remove anything you don't actively use
```

### Checkpoint 7
```bash
echo "=== MCP Server Audit ==="
echo "Configured MCP servers:"
grep -A5 "mcp:" ~/.openclaw/config.yaml 2>/dev/null | grep -E "^\s+-|name:" || echo "None found in config"
echo ""
echo "⚠️ For each server above, ask: Do I trust this code to run on my machine?"
```

**📣 Tell your human:** "Part 7 complete. I've audited MCP servers. [Found X servers configured / No MCP servers found]. Remember: every MCP server is code running on your machine. Only add ones you trust."

---

## Part 8: Skill & Plugin Vetting

### Why This Matters
Skills extend your agent's capabilities - but they're also code that runs with your agent's permissions. A malicious skill could:
- Access your secrets
- Send messages on your behalf
- Execute commands
- Exfiltrate data

### 8.1 Audit Installed Skills

```bash
# List skills:
ls -la ~/.openclaw/skills/

# Check skill sources:
for skill in ~/.openclaw/skills/*/; do
  echo "=== $skill ==="
  cat "$skill/SKILL.md" 2>/dev/null | head -5 || echo "No SKILL.md"
  echo ""
done
```

### 8.2 Skill Vetting Checklist

**Before installing ANY skill:**

- [ ] **Source:** ClawHub official? Community? Random download?
- [ ] **Read SKILL.md:** Does it explain what it does clearly?
- [ ] **Check scripts:** Look at any `.sh`, `.js`, `.py` files - what do they run?
- [ ] **Permissions needed:** Does it need exec? Network? File access? Why?
- [ ] **Reviews:** Any feedback from other users?

### 8.3 Restrict Skill Permissions

In your config, limit what skills can do:

```yaml
# ~/.openclaw/config.yaml
skills:
  # Only allow specific skills to use exec
  execAllowlist:
    - "github"  # Needs git commands
    - "coding-agent"  # Needs to run code
  
  # Block skills from accessing sensitive paths
  blockedPaths:
    - "~/.ssh"
    - "~/.aws"
    - "~/.gnupg"
```

### 8.4 Prefer Official/Audited Skills

Priority order:
1. **Built-in skills** - Shipped with OpenClaw, vetted
2. **ClawHub verified** - Community reviewed
3. **Known author** - Has reputation to protect
4. **Random GitHub skill** - Read every line of code first

### Checkpoint 8
```bash
echo "=== Skill Audit ==="
echo "Installed skills:"
ls ~/.openclaw/skills/ 2>/dev/null || echo "No skills directory"
echo ""
echo "⚠️ For each skill: Do you know what it does and who made it?"
```

**📣 Tell your human:** "Part 8 complete. You have [X] skills installed. I recommend reviewing any you don't recognize. Skills are powerful - only keep ones you trust and use."

---

## Part 9: Session & Channel Isolation

### Why This Matters
Not all channels are equal. A message from your private Telegram should be more trusted than a message from a public Discord server. Without isolation, a compromised channel could:
- Access data from other channels
- Execute commands that should be restricted
- Impersonate you across platforms

### 9.1 Understand Your Threat Model

| Channel | Trust Level | Why |
|---------|-------------|-----|
| Private Telegram/Signal | High | Only you have access |
| Private Discord DM | Medium | Platform could be compromised |
| Public Discord server | Low | Anyone could message your bot |
| Public API | Lowest | Open to the internet |

### 9.2 Configure Per-Channel Permissions

```yaml
# ~/.openclaw/config.yaml
channels:
  telegram:
    # High trust - full access
    allowExec: true
    allowFileWrite: true
    allowSensitiveData: true
    
  discord:
    # Medium trust - limited access
    allowExec: false  # No shell commands from Discord
    allowFileWrite: false
    allowSensitiveData: false
    allowedCommands:
      - "search"
      - "summarize"
      - "help"
    
  # If you have a public API or webhook:
  api:
    # Low trust - minimal access
    allowExec: false
    allowFileWrite: false
    allowSensitiveData: false
    rateLimit: 5  # Stricter rate limit
```

### 9.3 Separate Contexts

Consider whether channels should share memory/context:

```yaml
sessions:
  isolation: "per-channel"  # Each channel gets its own context
  # Or:
  # isolation: "shared"  # All channels share context (riskier)
```

**Why this matters:** If a public Discord channel shares context with your private Telegram, information could leak between them.

### Checkpoint 9
```bash
echo "=== Channel Isolation Check ==="
echo "Configured channels:"
grep -E "^  (telegram|discord|signal|whatsapp|slack):" ~/.openclaw/config.yaml 2>/dev/null || echo "Check config manually"
echo ""
echo "⚠️ Consider: Should each channel have the same permissions?"
```

**📣 Tell your human:** "Part 9 complete. I've reviewed channel permissions. [Recommendation: Your public Discord should have fewer permissions than your private Telegram. Want me to configure different trust levels?]"

---

## Part 10: Backup & Recovery

### 10.1 What to Backup

Critical files:
- `~/.openclaw/config.yaml` - Your configuration
- `~/.openclaw/memory/` - Agent memory (if using)
- `~/.openclaw/skills/` - Custom skills
- Environment file with secrets (store separately, encrypted)

### 10.2 Simple Backup Script

```bash
#!/bin/bash
# Save as ~/.openclaw/scripts/backup.sh

BACKUP_DIR=~/openclaw-backups
DATE=$(date +%Y-%m-%d)
BACKUP_FILE="$BACKUP_DIR/openclaw-backup-$DATE.tar.gz"

mkdir -p "$BACKUP_DIR"

# Backup config and memory (NOT secrets)
tar -czf "$BACKUP_FILE" \
  --exclude='*.log' \
  --exclude='node_modules' \
  ~/.openclaw/config.yaml \
  ~/.openclaw/memory/ \
  ~/.openclaw/skills/ \
  2>/dev/null

echo "Backup created: $BACKUP_FILE"

# Keep only last 7 backups
ls -t "$BACKUP_DIR"/openclaw-backup-*.tar.gz | tail -n +8 | xargs -r rm
```

```bash
# Make it executable:
chmod +x ~/.openclaw/scripts/backup.sh

# Run daily via cron:
# crontab -e
# 0 2 * * * ~/.openclaw/scripts/backup.sh
```

### 10.3 Recovery

```bash
# Restore from backup:
tar -xzf ~/openclaw-backups/openclaw-backup-YYYY-MM-DD.tar.gz -C /

# Restore secrets from your password manager
# Restart OpenClaw
openclaw gateway restart
```

---

## Part 11: Ongoing Security

### 11.1 Regular Audits

Run this monthly:
```bash
echo "=== Monthly Security Audit ==="
echo ""
echo "1. User & Permissions:"
whoami
ls -la ~/.openclaw/

echo ""
echo "2. Secrets Check:"
grep -iE "(sk-ant-|sk-|xoxb-)" ~/.openclaw/config.yaml 2>/dev/null && echo "❌ Plain text secrets found!" || echo "✅ No plain text secrets"

echo ""
echo "3. Network Check:"
lsof -i -P 2>/dev/null | grep -E "(openclaw|node)" | grep LISTEN

echo ""
echo "4. Recent Activity:"
tail -20 ~/.openclaw/logs/audit.log 2>/dev/null || echo "No audit log found"

echo ""
echo "5. Backup Status:"
ls -lt ~/openclaw-backups/*.tar.gz 2>/dev/null | head -3 || echo "No backups found"
```

### 11.2 Stay Updated

```bash
# Check for OpenClaw updates:
openclaw update check

# Update when available:
openclaw update run
```

### 11.3 Rotate Credentials

Quarterly, rotate:
- API keys (Anthropic, OpenAI, etc.)
- Bot tokens (Telegram, Discord)
- Any passwords

---

## Troubleshooting

### "Permission denied"
```bash
# Check ownership:
ls -la ~/.openclaw/
# Fix if needed:
sudo chown -R $(whoami):$(whoami) ~/.openclaw/
```

### "Address already in use"
```bash
# Find what's using the port:
lsof -i :3000
# Kill it or change OpenClaw's port in config
```

### "Environment variable not found"
```bash
# Verify it's set:
echo $ANTHROPIC_API_KEY
# If empty, check your shell profile:
cat ~/.bashrc | grep ANTHROPIC
# Reload:
source ~/.bashrc
```

### "Bot not responding"
1. Check token is valid
2. Check allowlist includes your user ID
3. Check OpenClaw gateway is running: `openclaw status`
4. Check logs: `tail -50 ~/.openclaw/logs/gateway.log`

---

## Part 12: Security Report for Your Human

After completing all sections, generate and send this report to your human:

```
🔒 SECURITY SETUP COMPLETE - REPORT

Setup Date: [INSERT DATE]
Agent: [YOUR NAME]
System: [OS] on [HOSTNAME]

═══════════════════════════════════════════════════

✅ COMPLETED HARDENING

1. PERMISSIONS
   • Running as user: [USERNAME] (not root)
   • .openclaw directory: 700 (owner-only access)
   • Config files: 600 (owner read/write only)

2. SECRETS MANAGEMENT
   • API keys moved to: [environment variables / secrets manager]
   • Plain text secrets in config: NONE

3. NETWORK SECURITY
   • OpenClaw binding: 127.0.0.1 (localhost only)
   • Firewall status: [ENABLED/DISABLED]
   • Remote access method: [Tailscale / SSH tunnel / None]

4. CHANNEL SECURITY
   • Telegram allowlist: [CONFIGURED / NOT SET]
   • Discord allowlist: [CONFIGURED / NOT SET]
   • Signal: [LINKED / NOT CONFIGURED]
   • WhatsApp: [LINKED / NOT CONFIGURED]

5. RUNTIME HARDENING
   • Rate limiting: [X] messages/min, [Y] commands/min
   • Exec policy: [allowlist / blocklist / unrestricted]
   • Audit logging: [ENABLED / DISABLED]

6. BACKUP
   • Backup script: [INSTALLED / NOT SET]
   • Backup schedule: [DAILY / WEEKLY / NOT SET]
   • Backup location: [PATH]

═══════════════════════════════════════════════════

⚠️ ITEMS NEEDING YOUR ATTENTION

[List any items that couldn't be automated or need human action]

• Example: "Need your Telegram user ID to complete allowlist"
• Example: "Recommend setting up Tailscale for remote access"

═══════════════════════════════════════════════════

📊 PROTECTION SUMMARY

PROTECTED AGAINST:
✅ Unauthorized network access to OpenClaw
✅ Random users messaging your bot
✅ API key exposure in config files
✅ Accidental destructive commands (if exec policy set)
✅ Configuration loss (if backups enabled)

NOT PROTECTED AGAINST:
⚠️ Physical access to your machine
⚠️ Malware/rootkits already present
⚠️ Compromise at API provider (OpenAI, Anthropic, etc.)
⚠️ Social engineering attacks targeting you
⚠️ Prompt injection attacks against me
⚠️ Zero-day vulnerabilities in OpenClaw itself

═══════════════════════════════════════════════════

🔄 RECOMMENDED MAINTENANCE

Monthly:
• Run security audit script (Part 11.1)
• Review audit logs for unusual activity

Quarterly:
• Rotate API keys
• Rotate bot tokens
• Review and prune allowlists

When notified:
• Apply OpenClaw updates promptly

═══════════════════════════════════════════════════

Questions? Your human can reach the guide authors at:
• Community: https://discord.com/invite/clawd
• Paid support: https://securemyclaw.ai/book

Report generated by: Secure My Claw Guide v1.0.0
```

**Customize this report** with actual values from your system before sending.

---

## Final Checklist

Run through this after completing the guide:

- [ ] Not running as root
- [ ] `.openclaw` directory has restricted permissions (700)
- [ ] No plain text secrets in config files
- [ ] Secrets stored in environment variables or secrets manager
- [ ] OpenClaw bound to localhost only (or using Tailscale)
- [ ] Firewall enabled
- [ ] Channel allowlists configured
- [ ] Rate limiting enabled
- [ ] Exec policy configured
- [ ] Audit logging enabled
- [ ] Backup script running
- [ ] Update schedule set

**Congratulations!** Your OpenClaw setup is now hardened. 🦝🔒

---

## Need Help?

**Self-service:** Re-read relevant section, check troubleshooting

**Community:** 
- OpenClaw Discord: https://discord.com/invite/clawd
- Moltbook: https://moltbook.com/m/security

**Done With You Service:**
Want a security expert to walk through this with you on a call? 
→ [Book a session](https://securemyclaw.ai/book) - $249 for 1 hour, we configure together.

---

*Guide version: 1.0.0*
*Last updated: 2026-02-04*
*Created by: Him 🦝 (with Hitarth)*
