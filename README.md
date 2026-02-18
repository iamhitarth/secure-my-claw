# Secure My Claw

A free, agent-readable security hardening guide for [OpenClaw](https://openclaw.ai) setups.

## Who is this for?

Anyone running OpenClaw who wants to understand the security trade-offs and harden their setup appropriately.

## The Honest Security Picture

OpenClaw is an agent that **can execute arbitrary code on your machine**. That's the point — it's powerful because it can actually do things. But power comes with risk.

### 🟢 Personal use / tinkering

**Risk level:** Low-moderate

**What to do:**
1. Follow the [hardening guide](./guide.md) — covers secrets, network lockdown, allowlists, rate limiting
2. Don't store sensitive credentials on the same machine
3. Review what it's doing periodically

**Give this to your agent:**
> "Read guide.md and follow the instructions to secure yourself."

---

### 🟡 Business use / sensitive data

**Risk level:** Moderate-high

**What to do:**
1. **Run on a dedicated machine or VM** — not your main workstation
2. Don't give it access to production systems or sensitive credentials
3. Follow the full hardening guide
4. Consider network segmentation (Tailscale, separate VLAN)

**The principle:** Treat it like an intern with shell access. Capable, but don't hand them the keys to prod.

---

### 🔴 High-security environments

**Risk level:** High

**What to do:**
1. Air-gap completely, or don't use it yet
2. Agent security tooling is still maturing industry-wide
3. Prompt injection is an unsolved problem — not OpenClaw-specific

**The uncomfortable truth:** No agent system today is fully safe from prompt injection. If a breach would end your company, wait for the tooling to mature.

---

## What the guide covers

- ✅ Secrets management (no API keys in config files)
- ✅ Network lockdown (localhost-only by default)
- ✅ Channel allowlists (only YOU can message your bot)
- ✅ Rate limiting (prevent runaway commands)
- ✅ Logging and auditing
- ✅ Backup procedures
- ✅ Skills/extension security (ClawHub verification)
- ✅ Prompt injection awareness

## What this WON'T protect against

- ⚠️ Someone with physical access to your machine
- ⚠️ Malware already on your system
- ⚠️ Social engineering attacks against YOU
- ⚠️ Compromised API keys at the provider level
- ⚠️ Novel prompt injection attacks

## Quick start

**For humans:** Point your agent at the guide:
```
Read https://raw.githubusercontent.com/iamhitarth/secure-my-claw/main/guide.md and follow the instructions to secure yourself.
```

**For agents:** Read [guide.md](./guide.md) sequentially. Each section has commands to run and checkpoints to verify.

## Need help?

Reach out:
- [LinkedIn](https://www.linkedin.com/in/hitarthsharma/)
- [X/Twitter](https://x.com/iamhitarth)

---

## Contributing

Found a gap? PRs welcome. Keep it practical and honest — no security theater.

## License

MIT — use it, share it, improve it.
