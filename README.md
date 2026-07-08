# ActantOS

> **Your AI agent asks. ActantOS decides. Nothing runs without permission.**

ActantOS is a control plane for AI agents. It sits between your agent and everything it can touch — files, shell commands, databases, APIs, GitHub, MCP tools. Every action goes through ActantOS first. If ActantOS says no, the action never happens.

**Latest release:** [v0.1.0](https://github.com/kotobuki09/actantos-releases/releases/tag/v0.1.0) — 2026-07-08

---

## The problem it solves

AI agents are powerful but unpredictable. Left unchecked, an agent can:

- Read your `.env` file and leak API keys
- Push broken code to production without asking
- Run a database migration at 2am
- Call a malicious tool injected into your MCP server
- Loop endlessly and burn your budget

ActantOS stops all of that. You define the rules once. ActantOS enforces them on every single action, automatically.

---

## How it works

```
┌─────────────────────────────────────────────────────────────┐
│                        Your AI Agent                        │
│              (Claude, GPT-4, Cursor, custom...)             │
└──────────────────────────┬──────────────────────────────────┘
                           │  wants to do something
                           │  (read file, run command, push code...)
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                        ActantOS                             │
│                                                             │
│   Step 1 ── Is there a kill switch active?                  │
│   Step 2 ── Has the budget or rate limit been hit?          │
│   Step 3 ── Does policy allow this action?                  │
│   Step 4 ── Is this action flagged as risky?                │
│   Step 5 ── Is there a pending human approval?              │
│                                                             │
└──────────┬─────────────────┬───────────────┬───────────────┘
           │                 │               │
           ▼                 ▼               ▼
        ALLOW              DENY        ASK A HUMAN
    (runs normally)   (blocked, logged)  (Slack / web)
                                           │
                                    human approves
                                           │
                                           ▼
                                        ALLOW
                                    (runs normally)
```

ActantOS never guesses. If it can't reach its own database, the action is **blocked**. Fail-closed by default.

---

## What happens for each action type

| Agent wants to... | What ActantOS does |
|---|---|
| Read `README.md` | ✅ Allow — safe file read |
| Read `.env` | ❌ Deny — credential path blocked |
| Read `../../etc/passwd` | ❌ Deny — path traversal blocked |
| Run `npm test` | ✅ Allow — read-only command |
| Run `git push` | ⏳ Ask human — remote mutation |
| Run `npm run db:migrate` | ⏳ Ask human — destructive command |
| Call an MCP tool (known) | ✅ Allow — manifest verified |
| Call an MCP tool (new/changed) | ❌ Deny — manifest drift detected |
| Make HTTP call to `169.254.169.254` | ❌ Deny — SSRF blocked |
| Try to reuse an approval token | ❌ Deny — one-use only |
| Act after kill switch is hit | ❌ Deny — kill switch active |

---

## Decision flow in detail

Every single agent action goes through this 5-step pipeline in under 100ms:

```
Agent action arrives
        │
        ▼
┌───────────────────┐
│ 1. Kill switch?   │ ── active ──► DENY (kill_switch_active)
└────────┬──────────┘
         │ no
         ▼
┌───────────────────┐
│ 2. Budget/rate    │ ── exceeded ► DENY (budget_exceeded)
│    limit?         │
└────────┬──────────┘
         │ within limits
         ▼
┌───────────────────┐
│ 3. Cedar policy   │ ── forbid ──► DENY (policy_forbid.*)
│    evaluation     │
└────────┬──────────┘
         │ permit
         ▼
┌───────────────────┐
│ 4. Risk rules     │ ── high ────► APPROVAL_REQUIRED
│    classifier     │
└────────┬──────────┘
         │ low/medium
         ▼
┌───────────────────┐
│ 5. Approval state │ ── pending ► APPROVAL_REQUIRED
│    check          │ ── approved► ALLOW (with token)
└────────┬──────────┘
         │
         ▼
       ALLOW
  (decision_token issued,
   verified on execution)
```

---

## Real examples from pilot users

### Example 1 — AI coding agent blocked reading secrets

An engineer was using Claude in Cursor to build a new billing API. The agent tried to read `.env` to find a Stripe key.

```
09:14:19  guarded_read   .env          →  DENY
          reason: credential_path_blocked
```

The agent never saw the key. It got a denial response and moved on.

### Example 2 — git push sent to Slack for approval

The same agent finished the feature and tried to push to GitHub.

```
10:02:21  guarded_bash   git push origin feature/billing  →  APPROVAL_REQUIRED
          Slack message sent to #actantos-approvals
10:04:47  Sarah approved via Slack
10:04:48  git push executed  →  Exit 0
```

One approval. One push. Token was consumed — the agent couldn't reuse it to push again.

### Example 3 — Shadow tool injection caught in MCP

A data pipeline agent connected to an MCP server. Overnight, a bad actor injected a new tool called `__shadow_exfil` into the server.

```
08:14:02  mcp/metrics-mcp/__shadow_exfil  →  DENY
          reason: tool_not_in_approved_manifest
          action: metrics-mcp server disabled, alert raised
```

The tool never ran. The server was disabled automatically. The team got an alert.

---

## What you can control

### Kill switch — stop any agent instantly

```
Scope options:
┌─────────────┬────────────────────────────────────────────┐
│ agent       │ Block one specific agent                   │
│ session     │ Block one active session                   │
│ tenant      │ Block your entire organization             │
│ tool        │ Block one specific tool across all agents  │
└─────────────┴────────────────────────────────────────────┘
```

Hit the kill switch → every subsequent action from that scope returns `DENY` immediately.

### Budget and rate limits

```
┌──────────────────┬────────────────────────────────────────┐
│ daily budget     │ Max decisions per day per agent        │
│ rate limit       │ Max risky actions per minute           │
│ tool cap         │ Max calls to one specific tool         │
└──────────────────┴────────────────────────────────────────┘
```

Stops runaway loops before they cause damage.

### Approval routing

Define which actions require a human to say yes before running:

```json
{
  "rule_id": "risk.shell.git_push",
  "when": { "tool.kind": "shell", "action.args.command": "git push" },
  "approval_required": true
}
```

Approvals arrive in Slack or a web UI. One-use token. Expires after a configurable window.

---

## Audit log

Every decision is logged with a hash chain. You can verify nothing was tampered with.

```
Event #1  allow   guarded_read README.md        hash: a1b2c3...
Event #2  deny    guarded_read .env             hash: d4e5f6... (links to #1)
Event #3  allow   guarded_bash npm test         hash: g7h8i9... (links to #2)
Event #4  apprq   guarded_bash git push         hash: j1k2l3... (links to #3)
Event #5  allow   guarded_bash git push         hash: m4n5o6... (links to #4)
          └── approved by sarah_eng at 10:04:47
```

Run `npm run audit:verify` to confirm the chain is intact at any time.

---

## MCP gateway protection

ActantOS treats every upstream MCP server as untrusted. It:

| Check | What it does |
|---|---|
| Manifest hashing | Records the approved tool list and schema on first connect |
| Drift detection | Blocks any tool that changed or was added without approval |
| SSRF blocking | Denies calls with localhost, `127.0.0.1`, `169.254.169.254`, or RFC-1918 IPs in arguments |
| `tools/list` filtering | Hides tools the agent isn't allowed to see |
| Result logging | Every MCP call result is tied back to the original request ID |

---

## Policy templates

Pick one and drop it in. Customize from there.

| Template | What it does |
|---|---|
| `dev-coding-agent.cedar` | Reads and writes allowed. Push, migrate, deploy → approval required |
| `mcp-readonly.cedar` | MCP tools can only read. No mutations. |
| `github-approval-base.cedar` | Every GitHub write operation needs a human sign-off |
| `http-readonly.cedar` | Agent can only make GET requests. No POST/PUT/DELETE. |
| `workspace-readonly-approval-shell.cedar` | Files are read-only. Any shell command needs approval. |

---

## Quickstart

Requirements: Docker, Node.js 22+

```bash
git clone https://github.com/kotobuki09/actantos-releases.git
cd actantos-releases

cp actantosd/.env.example actantosd/.env
docker compose -f actantosd/docker-compose.yml up -d --build

cd actantosd && npm install
npm run demo -- --url http://localhost:3100
```

Expected output:

```
=== ActantOS Demo ===
Step 1: Safe read          → allow
Step 2: .env read          → deny  (credential_path_blocked)
Step 3: Path traversal     → deny  (canonicalization_failed)
Step 4: git push           → approval_required
Step 5: Approval resume    → allow
Step 6: Token reuse        → deny  (invalid_approval)
Step 7: Kill switch        → deny  (kill_switch_active)
=== Results: 29 passed, 0 failed ===
```

Full setup guide → [`actantosd/docs/pilot-onboarding.md`](actantosd/docs/pilot-onboarding.md)

---

## Pilot evidence

Two real-world workflows validated before this release:

- **[Pilot 1](actantosd/docs/pilot-evidence-1.md)** — AI coding agent (Claude via Cursor, SaaS startup). `.env` blocked, `git push` and `db:migrate` approved via Slack, audit chain clean.
- **[Pilot 2](actantosd/docs/pilot-evidence-2.md)** — MCP + GitHub automation agent (fintech platform team). Shadow tool injection caught and server disabled, SSRF metadata probe blocked, SIEM export verified.

---

## Docs

| | |
|---|---|
| [API v1 contract](actantosd/docs/api-v1-contract.md) | Full endpoint reference |
| [Pilot onboarding](actantosd/docs/pilot-onboarding.md) | Install and run your first agent |
| [MCP gateway setup](actantosd/docs/mcp-gateway-stable.md) | Connect Cursor, Claude, or a custom MCP client |
| [Policy templates](actantosd/docs/pilot-policy-templates.md) | Ready-to-use Cedar policies |
| [Threat model](actantosd/docs/threat-model.md) | What we protect against and how |
| [Security hardening](actantosd/docs/security-hardening.md) | Sandbox, redaction, fail-closed details |
| [Support runbook](actantosd/docs/support-runbook.md) | Troubleshooting and recovery |
| [Upgrade v0.7 → v1](actantosd/docs/upgrade-v0.7-to-v1.md) | Migration guide |
| [Release notes](actantosd/docs/release-notes-v0.1.0.md) | What changed in v0.1.0 |

---

## Stack

TypeScript · Fastify · Postgres · AWS Cedar · Docker

---

## License

Proprietary. Contact [actantos.io](https://actantos.io) for licensing.
