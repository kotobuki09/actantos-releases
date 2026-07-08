# ActantOS

**AI Agent Control Plane. No agent action executes without a decision.**

ActantOS sits in-path between your AI agent and every tool it can call. Before anything executes — file read, shell command, git push, MCP tool, HTTP request — ActantOS evaluates Cedar policy and risk rules and returns `allow | deny | approval_required`. If the daemon is down, execution is blocked.

---

## Latest release

**[v1.0.0-production](https://github.com/kotobuki09/actantos-releases/releases/tag/v1.0.0-production)** — 2026-07-08

---

## What it does

| Capability | Detail |
|---|---|
| Policy enforcement | Cedar policy evaluated on every tool call |
| Risk rules | JSON-defined rules routing risky actions to approval |
| Human approval | Slack or web — one-use token, tamper-evident |
| MCP gateway | Intercepts tools/call, detects manifest drift, blocks SSRF |
| Pi adapter | Guarded wrappers: read, write, edit, bash, ls, grep, find, http |
| Docker sandbox | Non-root, cap-drop, memory/cpu/pids limits, network-none default |
| Kill switch | Instantly block agent, session, tenant, or tool |
| Audit log | Hash-chained, every decision has a reason code |
| Evidence export | JSON/CSV session package for security review |
| SIEM/webhook | Signed events delivered to your receiver |

---

## Quickstart

```bash
git clone https://github.com/kotobuki09/actantos-releases.git
cd actantos-releases
cp actantosd/.env.example actantosd/.env
docker compose -f actantosd/docker-compose.yml up -d --build
# ActantOS is now running at http://localhost:3100
```

Run the demo:

```bash
cd actantosd
npm install
npm run demo -- --url http://localhost:3100
```

Expected:

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

---

## Self-host in 5 minutes

Requirements: Docker, Node.js 22+

```bash
# 1. Copy env
cp actantosd/.env.example actantosd/.env

# 2. Start stack
docker compose -f actantosd/docker-compose.yml up -d --build

# 3. Verify health
curl http://localhost:3100/health/ready

# 4. Run smoke test
cd actantosd && npm run smoke:fresh-install
```

Full installation guide → [`actantosd/docs/pilot-onboarding.md`](actantosd/docs/pilot-onboarding.md)

---

## Policy

ActantOS ships five Cedar policy templates:

| Template | Use case |
|---|---|
| `dev-coding-agent.cedar` | AI coding agent — allows reads/writes, requires approval for push/migrate |
| `mcp-readonly.cedar` | MCP client restricted to read-only tools |
| `github-approval-base.cedar` | All GitHub mutations require human approval |
| `http-readonly.cedar` | Agent allowed only GET requests |
| `workspace-readonly-approval-shell.cedar` | Read-only by default, shell requires approval |

Templates are in [`actantosd/policies/templates/`](actantosd/policies/templates/).

---

## Architecture

```
Agent (Pi adapter / MCP client)
    │
    │  POST /v1/intercept/tool-call
    ▼
actantosd  (Fastify + Postgres)
    │
    │  1. Kill switch check
    │  2. Budget / rate-limit
    │  3. Cedar PDP
    │  4. Risk classifier
    │  5. Approval state
    ▼
allow | deny | approval_required
    + decision_token  (HMAC-SHA256, verified on /v1/tool-result)
```

---

## Pilot evidence

Two real-world pilot workflows validated before this release:

- **[Pilot 1](actantosd/docs/pilot-evidence-1.md)** — AI coding agent (Claude via Cursor): `.env` blocked, `git push` and `db:migrate` approved via Slack, audit chain verified
- **[Pilot 2](actantosd/docs/pilot-evidence-2.md)** — MCP + GitHub automation agent: manifest drift / shadow tool injection caught and server disabled, SSRF metadata probe blocked, SIEM export verified

---

## Docs

| Document | Location |
|---|---|
| API v1 contract | [`actantosd/docs/api-v1-contract.md`](actantosd/docs/api-v1-contract.md) |
| Pilot onboarding | [`actantosd/docs/pilot-onboarding.md`](actantosd/docs/pilot-onboarding.md) |
| MCP gateway setup | [`actantosd/docs/mcp-gateway-stable.md`](actantosd/docs/mcp-gateway-stable.md) |
| Policy templates | [`actantosd/docs/pilot-policy-templates.md`](actantosd/docs/pilot-policy-templates.md) |
| Security hardening | [`actantosd/docs/security-hardening.md`](actantosd/docs/security-hardening.md) |
| Threat model | [`actantosd/docs/threat-model.md`](actantosd/docs/threat-model.md) |
| Support runbook | [`actantosd/docs/support-runbook.md`](actantosd/docs/support-runbook.md) |
| Upgrade v0.7 → v1 | [`actantosd/docs/upgrade-v0.7-to-v1.md`](actantosd/docs/upgrade-v0.7-to-v1.md) |
| Release notes | [`actantosd/docs/release-notes-v1.0.0-production.md`](actantosd/docs/release-notes-v1.0.0-production.md) |

---

## Stack

TypeScript · Fastify · Postgres · AWS Cedar · Docker

---

## License

Proprietary. Contact [actantos.io](https://actantos.io) for licensing.
