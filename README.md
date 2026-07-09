# ActantOS

> **Your AI agent asks. ActantOS decides. Nothing runs without permission.**

**ActantOS** is an in-path, fail-closed **Agent Runtime Control Plane**. It sits between your agent and everything it can touch — files, shell, databases, APIs, GitHub, MCP tools. Every action goes through ActantOS first. If ActantOS says no, the action never happens.

| | |
| --- | --- |
| **Latest public release** | **[v1.0.0 Quiet Open-Core](https://github.com/kotobuki09/actantos-releases/releases/tag/v1.0.0)** (2026-07-09) |
| **Website** | [actantos.io/v1](https://actantos.io/v1) |
| **Stage** | Open-Core / Design Partner |
| **What this means** | Installable, API-frozen, lab-verified self-host kernel |
| **What this does *not* claim** | Living multi-customer “battle-tested in production” proof |

This repository is the **public release surface** (artifacts, notes, installable tree).

---

## The problem

AI agents are powerful but unpredictable. Left unchecked, an agent can:

- Read `.env` and leak API keys  
- Push broken code without asking  
- Run a migration at the wrong time  
- Call a malicious or drifted MCP tool  
- Loop and burn budget  

ActantOS stops that with **deterministic policy** — not LLM-as-judge.

---

## How it works

```text
Your AI agent (Cursor, Claude, GPT, custom…)
        │  wants to do something
        ▼
┌─────────────────────────────────────┐
│              ActantOS                 │
│  1. Kill switch?                      │
│  2. Budget / rate limit?              │
│  3. Cedar policy permit/forbid?       │
│  4. Risk rules → approval needed?     │
│  5. Approval state?                   │
└───────────────┬─────────────────────┘
                │
        ┌───────┼────────┐
        ▼       ▼        ▼
      ALLOW    DENY   APPROVAL_REQUIRED
   (token)  (blocked)  (web / Slack)
```

**Fail-closed:** if the control plane is unreachable, tools do **not** execute.

### Decision outcomes

| Outcome | Meaning |
| --- | --- |
| `allow` | Action may run; decision token issued |
| `deny` | Action must not run |
| `approval_required` | Human must approve once (TTL); then allow |

---

## What’s in v1.0.0 (Quiet Open-Core)

### Self-host free surface

- Enforcement kernel (`actantosd`) — Fastify + Postgres  
- Frozen **`/v1` API** (intercept, tool-result, operator surfaces, MCP transport)  
- **Cedar** policy bundles + risk rules  
- **Docker** sandbox baseline  
- **Pi Primary Path** — coding agents via `guarded_*` tools  
- **MCP Optional Path** — gateway with list filter, call intercept, manifest drift, SSRF block  
- **Web approval** (one-use, TTL) + optional **Slack**  
- Basic operator dashboard  
- Kill switch, budgets, rate limits  
- Hash-chained audit + evidence export  
- **Balanced Coding Policy** default; **Strict** opt-in  

### Intentionally later (not open-core v1)

- Hosted SaaS control plane  
- OIDC / SCIM  
- gVisor / Firecracker multi-tenant isolation  
- Managed compliance / WORM productization  

---

## Typical coding workflow

| Agent wants to… | ActantOS (Balanced) |
| --- | --- |
| Read `README.md` | ✅ `allow` |
| Read `.env` | ❌ `deny` (credential path) |
| Path traversal / escape workspace | ❌ `deny` |
| `npm test` / local build | ✅ `allow` (when not high-risk) |
| `git push` | ⏳ `approval_required` |
| Reuse an approval token | ❌ `deny` |
| Act after kill switch | ❌ `deny` |
| MCP tool not in approved manifest | ❌ `deny` |
| HTTP to metadata / private SSRF targets | ❌ `deny` |

Demo story (smoke): **allow → deny secret → approve push → kill switch → evidence export**.

---

## Quickstart

**Requirements:** Docker Desktop, Node.js 22+, Git.

```bash
git clone https://github.com/kotobuki09/actantos-releases.git
cd actantos-releases

cp actantosd/.env.example actantosd/.env
# set HMAC_SECRET (optional: ACTANTOS_API_KEY)

docker compose -f actantosd/docker-compose.yml up -d --build
cd actantosd && npm install
npm run demo -- --url http://localhost:3100
```

Or download **`actantosd-1.0.0.tgz`** from the [v1.0.0 release](https://github.com/kotobuki09/actantos-releases/releases/tag/v1.0.0).

Daemon default port: **3100** (so it does not collide with a site on 3000).

### Verify a release build

```bash
cd actantosd
npm run release:verify      # typecheck + tests + build + policy:regression
npm run smoke:fresh-install # compose + full demo (35 checks)
```

---

## Policy templates

| Template | Role |
| --- | --- |
| `dev-coding-agent.cedar` | **Balanced default** — local loop free; pair risk rules for push/publish |
| `workspace-readonly-approval-shell.cedar` | **Strict opt-in** — more friction on mutations |
| `mcp-readonly.cedar` | MCP read-only assistants |
| `github-approval-base.cedar` | GitHub / shell release actions |
| `http-readonly.cedar` | GET-only HTTP agents |

See [`actantosd/docs/pilot-policy-templates.md`](actantosd/docs/pilot-policy-templates.md).

---

## MCP gateway

ActantOS can sit in front of upstream MCP servers:

- Pin and hash tool manifests  
- Block drift until approved  
- Filter `tools/list`  
- Intercept `tools/call`  
- SSRF denylist (localhost, metadata, RFC-1918 by default)  

Setup: [`actantosd/docs/mcp-gateway-stable.md`](actantosd/docs/mcp-gateway-stable.md).

---

## Docs

| Doc | Purpose |
| --- | --- |
| [v1.0.0 release](https://github.com/kotobuki09/actantos-releases/releases/tag/v1.0.0) | Public artifacts & notes |
| [Website /v1](https://actantos.io/v1) | Release story |
| [API v1 contract](actantosd/docs/api-v1-contract.md) | Stable endpoints |
| [Open-core surface](actantosd/docs/open-core-surface.md) | Free vs paid boundary |
| [Pilot onboarding](actantosd/docs/pilot-onboarding.md) | Install → first governed session |
| [Policy templates](actantosd/docs/pilot-policy-templates.md) | Balanced / Strict |
| [Threat model](actantosd/docs/threat-model.md) | Risks & mitigations |
| [Security hardening](actantosd/docs/security-hardening.md) | Sandbox & fail-closed |
| [Support runbook](actantosd/docs/support-runbook.md) | Ops recovery |
| [Upgrade v0.7 → v1](actantosd/docs/upgrade-v0.7-to-v1.md) | Migration |
| [Release notes v1.0.0](actantosd/docs/release-notes-v1.0.0.md) | Changelog for this tag |

---

## Stack

TypeScript · Fastify · Postgres · AWS Cedar · Docker · Zod · Kysely

---

## License / contact

See repository license terms. Product site: [actantos.io](https://actantos.io) · hello@actantos.com

---

## Previous release

- [v0.1.0](https://github.com/kotobuki09/actantos-releases/releases/tag/v0.1.0) — pre-1.0 packaging milestone (superseded for public open-core messaging by **v1.0.0**)
