# ActantOS

> **Your AI agent asks. ActantOS decides. Nothing runs without permission.**

**ActantOS** is an in-path, fail-closed **Agent Runtime Control Plane**. It sits between your agent and everything it can touch — files, shell, databases, APIs, GitHub, MCP tools. Every action goes through ActantOS first. If ActantOS says no, the action never happens.

| | |
| --- | --- |
| **Mode A public baseline** | **[v1.2.0 Quiet Open-Core](https://github.com/kotobuki09/actantos-releases/releases/tag/v1.2.0)** — claim / maturity SoT for Mode A |
| **Engineering tree in this checkout** | Package `1.2.0` (`quiet-open-core` lineage) — the locally-verified build, including the v2 security fabric's source and tests; **not** production-qualified and **not** a production qualification. The earlier Stage 3 `v1.1.0` lineage remains at [tag v1.1.0](https://github.com/kotobuki09/actantos-releases/tree/v1.1.0). |
| **Website** | [actantos.com](https://actantos.com) · [roadmap](https://actantos.com/roadmap) · [v1](https://actantos.com/v1) |
| **What Mode A means** | Self-host Enforcement Kernel (Quiet Open-Core): fail-closed decisions, frozen `/v1`, installable open-core surface. Enterprise multi-tenant / production-qualified claims are Mode B / conditional. |
| **Ship rule (lab)** | Built + tests pass supports *local* ship evidence; it does **not** by itself authorize production-qualified marketing claims. |

This repository is the **public release surface** (artifacts, notes, installable tree).

> **Mode A note:** Public claim baseline is Quiet Open-Core **v1.2.0** per `release-maturity-truth.json`. Semver is not production qualification; nothing in this repository claims production-qualified maturity.

### v2 security fabric — source and evidence in this tree

The `actantosd/` tree is the locally-verified `v1.2.0` build itself. It contains the v2 agent
security fabric's source and tests, and the `docs/` directory carries its own record — test
matrix, invariant list, phase report, threat model, the machine-readable state file, and the
waiver that is still unsigned. The earlier Stage 3 engineering tree is unchanged at
[tag v1.1.0](https://github.com/kotobuki09/actantos-releases/tree/v1.1.0).

What the fabric currently says about itself, stated exactly as the documents state it:

- Fourteen invariants (S1–S14). Twelve are `HELD`; **S4 is `PARTIAL`**.
- Locally verified on one host: 1007 unit tests, 915 passing, 0 failing, 92 skipped, plus 135
  gated substrate tests against real Docker, PostgreSQL and gVisor. **Not production-qualified,
  and not a claim about any other host.**
- **Confidential computing is not implemented.** `docs/OPEN_WAIVERS.md` carries the itemized
  waiver `W-001`, which is **unsigned**. An unsigned waiver is an open item, not a concession.
- Nothing in this fabric defends against a compromised host kernel or root. It defends against a
  compromised agent.

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

## What’s in this tree (v1.2.0)

The `quiet-open-core` v1.2.0 build, locally verified on one host — full notes in
[`actantosd/docs/release-notes-v1.2.0.md`](actantosd/docs/release-notes-v1.2.0.md):

- Enforcement kernel (`actantosd`) — Fastify + Postgres, frozen `/v1` intercept API
- v2 agent security fabric (`src/v2/`): fourteen invariants (S1–S14), delegation and
  capability brokerage, hash-chained signed evidence — every control mutation-checked
- Cedar policy bundles + risk rules; evaluator modes where production mode fails closed
- Docker sandbox baseline; gVisor/runsc and Tetragon substrate tests are gated and measured
- Pi adapter (`guarded_*` tools), SDK and dashboard packages (`packages/`)
- Security bench (`security-bench/`): 26 attacks blocked, 2 controls, 0 prohibited external effects
- Verification tooling: `npm run release:verify`, `npm run security:state`,
  `npm run confidential:probe`, `npm run smoke:fresh-install`
- Built npm artifact + checksummed manifest: `actantosd/artifacts/`

The frozen `/v1` intercept API remains compatible. See `actantosd/docs/release-notes-v1.2.0.md`.

The Stage 3 governed-enterprise-autonomy lineage (multi-tenant foundation, OIDC/service
principals, RBAC + RLS, STS credential broker, WORM evidence archives, SIEM connectors) remains
published unchanged at [tag v1.1.0](https://github.com/kotobuki09/actantos-releases/tree/v1.1.0).
It is not the tree in this checkout.

## What’s in v1.0.1

- One-command portable install and agent test with `npm run quickstart`
- Windows, macOS, and Linux support through Node.js 22+
- No Docker or Postgres required for the first test
- Verified allow, deny, approval-required, and audit-evidence decisions
- Clean server shutdown, including native Windows process ownership

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

### Fastest portable test

**Requirements:** Node.js 22+ and Git. Docker is not required.

```bash
git clone https://github.com/kotobuki09/actantos-releases.git
cd actantos-releases/actantosd
npm install
npm test
```

The test suite runs the full unit suite; tests that need a local PostgreSQL or a Docker
daemon skip themselves when those are absent. A run that ends with `0 failed` verifies
everything that could run on that machine.

The one-command portable quickstart (`npm run quickstart`) belongs to the previous lineage:
check out tag `v1.0.1` and run it there.

### Persistent self-host setup

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

Or download the built tarball from `actantosd/artifacts/npm/` in this tree, or
**`actantosd-1.0.1.tgz`** from the [v1.0.1 release](https://github.com/kotobuki09/actantos-releases/releases/tag/v1.0.1).

Daemon default port: **3100** (so it does not collide with a site on 3000).

### Verify a release build

```bash
cd actantosd
npm run release:verify      # typecheck + tests + build + policy:regression + bench + state check
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
| [v1.2.0 release](https://github.com/kotobuki09/actantos-releases/releases/tag/v1.2.0) | Current release page (quiet-open-core lineage) |
| [v1.1.0 release](https://github.com/kotobuki09/actantos-releases/releases/tag/v1.1.0) | Release page (Stage 3 lineage, tagged) |
| `actantosd/artifacts/` | This tree's built npm tarball + checksum manifest |
| [Website /v1](https://actantos.io/v1) | Release story |
| [API v1 contract](actantosd/docs/api-v1-contract.md) | Stable endpoints |
| [Open-core surface](actantosd/docs/open-core-surface.md) | Free vs paid boundary |
| [Pilot onboarding](actantosd/docs/pilot-onboarding.md) | Install → first governed session |
| [Policy templates](actantosd/docs/pilot-policy-templates.md) | Balanced / Strict |
| [Threat model](actantosd/docs/threat-model.md) | Risks & mitigations |
| [Security hardening](actantosd/docs/security-hardening.md) | Sandbox & fail-closed |
| [Support runbook](actantosd/docs/support-runbook.md) | Ops recovery |
| [Upgrade v0.7 → v1](actantosd/docs/upgrade-v0.7-to-v1.md) | Migration |
| [Release notes v1.2.0](actantosd/docs/release-notes-v1.2.0.md) | Changelog for the current tree |

---

## Stack

TypeScript · Fastify · Postgres · AWS Cedar · Docker · Zod · Kysely

---

## License / contact

See repository license terms. Product site: [actantos.io](https://actantos.io) · hello@actantos.com

---

## Previous release

- [v0.1.0](https://github.com/kotobuki09/actantos-releases/releases/tag/v0.1.0) — pre-1.0 packaging milestone (superseded for public open-core messaging by **v1.0.0**)
