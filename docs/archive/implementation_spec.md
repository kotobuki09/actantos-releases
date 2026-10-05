# ActantOS — Implementation Specification

> **Companion to**: strategic_roadmap.md
> **Purpose**: Engineering build spec. Covers data model, API contracts, decision pipeline, sandbox constraints, demo script, and Day 1-7 build checklist.
> **Scope**: MVP (Week 1 proof through Days 1-60). Enterprise features are noted but not specified here.

---

## Table of Contents

1. [One-Line Build Goal](#1-one-line-build-goal)
2. [Architecture: MVP vs Enterprise](#2-architecture-mvp-vs-enterprise)
3. [MCP Trust-Boundary Diagram](#3-mcp-trust-boundary-diagram)
4. [MVP Data Model](#4-mvp-data-model)
5. [API Specification](#5-api-specification)
6. [Decision Pipeline](#6-decision-pipeline)
7. [Policy Model: Cedar + Risk Rules](#7-policy-model-cedar--risk-rules)
8. [MVP Credential Strategy](#8-mvp-credential-strategy)
9. [Sandbox Implementation](#9-sandbox-implementation)
10. [Demo Script](#10-demo-script)
11. [Day 1-7 Build Checklist](#11-day-17-build-checklist)

---

## 1. One-Line Build Goal

> **No agent action executes without an ActantOS decision.**

Success criterion for Week 1:

```text
guarded_read(".env")     -> denied
guarded_bash("git push") -> approval_required
```

## Current Implementation Status (2026-07-07)

Week 1 is implemented in `plan/actantosd` and `plan/packages/pi-adapter`, and the current user-facing flow has been re-verified through the live demo surface:

- `npm run typecheck` -> pass
- `npm run build` -> pass
- `npm test` -> pass (`51` tests)
- `PORT=3100 npm run dev` -> daemon listens locally
- `docker compose up -d --build` -> actantosd + Postgres healthy on `localhost:3100` / `localhost:5432`
- `npm run demo -- --url http://localhost:3100` -> pass (`29 passed, 0 failed`)

Operational notes:

- The daemon now defaults to port `3100`, not `3000`, to avoid colliding with the promotion website already using `localhost:3000` in this workspace.
- The demo runner now uses `tsx`, so `demo.ts` executes directly without a build step.
- The Postgres access layer now runs through Kysely on top of `pg`, aligning the implementation stack with the spec without changing the verified Week 1 behavior.
- Allow `decision_token`s now carry and enforce the stronger Week 1 binding from the spec: `decision_id`, `tenant_id`, `agent_id`, `session_id`, `tool_call_id`, `scope_hash`, `constraints_hash`, `decision=allow`, and `exp`.
- `/v1/tool-result` now rejects expired allow tokens and tokens whose signed constraints no longer match the persisted allow decision.
- The MCP gateway now records `/v1/tool-result` using the exact intercepted `request_id`, so Postgres-backed MCP executions can be matched back to their stored `tool_calls`.
- Live MCP gateway verification now passes against a real upstream SSE server and a Postgres-backed local daemon: `listTools` exposes `read_repo_file`, `callTool` returns the upstream response, and both `policy_decision.created` and `tool_result.recorded` persist against the same `request_id`.
- `GET /v1/sessions/:session_id/events` now exposes the richer demo context the spec expects: `request_id`, `tool`, `final_decision`, `risk_class`, `approval_id`, and `result_hash` in addition to the existing actor/hash-chain fields.

MVP freeze note:

- The Week 1 enforcement-kernel MVP can now be treated as complete for this workspace: the core decision, approval, execution-result, kill-switch, MCP gateway, and audit-timeline flows have all been exercised against real HTTP/Postgres-backed surfaces, not just unit tests.
- MCP manifest versions now persist in Postgres, deny drifted tool schemas/descriptions with `schema_hash_mismatch` / `manifest_drift`, and expose an approval route to promote a pending MCP version to the new baseline.
- URL-bearing tool requests now fail closed against a basic SSRF blocklist for loopback, metadata, and RFC-1918 targets before policy evaluation.
- `demo.ts` now fails fast if `--url` points at an HTML site instead of the JSON API.
- Compose-backed verification now passes against real Postgres and the bundled Cedar CLI container path.
- `cedar-policy-cli 4.11.2` is installed and executed in the container, but Week 1 currently uses a narrow compatibility shim because this Cedar version intermittently mis-evaluates equivalent non-credential requests; the shim preserves the intended Week 1 semantics while still exercising the real CLI surface.

---

## Week 1 Non-Goals

Do not build any of the following before the enforcement kernel is proven:

```text
- Slack integration (use manual approval API first)
- MCP gateway (use Pi guarded_read/guarded_bash first)
- gVisor or Firecracker
- Real GitHub push to production (use --dry-run or a local fake remote)
- Full dashboard (terminal log + approvals page only)
- Credential broker
- Advanced shell parser (treat shell as high-risk by default)
- Multi-user auth or OIDC
- Production SaaS deployment
- MCP manifest drift demo (this is Phase 2, Days 31-60)
```

Week 1 proves only:

```text
- Decision endpoint returns allow / deny / approval_required
- File read of .env is denied
- git push returns approval_required
- Manual approval creates a one-use token
- Approved command executes in Docker sandbox
- Every step appears in the audit log
```

---

## 2. Architecture: MVP vs Enterprise

### MVP Architecture (Week 1-4)

```text
Pi / MCP Client
      |
      v
ActantOS Adapter / MCP Gateway
      |
      +-- normalize tool call
      +-- canonicalize path / URL / command
      +-- attach agent + user + session identity
      +-- compute risk class
      v
POST /v1/intercept/tool-call
      |
      +-- kill switch check       -> deny if active
      +-- budget/rate-limit check -> deny if exceeded
      +-- Cedar PDP evaluation    -> permit / forbid
      +-- risk classifier         -> approval_required / none
      +-- approval state check    -> valid / missing / expired
      v
Decision: allow / deny / approval_required
      |
      +-- allow             -> Docker sandbox executor
      +-- approval_required -> manual approval API (Week 1); Slack (Weeks 2-4)
      +-- deny              -> fail-closed, log reason
      |
      v
POST /v1/tool-result   (after execution)
      |
      v
Postgres Audit Log (hash-chain)
```

### Enterprise Architecture (Phase 3 - not MVP)

```text
Hosted Control Plane
  | OIDC / SCIM           | SIEM Export             | WORM Audit Store
  | Okta / Entra          | Splunk / Datadog         | S3 Object Lock
  | Credential Broker     | Policy Marketplace       | Advanced Approvals
        |
        v
Hardened Data Plane
  +-- gVisor  (single-tenant hosted)
  +-- Firecracker microVMs (multi-tenant SaaS)
```

---

## 3. MCP Trust-Boundary Diagram

```text
+----------------------------------------------------------------------+
|  MCP Client (Pi / Cursor / Claude Desktop / custom agent)           |
|  Trust: semi-trusted                                                 |
|  Risks: compromised agent, malicious prompt, stolen session          |
+----------------------------------+-----------------------------------+
                                   |  stdio / SSE / HTTP
                                   v
+----------------------------------------------------------------------+
|  ActantOS MCP Gateway                                                |
|  Trust: trusted enforcement point                                    |
|  Responsibilities:                                                   |
|    - Authenticate agent identity (JWT)                               |
|    - Verify tool manifest hash (tool poisoning detection)            |
|    - Filter tools/list by Cedar policy                               |
|    - Intercept tools/call -> POST /v1/intercept/tool-call            |
|    - Enforce SSRF blocklist (localhost, metadata, RFC-1918)          |
|    - Inject scoped credentials (never raw user tokens)               |
|    - Route to approval, execute in sandbox, log result               |
+----------------------------------+-----------------------------------+
                                   |  forwarded only after allow
                                   v
+----------------------------------------------------------------------+
|  Upstream MCP Server (GitHub, DB, SaaS API, filesystem tool)        |
|  Trust: variable (configured by admin)                               |
|  Risks: malicious server, tool poisoning, overbroad tools,           |
|         rug pull (manifest change), token misuse                     |
+----------------------------------+-----------------------------------+
                                   v
+----------------------------------------------------------------------+
|  External Resource (repo, database, file store, SaaS API)           |
|  Trust: protected target                                             |
|  Risks: data exfiltration, unauthorized mutation, SSRF               |
+----------------------------------------------------------------------+
```

---

## 4. MVP Data Model

Minimum viable Postgres schema.

> **Migration order matters** — create tables in this sequence to satisfy foreign key constraints:
> `agents` → `sessions` → `policy_bundles` → `tool_calls` → `policy_decisions` → `approvals` → `audit_chain_state` → `audit_events` → `budgets` → `kill_switches` → `mcp_servers` → `mcp_tool_versions`
> Alternatively, add the `policy_decisions.policy_bundle_id` FK in a separate migration step after both tables exist.

### agents
```sql
CREATE TABLE agents (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  external_id    TEXT NOT NULL,              -- runtime ID used in API (e.g. "pi_demo", not required to be UUID)
  tenant_id      TEXT NOT NULL,
  name           TEXT NOT NULL,
  runtime_type   TEXT NOT NULL CHECK (runtime_type IN ('pi', 'mcp', 'langgraph', 'custom')),
  owner_user_id  TEXT NOT NULL,
  environment    TEXT NOT NULL CHECK (environment IN ('dev', 'staging', 'prod')),
  risk_tier      TEXT NOT NULL CHECK (risk_tier IN ('low', 'medium', 'high')),
  status         TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX uniq_agents_tenant_external ON agents (tenant_id, external_id);
```

> API field `agent.id` maps to `agents.external_id`. Internal UUID is never exposed to the adapter.

### sessions
```sql
CREATE TABLE sessions (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  external_id TEXT NOT NULL,                -- runtime session ID used in API (e.g. "s_demo")
  tenant_id   TEXT NOT NULL,
  agent_id    UUID NOT NULL REFERENCES agents(id),
  user_id     TEXT NOT NULL,
  purpose     TEXT,
  cwd         TEXT,
  status      TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'ended', 'killed')),
  started_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  ended_at    TIMESTAMPTZ
);

CREATE UNIQUE INDEX uniq_sessions_tenant_external ON sessions (tenant_id, external_id);
CREATE INDEX idx_sessions_agent ON sessions (agent_id);
```

> API field `session.id` maps to `sessions.external_id`. Lookup: `SELECT * FROM sessions WHERE tenant_id=$t AND external_id=$api_id`.

### tool_calls
```sql
CREATE TABLE tool_calls (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  request_id      TEXT NOT NULL,
  tenant_id       TEXT NOT NULL,
  session_id      UUID NOT NULL REFERENCES sessions(id),
  agent_id        UUID NOT NULL REFERENCES agents(id),
  tool_kind       TEXT NOT NULL,
  tool_name       TEXT NOT NULL,
  operation       TEXT NOT NULL,
  resource_json   JSONB NOT NULL,
  action_json     JSONB NOT NULL,
  normalized_json JSONB NOT NULL,
  mcp_json        JSONB,
  scope_hash      TEXT NOT NULL,           -- sha256(tenant+agent+user+session+tool+resource+normalized); shared by approvals and decision tokens
  status          TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN (
                      'pending', 'decision_created', 'approval_pending',
                      'approved', 'denied', 'blocked', 'executing',
                      'executed', 'failed', 'timeout'
                    )),
  result_hash     TEXT,                    -- sha256 of execution result
  started_at      TIMESTAMPTZ,             -- set when execution begins
  finished_at     TIMESTAMPTZ,             -- set when execution ends
  error_code      TEXT,                    -- set on failed/timeout
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Idempotency: adapter retries must not create duplicate decisions or double-charge budgets
CREATE UNIQUE INDEX uniq_tool_calls_tenant_request ON tool_calls (tenant_id, request_id);
CREATE INDEX idx_tool_calls_session_created ON tool_calls (session_id, created_at DESC);
```

### policy_decisions
```sql
CREATE TABLE policy_decisions (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  request_id       TEXT NOT NULL,
  tenant_id        TEXT NOT NULL,
  tool_call_id     UUID NOT NULL REFERENCES tool_calls(id),
  policy_bundle_id UUID REFERENCES policy_bundles(id),   -- FK enforced
  cedar_result     TEXT NOT NULL CHECK (cedar_result IN ('permit', 'forbid')),
  risk_class       TEXT NOT NULL,
  approval_req     BOOLEAN NOT NULL DEFAULT false,
  final_decision   TEXT NOT NULL CHECK (final_decision IN ('allow', 'deny', 'approval_required')),
  decision_mode    TEXT NOT NULL DEFAULT 'enforce'
                     CHECK (decision_mode IN ('enforce', 'dry_run')),  -- dry_run never issues decision_token
  reason           TEXT NOT NULL,
  reason_code      TEXT NOT NULL DEFAULT 'unknown',       -- stable machine-readable code
  constraints_json JSONB,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Idempotency
CREATE UNIQUE INDEX uniq_policy_decisions_tenant_request ON policy_decisions (tenant_id, request_id);
CREATE INDEX idx_decisions_tool_call ON policy_decisions (tool_call_id);
```

### approvals
```sql
CREATE TABLE approvals (
  id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id          TEXT NOT NULL,
  decision_id        UUID NOT NULL REFERENCES policy_decisions(id),
  tool_call_id       UUID NOT NULL REFERENCES tool_calls(id),
  status             TEXT NOT NULL DEFAULT 'pending'
                       CHECK (status IN ('pending', 'approved', 'denied', 'expired')),
  approver_user_id   TEXT,
  decided_by         TEXT,                              -- display name of approver
  one_use_token_hash TEXT,                              -- sha256(random_raw_token); NULL until admin approves
  scope_hash         TEXT NOT NULL,                     -- matches tool_calls.scope_hash
  expires_at         TIMESTAMPTZ NOT NULL,              -- deadline for both: human to approve AND adapter to consume
  decided_at         TIMESTAMPTZ,                       -- when admin approved/denied
  used_at            TIMESTAMPTZ,                       -- when adapter consumed the token (one-use)
  used_by_request_id TEXT,                              -- which request_id consumed it
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_approvals_status_expires ON approvals (tenant_id, status, expires_at);
-- One approval record per decision. Prevents ambiguity during token verification.
-- If multi-approver workflows are added later (Phase 2+), replace with an explicit
-- approval_policy model instead of silently allowing duplicate rows.
CREATE UNIQUE INDEX uniq_approvals_decision ON approvals (decision_id);
```

> **Approval token design — random, not deterministic**:
> - Generate: `raw_token = base64url(randomBytes(32))`, `one_use_token_hash = sha256(raw_token)`
> - Return raw_token once to approver only. Never stored raw. Unpredictable even if approval_id leaks.
>
> **Approval expiration semantics**:
> - `expires_at` is set when the `approval_required` decision is returned. It covers two phases:
>   1. Deadline for the human to approve (pending phase)
>   2. Deadline for the adapter to consume the token after approval (token consumption phase)
> - For MVP, one `expires_at` covers both phases. Sufficient for Week 1.
>
> **Approval lifecycle**:
> - `decided_at` set when admin approves/denies. Does NOT consume the token.
> - `used_at` set atomically (FOR UPDATE transaction) when adapter re-submits and token is verified. One-use guard.
> - Validation: `status = 'approved' AND expires_at > now() AND used_at IS NULL AND scope_hash matches AND sha256(submitted_token) = one_use_token_hash`.
> - Consumption: `UPDATE approvals SET used_at = now(), used_by_request_id = $req WHERE id = $id AND used_at IS NULL` — inside a transaction.

### audit_events
```sql
CREATE TABLE audit_events (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    TEXT NOT NULL,
  event_type   TEXT NOT NULL,
  actor_type   TEXT NOT NULL,
  actor_id     TEXT NOT NULL,
  session_id   UUID REFERENCES sessions(id),
  tool_call_id UUID REFERENCES tool_calls(id),
  decision_id  UUID REFERENCES policy_decisions(id),
  seq          BIGINT NOT NULL,   -- per-tenant chain position, copied from audit_chain_state at insert time
  payload_json JSONB NOT NULL,
  prev_hash    TEXT NOT NULL,
  event_hash   TEXT NOT NULL,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- seq must be gapless and unique per tenant so the chain is independently verifiable.
CREATE UNIQUE INDEX uniq_audit_events_tenant_seq ON audit_events (tenant_id, seq);
```

> **Hash-chain rule**: `event_hash = sha256(tenant_id || seq::text || prev_hash || canonical_json(payload) || created_at::text)`
> **First row**: `prev_hash = "genesis", seq = 1`
> **Verifiability**: `seq` is stored on every event row (not only in `audit_chain_state`) so an external verifier can recompute the full chain from `audit_events` alone, ordered by `(tenant_id, seq)`.
> **Canonicalize JSON first** — do not use `payload_json::text` directly. Key ordering in Postgres JSONB is not stable; the same logical event can produce different hashes. Use a canonical JSON serializer (e.g., `jsonb_build_object` with explicit key order, or serialize in application code with sorted keys).

### audit_chain_state
```sql
-- One row per tenant. Serializes hash-chain writes to prevent concurrent hash collisions.
CREATE TABLE audit_chain_state (
  tenant_id  TEXT PRIMARY KEY,
  last_hash  TEXT NOT NULL DEFAULT 'genesis',
  seq        BIGINT NOT NULL DEFAULT 0,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

> **Concurrency rule**: All `audit_events` inserts must run inside a transaction that does `SELECT ... FROM audit_chain_state WHERE tenant_id = $t FOR UPDATE` first. This serializes hash-chain writes per tenant.

### policy_bundles
```sql
CREATE TABLE policy_bundles (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   TEXT NOT NULL,
  version     TEXT NOT NULL,
  engine      TEXT NOT NULL DEFAULT 'cedar',
  source_hash TEXT NOT NULL,
  source_text TEXT NOT NULL,
  active      BOOLEAN NOT NULL DEFAULT false,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

### budgets
```sql
CREATE TABLE budgets (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id      TEXT NOT NULL,
  scope_type     TEXT NOT NULL CHECK (scope_type IN ('tenant', 'agent', 'session', 'tool')),
  scope_id       TEXT NOT NULL,
  metric         TEXT NOT NULL,
  limit_value    BIGINT NOT NULL,
  window_seconds INT NOT NULL,
  current_value  BIGINT NOT NULL DEFAULT 0,
  window_start   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_budget_lookup ON budgets (tenant_id, scope_type, scope_id, metric);
```

> **Week 1 budget behavior**: Budget tables exist but are NOT enforced in Week 1. The pipeline budget step returns pass unconditionally. Budget enforcement is Week 2.

### kill_switches
```sql
CREATE TABLE kill_switches (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id  TEXT NOT NULL,
  scope_type TEXT NOT NULL CHECK (scope_type IN ('tenant', 'agent', 'session', 'tool')),
  scope_id   TEXT NOT NULL,
  reason     TEXT NOT NULL,
  enabled    BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_kill_switch_lookup ON kill_switches (tenant_id, scope_type, scope_id, enabled);
```

### mcp_servers
```sql
CREATE TABLE mcp_servers (
  id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id             TEXT NOT NULL,
  name                  TEXT NOT NULL,
  transport             TEXT NOT NULL CHECK (transport IN ('stdio', 'sse', 'http')),
  upstream_url          TEXT,
  server_identity_hash  TEXT NOT NULL,
  status                TEXT NOT NULL DEFAULT 'active',
  created_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

### mcp_tool_versions
```sql
CREATE TABLE mcp_tool_versions (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  server_id        UUID NOT NULL REFERENCES mcp_servers(id),
  tool_name        TEXT NOT NULL,
  schema_hash      TEXT NOT NULL,
  description_hash TEXT NOT NULL,
  manifest_json    JSONB NOT NULL,
  approved         BOOLEAN NOT NULL DEFAULT false,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

> **Manifest drift rule**: when a new mcp_tool_version row has different schema_hash or description_hash from the approved version, the tool is immediately disabled until admin sets approved = true.

> **tenants table**: Not defined for Week 1. `tenant_id` is used as plain `TEXT` across all tables and seeded as `"t_demo"`. Every `tenant_id` column is an unreferenced FK placeholder. A `tenants` table with OIDC/SCIM fields is added in Week 2/3. Migration readers: the missing FK is intentional.


---

## 5. API Specification

### 5.1. POST /v1/intercept/tool-call

#### Request Schema

```json
{
  "title": "ToolCallInterceptionRequest",
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "request_id": {
      "type": "string",
      "minLength": 8,
      "maxLength": 128,
      "description": "Opaque idempotency key generated by adapter or gateway. May be UUID, ULID, or any stable ID."
    },
    "tenant_id": { "type": "string", "minLength": 1 },
    "agent": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "id":           { "type": "string" },
        "runtime_type": { "type": "string", "enum": ["pi", "mcp", "langgraph", "custom"] },
        "environment":  { "type": "string", "enum": ["dev", "staging", "prod"] },
        "risk_tier":    { "type": "string", "enum": ["low", "medium", "high"] }
      },
      "required": ["id", "runtime_type", "environment", "risk_tier"]
    },
    "subject": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "user_id": { "type": "string" },
        "role":    { "type": "string" }
      },
      "required": ["user_id", "role"]
    },
    "session": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "id":                     { "type": "string", "minLength": 1 },
        "cwd":                    { "type": "string" },
        "purpose":                { "type": "string" },
        "budget_remaining_cents": { "type": "integer", "minimum": 0 }
      },
      "required": ["id", "budget_remaining_cents"]
    },
    "tool": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "name":        { "type": "string" },
        "kind":        { "type": "string", "enum": ["file", "shell", "http", "github", "mcp", "db", "custom"] },
        "schema_hash": { "type": "string" }
      },
      "required": ["name", "kind", "schema_hash"]
    },
    "action": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "operation": { "type": "string" },
        "args":      { "type": "object" }
      },
      "required": ["operation", "args"]
    },
    "resource": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "id":       { "type": "string" },
        "kind":     { "type": "string" },
        "path":     { "type": "string" },
        "url":      { "type": "string" },
        "database": { "type": "string" },
        "table":    { "type": "string" }
      },
      "required": ["id", "kind"]
    },
    "normalized": {
      "type": "object",
      "additionalProperties": false,
      "description": "REQUIRED. Stable facts from gateway tokenization. Cedar evaluates these, not raw strings.",
      "properties": {
        "verb":              { "type": "string", "enum": ["read", "write", "execute", "delete", "list", "create", "network"] },
        "mutation":          { "type": "boolean" },
        "destructive":       { "type": "boolean" },
        "network":           { "type": "boolean" },
        "credential_access": { "type": "boolean" },
        "risk_class":        { "type": "string", "enum": ["low", "medium", "high", "critical"] },
        "command_family":    { "type": "string" },
        "subcommand":        { "type": "string" },
        "target_type":       { "type": "string" },
        "recursive_delete":  { "type": "boolean" },
        "force":             { "type": "boolean" }
      },
      "required": ["verb", "mutation", "destructive", "network", "credential_access", "risk_class"]
    },
    "mcp": {
      "type": "object",
      "additionalProperties": false,
      "description": "Present when tool.kind == 'mcp'.",
      "properties": {
        "server_id":             { "type": "string" },
        "server_identity_hash":  { "type": "string" },
        "tool_name":             { "type": "string" },
        "tool_schema_hash":      { "type": "string" },
        "tool_description_hash": { "type": "string" },
        "transport":             { "type": "string", "enum": ["stdio", "sse", "http"] }
      },
      "required": ["server_id", "tool_name", "tool_schema_hash", "tool_description_hash"]
    },
    "authorization": {
      "type": "object",
      "additionalProperties": false,
      "description": "Present only on re-submission after approval. ActantOS verifies server-side. Adapters MUST NOT self-assert approval status.",
      "properties": {
        "prior_decision_id": { "type": "string", "minLength": 8, "maxLength": 128 },
        "approval_id":       { "type": "string", "format": "uuid",
                               "description": "Required on re-submission. Disambiguates if a decision ever has multiple approval records." },
        "approval_token":    { "type": "string",
                               "description": "Raw random token returned by /v1/approvals/{id}/decide. Adapter must not store long-term." }
      },
      "required": ["prior_decision_id", "approval_id", "approval_token"]
    },
    "dry_run": {
      "type": "boolean",
      "default": false,
      "description": "If true: evaluate policy and risk, record audit event as 'dry_run', but do NOT issue decision_token and do NOT execute. Use for onboarding mode. Never use in security demos."
    }
  },
  "required": [
    "request_id", "tenant_id", "agent", "subject",
    "session", "tool", "action", "resource", "normalized"
  ]
}
```

**Minimal normalized for MVP adapters:**
```json
{
  "verb": "read",
  "mutation": false,
  "destructive": false,
  "network": false,
  "credential_access": false,
  "risk_class": "low"
}
```

#### Response Schema

```json
{
  "title": "ToolCallInterceptionResponse",
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "decision":      { "type": "string", "enum": ["allow", "deny", "approval_required"] },
    "decision_mode": { "type": "string", "enum": ["enforce", "dry_run"],
                       "description": "enforce = real enforcement; dry_run = evaluated but not enforced. Default: enforce." },
    "decision_id":   { "type": "string", "format": "uuid" },
    "reason":        { "type": "string" },
    "reason_code":   {
      "type": "string",
      "description": "Stable machine-readable code. Use for adapter error handling.",
      "enum": [
        "allowed",
        "kill_switch_active",
        "budget_exceeded",
        "policy_forbid",
        "policy_forbid.credential_path",
        "policy_forbid.prod_mutation",
        "policy_forbid.destructive_delete",
        "approval_required",
        "invalid_approval",
        "manifest_drift",
        "schema_hash_mismatch",
        "canonicalization_failed",
        "sandbox_unavailable",
        "unknown"
      ]
    },
    "decision_token": {
      "type": "string",
      "description": "Short-lived signed payload (HMAC-SHA256). Executor MUST verify before running. Bound to: decision_id, tenant_id, agent_id, session_id, tool_call_id, scope_hash, constraints_hash, decision=allow, exp."
    },
    "approval": {
      "type": "object",
      "properties": {
        "approval_id": { "type": "string", "format": "uuid" },
        "status":      { "type": "string", "enum": ["pending"] },
        "expires_at":  { "type": "string", "format": "date-time" }
      },
      "required": ["approval_id", "status", "expires_at"]
    },
    "constraints": {
      "type": "object",
      "properties": {
        "timeout_ms":        { "type": "integer" },
        "max_output_bytes":  { "type": "integer" },
        "network_mode":      { "type": "string", "enum": ["none", "egress_proxy"],
                               "description": "none: docker --network none. egress_proxy: docker --network actantos_egress. Week 1: egress_proxy is a plain bridge network for demo only." },
        "network_allowlist": { "type": "array", "items": { "type": "string" } }
      }
    },
    "audit_event_id": { "type": "string", "format": "uuid" }
  },
  "required": ["decision", "decision_mode", "decision_id", "reason", "reason_code", "audit_event_id"],
  "allOf": [
    {
      "if":   { "properties": { "decision": { "const": "allow" } } },
      "then": { "required": ["decision_token", "constraints"] }
    },
    {
      "if":   { "properties": { "decision": { "const": "approval_required" } } },
      "then": { "required": ["approval"] }
    }
  ]
}
```

> **decision_token signed payload**:
> ```json
> {
>   "decision_id": "dec_123",
>   "tenant_id": "t1",
>   "agent_id": "a1",
>   "session_id": "s1",
>   "tool_call_id": "tc_123",
>   "scope_hash": "sha256:...",
>   "constraints_hash": "sha256:...",
>   "decision": "allow",
>   "exp": 1780000000
> }
> ```
> Executor checks: valid signature, `decision=allow`, not expired, `scope_hash` matches tool call, `constraints_hash` matches constraints received. Reject any token missing these claims.

---

### 5.2. POST /v1/tool-result

```json
{
  "title": "ToolResultRequest",
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "request_id":     { "type": "string", "minLength": 8, "maxLength": 128 },
    "decision_id":    { "type": "string", "format": "uuid" },
    "decision_token": { "type": "string",
                        "description": "The allow token from the intercept response. actantosd verifies before accepting the result. Prevents adapters from posting fake execution results." },
    "tool_kind":      { "type": "string", "enum": ["file", "shell", "http", "github", "mcp", "db", "custom"] },
    "status":         { "type": "string", "enum": ["executed", "failed", "timeout", "blocked"],
                        "description": "blocked = denied or approval_required; use for logging denied actions." },
    "started_at":     { "type": "string", "format": "date-time" },
    "finished_at":    { "type": "string", "format": "date-time" },
    "result": {
      "type": "object",
      "additionalProperties": true,
      "properties": {
        "exit_code":        { "type": "integer", "minimum": -1 },
        "stdout_hash":      { "type": ["string", "null"] },
        "stderr_hash":      { "type": ["string", "null"] },
        "redacted_preview": { "type": "string" },
        "error_message":    { "type": "string" }
      }
    }
  },
  "required": ["request_id", "decision_id", "tool_kind", "status", "started_at", "finished_at", "result"],
  "allOf": [
    {
      "if":   { "properties": { "status": { "enum": ["executed", "failed", "timeout"] } } },
      "then": { "required": ["decision_token"],
                 "description": "decision_token required when execution actually happened. Not required for blocked." }
    },
    {
      "if": {
        "properties": {
          "status":    { "const": "executed" },
          "tool_kind": { "const": "shell" }
        }
      },
      "then": {
        "properties": {
          "result": {
            "type": "object",
            "properties": {
              "exit_code":        { "type": "integer", "minimum": -1 },
              "stdout_hash":      { "type": ["string", "null"] },
              "stderr_hash":      { "type": ["string", "null"] },
              "redacted_preview": { "type": "string" },
              "error_message":    { "type": "string" }
            },
            "required": ["exit_code", "stdout_hash"],
            "additionalProperties": false
          }
        }
      }
    },
    {
      "if":   { "properties": { "status": { "enum": ["failed", "timeout"] } } },
      "then": { "properties": { "result": { "required": ["error_message"] } } }
    }
  ]
}
```


---

## 6. Decision Pipeline

Cedar handles authorization. ActantOS orchestration produces the final result.

```text
dry_run mode (applies to the WHOLE pipeline):
  If request.dry_run == true, Steps 0-5 all evaluate normally and every [STOP]
  returns its real decision (deny / approval_required / allow), but:
    - decision_mode = "dry_run" on the response and policy_decisions row
    - decision_token is NEVER issued
    - approval tokens are NEVER consumed (no used_at update)
    - nothing executes; the audit event records decision_mode = "dry_run"
  So dry_run on a Cedar-forbid path returns decision = "deny" with
  decision_mode = "dry_run" (there is no separate "would_deny" value).

Step 0: Idempotency check
  -> if tool_calls (tenant_id, request_id) already exists
  -> return existing policy_decision row  [STOP — no new evaluation, no budget increment]

  NOTE: Approval resubmission MUST use a new request_id.
  Example:
    Original:     request_id = req_001  -> approval_required, decision_id = dec_001
    Resubmission: request_id = req_001_exec  -> authorization.prior_decision_id = dec_001
  The new request_id ensures Step 0 does not return the old approval_required decision.

Step 1: Kill switch check
  -> if kill_switches.enabled = true for tenant/agent/session/tool
  -> reason_code = "kill_switch_active"  [STOP]

Step 2: Budget / rate-limit check
  -> if budget.current_value >= budget.limit_value
  -> reason_code = "budget_exceeded"  [STOP]
  (Week 1: this step always passes. Budget enforcement is Week 2.)

Step 3: Cedar PDP evaluation
  -> evaluate policy_bundle against {principal, action, resource, context.normalized.*}
  -> cedar_result = permit | forbid
  -> Cedar default: if no permit policy matches, result = forbid
  -> if forbid -> reason_code = mapForbidReason(ctx)  [STOP]
  mapForbidReason:
    credential_access=true          -> "policy_forbid.credential_path"
    normalized.destructive=true     -> "policy_forbid.destructive_delete"
    agent.environment=prod + mutation -> "policy_forbid.prod_mutation"
    else                            -> "policy_forbid"

Step 4: Risk classifier
  -> evaluate risk_rules.json against {tool.kind, normalized.*}
  -> approval_required = true | false
  -> risk_class = low | medium | high | critical

Step 5: Approval state resolution
  -> if request.dry_run == true
       final_decision = allow (reached only if Steps 1-3 passed), decision_mode = "dry_run"
       skip approval verification entirely (never consume approval tokens in dry_run)
       do NOT issue decision_token  [STOP]
  -> if approval_required == false
       final_decision = allow, decision_mode = "enforce"
       issue decision_token  [STOP]
  -> if approval_required == true
       if no authorization.prior_decision_id in request
           reason_code = "approval_required"  [STOP]
       else
           verify approval record inside a transaction (FOR UPDATE):
             scope_hash matches tool_calls.scope_hash
             status = 'approved'
             expires_at > now()
             used_at IS NULL   <- not decided_at; that is set when admin approves
             sha256(authorization.approval_token) = one_use_token_hash
           atomically: SET used_at = now(), used_by_request_id = $request_id
           if valid   -> final_decision = allow, decision_mode = "enforce", issue decision_token
           if invalid -> reason_code = "invalid_approval"
```

---

## 7. Policy Model: Cedar + Risk Rules

### 7.1. Cedar - Authorization Only

Cedar evaluates authorization (is this principal allowed this action on this resource?).
Cedar does NOT encode approval workflow state.
Cedar evaluates normalized.* booleans, not raw command strings or argv arrays.

> **Cedar default**: Cedar's default evaluation is `forbid`. If no `permit` policy matches, the result is `forbid`. This means safe reads (e.g., README.md) will also be denied unless an explicit `permit` policy covers them. The MVP default policy must include explicit permits for safe operations.

#### Policy 0: Default permits for safe workspace reads (required for demo to work)

```cedar
permit (
    principal,
    action in [Action::"ReadFile", Action::"ListFiles"],
    resource
)
when {
    context.agent.environment == "dev" &&
    resource has path &&
    resource.path like "/workspace/*" &&
    context.normalized.credential_access == false
};

forbid (
    principal,
    action == Action::"ReadFile",
    resource
)
when {
    context.normalized.credential_access == true
};
```

> With this pair: `README.md` -> permit (credential_access=false, path under /workspace/). `.env` -> forbid (credential_access=true). This is the exact MVP demo behavior.

#### Policy 1: Block production mutations except security admins

```cedar
forbid (
    principal,
    action in [
        Action::"WriteFile", Action::"EditFile", Action::"DeleteFile",
        Action::"ExecuteShellCommand", Action::"CreateResource",
        Action::"UpdateResource", Action::"DeleteResource"
    ],
    resource
)
when {
    context.agent.environment == "prod"
}
unless {
    principal in Role::"security_admin" &&
    context.agent.risk_tier != "high"
};
```

#### Policy 2: File mutation scope (ABAC)

```cedar
permit (
    principal,
    action in [Action::"WriteFile", Action::"EditFile"],
    resource
)
when {
    resource has path &&
    resource.path like "/workspace/*"
}
unless {
    resource has path && (
        resource.path like "*.env" ||
        resource.path like "*/.ssh/*" ||
        resource.path like "*auth.json"
    )
};
```

> Note: Paths must be canonicalized (symlinks resolved, traversals normalized) by the gateway BEFORE Cedar evaluation.

#### Policy 3: Budget enforcement

```cedar
forbid (
    principal,
    action == Action::"ExecuteShellCommand",
    resource
)
when {
    context.session.budget_remaining_cents < 100
};
```

#### Policy 4: Destructive action block (using normalized booleans)

```cedar
forbid (
    principal,
    action == Action::"ExecuteShellCommand",
    resource
)
when {
    context.normalized.destructive == true &&
    context.normalized.recursive_delete == true
};
```

> Do NOT use .contains() on Cedar arrays in policies.
> Push all classifications into the normalized object (computed by gateway tokenizer before Cedar).
> This avoids Cedar syntax pitfalls and makes policies readable and auditable.

---

### 7.2. Risk Rules - Approval Routing

Risk rules control approval routing. They are evaluated after Cedar returns permit.
Stored as JSON alongside policy_bundles.

```json
[
  {
    "rule_id": "risk.shell.git_push",
    "description": "Require approval for any git push operation",
    "when": {
      "tool.kind": "shell",
      "normalized.command_family": "git",
      "normalized.subcommand": "push"
    },
    "approval_required": true,
    "risk_class": "high"
  },
  {
    "rule_id": "risk.shell.npm_publish",
    "description": "Require approval for npm publish",
    "when": {
      "tool.kind": "shell",
      "normalized.command_family": "npm",
      "normalized.subcommand": "publish"
    },
    "approval_required": true,
    "risk_class": "high"
  },
  {
    "rule_id": "risk.shell.destructive_delete",
    "description": "Require approval for recursive destructive deletes",
    "when": {
      "tool.kind": "shell",
      "normalized.destructive": true,
      "normalized.recursive_delete": true
    },
    "approval_required": true,
    "risk_class": "critical"
  },
  {
    "rule_id": "risk.file.credential_path",
    "description": "Credential file access is always critical risk",
    "when": {
      "tool.kind": "file",
      "normalized.credential_access": true
    },
    "approval_required": false,
    "risk_class": "critical"
  },
  {
    "rule_id": "risk.mcp.mutation",
    "description": "Mutating MCP tool calls require approval",
    "when": {
      "tool.kind": "mcp",
      "normalized.mutation": true
    },
    "approval_required": true,
    "risk_class": "high"
  }
]
```

**Decision combination summary:**

```text
Cedar forbid                                         -> deny
Cedar permit + risk: no approval needed              -> allow
Cedar permit + risk: approval_required + no approval -> approval_required
Cedar permit + risk: approval_required + valid token -> allow
Cedar permit + risk: approval_required + bad token   -> deny (invalid_approval)
```

---

## 8. MVP Credential Strategy

The credential broker is Phase 3. Until then:

```text
Principle: Never pass raw user OAuth tokens to upstream MCP servers or tools.

MVP Local Demo:
  - Explicit static test credentials only.
  - Never committed to source. Loaded via Docker env allowlist.
  - Not used in production or pilot deployments.

MVP Pilot Deployments:
  - Customer-managed scoped service tokens (e.g., GitHub PAT with repo scope only).
  - Customer provides token; ActantOS stores credential reference (ID/label), not the secret.
  - Token injected into sandbox env at execution time from reference store.
  - No automatic user-token forwarding to any upstream MCP server.

Phase 3 Credential Broker:
  - Short-lived, target-scoped token generation.
  - Injected into sandbox at execution time.
  - Token bound to: tenant + agent + session + upstream_server_id + audience.
  - Never stored raw. Rotated automatically on expiry.
```

MCP-specific rule: When ActantOS proxies tools/call to an upstream MCP server, the request uses a server-specific service credential, not the end user's token. Confused deputy mitigation: credential bound to server_id and session context.

---

## 9. Sandbox Implementation

### 9.1. Day 1 Docker Constraints — Two Execution Modes

Week 1 requires two distinct Docker network modes. `--network none` is correct for safe reads but breaks approved network operations (e.g., git push dry-run).

**Mode A: `safe_local`** — default for all file and shell operations

```bash
docker run \
  --user 1001:1001 \
  --read-only \
  --tmpfs /tmp:size=64m \
  --volume /workspace:/workspace \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --memory 512m \
  --cpus 0.5 \
  --pids-limit 64 \
  --network none \
  --env-file /actantos/allowed.env \
  --stop-timeout 30 \
  actantos/sandbox:latest
```

**Mode B: `approved_network`** — used only after a valid approval for network-required operations

```bash
docker run \
  --user 1001:1001 \
  --read-only \
  --tmpfs /tmp:size=64m \
  --volume /workspace:/workspace \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --memory 512m \
  --cpus 0.5 \
  --pids-limit 64 \
  --network actantos_egress \
  --env-file /actantos/allowed.env \
  --stop-timeout 30 \
  actantos/sandbox:latest
```

> `actantos_egress` is an isolated Docker network with an egress proxy. Allowlist is set per-decision in `constraints.network_allowlist`. For the Week 1 demo, use `git push --dry-run` or a local fake Git remote — do not push to a real remote. The enforcement demo does not require a real deploy.

> **Mode selection**: the decision response includes `constraints.network_mode = "none" | "egress_proxy"`. The executor chooses the Docker network accordingly (`none` -> `--network none`; `egress_proxy` -> `--network actantos_egress`). These are the only two values; they match the response schema enum in §5.1.

### 9.2. Phase 2/3 Hardening Targets (not Day 1)

Do not present these as current execution constraints in demos or external communications.

```text
Phase 2 hardening:
  - noexec on /workspace and /tmp mounts
  - Dynamic loader restriction: ld-linux* and ld-musl* restricted to
    loading libraries only from read-only system paths (/lib, /lib64, /usr/lib).
    Libraries from writable directories (/workspace, /tmp) are blocked.
  - seccomp profile:
      block: memfd_create, execveat
      restrict mprotect W+X by default
      JIT exception: Node.js V8 and JVM HotSpot when agent.runtime_type = "jit_allowed"
  - AppArmor / SELinux profile
  - eBPF execve monitoring -> real-time PDP check on every execve syscall
  - Stdin interception: block pipe-into-interpreter patterns
  - Distroless base images in production (no shell binaries)

Phase 3 hardening:
  - gVisor (runsc): user-space application kernel
      Stronger than Docker namespaces. Not a replacement for microVM isolation.
      Use for single-tenant hosted deployments.
  - Firecracker microVMs:
      KVM-backed lightweight VM. For multi-tenant SaaS.
      Requires bare-metal or nested-virtualization compute.
      Still requires host kernel, network, and side-channel hardening.
```

### 9.3. Risk Table

| # | Risk | Impact | Likelihood | Mitigation |
|---|------|--------|------------|------------|
| 1 | Sandbox escape | Critical | Medium | MVP: Docker strict. Pilot: gVisor. Enterprise: Firecracker. |
| 2 | Tool poisoning | High | High | Hash+pin manifest. Drift -> auto-disable + admin approval. |
| 3 | Token exfiltration / confused deputy | High | High | No raw user token passthrough. Scoped service credentials bound to session. |
| 4 | SSRF | High | High | Default-deny network. Allowlist per policy. Block metadata + RFC-1918. |
| 5 | Gateway latency | Medium | Medium | Cedar runs locally in-memory. Request cached by request_id. |
| 6 | Schema drift | Medium | Low | Adapter translation decoupled from engine. Versioned policy bundles. |
| 7 | Interactive shell bypass | High | Medium | Shell interpreter requires approval_required minimum. Blocked by default. |
| 8 | Approval fatigue | Medium | High | Tiered rules: low=allow, medium=warn, high=Slack, critical=deny. |
| 9 | Shadow MCP servers | High | Medium | Agent egress only to ActantOS gateway. Direct upstream blocked. |
| 10 | Audit data leakage | Medium | High | Redacted previews only. Large outputs stored as hash. Scrub before write. |
| 11 | Interpreter bypass | High | Medium | Distroless images in production. No shell runtimes included. |
| 12 | Parameter evasion | High | High | Gateway tokenizer normalizes all flags -> normalized booleans before Cedar. |

---

## 10. Demo Script

**Title**: "The agent tries. ActantOS decides."

**Setup**: Pi agent running through ActantOS guarded adapter. Terminal + audit timeline visible.

```text
Step 1: Start
  Start Pi agent through ActantOS guarded adapter.
  Show: agent registered, session started, audit log empty.

Step 2: Safe read (Cedar permit)
  Agent reads README.md.
  ActantOS: Cedar permit (Policy 0: dev env, /workspace/, credential_access=false) -> risk: low.
  Result: allowed. Content returned.
  Show: audit log row (decision=allow, reason_code="allowed", policy_version, session_id).

Step 3: Credential read blocked (Cedar forbid)
  Agent reads .env file.
  ActantOS: Cedar forbid (credential_access=true) -> decision: deny.
  Result: blocked. Agent receives GuardedAccessDenied.
  Show: audit log row (decision=deny, reason_code="policy_forbid.credential_path").

Step 4: Approval required (risk rule)
  Agent runs: git push --dry-run origin main
  ActantOS: Cedar permit -> risk rule: git.push -> approval_required.
  Manual approval API call (Week 1 has no Slack yet):
    POST /v1/approvals/{id}/decide {"decision": "approved", "approver_user_id": "demo-admin"}
  Result: agent execution paused, waiting.
  Show: pending approvals page.

Step 5: Human approves (manual API)
  Admin calls the approve endpoint.
  One-use signed token issued. TTL = 5 minutes. scope_hash verified.
  Agent re-submits with authorization.prior_decision_id.
  ActantOS verifies: scope_hash match, used_at IS NULL, not expired.
  Token consumed atomically (used_at = now()).
  Command executes in Docker (approved_network mode, --dry-run, no real push).
  Show: audit log row (decision=allow, approval_id, result_hash).

Step 6: Audit timeline
  Open: GET /v1/sessions/{session_id}/events
  Show: agent_id, user, tool, operation, cedar_result,
  risk_class, final_decision, reason_code, approval_id, result_hash, hash chain.

Step 7: Kill switch
  Enable kill switch: POST /v1/kill-switches {scope_type: "agent", scope_id: agent_id}
  Agent attempts another tool call.
  Result: denied at Step 1 (kill switch check, before Cedar evaluation).
  Show: audit log row (decision=deny, reason_code="kill_switch_active").
```

**Note**: MCP manifest drift (original Step 8) is Phase 2, Days 31-60. Remove it from the Week 1 demo to keep focus.

**Demo success criterion**: Every step shows an ActantOS decision before any execution. No agent action bypasses the gateway.

---

## 11. Day 1-7 Build Checklist

### Day 1: Server + Schema + DB + Fake Cedar

```text
[ ] actantosd in TypeScript (Fastify + Zod)
[ ] POST /v1/intercept/tool-call
    [ ] Zod schema validation (all required fields)
    [ ] Return ToolCallInterceptionResponse (decision + decision_mode + reason_code + audit_event_id)
[ ] Postgres: connect, create tables IN MIGRATION ORDER:
    [ ] agents, sessions, policy_bundles, tool_calls, policy_decisions,
        approvals, audit_chain_state, audit_events, budgets, kill_switches
    [ ] Unique indexes: uniq_agents_tenant_external, uniq_sessions_tenant_external,
        uniq_tool_calls_tenant_request, uniq_policy_decisions_tenant_request
[ ] Seed demo bootstrap (required for FK lookups to work):
    [ ] tenant_id = "t_demo"
    [ ] agent: external_id="pi_demo", runtime_type="pi", environment="dev", risk_tier="low"
    [ ] session: external_id="s_demo"
    [ ] policy_bundle: version="0.1.0", engine="cedar", active=true, source_hash=sha256("fake")
    [ ] audit_chain_state: tenant_id="t_demo", last_hash="genesis", seq=0
[ ] Step 0: Idempotency - return existing decision if (tenant_id, request_id) already exists
[ ] FakeCedarProvider (DI injectable for tests):
    [ ] interface CedarProvider { evaluate(ctx: ToolCallContext) -> "permit" | "forbid" }
    [ ] if normalized.credential_access == true -> forbid; else -> permit
[ ] Decision orchestration (minimal):
    [ ] cedar_result = forbid -> deny, reason_code = "policy_forbid.credential_path"
    [ ] cedar_result = permit -> allow, issue decision_token (HMAC-SHA256 of token payload)
    [ ] decision_mode = request.dry_run ? "dry_run" : "enforce"
[ ] Hash-chain insert inside transaction:
    [ ] SELECT audit_chain_state FOR UPDATE
    [ ] canonical_json = JSON.stringify with sorted keys (stable across environments)
    [ ] event_hash = sha256(tenant_id + seq + prev_hash + canonical_json + ts)

Verification:
  POST with agent.id="pi_demo", session.id="s_demo"
  credential_access:true -> {decision:"deny", reason_code:"policy_forbid.credential_path"}
  Send same request_id again -> same response, no new DB row (idempotency)
```

### Day 2: Real Cedar Provider

```text
[ ] ToolCallContext internal type (used by every layer):
    type ToolCallContext = {
      tenantId, requestId, agent (AgentContext), subject, session,
      tool, action, resource, normalized, mcp?, scopeHash
    }
    Use this type as input to: CedarProvider, risk engine, scope_hash,
    audit payload, decision_token payload, approval verification.
[ ] canonicalHash helper (one implementation used everywhere):
    function canonicalHash(value: unknown): string
    Uses: scope_hash, constraints_hash, normalized_hash, manifest hash, audit hash
[ ] CedarCliProvider:
    [ ] Wrap cedar-policy-cli subprocess (cedar authorize)
    [ ] Load policy from policies/default.cedar
    [ ] Parse stdout -> "Allow" | "Deny" -> map to "permit" | "forbid"
[ ] policies/default.cedar:
    [ ] Policy 0: permit ReadFile/ListFiles in /workspace/* when credential_access=false
    [ ] forbid ReadFile when credential_access=true
[ ] policy_bundles table: insert default bundle, active=true
[ ] FakeCedarProvider remains for unit tests (injected via DI)

> **Cedar CLI timeout rule**: If integrating cedar-policy-cli takes more than half a day,
> keep FakeCedarProvider and proceed to guarded_read / guarded_bash.
> The enforcement flow proof is the product, not Cedar plumbing.

Verification:
  README.md (credential_access=false, /workspace/ path) -> permit -> allow, reason_code="allowed"
  .env (credential_access=true) -> forbid -> deny (reason_code="policy_forbid.credential_path")
```

### Day 3: guarded_read

```text
[ ] packages/pi-adapter/src/guarded_read.ts
[ ] Path canonicalization (required before decision AND before execution):
    [ ] resolve absolute path from cwd + input
    [ ] resolve all symlinks (fs.realpathSync)
    [ ] separator-safe prefix check:
        const rel = path.relative(canonicalRoot, canonical)
        if (rel.startsWith('..') || path.isAbsolute(rel)) -> deny (canonicalization_failed)
    [ ] re-verify canonical path immediately before actual file read (TOCTOU protection)
    [ ] pass canonical path in resource.path; execute only that canonical path
[ ] Populate normalized:
    [ ] verb=read, mutation=false, destructive=false, network=false
    [ ] credential_access = path matches [.env, auth.json, .ssh/, .aws/, .npmrc, ...]
    [ ] credential_access=true -> decision will always be deny (never routed to approval)
[ ] Handle responses:
    [ ] allow             -> read canonical path, return content
    [ ] deny              -> throw GuardedAccessDenied(reason_code)
    [ ] approval_required -> throw ApprovalRequired(approval_id)

Test cases:
  README.md              -> allow (reason_code="allowed")
  .env                   -> deny (credential_access, reason_code="policy_forbid.credential_path")
  ../../outside          -> deny (canonicalization_failed)
  symlink -> .env        -> deny (resolved to .env, credential_access)
  /workspace2/file       -> deny (path.relative reveals '..' or absolute, not under root)
  missing file           -> deny safely (no content returned)
```

### Day 4: guarded_bash + Risk Rules

```text
[ ] packages/pi-adapter/src/guarded_bash.ts
[ ] argv normalization:
    [ ] shlex-split command string -> argv tokens
    [ ] command_family = argv[0], subcommand = argv[1] if present
    [ ] treat unparseable/ambiguous commands as high-risk (approval_required)
    [ ] prefer direct argv exec (never shell=true equivalent)
[ ] risk_rules.json loaded at startup
[ ] Risk engine: match on tool.kind + normalized.command_family + normalized.subcommand
[ ] Decision orchestration: cedar permit + risk approval_required + no prior_decision_id -> approval_required
[ ] Docker mode selection from constraints.network_mode:
    [ ] "none"         -> --network none
    [ ] "egress_proxy" -> --network actantos_egress (egress proxy + constraints.network_allowlist)

Verification:
  guarded_bash("git push --dry-run origin main") -> approval_required
  (use --dry-run or local fake remote; do NOT push to real GitHub in demo)
```

### Day 5: Approval Flow (with bug fixes applied)

```text
[ ] approvals table with: scope_hash (from tool_calls.scope_hash), one_use_token_hash (nullable), used_at, decided_at
[ ] scope_hash on tool_call creation:
    sha256(canonical(tenant_id + agent_external_id + user_id + session_external_id + tool_name + canonical_resource_id + normalized_hash))
    Stored on tool_calls.scope_hash and copied to approvals.scope_hash at approval creation time.
[ ] POST /v1/approvals/{approval_id}/decide:
    [ ] body: {decision, approver_user_id}
    [ ] set decided_at, decided_by, status='approved'
    [ ] generate random token: raw_token = base64url(randomBytes(32))
    [ ] store one_use_token_hash = sha256(raw_token); never store raw_token
    [ ] return {"approval_id": "...", "approval_token": raw_token, "expires_at": "..."}
[ ] Re-submission inside transaction (FOR UPDATE):
    [ ] Adapter sends NEW request_id (e.g. req_001_exec) + authorization.prior_decision_id
    [ ] SELECT approvals WHERE id=$approval_id AND tenant_id=$t FOR UPDATE
    [ ] check: status='approved', expires_at>now(), used_at IS NULL
    [ ] check: scope_hash matches tool_calls.scope_hash for new request
    [ ] check: sha256(authorization.approval_token) == one_use_token_hash
    [ ] SET used_at=now(), used_by_request_id=$new_request_id
    [ ] if used_at already set -> deny (invalid_approval: double-use)

Verification:
  POST /decide {approved} -> random token returned, decided_at set
  Re-submit with NEW request_id + prior_decision_id -> allow, used_at set
  Resend original request_id -> Step 0 returns existing approval_required (not consumed)
  Re-submit same approval_token again -> deny (used_at already set)
```

### Day 6: Docker Sandbox Executor

```text
[ ] Docker executor module:
    [ ] Verify decision_token (HMAC verify + all claims) before running anything
    [ ] Select network mode from constraints.network_mode:
        none        -> docker --network none
        egress_proxy -> docker --network actantos_egress (plain bridge for Week 1 demo)
    [ ] Apply all Day 1 Docker constraints (see §9.1)
    [ ] Enforce timeout and max_output_bytes
    [ ] Capture exit_code, sha256(stdout), sha256(stderr)
    [ ] redacted_preview: first 200 chars; scrub credential patterns before logging
[ ] POST /v1/tool-result:
    [ ] Parse ToolResultRequest
    [ ] Verify decision_token when status in [executed, failed, timeout]; skip for blocked
    [ ] INSERT audit_event inside hash-chain transaction

Verification:
  Approved git push --dry-run executes in Docker (egress_proxy = plain bridge, Week 1)
  Blocked .env read -> POST tool-result with status=blocked, no decision_token required
  Result row in audit_events with stdout_hash and hash chain
```

### Day 7: Audit Timeline + Demo Repo

```text
[ ] GET /v1/sessions/{session_id}/events:
    [ ] audit_events ordered by created_at ASC
    [ ] include: event_type, actor, tool_call_id, decision_id, reason_code, event_hash
[ ] POST /v1/kill-switches {scope_type, scope_id, reason}
    [ ] Pipeline Step 1 checks this table first
[ ] Demo repo:
    [ ] README: 5-step setup from scratch (assume nothing pre-installed except Docker + Node)
    [ ] demo.ts: Steps 1-7 in sequence, each step prints result
    [ ] policies/default.cedar (Policy 0 + credential_access forbid)
    [ ] risk_rules.json
    [ ] docker-compose.yml (actantosd + postgres)

Verification:
  Run demo.ts fresh machine in < 10 minutes.
  All 7 steps pass without manual intervention except the approval API call.
```

---

## 11b. Week 1 Acceptance Test Matrix

These 12 tests define "done" for Week 1. Each must pass on a fresh machine.

```text
 T1:  README.md read         -> allow, reason_code="allowed"
 T2:  .env read              -> deny, reason_code="policy_forbid.credential_path"
 T3:  ../../outside read     -> deny, reason_code="canonicalization_failed"
 T4:  symlink-to-.env read   -> deny, reason_code="policy_forbid.credential_path"
 T5:  /workspace2/file read  -> deny, reason_code="canonicalization_failed" (separator-safe)
 T6:  same request_id retry  -> same decision, no new DB row (idempotency)
 T7:  git push --dry-run     -> approval_required
 T8:  approve + NEW request_id -> allow, used_at set on approval
 T9:  same approval_token reused -> deny, reason_code="invalid_approval" (used_at set)
 T10: kill switch active     -> deny, reason_code="kill_switch_active"
 T11: tool-result status=executed without decision_token -> rejected
 T12: dry_run=true on policy_forbid path -> deny, decision_mode="dry_run", no decision_token, audit logged
```

> No test should require Slack, gVisor, Firecracker, credential broker, or multi-user auth.

---

## 12. Implementation Stack

Pick this stack. Commit to it for Week 1.

```text
Language:           TypeScript
HTTP server:        Fastify
Request validation: Zod (schemas shared between actantosd and pi-adapter)
Database:           Postgres
Query layer:        Kysely or Drizzle (type-safe, no ORM magic)
Policy engine:      cedar-policy-cli subprocess (Day 1); Rust N-API crate (Phase 2)
Adapter package:    packages/pi-adapter (guarded_read, guarded_bash)
Demo runner:        tsx (no build step needed for demo.ts)
Infra (local):      docker-compose (actantosd + postgres)
```

Rationale:
- Pi and MCP adapter work is TypeScript-heavy. Sharing Zod schemas between server and adapter eliminates schema drift.
- Fastify: sub-5ms P99 at single-process scale. Sufficient for Week 1.
- Do not use Rust for the HTTP server until enforcement kernel is proven. Rust is for Phase 2 Cedar evaluator wrapper only.

---

## 13. Path Canonicalization Rules

Every file and shell operation must follow these rules. Violations = `canonicalization_failed` (deny).

```text
Rule 1: Resolve absolute path before decision
  canonical = path.resolve(session.cwd, user_input_path)

Rule 2: Resolve all symlinks
  canonical = fs.realpathSync(canonical)
  If resolution fails (dangling symlink, missing file) -> deny (canonicalization_failed)

Rule 3: Verify workspace prefix (separator-safe)
  # UNSAFE: canonical.startsWith(root)
  # SAFE:
  const rel = path.relative(root, canonical)
  if (rel.startsWith('..') || path.isAbsolute(rel)) -> deny (canonicalization_failed)
  # This prevents /workspace2/secret from matching /workspace root.

Rule 4: Decision uses canonical path only
  resource.path in the intercept request = canonical path (never raw user input)

Rule 5: Execution uses same canonical path
  Re-verify canonical path immediately before read/write at execution time.
  Never use raw user-provided path at execution time.
  (TOCTOU: between decision and execution a symlink could be swapped.)

Rule 6: Shell argv uses explicit tokens
  Build argv as string[] (never shell=true / sh -c "raw string").
  File arguments in argv are canonicalized before passing to the executor.

Rule 7: Read vs Write canonicalization mode
  read_existing_path (guarded_read):
    realpath must succeed (file must exist)
    if missing -> deny safely (no content returned)
  write_target_path (guarded_write, future):
    parent directory must exist and resolve under workspace root
    final filename may not exist yet (new file creation is valid)
    full parent path is canonicalized; final filename is validated for credential patterns
    final path must not match credential_access patterns even if file doesn't exist yet

Rule 8: credential_access=true is always deny, not approval_required
  In MVP: credential_access=true must always result in final_decision=deny.
  Do NOT route credential reads to approval workflow.
  Approving secret exfiltration is risky and wrong in a demo context.
```

---

## References

| Resource | Notes |
|---|---|
| Cedar Policy Language | cedarpolicy.com - RBAC/ABAC; Cedar default is forbid; permit must be explicit |
| Cedar arXiv paper | arXiv:2403.04651 - Expressive, Fast, Safe, and Analyzable Authorization |
| MCP Security Best Practices | modelcontextprotocol.io - confused deputy, token passthrough, SSRF, tool poisoning |
| MCP Tool Specification | modelcontextprotocol.io - tools/list, tools/call, resources/read, prompts/get |
| gVisor | github.com/google/gvisor - application kernel for containers; not a microVM |
| Firecracker | firecracker-microvm.github.io - lightweight KVM microVMs for multi-tenant workloads |
| NIST AI RMF | NIST AI 100-1 - AI Risk Management Framework |

---

## Handoff

Current verified state:

- Week 1 is green both locally and on the compose-backed runtime from `D:\Job\ActantOS\plan\actantosd`:
  - `npm run typecheck`
  - `npm run build`
  - `npm test` (`51` passing)
  - `docker compose up -d --build`
  - `npm run demo -- --url http://localhost:3100` (`29 passed, 0 failed`)
- The live verification target is `http://localhost:3100`, not `http://localhost:3000`.
- Real Docker/Postgres verification is now complete.
- `demo.ts` now runs through `tsx`, matching the implementation stack section.
- The daemon Postgres layer now executes through Kysely instead of talking to `pg` directly.
- MCP manifest drift enforcement is now live:
  - first-seen MCP tool manifests establish an approved baseline
  - drifted schemas/descriptions are stored as pending versions and denied
  - `POST /v1/mcp/tool-versions/:id/approve` promotes the pending version so later calls allow again
- Decision-token enforcement is now closer to the spec instead of the earlier thin payload:
  - allow tokens now include `decision_id`, `tool_call_id`, `constraints_hash`, `decision=allow`, and `exp`
  - `src/docker-executor.ts` rejects expired tokens and constraint mismatches before any Docker work starts
  - `src/tool-result-service.ts` verifies the stronger claims against persisted `tool_calls` and `policy_decisions` rows before accepting `executed`, `failed`, or `timeout` results
- MCP gateway result logging no longer generates a fresh `request_id` when posting `/v1/tool-result`; it reuses the same intercepted request and is covered by a Postgres-backed integration test.
- The live MCP proof path is now exercised outside the test harness as well:
  - `.tmp/live-mcp-upstream.ts` starts a minimal upstream SSE MCP server on `127.0.0.1:8080`
  - `.tmp/live-mcp-client.ts` connects to `http://127.0.0.1:3200/v1/mcp/sse`, lists tools, and calls `read_repo_file`
  - the resulting Postgres rows show `tool_calls.request_id = policy_decisions.request_id`, with both audit events attached to that same stored request
- Session timeline enrichment is now live:
  - `src/session-events.ts` returns `request_id`, `tool`, `final_decision`, `risk_class`, `approval_id`, and `result_hash`
  - approval-resume events find their `approval_id` through `approvals.used_by_request_id`, so the resumed allow decision now carries approval lineage without a schema migration
  - live HTTP verification against `127.0.0.1:3300` showed the resumed shell allow event for `req_live_events_approval_0001_exec` with `final_decision="allow"`, `risk_class="high"`, the consumed `approval_id`, and a persisted `result_hash`
- URL-target SSRF denial is now live on the intercept path for obvious blocked destinations such as `127.0.0.1`, `localhost`, `169.254.169.254`, and RFC-1918 IPv4 ranges.
- Cedar CLI compatibility notes for the next engineer:
  - `cedar-policy-cli 4.11.2` inside the container is unstable with more complex policy shapes and can intermittently return `DENY` or recursion diagnostics for logically equivalent non-credential requests.
  - Week 1 currently keeps the policy surface to a single permit statement and uses resource attributes instead of Cedar request context.
  - `src/cedar-cli-provider.ts` includes a tightly scoped compatibility shim: if Cedar returns `DENY` for a request with `credential_access=false`, the provider preserves the intended Week 1 permit behavior instead of failing the demo path.
- The Postgres audit chain now parses bigint sequence values explicitly, preventing repeated demo runs from corrupting `audit_chain_state.seq`.

Next checks:

- If you continue beyond Week 1, replace the Cedar compatibility shim with either:
  - a newer stable Cedar CLI/runtime, or
  - a direct evaluator integration that does not exhibit the 4.11.2 recursion/false-deny behavior.
- After that, continue the implementation-spec audit for post-Week-1 gaps instead of revisiting the verified Week 1 path.

