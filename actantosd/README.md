# actantosd — ActantOS Enforcement Kernel

In-path runtime permission gateway for AI agents. Intercepts every tool call, evaluates Cedar policy + risk rules, and returns `allow | deny | approval_required` before execution happens.

The daemon defaults to port `3100` so it does not collide with the promotion website that already uses `localhost:3000` in this workspace.

The demo runner uses `tsx`, so `demo.ts` can be executed directly without a separate build step.

Security planning and release evidence for the current control plane are tracked in [`docs/threat-model.md`](docs/threat-model.md), [`docs/security-hardening.md`](docs/security-hardening.md), and [`docs/security-review-checklist.md`](docs/security-review-checklist.md). The frozen production API boundary lives in [`docs/api-v1-contract.md`](docs/api-v1-contract.md). Production release docs now also include [`docs/upgrade-v0.7-to-v1.md`](docs/upgrade-v0.7-to-v1.md), [`docs/mcp-gateway-stable.md`](docs/mcp-gateway-stable.md), [`docs/release-checklist-v1.md`](docs/release-checklist-v1.md), and [`docs/release-notes-v1.0.0-production.md`](docs/release-notes-v1.0.0-production.md). Pilot rollout docs live in [`docs/pilot-onboarding.md`](docs/pilot-onboarding.md), [`docs/pilot-policy-templates.md`](docs/pilot-policy-templates.md), and [`docs/support-runbook.md`](docs/support-runbook.md).

## Architecture

```
Agent (Pi runtime)
    │
    │  POST /v1/intercept/tool-call
    ▼
actantosd (Fastify + Postgres)
    │  5 pipeline steps:
    │  0. Idempotency (request_id dedup)
    │  1. Kill switch check
    │  2. Budget / rate-limit
    │  3. Cedar PDP (policy evaluation)
    │  4. Risk classifier (risk_rules.json)
    │  5. Approval state resolution
    ▼
decision: allow | deny | approval_required
    + decision_token (HMAC-SHA256, enforced on /v1/tool-result)
```

## 5-Step Setup

### One-command portable agent test

On Windows, macOS, or Linux with Node.js 22+:

```bash
npm run quickstart
```

The command installs dependencies (`npm ci` in a Git clone, `npm install` in a
packed release), builds the service when source is present, or uses the shipped
compiled service from a release tarball,
starts it in memory on `127.0.0.1:4310`, runs the full simulated-agent demo,
and stops it. Docker and Postgres are not required. Set
`ACTANTOS_QUICKSTART_PORT` if port 4310 is already occupied.

### 1. Install Node.js 22+
```bash
node --version  # must be 22+
```

### 2. Install dependencies
```bash
cd actantosd
npm install
```

### 3a. Run in-memory mode (no DB required)
```bash
npm run dev
# Server starts at http://localhost:3100
```

### 3b. Run with Postgres (recommended for demo and self-host validation)
```bash
cp .env.example .env
docker compose up -d --build
# Postgres starts, actantosd waits for database health, runs the migration runner,
# optionally seeds demo data when ACTANTOS_SEED_DEMO=true,
# and serves the bundled dashboard, kill switch, approvals, audit, and
# evidence-export surface on http://localhost:3100.
```

On Windows PowerShell:

```powershell
Copy-Item .env.example .env
docker compose up -d --build
```

For a non-Compose Postgres target, run the database commands explicitly before starting the server:

```bash
DATABASE_URL=postgres://... npm run db:migrate
DATABASE_URL=postgres://... npm run db:seed-demo   # optional demo tenant/session seed
DATABASE_URL=postgres://... npm run dev
```

### Backup and restore

Create a logical backup from the Compose-managed Postgres instance with:

```bash
docker compose exec postgres pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" > actantosd-backup.sql
```

Restore a backup into a running stack with:

```bash
cat actantosd-backup.sql | docker compose exec -T postgres psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"
```

If you are restoring into an empty deployment, start Postgres first, run migrations, and then replay the dump:

```bash
docker compose up -d postgres
DATABASE_URL=postgres://... npm run db:migrate
cat actantosd-backup.sql | docker compose exec -T postgres psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"
```

### Fresh install smoke test

Run the self-host smoke path from dependency install through the demo with:

```bash
npm run smoke:fresh-install
```

That command will:
- create `.env` from `.env.example` when needed
- install dependencies with `npm ci`
- build the service
- start the Compose stack
- wait for `/health/ready`
- run the demo against `http://localhost:3100`

For the production release gate, run:

```bash
npm run release:verify
npm run release:artifacts
```

### 4. Run verification
```bash
npm test
# daemon tests — intercept pipeline, Cedar selection, approvals, budgets,
# kill switches, tool-result, session events, and Postgres-backed flows

cd ../packages/pi-adapter
npm test
# adapter tests — canonicalization, approval resume, and shell normalization
```

### Policy bundle smoke test
```bash
npm run policy:test -- --request-file fixtures/request.json --tenant-id t_demo
npm run policy:test -- --request-file fixtures/request.json --policy-file policies/default.cedar --tenant-id t_demo
npm run policy:regression
```

The command prints the evaluated policy source together with the resulting
`allow | deny | approval_required` decision and reason code.

`npm run policy:regression` locks the production policy matrix in one pass:
safe allow, credential deny, approval-required shell escalation, budget
enforcement, and dry-run non-executing behavior.

If you already seeded an older demo database, rerun `npm run db:migrate` before
using the active-bundle path so the placeholder demo policy is backfilled to the
checked-in Cedar source.

### 5. Run end-to-end demo
```bash
# While actantosd is running from a fresh compose-backed stack:
npm run demo -- --url http://localhost:3100
npm run demo -- --url http://localhost:3100 --approval-mode slack
```

Expected output:
```
=== ActantOS Demo ===
Targeting: http://localhost:3100
Approval mode: api
Step 7: Kill switch and evidence export
...
=== Results: X passed, 0 failed ===
```

If you accidentally point the demo at the promotion site, the script now fails fast with a clear "expected JSON" error instead of printing misleading policy failures.
If you want a fresh rerun with reset demo state, use `docker compose down -v` before bringing the stack back up.

## API Reference

The release-frozen `/v1` surface is documented in [`docs/api-v1-contract.md`](docs/api-v1-contract.md). The quick reference below keeps the most-used request and response examples close to the setup guide.

### POST /v1/intercept/tool-call
Main interception endpoint. Called before every tool execution.

**Request body**:
```json
{
  "request_id": "req_abc123def",
  "tenant_id": "t_demo",
  "agent": { "id": "pi_demo", "runtime_type": "pi", "environment": "dev", "risk_tier": "low" },
  "subject": { "user_id": "u_demo", "role": "developer" },
  "session": { "id": "s_demo", "cwd": "/workspace", "budget_remaining_cents": 10000 },
  "tool": { "kind": "file", "name": "guarded_read", "operation": "ReadFile", "schema_hash": "" },
  "resource": { "id": "/workspace/README.md", "kind": "file", "path": "/workspace/README.md" },
  "action": { "operation": "ReadFile", "args": { "path": "/workspace/README.md" } },
  "normalized": {
    "verb": "read", "mutation": false, "destructive": false,
    "network": false, "credential_access": false, "risk_class": "low"
  }
}
```

**Response (allow)**:
```json
{
  "decision": "allow",
  "decision_mode": "enforce",
  "reason": "permitted by policy",
  "reason_code": "allowed",
  "audit_event_id": "uuid",
  "decision_token": "base64url-hmac",
  "constraints": { "timeout_ms": 30000, "max_output_bytes": 200000, "network_mode": "none" }
}
```

**Response (deny)**:
```json
{
  "decision": "deny",
  "reason_code": "policy_forbid.credential_path | kill_switch_active | ...",
  ...
}
```

**Response (approval_required)**:
```json
{
  "decision": "approval_required",
  "reason_code": "approval_required",
  "approval": { "approval_id": "uuid", "status": "pending", "expires_at": "iso8601" },
  ...
}
```

### GET /v1/approvals/pending
List pending approvals for the dashboard approval queue.

**Response**:
```json
{
  "tenant_id": "t_demo",
  "approvals": [
    {
      "approval_id": "uuid",
      "status": "pending",
      "expires_at": "iso8601",
      "created_at": "iso8601",
      "decision_id": "uuid",
      "request_id": "req_abc123",
      "reason": "risk.shell.git_push — approval required",
      "reason_code": "approval_required",
      "tool": { "kind": "shell", "name": "guarded_bash" },
      "session_id": "s_demo",
      "agent_id": "pi_demo"
    }
  ]
}
```

### POST /v1/approvals/:approval_id/decide
Admin endpoint to approve or deny a pending approval.

**Request**: `{ "decision": "approved", "approver_user_id": "admin" }`

**Response**: `{ "approval_id": "...", "decision": "approved", "approval_token": "..." }`

The demo seed creates `u_demo`, `u_dashboard`, `u_admin`, and `admin` user rows under tenant `t_demo`.

The `approval_token` must be included in the re-submitted intercept request in `authorization.approval_token`.

### GET /v1/policy-bundles
List policy bundle summaries for a tenant, with the currently active bundle surfaced explicitly.

### POST /v1/policy-bundles
Create a new policy bundle version.

**Request**:
```json
{
  "tenant_id": "t_demo",
  "version": "0.2.0",
  "engine": "cedar",
  "source_text": "permit(principal, action, resource);",
  "active": false
}
```

If `active` is `true`, the new bundle becomes the only active bundle for that tenant.
If Cedar syntax validation fails, the API returns `400 { "error": "invalid_policy_bundle", ... }` with a parse detail for the operator.

### GET /v1/policy-bundles/:id
Return the full stored policy bundle record, including `source_text`.

### POST /v1/policy-bundles/:id/activate
Promote a stored bundle version to the active tenant policy. Activating an older version is the rollback path.

### GET /dashboard/policy
Operator-facing policy bundle page for reviewing the active Cedar source, uploading a candidate bundle, and promoting a stored bundle version.

### GET /v1/risk-rules
Return the active risk rule set for a tenant. If no tenant-specific rule set has been stored yet, the API returns the checked-in bootstrap rules with `source: "file_fallback"`.

### PUT /v1/risk-rules
Replace the tenant risk rule set used by runtime enforcement.

**Request**:
```json
{
  "tenant_id": "t_demo",
  "rules": [
    {
      "rule_id": "risk.file.readme.approval",
      "description": "Require approval for README reads",
      "when": {
        "tool.kind": "file",
        "resource.path": "/workspace/README.md"
      },
      "approval_required": true,
      "risk_class": "medium"
    }
  ]
}
```

### GET /v1/rate-limits
List current high-risk rate-limit rows for a tenant.

### PUT /v1/rate-limits
Create or replace a high-risk rate limit for a tenant scope plus action key.

High-risk rate limits key off the matched risk rule id, so repeated risky actions can be throttled separately from coarse `budgets` ceilings.

### POST /v1/tool-result
Record execution result. `decision_token` is **required** for `executed/failed/timeout` status — enforces that tools can only report results if they were permitted.

### GET /health/live
Process liveness probe. Returns `200` when the Fastify process is serving requests.

### GET /health/ready
Dependency readiness probe. Returns `200` when the process is ready and, if `DATABASE_URL` is configured, the database probe succeeds. Returns `503` when Postgres is configured but unreachable.

When `ACTANTOS_API_KEY` is configured, operator routes accept the API key via the `x-actantos-api-key` header. The dashboard also accepts `api_key` in the query string so the browser UI can keep operating across section changes and operator actions.

### GET /v1/sessions/:session_id/events
Audit timeline for a session (hash-chained, ordered by `created_at ASC`).

Each event includes:
- `actor`
- `request_id`
- `tool`
- `tool_call_id`
- `decision_id`
- `final_decision`
- `risk_class`
- `reason_code`
- `approval_id`
- `result_hash`
- `event_hash`
- `created_at`

### GET /v1/budgets
List current budget rows for a tenant.

### GET /v1/mcp/tool-versions/pending
List drifted MCP tool manifests waiting for approval.

### POST /v1/mcp/tool-versions/:id/approve
Approve a pending MCP tool manifest version and promote it to the active baseline for that tool.

### POST /v1/kill-switches
Immediately disable an agent, session, tenant, or tool.

### GET /v1/kill-switches
List active kill switches for ops visibility.

### DELETE /v1/kill-switches/:id
Re-enable a kill switch.

## Production v1 docs

- `/v1` contract: [`docs/api-v1-contract.md`](docs/api-v1-contract.md)
- upgrade path: [`docs/upgrade-v0.7-to-v1.md`](docs/upgrade-v0.7-to-v1.md)
- MCP gateway clients: [`docs/mcp-gateway-stable.md`](docs/mcp-gateway-stable.md)
- policy templates: [`docs/pilot-policy-templates.md`](docs/pilot-policy-templates.md)
- release checklist: [`docs/release-checklist-v1.md`](docs/release-checklist-v1.md)
- release notes: [`docs/release-notes-v1.0.0-production.md`](docs/release-notes-v1.0.0-production.md)

## Acceptance Tests

| ID  | Scenario                                      | Expected                              |
|-----|-----------------------------------------------|---------------------------------------|
| T1  | README.md read                                | allow, decision_token issued          |
| T2  | .env read                                     | deny, policy_forbid.credential_path   |
| T3  | ../../outside path traversal                  | deny, canonicalization_failed         |
| T4  | symlink-to-.env                               | deny, credential_access detected      |
| T5  | Path in different workspace                   | deny, canonicalization_failed         |
| T6  | Same request_id × 2                           | same response, no duplicate DB row    |
| T7  | git push                                      | approval_required                     |
| T8  | Approve + new request_id                      | allow, decision_token                 |
| T9  | Reuse approval_token                          | deny, invalid_approval                |
| T10 | Kill switch active                            | deny, kill_switch_active              |
| T11 | tool-result without decision_token            | 400 decision_token_required           |
| T12 | dry_run on credential path                    | deny, decision_mode=dry_run           |

## Configuration

| Env var          | Default                    | Description                   |
|------------------|----------------------------|-------------------------------|
| `DATABASE_URL`   | (none — uses in-memory)    | Postgres connection string    |
| `PORT`           | `3100`                     | Server port                   |
| `HOST`           | `0.0.0.0`                  | Bind address                  |
| `HMAC_SECRET`    | `actantos-dev-secret`      | HMAC secret for decision tokens |
| `ACTANTOS_API_KEY` | (unset)                  | Optional operator-plane API key |
| `ACTANTOS_SEED_DEMO` | `true`                 | Whether Postgres startup seeds the demo tenant |
| `POSTGRES_USER`  | `actantos`                 | Compose Postgres username     |
| `POSTGRES_PASSWORD` | `actantos`              | Compose Postgres password     |
| `POSTGRES_DB`    | `actantos`                 | Compose Postgres database name |
| `POSTGRES_PORT`  | `5432`                     | Host port for Postgres        |
| `CEDAR_CLI_PATH` | `cedar` if available       | Override Cedar CLI binary path |
| `CEDAR_POLICY_PATH` | `policies/default.cedar` | Override Cedar policy path    |
| `ACTANTOS_MCP_UPSTREAM_URL` | `http://localhost:8080/sse` | Optional upstream MCP SSE endpoint |
| `ACTANTOS_MCP_SERVER_ID` | `upstream-mcp`      | Optional upstream MCP server identity |

## Project Structure

```
actantosd/
├── src/
│   ├── contracts.ts            # Zod schemas (request/response types)
│   ├── intercept-service.ts    # 5-step decision pipeline
│   ├── risk-engine.ts          # risk_rules.json evaluator
│   ├── cedar-provider.ts       # Cedar CLI adapter factory
│   ├── cedar-cli-provider.ts   # Cedar subprocess wrapper
│   ├── fake-cedar-provider.ts  # In-memory Cedar (credential_access → forbid)
│   ├── approval-routes.ts      # Pending approvals + approve/deny routes
│   ├── budget-routes.ts        # Budget listing routes
│   ├── kill-switch-routes.ts   # Kill switch create/list/delete routes
│   ├── intercept-response.ts   # Shared response/context builders
│   ├── tool-call-repository.ts # In-memory + Postgres repositories
│   ├── database.ts             # Postgres pool wrapper + migrations
│   ├── server.ts               # Fastify routes
│   └── index.ts                # Entrypoint
├── sql/
│   ├── migrations/001_day1_core.sql   # Schema (10 tables)
│   └── seeds/001_demo.sql            # Demo tenant/agent/session data
├── policies/
│   ├── default.cedar           # Cedar policies (permit/forbid rules)
│   └── risk_rules.json         # Risk rules (approval routing)
├── packages/
│   └── pi-adapter/
│       └── src/
│           ├── guarded_read.ts   # File read with canonicalization
│           └── guarded_bash.ts   # Shell exec with sandbox
├── demo.ts                     # End-to-end demo (T1-T12)
├── docker-compose.yml          # Postgres + actantosd
├── Dockerfile                  # actantosd image
└── Dockerfile.sandbox          # actantos/sandbox:latest
```
