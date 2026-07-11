# ActantOS `/v1` API Contract

This document freezes the supported HTTP contract for Quiet Open-Core **`v1.0.0`** (formerly referred to as `v1.0.0-production` in drafts).

The goal of this contract is narrow:

- define the supported `/v1` surface that release work can build against
- separate stable `/v1` endpoints from unversioned operator conveniences
- call out demo-era behavior that still exists but is not part of the production contract

## Contract rules

- The supported API boundary is the set of `/v1` endpoints listed below.
- `HEAD` handling is provided by Fastify and is not part of the supported contract.
- Clients should treat JSON field names and HTTP status codes documented here as stable.
- Clients should not rely on JSON object key order, framework-generated headers, or exact error formatting beyond the named `error` values already documented.
- Clients should always send `tenant_id` explicitly. The current `t_demo` fallback remains for local seeded demos, but it is not a production contract guarantee.

## Runtime enforcement endpoints

These are the runtime-critical endpoints that remain available even when operator API key auth is configured:

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/v1/intercept/tool-call` | Evaluate a tool call before execution and return `allow`, `deny`, or `approval_required`. |
| `POST` | `/v1/tool-result` | Record the result of an allowed or blocked execution attempt. |
| `GET` | `/v1/mcp/sse` | Start the ActantOS MCP gateway SSE transport. |
| `POST` | `/v1/mcp/message` | Deliver MCP transport messages for an existing gateway session. |

Stable runtime semantics:

- `POST /v1/tool-result` requires `decision_token` for `executed`, `failed`, and `timeout` statuses.
- `POST /v1/intercept/tool-call` and `POST /v1/tool-result` are part of the enforcement path and are intentionally excluded from operator API key auth.
- MCP gateway session ids are transport details and must be treated as opaque values.

## Operator endpoints available without Postgres

These endpoints are part of the supported `/v1` surface even when the daemon is running in in-memory mode. In that mode, list-style endpoints can legitimately return empty collections because there is no persisted state.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/v1/agents` | List tenant agents. |
| `GET` | `/v1/approvals/pending` | List pending approvals. |
| `POST` | `/v1/approvals/:approval_id/decide` | Approve or deny a pending approval. |
| `GET` | `/v1/decisions` | List policy decisions for a tenant. |
| `GET` | `/v1/evidence/export` | Export an evidence package for a tenant or session. |
| `GET` | `/v1/kill-switches` | List active kill switches. |
| `POST` | `/v1/kill-switches` | Create a kill switch. |
| `DELETE` | `/v1/kill-switches/:id` | Disable an existing kill switch. |
| `GET` | `/v1/sessions` | List sessions for a tenant. |
| `GET` | `/v1/sessions/:session_id/events` | Return the audit timeline for a session. |
| `POST` | `/v1/webhooks/evidence` | Deliver a signed evidence export to a destination URL. |

## Postgres-backed `/v1` endpoints

These endpoints are part of the supported contract for production deployments, but they require a configured database and are not registered in in-memory mode.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/v1/budgets` | List budgets for a tenant. |
| `POST` | `/v1/budgets` | Create or replace a budget row. |
| `GET` | `/v1/metrics/usage` | Return tenant usage totals and tool-kind counts. |
| `GET` | `/v1/mcp/tool-versions/pending` | List drifted MCP tool manifests waiting for approval. |
| `POST` | `/v1/mcp/tool-versions/:id/approve` | Promote a pending MCP tool manifest version. |
| `GET` | `/v1/policy-bundles` | List policy bundle summaries for a tenant. |
| `GET` | `/v1/policy-bundles/:id` | Return a full stored policy bundle. |
| `POST` | `/v1/policy-bundles` | Create a policy bundle version. |
| `POST` | `/v1/policy-bundles/:id/activate` | Activate a stored policy bundle version. |
| `GET` | `/v1/rate-limits` | List rate-limit rows for a tenant. |
| `PUT` | `/v1/rate-limits` | Create or replace a rate-limit row. |
| `GET` | `/v1/risk-rules` | Return the active tenant risk rule set or file fallback. |
| `PUT` | `/v1/risk-rules` | Replace the tenant risk rule set. |

## Auth boundary

When `ACTANTOS_API_KEY` is configured:

- operator-facing `/v1` endpoints require `x-actantos-api-key`
- runtime endpoints for enforcement and MCP transport remain callable without that key

The dashboard's `api_key` query string support is an operator UI convenience and is not part of the `/v1` contract.

## Out of scope for the `/v1` contract

These surfaces remain intentionally outside the frozen `/v1` API boundary:

- `/health/live`
- `/health/ready`
- `/dashboard`
- `/dashboard/policy`
- `/dashboard/metrics`

They are still supported product surfaces, but they are not part of the versioned API freeze for `V1-01`.
