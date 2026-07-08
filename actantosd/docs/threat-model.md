# ActantOS Threat Model

Status: draft for `E8-01 Threat model`  
Scope date: 2026-07-07

## 1. Objective

ActantOS exists to enforce one rule:

> No agent action executes without an ActantOS decision.

This document maps the current `actantosd` control plane to concrete threats so the security milestone can prioritize fail-closed tests, hardening, and operational guardrails from evidence rather than intuition.

## 2. System scope

In scope for this version:

- runtime intercept API: `/v1/intercept/tool-call`
- runtime result API: `/v1/tool-result`
- operator plane: dashboard, approvals, policy bundles, budgets, rate limits, risk rules, kill switches, evidence export
- MCP gateway: `/v1/mcp/sse` and `/v1/mcp/message`
- Postgres state: decisions, approvals, audit chain, policy bundles, rate limits, budgets, manifests
- Docker-backed execution path and decision-token verification

Out of scope for this version:

- enterprise identity features not yet built, including OIDC and SCIM
- SaaS tenancy isolation beyond the current self-hosted deployment model
- host-level container escape defenses outside Docker and the underlying OS

## 3. Security goals

Primary goals:

1. prevent unauthorized execution
2. prevent replay or tampering of approval and execution authorizations
3. preserve reliable audit evidence
4. bound risky or runaway agent behavior
5. keep operator controls from becoming a bypass channel

Secondary goals:

1. reduce blast radius of upstream MCP compromise
2. reduce secret exposure in runtime and audit surfaces
3. make unsafe deployment choices visible as explicit residual risk

## 4. Assets

High-value assets:

- `decision_token` integrity and expiry
- `approval_token` one-time authorization state
- active policy bundles and risk rules
- audit chain (`prev_hash`, `event_hash`, per-tenant sequence)
- operator-plane capabilities
- tenant/session/agent identifiers used for enforcement scope
- MCP tool metadata baselines
- evidence export payloads
- Docker execution constraints and output redaction

## 5. Trust boundaries

1. Agent/runtime to ActantOS  
   Untrusted tool-call requests cross into the intercept API.

2. Operator to ActantOS  
   Higher-trust admin actions cross into dashboard and `/v1/*` operator routes.

3. ActantOS to Postgres  
   Persistent source of truth for decisions, approvals, audit, and policy state.

4. ActantOS to upstream MCP server  
   Tool metadata and tool execution results arrive from an external server boundary.

5. ActantOS to Docker / host execution  
   Approved commands cross into a lower-level execution substrate with host interaction risk.

6. ActantOS to outbound URLs  
   HTTP targets may point at internal infrastructure or metadata services.

## 6. Data flow summary

1. An agent posts a normalized tool call to `/v1/intercept/tool-call`.
2. ActantOS parses the request, checks idempotency, kill switches, budgets, manifest drift, URL target policy, Cedar policy, risk rules, and rate limits.
3. It returns `allow`, `deny`, or `approval_required`.
4. `allow` responses may carry an HMAC-signed `decision_token`.
5. Approved execution later reports to `/v1/tool-result`, which verifies the token against the stored decision and constraints before recording outcome evidence.
6. Operator routes modify policies, budgets, kill switches, approvals, and exports through the same database-backed control plane.
7. The MCP gateway converts upstream tool calls into the same intercept/result lifecycle.

## 7. Existing controls

Controls already present in the codebase:

- Zod parsing at request boundaries
- idempotent decision lookup by `tenant_id + request_id`
- kill-switch checks before policy evaluation
- Cedar policy evaluation plus syntax validation for bundle activation
- budget and rate-limit enforcement before execution
- MCP manifest drift guard before tool use
- URL target guard blocking localhost, loopback, RFC1918 IPv4 ranges, and common metadata endpoints
- HMAC-signed `decision_token` verification with constraint hashing and expiry
- one-time approval verification and consumption
- per-tenant audit hash chaining
- optional operator API key enforcement on non-runtime routes
- Docker execution constraint binding via the verified decision token
- output truncation and preview redaction for common secret patterns

## 8. STRIDE analysis

| Category | Threat | Surface | Current mitigation | Residual risk / gap |
| --- | --- | --- | --- | --- |
| Spoofing | Forged execution authorization | `/v1/tool-result`, Docker executor | HMAC `decision_token`, expiry, claim matching, constraint hash matching | Secret rotation and key-management process not yet documented |
| Spoofing | Forged operator actions | dashboard and operator APIs | optional `ACTANTOS_API_KEY` gate | Query-string `api_key` is convenient but leak-prone in logs/history; no user-level auth yet |
| Spoofing | Forged approval reuse | approval replay path | approval verification scoped to tenant and `scope_hash`, one-time consume | No external MFA or identity proof beyond current operator identity model |
| Tampering | Policy bundle replacement with invalid Cedar | `/v1/policy-bundles`, activation | syntax validation before activation, stored inactive candidates | No signed policy provenance yet |
| Tampering | MCP tool schema drift alters trusted tool behavior | MCP gateway | manifest drift guard and approval flow | Upstream MCP identity is still env-configured and trust-on-config |
| Tampering | Audit evidence rewrite in database | Postgres | per-tenant hash chain, append-style audit events | No external notarization or off-box replication yet |
| Repudiation | Operator denies approving or changing policy | approvals, policy UI, budgets/risk routes | database records and audit events | Need explicit operator identity story stronger than shared API key |
| Repudiation | Agent denies making a risky request | intercept API | request and decision persistence by tenant/session/agent/request id | Caller identity is only as strong as upstream headers/runtime integration |
| Information disclosure | SSRF to cloud metadata or private services | HTTP tools, MCP tools with URL args | URL target guard blocks localhost, loopback, RFC1918, metadata hosts | No DNS rebinding or IPv6 private-range enforcement yet |
| Information disclosure | Secrets leak in result previews or audit export | `/v1/tool-result`, evidence export | preview redaction and output truncation | Redaction is pattern-based and incomplete for arbitrary secrets |
| Information disclosure | Operator API key leakage via query param | dashboard links and browser history | optional header alternative exists | README and operators should prefer header-bearing clients where possible |
| Denial of service | Runaway tool loops overwhelm control plane | intercept API | budgets, rate limits, kill switches, idempotency | No explicit ingress rate limiting or queue backpressure yet |
| Denial of service | Oversized outputs or long-running commands | Docker executor, tool result | timeout, max output bytes, output hashing | Container/resource quotas beyond current flags need explicit validation |
| Denial of service | Upstream MCP instability stalls gateway | MCP gateway | structured gateway/session handling | No circuit-breaker or upstream auth/TLS posture documented yet |
| Elevation of privilege | Unapproved command executes after policy allow for a different scope | Docker executor | token claim matching for tenant/agent/session/tool/scope | Depends on secrecy of `HMAC_SECRET` and correct caller wiring |
| Elevation of privilege | Operator plane bypasses runtime guardrails | policy/budget/risk/kill-switch routes | API-key protected operator plane, stored changes, audit | Privileged operators can still create dangerous state; needs separation of duties later |
| Elevation of privilege | Container breakout or unsafe host interaction | Docker executor | constrained docker plan, network mode binding | Host hardening, image policy, and runtime sandbox guarantees are not yet modeled deeply |

## 9. Priority attack paths

### A. Forged tool-result completion

Goal: convince ActantOS that a tool executed legitimately without prior approval.

Path:

1. obtain or forge a `decision_token`
2. submit `/v1/tool-result` with matching request metadata
3. record an execution outcome and audit event

Current blockers:

- HMAC verification
- expiry check
- decision id, tool call id, tenant, agent, session, tool, and scope hash matching
- constraints hash matching

Next hardening:

- document rotation for `HMAC_SECRET`
- add explicit tests for malformed claim permutations if not already covered

### B. SSRF via HTTP or MCP-originated URL arguments

Goal: reach metadata or internal services through an approved tool call.

Path:

1. submit a request with an internal target URL
2. rely on policy allow and tool execution
3. extract internal credentials or service data

Current blockers:

- URL parsing and deny on invalid targets
- blocklist for localhost, loopback, metadata hosts, and RFC1918 IPv4

Next hardening:

- add IPv6 private/link-local coverage
- resolve DNS rebinding exposure explicitly

### C. Operator-plane compromise

Goal: change policy/budgets/kill switches or export evidence without legitimate operator authority.

Path:

1. obtain `ACTANTOS_API_KEY` or ride an operator browser session
2. activate permissive policy or export sensitive evidence
3. hide traces or persist privileged state

Current blockers:

- optional API-key gate
- audit/event persistence for state changes

Next hardening:

- prefer headers over query-string auth where possible
- move toward named operator identities and stronger auth

### D. Upstream MCP trust abuse

Goal: introduce a tool or schema change that gains more capability than operators expect.

Path:

1. upstream server advertises changed tool metadata
2. downstream runtime keeps using the tool without review
3. new arguments or semantics bypass prior human expectations

Current blockers:

- manifest drift persistence and approval workflow

Next hardening:

- document trusted upstream requirements
- add deployment guidance for TLS/authenticated upstream channels

## 10. Security assumptions

This version assumes:

- Postgres is trusted and access-controlled by deployment
- `HMAC_SECRET` and `ACTANTOS_API_KEY` are stored securely by operators
- runtimes populate tenant/agent/session identity truthfully
- Docker is available and the host runtime is not already compromised
- upstream MCP servers are explicitly chosen and not anonymous internet endpoints

If any assumption fails, enforcement guarantees weaken materially.

## 11. Backlog derived from this threat model

Immediate next slices this document supports:

1. `E8-02` fail-closed tests around runtime and operator boundaries
2. `E8-03` more explicit token verification abuse cases
3. `E8-04` approval replay coverage across boundary conditions
4. `E8-05` expanded SSRF coverage, especially IPv6 and rebinding scenarios
5. `E8-06` standalone audit chain verifier
6. operator-auth hardening beyond shared API key
7. secret-handling review for evidence export and preview redaction

## 12. Exit criteria for E8-01

This milestone is done when:

- assets, trust boundaries, and attack paths are documented
- current mitigations are mapped to code-level controls
- known gaps are called out as explicit residual risk or backlog work
