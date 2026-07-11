# Stage 2 Product Inventory (`actantosd`)

**Ship rule:** built + tests pass = done. No design-partner gate.  
**Stage:** Stage 1 Enforcement Kernel **done** (v1.0.x). Stage 2 Agent Runtime Control Plane **active**.

## Already shipped (Stage 1 foundation)

| Area | Modules | Tests (representative) |
|------|---------|------------------------|
| Intercept pipeline | `intercept-service.ts`, `intercept-fail-closed.ts`, `intercept-response.ts`, `decision-constraints.ts` | `intercept-service.test.ts`, `fail-closed.test.ts` |
| Policy / risk | `cedar-provider.ts`, `cedar-cli-provider.ts`, `risk-engine.ts`, `policy-test.ts` | `cedar-provider.test.ts`, `policy-regression.test.ts`, `policy-test.test.ts` |
| Approvals | `approval-routes.ts`, webhook hooks | `approval-routes.test.ts` |
| Budgets / rate limits | `budget-provider.ts`, `budget-routes.ts`, `rate-limit-provider.ts`, `rate-limit-routes.ts` | `budget-*.test.ts`, `rate-limit-routes.test.ts` |
| Kill switch | `kill-switch-routes.ts` | `kill-switch-routes.test.ts` |
| Sessions / agents | `sessions-routes.ts`, `session-events.ts`, `agents-routes.ts` | `sessions-routes.test.ts`, `session-events.test.ts`, `agents-routes.test.ts` |
| Audit / evidence | `audit-chain-verifier.ts`, `evidence-export-routes.ts`, `hash.ts` | `audit-chain-verifier.test.ts`, `evidence-export-routes.test.ts` |
| MCP | `mcp-gateway.ts`, `mcp-manifest-guard.ts`, tool-version routes | `mcp-gateway.test.ts`, `mcp-manifest-guard.test.ts` |
| Sandbox | `docker-executor.ts`, `docker-command-plan.ts` | `docker-executor.test.ts`, `docker-command-plan.test.ts` |
| Operator surfaces (basic) | `dashboard-routes.ts`, `metrics-dashboard-routes.ts`, `policy-dashboard-routes.ts`, `usage-metrics-routes.ts`, `policy-dashboard-page.ts` | matching `*-routes.test.ts` |
| Policy bundles | `policy-bundle-routes.ts`, activation routes, risk-rules routes | matching tests |
| API contract | `contracts.ts`, `api-contract.test.ts` | frozen `/v1` |

## Stage 2 gap map

| ID | Capability | Current state | Gap | Acceptance tests (target) |
|----|------------|---------------|-----|---------------------------|
| **S2-1** | Operator visibility | Routes + basic dashboard exist; **session/decision list filters shipped** (`status`, `agent_id`, `final_decision`, `risk_class`, `session_id`) + dashboard decision filter bar | Richer metrics home UX still open | Filter contract tests green; remaining: metrics home polish |
| **S2-2** | Policy operations | Bundle create/activate + dashboard; **dry-run test API shipped** (`POST /v1/policy-bundles/:id/test`) + policy dashboard dry-run form | Risk-rules ops UX polish still open | Bundle test route green; activation unchanged |
| **S2-3** | Multi-channel approvals | Web + Slack optional | Channel interface; Teams/webhook channels | `approval-channel-*.test.ts`; decide path with non-web channel |
| **S2-4** | Federated identity | Not present | OIDC (then SAML/SCIM) for operators/approvers | Auth middleware tests; unauthenticated deny on ops routes |
| **S2-5** | Hosted control plane | Docker Compose self-host | Single-tenant package, health probes, upgrade notes | Compose health smoke; docs install path |

## Recommended build order

1. **S2-1** Operator visibility UX on existing APIs (highest leverage).  
2. **S2-2** Policy ops polish (bundles already partial).  
3. **S2-3** Multi-channel approvals (abstract channel first).  
4. **S2-4** OIDC for operator/approver.  
5. **S2-5** Hosted/single-tenant packaging.

## Explicit non-Stage-2 (Stage 3)

- gVisor / Firecracker multi-tenant isolation  
- WORM Object Lock productization  
- Full SIEM connector product  
- Enterprise memory vault  

## Site coordination

When a gap row moves to done, flip marketing:

- `web/actantos` → `src/components/stage2-data.ts` status  
- Pricing / badges only after product tests green  

## Inventory maintenance

Update this file when modules land. Prefer adding test files named for the capability area.
