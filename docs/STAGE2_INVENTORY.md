# Stage 2 Product Inventory (`actantosd`)

**Ship rule:** built + tests pass = done. No design-partner gate.  
**Stage:** Stage 1 Enforcement Kernel **done**. Stage 2 Agent Runtime Control Plane **done**.

## Already shipped (Stage 1 foundation)

| Area | Modules | Tests (representative) |
|------|---------|------------------------|
| Intercept pipeline | `intercept-service.ts`, fail-closed, responses | `intercept-service.test.ts`, `fail-closed.test.ts` |
| Policy / risk | Cedar providers, `risk-engine.ts` | cedar/policy regression tests |
| Approvals | `approval-routes.ts` | `approval-routes.test.ts` |
| Budgets / rate limits | budget + rate-limit routes | matching tests |
| Kill switch | `kill-switch-routes.ts` | `kill-switch-routes.test.ts` |
| Sessions / audit / MCP / sandbox | existing modules | matching tests |

## Stage 2 ship map (complete)

| ID | Capability | Shipped surface | Tests |
|----|------------|-----------------|-------|
| **S2-1** | Operator visibility | Session/decision filters; `ops_home` rates + kill switch + budgets on `/v1/metrics/usage`; `/dashboard/metrics` | `sessions-routes.test.ts`, `decisions-routes.test.ts`, `ops-metrics.test.ts`, `usage-metrics-routes.test.ts` |
| **S2-2** | Policy operations | Bundle create/activate; `POST /v1/policy-bundles/:id/test`; risk-rules GET/PUT; Policy Ops UI | `policy-bundle-*.test.ts`, `risk-rules-routes.test.ts` |
| **S2-3** | Multi-channel approvals | Channel model + webhook notify + `POST /v1/approvals/channels/webhook/decide` | `approval-channels.test.ts` |
| **S2-4** | Federated identity | OIDC HS256 bearer for ops when `ACTANTOS_OIDC_*` set; 401 without token | `oidc-auth.test.ts` |
| **S2-5** | Hosted control plane | Docker Compose single-tenant; `/health/live` + `/health/ready` (+ stage2 flags); `docs/HOSTED.md` | `server.test.ts` health tests; HOSTED smoke checklist |

## Stage 3 (not Stage 2)

- gVisor / Firecracker multi-tenant isolation  
- WORM Object Lock productization  
- Full SIEM connector product  
- Enterprise memory vault  

## Site coordination

`web/actantos` `stage2-data.ts` marks S2-1…S2-5 as `done`.
