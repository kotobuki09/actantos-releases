# Quiet Open-Core Surface

**Stage:** Open-Core / Design Partner  
**Artifact tag:** `v1.0.0`  
**Proven Claim Gate:** living Design Partner Pilot proof is **not** implied by this tag.

## Self-Host Free Surface

Everything needed to govern agents on your own infrastructure without paying ActantOS:

| Capability | Included |
| --- | --- |
| Enforcement Kernel (`actantosd` decision API) | Yes |
| Cedar policy evaluation + policy bundles | Yes |
| Docker sandbox execution baseline | Yes |
| Pi Primary Path (`guarded_*` adapter) | Yes |
| Web Approval (one-use, TTL-bounded) | Yes |
| Optional Slack Approval connector | Yes |
| Basic operator dashboard (sessions, decisions, approvals, audit) | Yes |
| Starter policy templates (Balanced default, Strict opt-in) | Yes |
| Local audit hash-chain + evidence export | Yes |
| Kill switch, budgets, rate limits | Yes |
| MCP Optional Path (gateway) | Yes (supported, not pilot-gating) |

## Paid Platform Surface (not required for open-core tag)

Commercial / later platform value — **not** locked behind the free approval button:

| Capability | Notes |
| --- | --- |
| Hosted control plane | Managed SaaS |
| Enterprise identity (OIDC / SCIM) | Pilot Freeze unless Escape Hatch |
| Stronger isolation (gVisor / Firecracker) | Later isolation tiers |
| Managed storage / compliance export (e.g. WORM) | Later |
| White-glove Success Package / support | Optional paid onboarding; product remains free self-host |

## Claim language

| Allowed at `v1.0.0` tag | Not allowed until Proven Claim Gate |
| --- | --- |
| Self-host install works | “Battle-tested at customers” |
| Lab/demo Decision loop works | Living multi-team production proof |
| Open-Core / Design Partner stage | Repeatability claims (need clone Pilot #2) |

Lab packages under `docs/pilot-evidence-*.md` are **fixtures**, not living partner proof.

## Related docs

- [Release notes](./release-notes-v1.0.0.md)
- [Go/no-go](./go-no-go-v1.md)
- [Pilot policy templates](./pilot-policy-templates.md)
- [Design Partner kit](./design-partner-kit.md)
- [Pilot onboarding](./pilot-onboarding.md)
