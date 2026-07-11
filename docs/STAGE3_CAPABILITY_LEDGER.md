# Stage 3 Capability Release Ledger

`actantosd/stage3-capabilities.json` is the product-owned source of truth for Stage 3 release state. It does not change public website claims by itself.

## Stable capabilities

| ID | Capability |
|---|---|
| `foundation` | Multi-tenant identity, authorization, and platform hardening |
| `isolation` | Production-grade isolated execution |
| `credentials` | Short-lived credential brokerage |
| `evidence` | Immutable evidence archives |
| `siem` | Durable SIEM delivery |

Each capability has a `future`, `active`, or `done` status and evidence arrays for automated tests, manual QA, and documentation. A capability marked `done` must have at least one entry in every evidence array.

The stage aggregate is derived: it remains `active` until all five capabilities are `done`. The validator rejects stale or misleading aggregate values, missing or duplicate capability IDs, malformed evidence, and unsupported statuses.

Run `npm run stage3:validate` from `actantosd` before updating release or website claims. A zero exit status is the only success signal; text copied from another run is not evidence.
