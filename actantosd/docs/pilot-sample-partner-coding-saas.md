# Sample Partner Profile — Coding SaaS (Cursor)

> **Classification: SAMPLE / REFERENCE PERSONA only.**  
> Not a living Design Partner. Not Proven Claim Gate proof.  
> Do **not** mark [pilot-1-status.md](./pilot-1-status.md) as **accepted** based on this file alone.  
> Use for Fit Checklist practice, Success Package walkthroughs, demos, and outreach storytelling.

**Popular case archetype:** Small AI-native product team shipping with Cursor / Claude-style coding agents.  
**Matches:** ICP 1 (AI-native coding), **Pi Primary Path**, **Balanced Coding Policy**, demo Pilot Workflow.

---

## Persona card

| Field | Sample value |
| --- | --- |
| **Codename** | `sample-coding-saas` |
| **Org type** | Stealth / early B2B SaaS, backend-heavy |
| **Team size** | ~4 engineers |
| **Stack** | Node/TS or similar monorepo; GitHub; Slack |
| **Agent tooling** | Cursor (or Claude) with file + shell tools |
| **Pain trigger** | Agent read `.env`, almost pushed broken code, or security asked “what did the agent do?” |
| **Why ActantOS** | Want allow/deny/approval **before** tool exec + audit timeline — without changing IDE |
| **Deploy** | Self-host Compose on internal Ubuntu/dev server |
| **Policy posture** | **Balanced Coding Policy** (default) |
| **Approval channel** | Slack `#actantos-approvals` + web fallback |
| **Success Package** | Fee-waived strategic #1 style (illustrative) |

---

## Fit Checklist (worked example — all Yes)

| # | Hard requirement | Sample answer | Notes |
| --- | --- | --- | --- |
| 1 | Self-host OK | **Yes** | Compose on internal box; not SaaS-only |
| 2 | Pi Primary Path OK | **Yes** | Guarded tools via adapter in repo |
| 3 | Real coding workflow | **Yes** | Feature branches, tests, PRs — not pure demo theater |
| 4 | Human approver available | **Yes** | Tech lead + oncall in Slack |
| 5 | Second engineer available | **Yes** | Another IC will try docs-only session in week 3 |
| 6 | Balanced default OK | **Yes** | Strict would slow them; Balanced matches loop |

**Score:** 0 hard fails → **would accept** if this were a real warm contact.  
**This file is still SAMPLE** until a real org is written into `pilot-1-status.md`.

---

## Expected Pilot Workflow (same as product demo)

```text
1. Safe workspace read          → allow
2. Read .env / credential path  → deny
3. Edit source + npm test       → allow (Balanced)
4. git push origin feature/*    → approval_required
5. Human approves (Slack/web)   → allow + one-use token
6. Optional kill switch         → next action deny
7. Export evidence package      → verify audit chain
```

Policy: `dev-coding-agent.cedar` + default `risk_rules.json` (see [pilot-policy-templates.md](./pilot-policy-templates.md)).  
Install path: [pilot-onboarding.md](./pilot-onboarding.md) against public `v1.0.0`.

---

## Success Package walkthrough (illustrative calendar)

Use with [success-package-runbook.md](./success-package-runbook.md). Dates are examples only.

| Day | Sample activity |
| --- | --- |
| 0 | Kickoff: Fit re-confirm, Balanced, Slack channel, install_start = T0 |
| 1–2 | Compose up; smoke/demo green; Pi adapter in monorepo |
| 3–10 | Real feature work with ActantOS left on; 2+ push Approvals |
| 14 | Cutover to public docs only |
| 15–21 | Second engineer unaided session (checklist) |
| ≤28 | Unaided Done **or** Auto-Kill retro |

---

## Outreach angle (for real lookalikes)

When messaging **real** teams that match this persona, reuse [warm-outreach-template.md](./warm-outreach-template.md).  
Pitch line: *“Same stack as a typical Cursor coding team: block secrets, approve pushes, keep the local loop fast.”*

Do **not** claim this sample already ran a paid/production pilot.

---

## What this unlocks vs does not

| Unlocks | Does not unlock |
| --- | --- |
| Training / docs / dry-run of ops | Closing #8 as accepted |
| Clear “popular case” story for sales | Proven Claim Gate language |
| Template for real Fit scoring | Living evidence package |
| Consistency with demo + Balanced posture | Clone Pilot #2 start |

---

## Related

- [pilot-1-status.md](./pilot-1-status.md) — real Pilot #1 only  
- [pilot-ops-index.md](./pilot-ops-index.md)  
- [design-partner-kit.md](./design-partner-kit.md)  
- Lab fixture (also non-living): [pilot-evidence-1.md](./pilot-evidence-1.md)  
