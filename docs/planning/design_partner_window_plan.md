# Design Partner Window — Post `v1.0.0` Quiet Open-Core

> **Status:** ⏸ **OPTIONAL / INACTIVE** (2026-07-11). Quiet Open-Core, public-artifact verification, and the internal dogfood scenario are complete. No external pilot is required for the current local/self-hosted scope, and no customer proof is claimed.
>
> **Ops index:** `actantosd/docs/pilot-ops-index.md`  
> **Sample dry-run:** `actantosd/docs/pilot-sample-dry-run-complete.md`  
> **Prerequisites:** `CONTEXT.md`, `docs/adr/`, shipped release `v1.0.0`.
>
> **Strategy ADRs:** 0001 free surface · 0002 freeze/hatch · 0003 claims · 0004 sequencing.

## Goal

Optional future runbook for proving ActantOS on a real external coding team. Do not activate this plan unless external validation becomes a deliberate product goal.

## 90-day outcomes

| Bar | Definition |
| --- | --- |
| **Current scope** | Public `v1.0.0` + verified local/self-hosted path + internal dogfood |
| **Optional future** | Pilot #1 **Pilot Done (Unaided)**, then clone Pilot #2 |

## Non-goals (Pilot Freeze)

```text
Always frozen:
- Firecracker, multi-tenant SaaS
- Credential broker
- SCIM / full enterprise IdP product
- S3 WORM productization
- Policy marketplace
- LangGraph / AutoGen / extra adapters

Frozen unless Escape Hatch (written one-pager first):
- OIDC login
- gVisor runtime
- HA / multi-node
- Multi-step advanced approvals product
- Custom SDKs beyond Pi adapter
- Deep SIEM productization
- MCP-first pilot as a hard requirement
```

**Escape Hatch rule:** only if two independent partners hit the same blocker, or one partner is strategically existential and workarounds fail. Record in `docs/adr/` or a dated hatch note before coding.

---

## Pilot profile

| Field | Value |
| --- | --- |
| ICP | AI-native coding team (Cursor/Claude/similar) |
| Path | **Pi Primary Path** (MCP Optional) |
| Default policy | **Balanced Coding Policy** |
| Opt-in policy | **Strict Coding Policy** |
| Sequencing | One active pilot; #2 only after #1 unaided |
| Pilot #2 | **Clone** coding team (not MCP-first stretch) |

## Pilot Fit Checklist (entry)

Partner must accept:

```text
[ ] Self-host OK (not SaaS-only)
[ ] Pi adapter / guarded tools OK
[ ] Real coding workflow (not pure demo theater)
[ ] Human approver available (web and/or Slack)
[ ] Second engineer available for unaided session
[ ] Balanced default acceptable (or explicit Strict)
```

Fail **2+** hard items → decline or defer.

## Success Package

```text
Duration: 2 weeks
Includes: kickoff + limited office hours + async; template setup (Balanced/Strict)
Excludes: custom feature development
Fee: first 1–2 strategic partners may waive; then fixed one-time fee
Cutover: Day 14 → public docs only unless P0
```

## Pilot Done (Unaided)

```text
1. Multi-day real feature work with ActantOS left on
2. Second engineer completes a governed session using only public docs/templates
3. No founder live support for that session
4. Time box: ≤ 4 weeks from first successful install
```

Minimum technical path (coding):

```text
- Safe workspace read/write allow (Balanced)
- Credential path deny
- Risky remote/mutating action → approval_required
- Approve via web or Slack
- Kill switch can block next action
- Evidence export works
```

## Pilot Auto-Kill

```text
If no credible path to Unaided Done by day 28 from first successful install:
→ formal kill + written retro
→ or Escape Hatch proposal
→ no open-ended support
```

## Sourcing

```text
- Pilot #1: warm network / nearly committed (not HN-inbound as plan)
- Pipeline: light outbound to coding ICPs
- Inbound from public repo: bonus only
- Parallel Launch Window: outreach starts with tag work (see v1.0.0_plan)
```

---

## Workstreams

### DP-A: Pilot #1 delivery

**Owner:** A9  
**Support:** A0, A3 (Pi), A6 (approvals), A2 (templates)

```text
DP-A-001 Lock warm candidate against Fit Checklist
DP-A-002 Run Success Package kickoff (public v1.0.0 or agreed RC)
DP-A-003 Confirm Balanced (or Strict) active; Slack optional
DP-A-004 Multi-day real use with product left on
DP-A-005 Unaided second-engineer session
DP-A-006 Export evidence from living session (not fixture reuse)
DP-A-007 Retro: blockers, template gaps, docs holes only
```

**Done when:** Pilot Done (Unaided) **or** Auto-Kill with retro.

### DP-B: Freeze-allowed product work

**Owner:** by component  
**Rule:** pilot-blocking only

```text
DP-B-001 Pi adapter install/friction bugs
DP-B-002 Approval (web/Slack) reliability
DP-B-003 Balanced/Strict template correctness
DP-B-004 Onboarding/docs holes found in pilot
DP-B-005 Fail-closed / redaction P0-P1 only
DP-B-006 Escape Hatch implementation only if written and approved
```

**Done when:** each item has pilot evidence of need; no speculative platform work.

### DP-C: Clone Pilot #2 (after #1)

**Owner:** A9  

```text
DP-C-001 Start only after Pilot #1 Unaided Done
DP-C-002 Same ICP and Pi Primary Path
DP-C-003 Prefer shorter Success Package if docs improved
DP-C-004 Evidence package from living session
```

**Done when:** second unaided coding pilot **or** stretch abandoned with written reason.

### DP-D: Proven Claim Gate

**Owner:** A0 + A9  

```text
DP-D-001 After Pilot #1 unaided: allow limited proof language / anonymized note
DP-D-002 After Pilot #2: allow repeatability claims
DP-D-003 Never backdate claims onto the original v1.0.0 tag notes
```

---

## Team focus during this window

| Lane | Role in window |
| --- | --- |
| A0 | Freeze enforcement, hatch approval, claim language |
| A3 | Pi pilot-blocking fixes only |
| A4 | MCP only if partner already uses it or hatch |
| A6 | Approval reliability |
| A7 | Console polish only if blocks unaided use |
| A8 | Install/docs from public artifact |
| A9 | Success Package, fit, kill, evidence |
| A5 | Security P0/P1 only |

## Exit criteria (window success)

```text
Must-hit:
- v1.0.0 public (from v1.0.0_plan)
- Pilot #1 Pilot Done (Unaided)
- Evidence from living partner session
- Claims language still matches Proven Claim Gate

Stretch:
- Clone Pilot #2 unaided or clearly in progress

Always:
- ≤ 1 Escape Hatch written and justified (prefer zero)
- No always-frozen items shipped
```
