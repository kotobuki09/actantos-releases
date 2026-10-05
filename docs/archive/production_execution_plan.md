# ActantOS Production Execution Plan — Index

> This is the master index for **historical version tracks** (v0.2–v1.0) and related status tables.
>
> **Canonical planning and execution entrypoint:** [`ActantOS_Canonical_Overview_Vision.md`](./ActantOS_Canonical_Overview_Vision.md)
> **Active Mode A milestones:** [`milestones/`](./milestones/) — current next action **A-01**
> **Strategy language:** `CONTEXT.md` + `docs/adr/`
> **This file:** Supporting index for completed version plans; defer Mode A/B execution to the overview.
>
> **Forward plan / FWD steps:** historical/supporting relative to the Mode A queue.
> **Long-form completion narrative:** `working_plan.md` (historical; not the entrypoint).

## How to use

1. **Every agent** reads `00_global_rules_and_teams.md` first.
2. **Then** reads only the version/phase plan they are working on.
3. **Do not** open work on ✅ complete version files.

## File Index

| File | Contents | Status |
| ---- | -------- | ------ |
| `00_global_rules_and_teams.md` | Team lanes, global rules, dependency order, ticket format, current tickets | Living |
| `CONTEXT.md` | Domain language from strategy grill | Living |
| `docs/adr/` | Strategic ADRs (open-core, freeze, claims, sequencing) | Living |
| `v0.2.0_plan.md` | Demo Hardening MVP | ✅ Complete |
| `v0.3.0_plan.md` | MCP Hardening Beta | ✅ Complete |
| `v0.4.0_plan.md` | Self-Host Alpha | ✅ Complete |
| `v0.5.0_plan.md` | Policy & Budget Beta | ✅ Complete |
| `v0.6.0_plan.md` | Security Beta | ✅ Complete |
| `v0.7.0_plan.md` | Pilot Readiness Beta (engineering) | ✅ Complete |
| `v1.0.0_plan.md` | Quiet Open-Core Release (`v1.0.0` tag) | ✅ Complete (shipped) |
| `forward_plan.md` | Local/self-hosted completion status; optional future tracks | ✅ Current scope complete |
| `forward_steps/` | FWD-001–005 complete; FWD-006–014 internal scenario complete | ✅ Scenario complete |
| `design_partner_window_plan.md` | Optional external pilot operating runbook | ⏸ Optional / inactive |

## Execution Order

### Historical (done)

```text
v0.2.0 → v0.3.0 → v0.4.0 → v0.5.0 → v0.6.0 → v0.7.0 → v1.0 local Go
```

### Version path to v1 (done)

```text
v0.2.0 → v0.3.0 → v0.4.0 → v0.5.0 → v0.6.0 → v0.7.0 → v1.0.0 Quiet Open-Core ✅
```

### After v1 (current scope)

```text
local/self-hosted install → allow/deny/approval/audit smoke → internal dogfood ✅
optional later: external design partner → Proven Claim Gate
```

## Current Status

| Milestone | Status |
| --- | --- |
| v0.1.0 Week 1 kernel | ✅ Complete |
| v0.2.0 Demo Hardening | ✅ Complete |
| v0.3.0 MCP Hardening | ✅ Complete |
| v0.4.0 Self-Host Alpha | ✅ Complete |
| v0.5.0 Policy & Budget | ✅ Complete |
| v0.6.0 Security Beta | ✅ Complete |
| v0.7.0 Pilot Readiness (engineering) | ✅ Complete |
| v1.0 local regression / artifacts / API freeze | ✅ Go |
| v1.0.0 **public** Quiet Open-Core | ✅ **Shipped** — https://github.com/kotobuki09/actantos-releases/releases/tag/v1.0.0 |
| Local/self-hosted operational proof | ✅ Public smoke 35/35; Pi adapter 38/38 |
| Living Pilot #1 (coding, Pi, unaided) | ⏸ Optional / inactive |
| Proven customer claims | ⏸ Not claimed; requires optional living validation |
| Sample popular-case dry-run | ✅ Complete |

## 90-day must-hit

```text
1. Public tag v1.0.0 (quiet; no launch campaign)  ✅ DONE
2. Local/self-hosted operational proof  ✅ DONE
Optional later: living Pilot #1 and clone Pilot #2
```

**Version-engineering stop:** All v0.2–v1.0 version plans, Quiet Open-Core ship, public-artifact verification, and internal dogfood rehearsal are done. Make only security, correctness, install, or documentation fixes needed to keep the simple local/self-hosted path working. External validation is optional.
