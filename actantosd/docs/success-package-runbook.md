# Success Package Runbook (Pilot #1)

**Ticket:** [#10](https://github.com/kotobuki09/actantos-plan/issues/10)  
**Prerequisites:** Pilot #1 **accepted** on Fit Checklist ([pilot-1-status.md](./pilot-1-status.md)); public **`v1.0.0`** Quiet Open-Core; kit ([design-partner-kit.md](./design-partner-kit.md)).

**Hard rules:** No custom features. **Pilot Freeze** holds. Day **14** cutover to public docs. Auto-Kill path if unaided not credible by day **28** from first successful install.

---

## Day 0 — Kickoff (≤ 60 min)

| Step | Owner | Done |
| --- | --- | --- |
| Confirm Fit Checklist still true | Founder + partner | [ ] |
| Confirm fee waive or fee agreed | Founder | [ ] |
| Share install links: release `v1.0.0`, [pilot-onboarding](./pilot-onboarding.md), [open-core-surface](./open-core-surface.md) | Founder | [ ] |
| Nominate approver + second engineer names | Partner | [ ] |
| Choose Balanced (default) or Strict | Partner | [ ] |
| Schedule office hours (2× in 2 weeks) | Both | [ ] |
| Record **install_start** timestamp (day-28 clock) | Founder | [ ] |

### Kickoff script (short)

1. Core promise: no tool action without a **Decision**.  
2. Pi Primary Path only for pilot success; MCP optional.  
3. Balanced: local loop free; credentials deny; push/migrate-class need **Approval**.  
4. We will not build OIDC/gVisor/custom adapters in this package.  
5. Day 14 = docs only; goal = second engineer unaided.

---

## Days 1–3 — Install + first governed session

| Step | Done |
| --- | --- |
| Partner installs from public `v1.0.0` (Compose or agreed path) | [ ] |
| `/health/ready` OK | [ ] |
| Demo or equivalent: allow / deny / approval_required | [ ] |
| Balanced (or Strict) policy + risk rules active | [ ] |
| Web Approval works; Slack optional | [ ] |
| Pi guarded tools pointed at actantosd | [ ] |
| First real coding session with ActantOS **left on** | [ ] |
| Evidence export once for baseline | [ ] |

**Founder support:** async + office hours only. Prefer doc links over custom scripts.

---

## Days 4–13 — Multi-day real use

| Step | Done |
| --- | --- |
| ActantOS remains on for normal feature work | [ ] |
| At least 2 Approvals exercised (e.g. push-class) | [ ] |
| Kill switch demonstrated once (optional but preferred) | [ ] |
| Collect friction list (docs/template only unless P0) | [ ] |
| File freeze-allowed bugs only; Escape Hatch writeup before platform work | [ ] |

---

## Day 14 — Cutover

| Step | Done |
| --- | --- |
| Announce cutover: public docs only (except P0) | [ ] |
| Confirm partner has [pilot-onboarding](./pilot-onboarding.md), [policy templates](./pilot-policy-templates.md), [support-runbook](./support-runbook.md) | [ ] |
| Stop scheduled office hours (async P0 only) | [ ] |
| Point to [pilot-unaided-checklist.md](./pilot-unaided-checklist.md) for Pilot Done (Unaided) | [ ] |

---

## Days 15–28 — Unaided window

| Step | Done |
| --- | --- |
| Second engineer runs governed session with **public docs only** | [ ] |
| Living evidence package exported + audit verified | [ ] |
| Update [pilot-1-status.md](./pilot-1-status.md) → Unaided Done **or** Auto-Kill | [ ] |

If no credible path by day 28 → **Auto-Kill** + written retro (or Escape Hatch proposal). See [pilot-auto-kill-retro.md](./pilot-auto-kill-retro.md).

---

## Exit to next tickets

| Outcome | Next |
| --- | --- |
| Unaided Done | Close #10/#11; open Proven Claim Gate language (#12); optional clone Pilot #2 (#13) |
| Auto-Kill | Close #10/#11 as failed/killed; retro; do not claim living proof |
| Escape Hatch | Written hatch first; thin freeze-exception only |
