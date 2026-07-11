# Pilot Done (Unaided) Checklist

**Ticket:** [#11](https://github.com/kotobuki09/actantos-plan/issues/11)  
**Definition:** Second engineer completes a governed **Pi Primary** coding session using **only public docs/templates** — no founder live support. Multi-day real use with ActantOS left on. ≤ **4 weeks** from first successful install (Auto-Kill by day **28** if not on path).

## Before the unaided session

| Check | Yes |
| --- | --- |
| Success Package cutover done (or partner already docs-only) | [ ] |
| Public `v1.0.0` (or documented same artifact) in use | [ ] |
| Balanced or explicit Strict active | [ ] |
| Second engineer has not been pair-programmed through the path by founder today | [ ] |
| Links given only: onboarding, policy templates, support runbook, open-core surface | [ ] |

## During the session (second engineer)

| Step | Observed |
| --- | --- |
| Start/confirm session + agent identity | [ ] |
| Safe workspace read → **allow** | [ ] |
| Credential / `.env` style read → **deny** | [ ] |
| Local edit or safe shell that should allow (Balanced) | [ ] |
| Side-effect command → **approval_required** | [ ] |
| Approver completes Approval (web or Slack) | [ ] |
| Action proceeds only after Approval | [ ] |
| Optional: kill switch blocks a later action | [ ] |
| Export session evidence package | [ ] |
| Audit-chain / package verify succeeds | [ ] |

## Living evidence (not fixtures)

| Artifact | Location / note |
| --- | --- |
| Session id | |
| Evidence export file | |
| Verifier result | |
| Policy bundle version / hash | |
| Partner confirmation (date) | |

**Do not** reuse `docs/pilot-evidence-1.md` fixtures as living proof.

## Outcome

| Result | Criteria |
| --- | --- |
| **Unaided Done** | All critical steps above + multi-day use + no founder live support |
| **Auto-Kill** | Day 28 with no credible path — write retro |
| **In progress** | Still inside 4-week window |

Record outcome in [pilot-1-status.md](./pilot-1-status.md).
