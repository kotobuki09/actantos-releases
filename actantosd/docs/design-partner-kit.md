# Design Partner Kit

Sendable pack for warm-network coding teams. Uses ActantOS domain language from the project glossary.

**Sample popular case (practice only):** [pilot-sample-partner-coding-saas.md](./pilot-sample-partner-coding-saas.md) — Cursor coding SaaS persona with a fully scored Fit Checklist. Not a living Design Partner.

**Product:** Self-host Enforcement Kernel that returns a **Decision** (`allow` | `deny` | `approval_required`) before any agent tool action executes.  
**Pilot path:** **Pi Primary Path** (guarded tools). **MCP Optional Path** is supported but does not define pilot success.  
**Default policy posture:** **Balanced Coding Policy**. **Strict Coding Policy** is opt-in.

---

## 1. Pilot Fit Checklist

Partner must accept **all hard items**. Fail **2+** → decline or defer.

| # | Hard requirement | Yes / No |
| --- | --- | --- |
| 1 | **Self-host OK** (not SaaS-only) | |
| 2 | **Pi Primary Path** OK (guarded file/shell tools) | |
| 3 | Real **coding** workflow (not pure demo theater) | |
| 4 | Human **approver** available (web and/or Slack) | |
| 5 | **Second engineer** available for unaided session | |
| 6 | **Balanced** default acceptable, or explicit **Strict** choice | |

Soft pluses: existing Cursor/Claude coding agents, Slack already in use, willingness to leave ActantOS **on** for multi-day work.

---

## 2. Success Package (one-pager)

| Item | Term |
| --- | --- |
| **Duration** | 2 weeks |
| **Includes** | Kickoff call, limited office hours, async support, Balanced/Strict template setup |
| **Excludes** | Custom feature development, platform work under Pilot Freeze |
| **Product license** | Free self-host (Self-Host Free Surface) |
| **Fee** | First 1–2 strategic partners may be **fee-waived**; afterward fixed one-time fee |
| **Cutover** | **Day 14** → public docs only (except P0 production breakers) |
| **Goal path** | Install → multi-day real use → **Pilot Done (Unaided)** |

### What “done” looks like for the package week

1. Public (or agreed) `v1.0.0` install on partner infrastructure  
2. Pi adapter + Balanced (or Strict) active  
3. At least one Approval exercised (e.g. `git push` or migrate-class command)  
4. Partner keeps ActantOS on during real feature work  

---

## 3. Pilot Done (Unaided)

Success for Design Partner Pilot #1:

1. Multi-day real coding use with ActantOS **left on**  
2. A **second engineer** completes a governed session using **only public docs and templates**  
3. No founder live support for that session  
4. Time box: **≤ 4 weeks** from first successful install  

Minimum technical path:

- Safe workspace read/write **allow** (Balanced)  
- Credential path **deny**  
- Risky remote/mutating action → **approval_required**  
- Approve via web or Slack  
- Kill switch can block next action  
- Evidence export works  

---

## 4. Pilot Auto-Kill

If after Success Package cutover there is **no credible path** to Pilot Done (Unaided) by **day 28** from first successful install:

- End the pilot with a **written retro**, or  
- Propose a written **Escape Hatch** (rare), or  
- Decline further open-ended support  

No quiet endless white-glove.

---

## 5. Pilot Freeze (what we will not build mid-pilot)

**Always frozen:** Firecracker, multi-tenant SaaS, credential broker, SCIM, S3 WORM productization, policy marketplace, new framework adapters.

**Frozen unless Escape Hatch (written first):** OIDC, gVisor, HA, multi-step approval products, extra SDKs beyond Pi, deep SIEM productization, MCP-first as hard requirement.

**Escape Hatch rule:** only if two independent partners hit the same blocker, or one partner is strategically existential and workarounds fail — recorded in writing before implementation.

Default answer to feature asks: **docs, templates, or freeze-allowed bugfix**.

---

## 6. Commercial boundary (one line)

| Free | Paid later / package |
| --- | --- |
| Self-host kernel, web approval, basic dashboard, optional Slack, templates, local evidence | Hosted control plane, enterprise identity/isolation, managed compliance, white-glove Success Package after waivers |

---

## 7. Links for the partner

| Doc | Why |
| --- | --- |
| [Pilot onboarding](./pilot-onboarding.md) | Install → first Pi governed session |
| [Policy templates](./pilot-policy-templates.md) | Balanced default / Strict opt-in |
| [Open-core surface](./open-core-surface.md) | Free vs paid, claim language |
| [Support runbook](./support-runbook.md) | When something breaks |
| [MCP gateway](./mcp-gateway-stable.md) | Optional path only |

---

## 8. Founder outreach script (optional)

1. Confirm Fit Checklist (table above)  
2. Offer Success Package (waive if strategic #1/#2)  
3. Install from public `v1.0.0` Quiet Open-Core  
4. Day 14 cutover  
5. Target Pilot Done (Unaided) by day 28  
6. Only then discuss Proven Claim Gate quote / clone Pilot #2  
