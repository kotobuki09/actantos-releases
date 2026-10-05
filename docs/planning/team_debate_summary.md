# ActantOS Team Debate Summary
**Date:** 2026-07-12  
**Participants:** agy (security), agy (product), agy (engineering), agy (ops)  
**Based on:** commit `62b9224`, `forward_plan.md`, audit findings, live code review

---

## Debate 1 — Fix the 4 medium audit findings FIRST before any new features?

### Arguments FOR fixing first
- The SQL injection was already critical and caught mid-feature batch. Medium findings left open invite the same pattern in the next batch.
- `ACTANTOS_HMAC_SECRET` defaulting to `"actantos-dev-secret"` means any operator who forgets to set it ships a predictable signature key — evidence packages can be forged silently.
- gVisor without an availability check means `ACTANTOS_USE_GVISOR=true` on a host without `runsc` silently falls back to standard Docker — operator *thinks* they have stronger isolation, they don't.
- MCP header context (`x-actantos-tenant-id`, `x-actantos-agent-id`, etc.) is fully trust-on-arrival: any caller can claim any tenant. In a multi-tenant deployment this is an access control bypass.
- These are small, surgical fixes — each is < 15 lines. Cost is low; risk of skipping is high.

### Arguments AGAINST fixing first
- All 4 are documented and scoped. The codebase is still in `development` mode; no production operator has been harmed.
- Forward plan §8 says "install and upgrade reliability" is the top Month 3–6 priority. Without a reliable installer, no pilot ever reaches the code with the medium findings.

### Verdict ✅ FIX FIRST
Fix all 4 medium findings before the next feature batch. The MCP header trust issue is functionally HIGH in any shared environment (tenant identity spoofing). The HMAC default is an operations foot-gun. Both must be closed before claiming production-ready. Cost ≤ 2 hours; risk of skipping is unbounded.

---

## Debate 2 — What is the single highest-value next feature after the fixes?

### Candidates debated

| Option | Summary | Verdict |
|--------|---------|---------|
| A — Production startup guards | Enforce HMAC secret + gVisor check in `index.ts` | ✅ Do in same pass as fixes |
| B — Install/upgrade reliability CLI | Preflight checks, versioned installer | ✅ Highest user-facing value |
| C — Pi adapter as published package | Distributable without cloning repo | Defer — packaging work, not correctness |
| D — OIDC identity layer | Enterprise identity | ❌ Unlock criterion not met (need 2 partner blockers) |
| E — Policy dry-run / simulation | Safe policy tuning without live impact | Defer — valuable but not pilot-blocking |

### Verdict ✅ B + A together (install reliability + startup guards)
Startup guards (A) are a prerequisite to any production install claim. Install reliability CLI (B) directly attacks the 90-minute install metric. These form the natural "v1.0.1 hardening + v1.1 installer" release.

---

## Debate 3 — Minimum bar for a first external pilot

| # | Requirement | State | Gap |
|---|-------------|-------|-----|
| 1 | Install from public `v1.0.0` in < 90 min | Unknown | No preflight check |
| 2 | Allow, deny, approval work end-to-end | Locally verified | Needs re-verify from public artifact |
| 3 | No fail-open path | Verified (Cedar guard, token expiry) | Continuous regression |
| 4 | No default secret in production | ❌ | `ACTANTOS_HMAC_SECRET` not enforced |
| 5 | Audit chain independently verifiable | Implemented | `audit:verify` needs public docs |
| 6 | No SQL injection in tenant path | ✅ Fixed `62b9224` | Done |
| 7 | Evidence export signed with non-default key | ❌ | HMAC secret not enforced |
| 8 | Public docs cover install, first session, kill switch, evidence | Partially | Missing preflight + troubleshooting |

**4 gaps must close before any external pilot.**

---

## Debate 4 — Biggest public embarrassment risk

| Risk | Score |
|------|-------|
| 🔴 MCP gateway accepts any tenant claim from headers — tenant spoofing in shared deploy | **#1** |
| 🔴 Default HMAC secret ships in production — evidence packages can be forged | **#2** |
| 🟡 "Fail-closed" claim but gVisor fallback is silent | **#3** |
| 🟡 Approval TTL bypass via clock skew | **#4** |

**Verdict: MCP tenant spoofing is the #1 public risk.**  
`mcp-gateway.ts:115` accepts `x-actantos-tenant-id` from any header with zero authentication. In any multi-tenant deploy, an unprivileged caller can forge another tenant's identity, completely undermining the RLS enforcement added in the last batch.

---

## Final Prioritized Action List (Top 5)

| Priority | Action | Effort | Risk if skipped |
|----------|--------|--------|----------------|
| **P1** | Fix MCP header tenant trust — validate against authenticated session or reject unauthenticated context | Small | Critical: tenant spoofing |
| **P2** | Enforce `ACTANTOS_HMAC_SECRET` at production startup — same guard pattern as Cedar in `index.ts` | Small | High: forgeable evidence |
| **P3** | Add gVisor availability warning at startup if `runsc` absent | Tiny | Medium: silent isolation downgrade |
| **P4** | Install preflight check — Docker, Cedar CLI, env vars | Medium | High: pilot install failure |
| **P5** | Document `audit:verify` + top-5 install troubleshooting in public README | Small | Medium: unassisted pilot fails audit step |

---

## Risk Register Updates

| New Risk | Mitigation |
|----------|-----------|
| Tenant identity spoofing via MCP headers | P1: require authenticated session context |
| Default HMAC secret in production | P2: startup guard |
| Silent gVisor isolation downgrade | P3: startup warning |
| Pilot install > 90 min | P4 + P5 |

---

## Dissenting Opinions

> **Engineering:** P4 (install preflight) should be P1. Nothing else matters if the pilot can't install.  
> *Overruled:* A running-but-insecure install is worse than a failed install. Tenant spoofing must close first.

> **Product:** Skip P3 (gVisor check). Operators who enable it should know what they're doing.  
> *Partially accepted:* Implement as a warning, not a hard failure, to preserve operator flexibility.
