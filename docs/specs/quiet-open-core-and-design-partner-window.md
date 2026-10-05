# Spec: Quiet Open-Core v1.0.0 + Design Partner Window

> Synthesized from the strategy grill, ADRs 0001–0004, version plans, and current codebase state.  
> Test seams (approved): (1) ship/release gate, (2) Pi Pilot Workflow Decision loop, (3) living evidence export + audit verify.

## Problem Statement

ActantOS has a working Enforcement Kernel that can block unsafe agent tool actions and record Decisions, but the project is stuck between “lab complete” and “market real.” Local release verification is green, yet there is no quiet public `v1.0.0` artifact with honest Open-Core language, and there is no living Design Partner Pilot that proves a second engineer can run a governed coding workflow without founders in the loop. Without that, the team risks either over-claiming production readiness from fixtures or drifting into frozen enterprise platform work (OIDC, gVisor, multi-tenant SaaS) before the core promise is proven on a real coding team.

## Solution

Ship a Quiet Open-Core Release tagged `v1.0.0` (installable self-host kernel, claim hygiene, no launch campaign), then run a Design Partner Window: one coding-team pilot on the Pi Primary Path with a two-week Success Package, default Balanced Coding Policy, and Pilot Done (Unaided) within four weeks of install. Only pilot-blocking free-surface work ships under Pilot Freeze (one Escape Hatch max). After Pilot #1 unaided success, run a clone coding Pilot #2 for repeatability. Proven Claim Gate language follows living pilots—not the tag alone. MCP remains supported as the MCP Optional Path and does not gate pilot success.

## User Stories

1. As a founder/release owner, I want a public `v1.0.0` artifact, so that partners install a named release instead of a private workspace snapshot.
2. As a founder/release owner, I want Quiet Open-Core publish without a launch campaign, so that we can ship without support overload from vanity traffic.
3. As a founder/release owner, I want release notes that distinguish install quality from living-customer proof, so that we do not overclaim under the Proven Claim Gate.
4. As a security reviewer, I want local release verification still green at tag time, so that open-core does not regress the Enforcement Kernel.
5. As an operator, I want a clean-machine install from the public artifact, so that Self-Host Free Surface setup is reproducible.
6. As an operator, I want Docker Compose self-host with Postgres, so that I can run actantosd without custom infrastructure.
7. As an operator, I want health/readiness signals, so that I know the control plane is up before connecting agents.
8. As an operator, I want API-key protected operator routes, so that policy and approval surfaces are not open by default.
9. As an operator, I want backup and restore guidance, so that pilot data is not a single point of failure.
10. As an operator, I want upgrade notes from pilot-beta schema to `v1.0.0`, so that early installs can migrate safely.
11. As a platform engineer on a design partner team, I want to install ActantOS on our infrastructure, so that agent governance stays inside our network.
12. As a platform engineer, I want the Pi Primary Path documented first, so that coding agents are governed through guarded tools without guessing.
13. As a developer using a coding agent, I want ordinary workspace reads to be allowed under Balanced Coding Policy, so that the agent can still do useful work.
14. As a developer using a coding agent, I want ordinary workspace writes/edits allowed under Balanced Coding Policy, so that local feature work is not blocked by approval fatigue.
15. As a developer using a coding agent, I want tests/builds/local git non-push commands allowed, so that the inner loop stays fast.
16. As a security-conscious developer, I want `.env` and credential path reads denied, so that secrets are not exfiltrated by the agent.
17. As a tech lead, I want `git push` and other remote side effects to require Approval, so that humans stay in the loop for irreversible actions.
18. As a tech lead, I want database migrate and publish/deploy class commands to require Approval, so that production-adjacent mutations are not autonomous.
19. As an approver, I want a web approval flow, so that I can approve or deny without Slack if Slack is unavailable.
20. As an approver, I want optional Slack approval buttons, so that approvals fit existing team chat habits on the free surface.
21. As an approver, I want one-use, TTL-bounded Approvals, so that replay cannot re-authorize later tool calls.
22. As an operator, I want pending approvals visible in the basic dashboard, so that nothing sits invisible in the queue.
23. As an operator, I want a session audit timeline, so that I can see Decision-before-execution ordering.
24. As an operator, I want a kill switch for tenant/agent/session/tool scope, so that I can stop runaway agents immediately.
25. As a security engineer, I want fail-closed behavior when the daemon is down or times out, so that tools never execute without a Decision.
26. As a security engineer, I want decision tokens bound and verified on tool results, so that execution cannot be forged after the fact.
27. As a security engineer, I want redacted audit previews, so that secrets do not land in logs.
28. As a security engineer, I want an audit hash chain I can verify, so that tampering is detectable.
29. As a design partner engineer, I want to export a session evidence package, so that we can prove governance to our own security team.
30. As a design partner engineer, I want the evidence package to verify with the audit verifier, so that export is trustworthy.
31. As a second engineer on the partner team, I want public docs and templates sufficient to complete a governed session, so that Pilot Done (Unaided) is achievable without founders.
32. As a founder running Success Package, I want a two-week kickoff with limited office hours, so that partners get unblocked without open-ended white-glove.
33. As a founder running Success Package, I want a hard cutover to public docs at day 14, so that unaided success is forced.
34. As a founder, I want no custom feature development inside the Success Package, so that Pilot Freeze is not bypassed by “just this one feature.”
35. As a founder, I want to waive fees for the first one or two strategic partners, so that learning is not blocked by procurement.
36. As a founder later, I want a fixed one-time Success Package fee, so that support is commercially sustainable.
37. As a founder qualifying pilots, I want a Pilot Fit Checklist, so that SaaS-only or OIDC-blocked teams are declined early.
38. As a founder, I want Pilot Auto-Kill by day 28 when unaided path is not credible, so that endless onboarding does not consume the 90-day must-hit.
39. As a founder, I want only one active Design Partner Pilot until unaided done, so that focus is not split.
40. As a founder, I want Pilot #2 to be a clone coding team on Pi Primary Path, so that we prove repeatability before stretching ICP.
41. As a founder, I want MCP documented as MCP Optional Path, so that partners who already use MCP can try it without making it the pilot gate.
42. As an MCP-using operator, I want the existing MCP gateway still work (list filter, call intercept, drift, SSRF), so that optional path remains real product.
43. As a policy admin, I want Balanced Coding Policy as the default template posture, so that pilots do not disable the product from friction.
44. As a policy admin, I want Strict Coding Policy as opt-in, so that risk-averse teams can choose more approvals.
45. As a policy admin, I want risk rules to drive approval_required for side effects while Cedar handles permit/forbid, so that workflow state stays out of pure authorization policy.
46. As a release owner, I want package and image versioning aligned to `v1.0.0`, so that manifests, tags, and docs match.
47. As a release owner, I want SBOM and checksums on the release surface, so that consumers can verify what they install.
48. As a docs owner, I want Self-Host Free Surface clearly listed, so that open-core boundaries are not ambiguous.
49. As a docs owner, I want Paid Platform Surface described as future/not-in-tag, so that OIDC/hosted isolation are not implied free today.
50. As a docs owner, I want lab pilot-evidence packages labeled as fixtures, so that they are not mistaken for Proven Claim Gate proof.
51. As a security reviewer, I want residual risks (e.g. seccomp/AppArmor pending) called out, so that partners know the baseline.
52. As an agent developer (internal), I want Pilot Freeze enforced on tickets, so that platform work does not restart without Escape Hatch.
53. As a founder, I want at most one written Escape Hatch in the window, so that exceptions remain rare and explicit.
54. As a founder after Pilot #1 unaided, I want limited proof language allowed, so that GTM can cite a real partner carefully.
55. As a founder after clone Pilot #2, I want repeatability claims allowed, so that “works more than once” is honest.
56. As a warm-network contact, I want a clear Fit Checklist pitch, so that I know if my team is a fit before kickoff.
57. As an outbound prospect, I want to understand free self-host vs Success Package, so that commercial expectations are clear.
58. As an inbound GitHub user, I want install docs that work without a sales call, so that open-core is real—but not the must-hit pilot plan.
59. As a Parallel Launch Window owner, I want tag work and warm outreach in the same week, so that Success Package can install from public `v1.0.0` within about seven days.
60. As a QA engineer, I want ship seam tests (release verify, fresh install, artifacts) to stay green, so that Quiet Open-Core quality is measurable.
61. As a QA engineer, I want Pilot Workflow seam tests for allow/deny/approval on coding path, so that Balanced posture regressions are caught.
62. As a QA engineer, I want evidence export + audit verify seam tests, so that living pilot packages can be validated the same way as lab packages.
63. As an incident responder, I want a support runbook and kill-switch guide, so that pilot outages are recoverable.
64. As a partner security team, I want webhook/SIEM export of signed events, so that Decisions can land in our monitoring stack.
65. As a budget owner on a partner team, I want rate limits and budgets to block runaway loops, so that agents cannot burn resources unbounded.
66. As a founder measuring 90 days, I want must-hit defined as public `v1.0.0` plus Pilot #1 unaided, so that success is not vague.
67. As a founder measuring 90 days, I want stretch defined as clone Pilot #2 underway or done, so that extra ambition is explicit.
68. As a product owner, I want historical v0.2–v0.7 plans marked complete, so that agents do not reopen finished milestones.
69. As a product owner, I want domain language from the glossary used in tickets and docs, so that Decision/Approval/Pilot terms stay consistent.
70. As a future enterprise buyer, I want a visible path to Paid Platform Surface later, so that self-host success can convert without rewriting the kernel.

## Implementation Decisions

### Scope and sequencing
- Execute two phases that may overlap in the Parallel Launch Window: Quiet Open-Core Release, then Design Partner Window delivery.
- Historical engineering milestones through local v1 regression are complete; do not reopen them as greenfield work.
- Public artifact tag is `v1.0.0` for Quiet Open-Core; do not use pre-1.0 public tag as the open-core ship name; do not treat the tag as Proven Claim Gate.
- Design Partner Pilot #1 is a coding ICP on Pi Primary Path; MCP Optional Path is supported, not pilot-gating.
- Pilot Sequencing: one active pilot until Pilot Done (Unaided); Pilot #2 is a clone coding team.
- 90-Day Must-Hit: public `v1.0.0` + Pilot #1 unaided. Stretch: clone Pilot #2.

### Open-core and commercial boundary (ADR 0001)
- Self-Host Free Surface includes Enforcement Kernel, web Approval, basic dashboard, optional Slack connector, policy templates, local audit/evidence export.
- Paid Platform Surface is hosted control plane, enterprise identity, stronger isolation runtimes, managed compliance export, white-glove support—not core approval UX.
- Success Package is a two-week optional paid (or fee-waived early) onboarding engagement ending in docs cutover; product itself remains free self-host.

### Policy postures
- Balanced Coding Policy is the default Design Partner template posture: credential/secret paths deny; local coding loop allow; remote/mutating side effects approval_required.
- Strict Coding Policy is opt-in for higher friction.
- Orchestration model remains: Cedar permit/forbid combined with risk rules, budgets, kill switch, and Approval state into Decision outcomes `allow` | `deny` | `approval_required`.
- `credential_access` true remains always deny (never routed to Approval).

### Pilot Freeze and Escape Hatch (ADR 0002)
- Always frozen: Firecracker, multi-tenant SaaS, credential broker, SCIM, S3 WORM productization, policy marketplace, new framework adapters.
- Frozen unless Escape Hatch: OIDC, gVisor, HA, advanced multi-step approval products, extra SDKs beyond Pi adapter, deep SIEM productization, MCP-first as hard pilot requirement.
- Escape Hatch requires a short written decision before coding; at most one preferred in the window; criteria are dual-partner same blocker or strategically existential partner with failed workarounds.

### Modules / surfaces to touch (conceptual, not paths)
- Release packaging and version identity: align package/image/manifest/tag to `v1.0.0` and Quiet Open-Core stage language.
- Public docs and onboarding: claim hygiene, free vs paid surface, Pi primary vs MCP optional, Balanced/Strict templates, fixture labeling for lab pilot evidence.
- Policy template pack and risk-rule pairing for Balanced default and Strict opt-in clarity.
- Pi guarded adapter and intercept Decision pipeline only for pilot-blocking defects.
- Approval (web and optional Slack), dashboard, kill switch only for pilot-blocking reliability.
- Evidence export and audit verification for living partner sessions.
- No `/v1` API expansion as part of this phase unless Escape Hatch demands it; frozen contract remains the boundary.

### Architectural constraints (respect existing)
- Fail-closed adapters: no tool execution without explicit allow Decision.
- Out-of-process policy evaluation relative to the agent.
- Docker sandbox baseline for execution isolation in this phase.
- Hash-chained audit events; redacted previews.
- Approvals one-use and TTL-bounded.
- MCP gateway remains available for optional path (manifest pin/drift, SSRF blocklist, tools/list filter, tools/call intercept) without becoming pilot success criteria.

### Operational process decisions
- Pilot Fit Checklist required at entry; fail two or more hard items → decline/defer.
- Success Package: kickoff + limited office hours + async; day-14 cutover; no custom features in package.
- Pilot Done (Unaided): multi-day real use with product left on; second engineer completes governed session from public docs only; ≤4 weeks from first successful install.
- Pilot Auto-Kill: no credible unaided path by day 28 from install → kill + retro or Escape Hatch writeup.
- Sourcing: warm network for Pilot #1; light outbound pipeline; inbound is bonus.
- Proven Claim Gate: living Pilot #1 unaided enables limited proof language; clone Pilot #2 enables repeatability claims; never backdate onto original tag notes.

## Testing Decisions

### What makes a good test here
- Test external, observable behavior: Decisions returned, actions blocked/allowed, Approvals one-use, install succeeds, evidence verifies, fail-closed on daemon failure.
- Do not test implementation details of Cedar internals, private helpers, or UI layout chrome.
- Prefer existing highest seams over new micro-seams.
- Lab/fixture evidence is valid for regression; living partner evidence is required for Proven Claim Gate stories.

### Approved seams (user confirmed)

1. **Ship / Quiet Open-Core seam**  
   Operator-facing release gate: typecheck/build/test/policy regression as release verify, fresh-install smoke, release artifact generation.  
   Proves: installable kernel, versioned package, demo path green.

2. **Pilot Workflow seam (Pi Primary Path)**  
   Guarded tool call → intercept Decision (`allow` / `deny` / `approval_required`) → Approval consume → tool-result → audit ordering.  
   Proves: Balanced posture (workspace allow, credential deny, side-effect approval), fail-closed, kill switch blocks subsequent action.  
   Prior art: demo flow, policy regression, intercept/approval/fail-closed suites, Pi adapter guarded tool tests.

3. **Living evidence seam**  
   Session evidence export + audit-chain verification.  
   Proves: decision-before-execution package integrity for partner and lab packages.  
   Prior art: evidence export tests, audit-chain verifier tests.

### Modules / surfaces under test
- Enforcement Decision pipeline and fail-closed behavior
- Approval lifecycle (create, approve/deny, expiry, replay denial)
- Pi guarded tool boundary behavior (not MCP as pilot gate)
- Policy regression for Balanced/Strict-relevant outcomes
- Fresh install / compose smoke
- Release artifact version identity
- Evidence export + verifier
- Optional: MCP gateway regression remains green but is non-gating for pilot success

### Explicit non-test automation for this phase
- Marketing claim wording → checklist / human review gate
- Success Package commercial process → operational checklist
- Pilot Fit / Auto-Kill calendars → process, not unit tests

## Out of Scope

- Launch marketing (blog, HN campaign, paid ads)
- Requiring two living external pilots before Quiet Open-Core tag
- Treating lab/fixture pilot evidence as Proven Claim Gate
- New feature platforms: OIDC/SSO productization, SCIM, credential broker, gVisor default, Firecracker, multi-tenant SaaS, S3 WORM product, policy marketplace
- New agent framework adapters (LangGraph, AutoGen, etc.)
- Major `/v1` API redesign or new endpoint families without Escape Hatch
- Full enterprise compliance certifications (SOC2, ISO) as a deliverable of this phase
- Hosted SaaS control plane as the pilot default
- MCP-first pilot as the definition of success for Pilot #1
- Parallel dual-ICP pilots before Pilot #1 unaided done
- Custom per-partner feature development inside Success Package
- Open-ended white-glove support after Success Package cutover

## Further Notes

- Domain vocabulary: use `CONTEXT.md` terms (Decision, Approval, Quiet Open-Core Release, Self-Host Free Surface, Pi Primary Path, MCP Optional Path, Pilot Done (Unaided), Pilot Freeze, Escape Hatch, Proven Claim Gate, Balanced/Strict Coding Policy).
- Strategy ADRs: 0001 open-core free surface; 0002 pilot freeze and escape hatch; 0003 v1 tag vs proven claims; 0004 pilot sequencing Pi primary.
- Local engineering was already Go for code/package; remaining risk is publish honesty + living pilot proof.
- Agent execution should open tickets only under Quiet Open-Core and Design Partner Window plans—not historical v0.2–v0.7 streams.
- If implementation work appears during pilots, default answer is docs/template/bugfix; platform work requires Escape Hatch writeup first.
- Success is not “more features”; success is public `v1.0.0` + a coding team whose second engineer can run the Pilot Workflow without founders.
