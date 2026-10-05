# ActantOS Forward Plan

**Planning date:** 2026-07-10
**Horizon:** Immediate through 24+ months
**Current stage:** Post-release, local/self-hosted operational scope complete
**Execution source of truth:** [`ActantOS_Canonical_Overview_Vision.md`](./ActantOS_Canonical_Overview_Vision.md) (Mode A next action **A-01**). This document is a supporting post-v1 assessment and historical FWD roadmap, not the active milestone queue.
**Technical contracts:** `implementation_spec.md`
**Terminology and strategic decisions:** `CONTEXT.md` and `docs/adr/`

---

## 1. Executive direction

ActantOS has completed the current objective: a public, self-hosted enforcement kernel that can decide, approve, deny, execute, and audit agent tool actions. The published artifact and internal dogfood path are verified. External adoption and commercial validation are optional future goals, not requirements for the simple working solution.

The active strategy is therefore:

1. Keep the published local/self-hosted install working.
2. Preserve verified Pi allow/deny enforcement, approval, and audit behavior.
3. Fix only security, correctness, installation, or documentation regressions.
4. Do not start customer-development, hosted, or enterprise work unless it becomes an explicit future goal.

The core promise remains:

> **No agent action executes without an ActantOS Decision.**

---

## 2. Current-stage assessment

### 2.1 What is verified

| Area | Current evidence |
| --- | --- |
| Public release | `v1.0.0` Quiet Open-Core published |
| Kernel | TypeScript/Fastify/Postgres service with frozen `/v1` API |
| Decisions | Deterministic `allow`, `deny`, `approval_required` pipeline |
| Policy | Cedar provider abstraction plus deterministic risk rules |
| Enforcement | Fail-closed Pi guarded tools and MCP gateway |
| Approval | Web approval and optional Slack, one-use TTL-bounded tokens |
| Isolation | Docker sandbox baseline with constrained execution |
| Evidence | Hash-chained audit log, timeline, verifier, evidence export |
| Operations | Kill switches, budgets, rate limits, support runbook |
| Packaging | Compose self-host path, release artifact, SBOM, upgrade path |
| Quality | Current release suite passes; Pi adapter tests pass; website builds |
| Lab usability | Fresh-install smoke and sample pilot process dry-run complete |

### 2.2 What is not verified

| Unproven area | Evidence required |
| --- | --- |
| External adoption | A living partner installs and uses the public artifact |
| Unassisted operation | Second partner engineer completes a governed session from public docs |
| Persistent value | Partner leaves ActantOS enabled for multi-day real work |
| Repeatability | Clone Pilot #2 reaches the same unaided outcome |
| Willingness to pay | Partner accepts a defined Success Package or platform price |
| Hosted demand | At least two qualified prospects reject self-host for the same reason |
| Enterprise identity demand | Repeated OIDC/SCIM blocker from qualified buyers |
| Stronger isolation demand | Workload/risk profile makes Docker an evidenced blocker |
| Broader ICP | Coding wedge succeeds before legal, R&D, support, or regulated workflows |
| Memory/IP product | Real workflow exposes an enforceable memory or sensitive-content boundary |
| Compliance product | Buyer requests a specific evidence mapping/export during procurement |
| Quantum-safe product | Customer/security architecture requires it; standards and integration path mature |

### 2.3 Stage label

Use this externally and internally:

> **Quiet Open-Core v1.0.0: verified local/self-hosted kernel.**

Do not use:

- battle-tested;
- production-proven;
- enterprise-ready suite;
- repeatable across teams;
- cryptographically verified memory vault;
- compliance-certified;
- multi-tenant SaaS ready.

---

## 3. North-star outcomes and metrics

### 3.1 Product north star

**Weekly Governed Actions (WGA):** number of real external agent tool actions that pass through an ActantOS Decision while enforcement is enabled.

WGA must be segmented by:

- partner;
- active agent;
- tool/action class;
- allow/deny/approval result;
- real workflow versus demo/fixture;
- Pi versus MCP path.

Do not optimize raw WGA alone. Pair it with safety and friction metrics.

### 3.2 Pilot scorecard

| Metric | Pilot #1 target | Why it matters |
| --- | ---: | --- |
| Qualified warm prospects | 10 identified | Prevents dependence on one conversation |
| Fit interviews | 5 completed | Tests urgency and constraints |
| Fit-qualified candidates | 2 or more | Provides a fallback candidate |
| First successful install | Within 90 minutes | Measures onboarding quality |
| First governed real action | Within 2 hours of install | Measures time to value |
| Multi-day use | 3 or more working days | Separates trial from real adoption |
| Active engineers | At least 2 | Required for unaided test |
| Governed real actions | At least 100 | Creates a useful behavior sample |
| Credential-path protection | 100% expected denies | Core security invariant |
| Fail-open events | 0 | Hard safety requirement |
| Incorrect allows | 0 known P0/P1 | Hard safety requirement |
| Approval completion | 95% within agreed workflow window | Tests operational viability |
| Approval median latency | Baseline measured; target under 5 minutes for interactive coding | Measures disruption |
| False-deny/friction rate | Under 5% of ordinary local actions | Measures Balanced policy quality |
| Founder live support after day 14 | 0 for unaided session | Proves self-service |
| Founder total support | Under 4 hours after initial kickoff | Tests scalability |
| Evidence export | Successful and independently readable | Proves audit value |
| Continued-use intent | Explicit yes/no recorded | Tests value |
| Price response | Explicit acceptance/rejection at a stated price | Tests commercial value |

### 3.3 Commercial scorecard

Track weekly:

- prospects contacted;
- response rate;
- meetings booked;
- Fit-qualified rate;
- pilot acceptance rate;
- install activation rate;
- Pilot Done rate;
- stated willingness to pay;
- requested deployment model;
- top three objections;
- top three repeated blockers;
- founder hours per active pilot;
- number of feature requests rejected under Pilot Freeze.

---

## 4. Immediate plan: Days 0–14

### Objective

Restore a single truthful operating picture and make founder outreach executable within two weeks.

### Workstream A: Plan and claim hygiene

| ID | Deliverable | Owner | Done when |
| --- | --- | --- | --- |
| I-01 | Declare this file the post-v1 execution source | Founder/Product | All plan indexes point here |
| I-02 | Restore living Pilot #1 as mandatory validation | Founder/Product | “Optional GTM” removed from canonical success language |
| I-03 | Archive completed version work from active queues | Release owner | No v0.2–v1 tickets appear as current work |
| I-04 | Reconcile website claims with verified v1 surface | Product/Marketing | No memory-vault or production-proof implication |
| I-05 | Reconcile pricing with open-core surface | Founder/Product | Free self-host surface and paid Success Package are explicit |

### Workstream B: Pilot instrumentation

| ID | Deliverable | Owner | Done when |
| --- | --- | --- | --- |
| I-06 | Pilot scorecard template | Pilot owner | Every metric in section 3.2 has a field and source |
| I-07 | Support-time log | Pilot owner | Founder assistance is timestamped and categorized |
| I-08 | Friction taxonomy | Product | Install, docs, policy, approval, runtime, evidence, security categories exist |
| I-09 | Pilot evidence labeling | Security/QA | Living, lab, sample, and fixture evidence cannot be confused |
| I-10 | Price interview script | Founder | Candidate must react to a concrete fee/range |

### Workstream C: Supply-chain residual

| ID | Deliverable | Owner | Done when |
| --- | --- | --- | --- |
| I-11 | Decide artifact/image signing path | Release/Security | Implemented or explicitly deferred with trigger and owner |
| I-12 | Verify public artifact from clean environment | QA | Install and core demo run from published release, not plan source |

### Workstream D: Candidate pipeline

| ID | Deliverable | Owner | Done when |
| --- | --- | --- | --- |
| I-13 | Warm candidate list | Founder | 10 named teams with relationship and fit hypothesis |
| I-14 | Outreach batch 1 | Founder | First 5 personalized messages sent |
| I-15 | Fit interviews | Founder + technical owner | At least 3 scheduled |
| I-16 | Candidate fallback | Founder | At least two plausible candidates remain in pipeline |

### Day-14 gate

**GO** when:

- canonical status is truthful;
- scorecard and evidence capture are ready;
- one clean public-artifact verification passes;
- at least one Fit-qualified living candidate is available or three interviews are scheduled.

**NO-GO / adjust** when:

- no candidate accepts self-host + Pi;
- the public artifact cannot be installed without custom intervention;
- the website creates expectations for unavailable functionality;
- the founder cannot name an accountable pilot owner.

No new platform feature work is allowed to resolve a pipeline problem.

---

## 5. Short-term plan: Days 15–30

### Objective

Accept one living Pilot #1 and reach the first real governed workflow.

### Required sequence

1. Complete five Fit conversations.
2. Score each candidate against hard requirements and urgency.
3. Select the candidate with the strongest real workflow, available second engineer, and shortest path to use.
4. Agree Success Package terms, including fee waiver or stated fee.
5. Record baseline workflow and risk before installation.
6. Install from public `v1.0.0` on partner infrastructure.
7. Reach first allow, credential deny, risky-action approval, kill-switch denial, and evidence export.
8. Begin real multi-day feature work with ActantOS left enabled.

### Baseline interview questions

- Which agent performs the workflow today?
- Which tools and sensitive resources can it reach?
- What action would create material harm?
- Who owns the agent and who should approve risky actions?
- What incident, customer request, security review, or board concern creates urgency?
- What is the current control or workaround?
- What would make the pilot fail?
- Must deployment be self-hosted, hosted, or either?
- What evidence must security or customers see?
- What would the team pay to retain the control after the pilot?

### Days 15–30 product rule

Only these changes are allowed:

- P0/P1 safety defects;
- install blockers;
- Pi adapter blockers;
- Balanced/Strict policy correctness;
- approval reliability;
- missing public documentation;
- evidence export correctness.

Every change requires a linked living-pilot observation. A preference or speculative request is not evidence.

### Day-30 gate

**GO** when:

- a living partner is accepted;
- public artifact is installed;
- first real workflow is governed;
- the partner agrees to leave enforcement enabled;
- no fail-open or known incorrect allow exists.

**PIVOT candidate acquisition** when 10 qualified outreaches produce no Fit-qualified candidate. Review ICP, Pi requirement, self-host burden, and urgency before changing product scope.

**STOP feature development** when the partner is only willing to run demos or the founder performs all operational work.

---

## 6. Short-term plan: Days 31–60

### Objective

Reach Pilot Done (Unaided), determine whether the wedge delivers recurring value, and quantify the product changes genuinely required.

### Execution

#### Week 5–6: Supported real use

- Keep ActantOS enabled for at least three working days.
- Record all governed actions and approval outcomes.
- Record false denies, confusing reasons, approval fatigue, latency, and bypass attempts.
- Prefer policy/template/docs changes before code.
- Cap scheduled support at the Success Package boundary.
- Review evidence with the partner security or engineering owner.

#### Day 14 of the Success Package: Cutover

- Stop scheduled live assistance.
- Confirm public docs and runbooks are the only operating guide.
- Nominate the second engineer.
- Schedule the unaided session.

#### Unaided session

The second engineer must independently:

1. start or verify the deployment;
2. run a normal governed coding session;
3. observe an allow;
4. observe a credential deny;
5. complete an approval-required action;
6. use or understand the kill switch;
7. export and inspect evidence;
8. recover from one documented failure mode.

### Product decision after Pilot #1

Classify each observed issue:

| Class | Response |
| --- | --- |
| P0 safety/correctness | Fix immediately; regression test required |
| P1 pilot blocker | Fix before clone pilot |
| Repeated onboarding problem | Improve docs/template/installer |
| Single-partner preference | Do not build |
| Enterprise platform request | Log hypothesis; keep frozen |
| New adapter request | Defer until clone success or Escape Hatch |
| Compliance request | Map evidence manually before productizing |

### Day-60 gate

**GO to clone pilot** when:

- Pilot Done (Unaided) is achieved within 28 days of first successful install;
- no P0/P1 security defect remains;
- partner wants continued use;
- founder support is within target;
- willingness-to-pay response is recorded;
- living evidence package passes audit verification.

**AUTO-KILL** when unaided success is not credible by day 28. Produce a retro distinguishing product, ICP, urgency, deployment, and support failures.

**ESCAPE HATCH** only under ADR 0002 conditions, with written evidence before coding.

---

## 7. Short-term plan: Days 61–90

### Objective

Prove repeatability with a clone pilot and make the first commercial/roadmap decision.

### Clone rule

Pilot #2 must resemble Pilot #1:

- coding team;
- Pi Primary Path;
- self-host acceptable;
- Balanced default unless explicitly Strict;
- comparable governed workflow;
- second engineer available;
- no new platform dependency.

Do not use Pilot #2 to test a second ICP, MCP-first deployment, hosted SaaS, or advanced compliance workflow.

### Improvements allowed before clone

- P0/P1 fixes from Pilot #1;
- onboarding steps that clearly reduced time to value;
- policy template corrections;
- approval usability fixes;
- evidence clarity;
- public docs corrections.

### Commercial experiment

Offer one of the following explicitly:

1. Fixed-fee Success Package with free self-host software.
2. Paid support/implementation package with defined scope.
3. Design-partner agreement with a written future hosted-price range.

Do not invent artificial agent limits in the free self-host kernel. Paid value should be service, hosting, enterprise identity/isolation, managed evidence, and support.

### Day-90 decision matrix

| Pilot #1 | Pilot #2 | Payment signal | Decision |
| --- | --- | --- | --- |
| Success | Success | Positive | Proceed to stable product and paid design partners |
| Success | Success | Weak | Refine packaging/value; avoid broad platform build |
| Success | Fails | Any | Diagnose repeatability; run one controlled remediation cycle |
| Fails | Not run | Any | Reassess ICP/workflow before more engineering |
| Success | Not sourced | Positive | Continue focused acquisition; do not broaden product |
| Success | Not sourced | Negative | Test urgency and economic buyer before platform work |

### Proven Claim Gate

After Pilot #1:

- allow narrow, anonymized proof of living unaided use;
- do not claim repeatability.

After clone Pilot #2:

- allow repeatability language supported by both evidence packages;
- publish a case study only with partner approval;
- never backdate claims into the `v1.0.0` release.

---

## 8. Medium-term plan: Months 3–6

### Entry gate

Begin only after at least one unaided pilot and a credible path to the clone outcome.

### Objective

Turn the validated wedge into a stable product that can support 3–5 design partners and 1–2 paid engagements without founder-as-SRE.

### Product priorities, in order

1. **Install and upgrade reliability**
   - versioned installer/CLI workflow;
   - automated preflight checks;
   - backup/restore validation;
   - compatibility matrix;
   - signed artifacts if the supply-chain decision selects signing.

2. **Operator usability**
   - clear agent/session ownership;
   - actionable reason codes;
   - approval queue reliability;
   - policy test/dry-run workflow;
   - evidence export that a security reviewer can consume.

3. **Integration stability**
   - version and publish the Pi adapter as a supported package;
   - maintain MCP compatibility as a supported optional path;
   - add conformance tests before adding frameworks.

4. **Operational telemetry**
   - privacy-preserving product metrics;
   - install health;
   - decision/approval latency;
   - policy error and fail-closed events;
   - audit-chain verification status.

5. **Security maintenance**
   - dependency and SBOM cadence;
   - threat-model updates from living use;
   - incident and disclosure process;
   - release signing/provenance;
   - regression corpus from bypass attempts.

### Conditional unlocks

| Capability | Unlock evidence |
| --- | --- |
| OIDC | Two qualified partners share the same identity blocker |
| Hosted single-tenant control plane | Two partners reject self-host or pay for managed operation |
| gVisor | Workload risk or security review makes Docker insufficient |
| Teams approval | Two partners require Teams and Slack/web cannot satisfy workflow |
| Python/TypeScript SDK | Two validated integrations cannot use Pi or MCP |
| Compliance mapping pack | Procurement requests the same mapping twice |

### Month-6 exit criteria

- 3–5 living design partners started;
- at least two reach unaided operation;
- at least one paid engagement or equivalent signed commitment;
- median time to first governed action under 60 minutes;
- no unresolved P0/P1 safety findings;
- support load below four founder hours per partner per month after onboarding;
- one repeatable deployment and upgrade path;
- clear decision on self-host-only versus managed single-tenant demand.

---

## 9. Long-term plan: Months 6–12

### Entry gate

Require repeatable customer value, a defined buyer, and a positive commercial signal. Do not enter because the calendar reached month six.

### Objective

Build the enterprise foundation around the enforcement kernel without weakening the open-core promise.

### Track A: Enterprise identity and administration

- OIDC/SAML authentication;
- SCIM only after OIDC demand is proven;
- organization, team, role, and agent ownership model;
- separation of policy author, approver, operator, and auditor;
- service identities and scoped API credentials;
- policy change approval and rollback history.

### Track B: Managed deployment

- start with single-tenant managed deployments;
- control-plane/data-plane separation;
- tenant isolation model and documented trust boundaries;
- secrets management and rotation;
- regional backup and recovery;
- service health, alerting, and incident response;
- SLA only after measured reliability supports it.

Do not jump directly to multi-tenant arbitrary code execution.

### Track C: Stronger execution isolation

Progression:

1. Harden Docker baseline.
2. Add gVisor for evidenced single-tenant high-risk workloads.
3. Evaluate Kata or Firecracker only for multi-tenant execution demand.
4. Commission an external security review before selling the strongest isolation tier.

### Track D: Enterprise evidence

- configurable retention;
- signed export packages;
- SIEM destinations selected from customer demand;
- WORM/Object Lock export after two procurement requirements;
- evidence mappings for NIST AI RMF, the NIST GenAI Profile, and applicable EU AI Act control themes;
- explicit disclaimer that mappings are not legal advice or certification.

### Track E: Approval and policy operations

- temporary/TTL grants;
- escalation and fallback;
- approval fatigue analytics;
- policy simulation against historical events;
- staged policy rollout;
- template registry with provenance and compatibility.

### Month-12 exit criteria

- 5–10 active organizations or a smaller set with equivalent revenue evidence;
- at least three paying customers/partners;
- repeatable onboarding and renewal signal;
- documented enterprise buyer and buying trigger;
- one supported identity path;
- one supported managed deployment model if demanded;
- one externally reviewed security posture;
- clear unit economics for support and hosting.

---

## 10. Long-term plan: Months 12–24

### Objective

Expand from the validated coding-agent wedge into a governed enterprise agent platform.

### Expansion gate

New use cases must share the existing enforcement primitive:

- identifiable agent and human owner;
- interceptable tool or data action;
- deterministic policy context;
- meaningful allow/deny/approval decision;
- auditable result;
- buyer with a costly risk.

### Candidate expansion order

1. **MCP-native enterprise agents**
   - graduate MCP from optional support to a primary distribution path only when adoption data supports it;
   - authorization boundary, server registry, manifest provenance, shadow-server detection;
   - target-scoped credentials.

2. **Engineering and deployment agents**
   - repository, CI/CD, package registry, cloud mutation, and database migration controls;
   - start with policy packs before custom connectors.

3. **Support and operations agents**
   - customer data boundaries;
   - ticket and production-action approvals;
   - higher identity and retention requirements.

4. **R&D and IP-sensitive agents**
   - labeled resource boundaries;
   - model/provider routing restrictions;
   - external-sharing approvals;
   - content inspection only after a labeled-data pilot demonstrates value.

5. **Legal/regulated workflows**
   - evidence packs and workflow-specific policy templates;
   - avoid claiming full compliance automation.

### Memory governance track

Do not begin with a generic memory vault. Start when a customer workflow exposes a specific enforceable boundary:

- whether data may be stored;
- retention duration;
- tenant/user/session scope;
- approved model/provider;
- deletion and evidence requirements;
- recall across sessions.

First product form should be a memory-policy decision and audit interface around an existing store, not a new vector database.

### IP protection track

Progression:

1. deterministic labels and paths;
2. repository/document classifications supplied by the customer;
3. external-sharing and provider-routing controls;
4. secret/structured-data detectors;
5. classifiers only after precision/recall can be measured on partner data.

### Month-24 exit criteria

- coding wedge remains healthy while at least one adjacent workflow repeats;
- multiple runtimes use the same stable Decision and evidence model;
- enterprise deployment/security model survives external review;
- memory or IP capability is linked to a paying workflow, not only marketing;
- expansion revenue justifies added platform complexity.

---

## 11. Vision horizon: 24+ months

### Objective

Become the governance and security control plane for enterprise AI agents across identity, permissions, approvals, memory, evidence, and secure agent-to-agent interaction.

### Potential platform capabilities

- universal agent capability manifest;
- cross-runtime identity and policy federation;
- credential brokering with short-lived target-scoped tokens;
- multi-agent delegation constraints;
- provenance for agent actions and outputs;
- governed memory lifecycle;
- agent-to-agent trust and secure messaging;
- cryptographic agility and post-quantum migration readiness.

### Quantum-safe rule

Post-quantum work is a cryptographic-agility program before it is a product module:

1. inventory cryptographic dependencies and long-lived data;
2. separate algorithms from protocols and key management;
3. follow finalized standards and ecosystem support;
4. add hybrid migration where customer threat models require it;
5. never use quantum-safe language as near-term differentiation without a working, reviewed implementation.

---

## 12. Product architecture guardrails

1. Authorization remains deterministic; no LLM-as-judge for execution permission.
2. Adapters fail closed on timeout, malformed response, or control-plane failure.
3. Every execution binds to a Decision and every result binds to the authorized request.
4. Credential access remains deny by default, not a routine approval.
5. The core Decision contract stays runtime-neutral.
6. Pi and MCP translation logic remain outside core policy semantics.
7. Open-core self-host users retain the complete basic enforcement loop.
8. Paid value comes from managed operation, enterprise controls, stronger isolation, evidence, and support.
9. Security-critical behavior requires regression evidence and operator documentation.
10. New abstractions require at least two real use cases.

---

## 13. Roadmap unlock matrix

| Requested capability | Default decision | Evidence that unlocks it |
| --- | --- | --- |
| Pi fixes | Allowed | Living pilot blocker |
| MCP fixes | Allowed | Security/correctness defect or active partner use |
| New MCP product surface | Deferred | Repeated partner demand after clone pilot |
| OIDC | Frozen | Two independent qualified partner blockers |
| SCIM | Frozen | Paying enterprise lifecycle requirement |
| Hosted control plane | Frozen | Two partners reject self-host or one pays strategically |
| gVisor | Frozen | Documented workload/security blocker |
| Firecracker | Frozen | Validated multi-tenant code-execution business |
| Credential broker | Frozen | Repeated target-credential workflow and threat model |
| Advanced approvals | Frozen | Measured approval workflow limitation in two partners |
| WORM export | Frozen | Two procurement/compliance requirements |
| New framework adapter | Frozen | Two qualified users share the runtime requirement |
| Memory governance | Research only | Specific paying retention/recall boundary |
| IP classifier | Research only | Labeled partner dataset and measurable precision target |
| Quantum-safe module | Research only | Customer threat model plus mature standards/integration |

---

## 14. Operating model

### Accountable roles

One person may hold several roles, but each role must have one named human:

| Role | Accountability |
| --- | --- |
| Founder/Product | Strategy, ICP, pricing, roadmap gates |
| Pilot owner | Candidate pipeline, Success Package, scorecard, support boundary |
| Technical owner | Kernel/adapters, release decisions, reliability |
| Security owner | Threat model, P0/P1 classification, incident response, claim review |
| Release owner | Versioning, artifacts, provenance, changelog |
| Marketing owner | Website truth, case studies, claim-gate enforcement |

### Weekly cadence during Design Partner stage

**Monday:** pipeline, pilot state, risks, and one measurable weekly outcome.
**Wednesday:** product friction review; decide docs/template/bug/no-build.
**Friday:** scorecard, support hours, security events, evidence quality, and gate status.

### Decision record

Record decisions when:

- a Pilot Freeze exception is proposed;
- the ICP changes;
- the primary integration changes;
- pricing model changes;
- hosted/multi-tenant work begins;
- a claim gate unlocks;
- memory, IP, or quantum-safe work becomes product scope.

---

## 15. Risk register

| Risk | Leading indicator | Response |
| --- | --- | --- |
| No urgent buyer | Low response/meeting rate | Revisit trigger and ICP, not feature breadth |
| Pi is too narrow | Fit candidates reject Pi consistently | Validate MCP path after documented pattern |
| Self-host friction | Install exceeds 90 minutes repeatedly | Fix packaging/preflight before hosted build |
| Founder-as-SRE | Support exceeds four hours after onboarding | Improve docs/automation; enforce cutover |
| Approval fatigue | High approval rate or long latency | Tune Balanced policy and add analytics before workflows |
| False allow | Any critical incorrect allow | Stop pilot, fix, regression test, disclose appropriately |
| Fail-open path | Any ungoverned execution | Stop release/pilot; treat as P0 |
| Audit contains secrets | Sensitive payload found | Contain, redact, rotate, add regression coverage |
| Website overclaims | Lead expects unavailable feature | Correct immediately; use claim inventory |
| Roadmap dilution | Multiple ICPs/adapters before repeatability | Enforce unlock matrix |
| Open-core confusion | Pricing contradicts free surface | Publish explicit free/paid boundary |
| Compliance overclaim | Buyer treats mapping as certification | Use scoped mapping and disclaimers |
| Hosted isolation risk | Demand for arbitrary multi-tenant execution | Start single-tenant; external review before expansion |

---

## 16. Versioning strategy after v1.0.0

- `v1.0.x`: security, correctness, install, documentation, and pilot-blocking fixes that preserve `/v1` compatibility.
- `v1.1`: first evidence-backed usability/integration improvement set after Pilot #1.
- `v1.2`: repeatability improvements after clone Pilot #2.
- `v2.0`: only for a deliberate contract or deployment-model break; not a marketing milestone.

Every release must state:

- verified environment;
- tests and smoke results;
- known residuals;
- customer-proof level;
- migration impact;
- security impact;
- which roadmap evidence unlocked the work.

---

## 17. Next executable queue

Current queue status:

Detailed execution conventions and the dependency graph: [`forward_steps/README.md`](forward_steps/README.md).

1. [`FWD-001`](forward_steps/FWD-001-status-reconciliation.md) through [`FWD-005`](forward_steps/FWD-005-artifact-signing-decision.md): **complete**.
2. FWD-006 through FWD-014 internal dogfood scenario: **scenario complete**.
3. Active next step: **none**. Maintain the simple verified local/self-hosted path.
4. External outreach, living pilots, clone pilots, and commercial validation: **optional future track**.

---

## 18. External reference watchlist

Review quarterly rather than hard-coding legal or protocol assumptions:

- NIST AI Risk Management Framework and Playbook: https://www.nist.gov/itl/ai-risk-management-framework
- NIST Generative AI Profile: https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf
- EU AI Act official policy and implementation timeline: https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai
- EU AI Act Service Desk timeline: https://ai-act-service-desk.ec.europa.eu/en/ai-act/timeline/timeline-implementation-eu-ai-act
- MCP Security Best Practices: https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices

These sources guide evidence mapping and threat-model maintenance. They do not automatically justify building a compliance product.
