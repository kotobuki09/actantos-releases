# ActantOS Final Canonical Production Plan, Architecture Review, and Release Program

> **Canonical planning and execution entrypoint:** [`ActantOS_Canonical_Overview_Vision.md`](./ActantOS_Canonical_Overview_Vision.md)
> **Executable milestones:** [`milestones/`](./milestones/) — current next action **A-01**
> **This document’s role:** Supporting detailed architecture, repository audit, and historical production-qualification design notes.
> **Not** the active task sequence. Do not schedule Mode B work from this file while Mode A is active and Mode B is frozen.

**Review date:** July 12, 2026
**Audience:** Engineering, security, product leadership, design partners, and stakeholders
**Document status:** Repository-audited planning baseline v5 — planning quality is evidence-gated; no self-awarded completeness score
**Current engineering baseline:** **Quiet Open-Core v1.0.0, local/self-hosted verified**; external validation is optional/inactive and enterprise qualification is not claimed
**Repository audit basis:** Working tree reviewed and verification rerun on July 12, 2026; see §0 for commands, limits, and unresolved drift
**Canonicalization rule:** This document is a review and improvement proposal. `implementation_spec.md` controls technical contracts; `forward_plan.md`, `production_execution_plan.md`, ADRs, and `forward_steps/STATUS.md` control current execution status until an explicit owner decision supersedes them.

---

## 0. July 12 Repository Audit and Plan Correction

### 0.1 Audit scope and exclusions

The audit inspected the repository root, the `plan` Git repository, the `plan/actantosd` product, the Pi/MCP planning and evidence material, release artifacts, and the separate `web/actantos` marketing repository. Generated or duplicated trees (`node_modules`, `.next`, `dist`, `.qa-public-v1*`, `worktrees`, extracted release copies, and tool caches) were not treated as independent source implementations.

The plan repository was audited with a dirty working tree containing both modified and untracked work. Findings therefore describe the current filesystem, not a clean fixed commit. No existing user changes were reverted.

### 0.2 Fresh verification snapshot

| Surface | Command | Result | Interpretation |
|---|---|---|---|
| Kernel | `npm run release:verify` | **PASS** | Typecheck and build pass; main suite: 147 tests, 146 pass, 1 skip; policy regression: 5/5 pass |
| Cedar integration | Main-suite Cedar direct-safe-read test | **SKIPPED** | Cedar CLI is unavailable in the audit environment; full real-engine conformance is not proven by this run |
| Marketing site | `npm run check` | **PASS** | Lint, typecheck, 26 tests, and Next.js production build pass; 40 routes generated |
| Plan repository hygiene | `git diff --check` | **FAIL** | Four pre-existing trailing-whitespace findings in `actantosd/docs/pilot-1-status.md` |
| Release identity | `actantosd/artifacts/release-manifest.json` | **PRESENT** | Declares `v1.0.0` / `quiet-open-core`; current tree also contains uncommitted provenance/signing work |

These results replace the stale 51-test and 29-demo figures as the current local verification snapshot. A live Compose fresh-install/demo and independent public-artifact verification were not rerun in this audit, so prior evidence for those surfaces remains historical rather than freshly confirmed here.

### 0.3 Material plan drift found

| Severity | Drift | Repository evidence | Correction |
|---|---|---|---|
| **P0 planning** | The plan presented itself as final and 100/100 although it contradicted canonical execution status. | `forward_steps/STATUS.md`, `task_plan.md`, and `progress.md` define the terminal goal as simple local/self-hosted operation with external validation optional/inactive. | Remove the self-score and make the execution-mode decision explicit before scheduling enterprise work. |
| **P0 accuracy** | Budgets were described as designed and inactive. | `PostgresBudgetProvider`, budget routes, policy regression coverage, and passing budget tests show active enforcement. | Mark budgets **VERIFIED baseline**, while retaining concurrency/transaction-coupling limitations. |
| **P0 accuracy** | The plan said no source snapshot, Git history, or raw logs were supplied. | The full source tree, nested Git repositories, tests, logs, release artifacts, and status files are present locally. | Replace package-only caveats with the working-tree/fixed-commit limitation in §0.1. |
| **P1 governance** | Website copy declares Stage 3/v1.1.0 while the kernel package and public release manifest are v1.0.0 Quiet Open-Core. | `web/actantos` commits and tests use Stage 3/v1.1.0; `actantosd/package.json` and release manifest use v1.0.0. | Create one machine-readable release/maturity source and prohibit independent site-stage advancement. |
| **P1 security** | `egress_proxy` currently selects/creates a Docker network named `actantos_egress`; that is not itself a destination-enforcing proxy. | `src/docker-executor.ts` and its tests verify network selection, not authenticated connect-time policy. | Rename claims to “egress network mode” until an actual proxy, route denial, DNS/redirect controls, and adversarial tests exist. |
| **P1 security** | Cedar can fall back to `FakeCedarProvider` when the CLI is unavailable. | Provider-selection tests explicitly verify the fallback. | Development fallback may remain explicit, but production startup/release gates must fail closed when the authoritative evaluator is unavailable. |
| **P1 release** | Signing/provenance is documented but the verifier permits digest-only success unless `--require-cosign` is used. | `verify-release-artifacts.mjs` and `artifact-verification.md`. | Make signed verification mandatory only for a newly named signed-release maturity gate; do not describe current v1.0.0 as signed until bundle evidence exists. |
| **P2 hygiene** | Status artifacts still disagree and the plan repository fails whitespace checking. | `forward_steps/STATUS.md` says no active next step; `pilot-1-status.md` retains external-pilot language and trailing whitespace. | Reconcile status documents in one small documentation change after the product-mode decision. |

### 0.4 Required product-mode decision

The repository currently encodes two incompatible programs. Choose one before executing the backlog:

| Mode | Goal | Immediate work allowed | Work kept frozen |
|---|---|---|---|
| **A. Maintain local/self-hosted (current canonical mode)** | Keep v1.0.0 installable and the allow/deny/approval/audit paths healthy. | Fix release/status drift, require reproducible fresh-install evidence, close high-impact fail-open or claim bugs, maintain dependencies. | OIDC, RLS, HA, gVisor, enterprise egress, external pilots, SCIM, Firecracker unless an ADR/escape hatch explicitly unlocks them. |
| **B. Resume production-qualification program** | Progress EKV → DPR → ESR using the security gates in this document. | Transactional state machine, authoritative Cedar, authenticated identity/RLS, execution binding, mandatory egress, recovery, signed evidence. | Broad UI, connector expansion, SCIM, Firecracker, and multi-tenant SaaS until their predecessor gates pass. |

**Default used by this revision:** Mode A, because it is the newest canonical repository status. Sections describing DPR/ESR remain a conditional backlog, not the active 30-day commitment.

### 0.5 Improved immediate plan for Mode A

| Order | Deliverable | Acceptance evidence |
|---:|---|---|
| 1 | Reconcile release and maturity truth across kernel, release manifest, plan status, and website. | One structured source reports package version, release tag, maturity, validation class, and last evidence date; site and docs consume or test against it. |
| 2 | Freeze a clean evidence commit. | Clean checkout SHA recorded; `npm ci`; kernel `release:verify`; website `npm run check`; logs stored without secrets. |
| 3 | Re-run the public-artifact user journey. | Two clean installs from the published artifact; allow/deny/approval/replay/kill-switch/audit verification; teardown confirmed. |
| 4 | Make evaluator mode explicit and safe. | Production profile refuses startup when real Cedar is unavailable; development fake mode is visibly labeled; direct Cedar conformance runs in CI. |
| 5 | Correct egress terminology and isolation claims. | Docs and site no longer imply proxy enforcement from a Docker network; `network_mode=none` remains verified; proxy work stays conditional. |
| 6 | Close repository hygiene drift. | `git diff --check` passes for the intended patch; generated/cache directories are documented or ignored; status files agree on active mode. |

**Mode A exit gate:** a new operator can install the public artifact and complete the governed action loop from public documentation without maintainer intervention, while every public claim maps to fixed-commit evidence.

---

## Executive Decision

ActantOS has established a credible technical foundation for an **in-path, out-of-process, fail-closed Agent Runtime Control Plane**. The verified baseline demonstrates that guarded agent actions can be intercepted, evaluated by deterministic policy, routed to approval, executed under Docker constraints, correlated with results, and recorded in a Postgres-backed hash chain.

The central product thesis remains strong:

> **Govern every agent action before it executes.**

The project should now move from proof-of-enforcement to **hardening, pilot packaging, operational resilience, and enterprise identity**. It should not expand into broad “Agent OS” features, cryptographic memory, decentralized governance, or multi-tenant arbitrary-code execution until the authorization path, tenant boundaries, credential handling, and operational evidence are production-grade.

### Recommended current classification

| Dimension | Assessment |
|---|---|
| Product category | Agent Runtime Control Plane / Agent Permission Gateway |
| Verified scope | Enforcement-kernel MVP with Pi and MCP proof paths |
| Deployment maturity | Development and controlled self-host evaluation |
| Pilot readiness | Promising, but requires identity, packaging, runbooks, and hardening |
| Enterprise production readiness | Not yet established |
| Multi-tenant SaaS readiness | Not ready |


### Dual score: plan completeness versus product readiness

A high-quality plan and a production-ready product are different things. This document uses two separate scores.

#### A. Planning-quality assessment: **not numerically scored**

The earlier 100/100 self-score is withdrawn. The repository audit found status contradictions, stale implementation facts, missing fixed-commit evidence, and an unresolved choice between maintenance and production qualification. The table remains a coverage checklist; it is not evidence of completeness.

| Planning domain | Weight | Required coverage | Score |
|---|---:|---|---:|
| Product scope and non-goals | 10 | Category, wedge, customer, exclusions, maturity vocabulary | 10 |
| Architecture and trust boundaries | 10 | Control/data planes, trusted stores, PDP, executor, gateway, egress | 10 |
| Authorization correctness | 10 | Cedar semantics, policy lifecycle, token contract, revocation, retries | 10 |
| Transactional integrity | 10 | State machine, approval atomicity, budgets, outbox, reconciliation | 10 |
| Identity and tenant isolation | 10 | OIDC/workload identity, RLS, runtime roles, cross-tenant tests | 10 |
| Execution and network security | 10 | Sandbox, object binding, TOCTOU, egress proxy, SSRF, bypass prevention | 10 |
| Audit, privacy, and evidence | 10 | Hash chain, external anchors, content separation, retention, verifier | 10 |
| Operations and supply chain | 10 | HA, recovery, observability, SBOM, provenance, signed releases | 10 |
| Roadmap and ownership | 10 | Version gates, dates, RACI, effort, critical path, external reviews | 10 |
| Verification and commercial readiness | 10 | Test matrix, capacity envelope, pilot metrics, open-core boundary | 10 |
| **Total coverage weight** | **100** |  | **Review required** |

**Interpretation:** Coverage of a planning domain means the topic is discussed. It does **not** prove that decisions are internally consistent, current, funded, owned, or implemented.

#### B. Conditional production-readiness estimate: **not a release claim**

| Area | Score | Reason |
|---|---:|---|
| Core enforcement correctness | 76 | Main decision, approval, result, kill-switch, MCP, and audit paths have live verification evidence |
| Authorization engine maturity | 48 | Cedar integration is active, but the compatibility shim is a material blocker |
| Approval and replay safety | 70 | Scope-bound, one-use approval design is strong; full transactional and channel evidence remains |
| Sandbox and execution isolation | 52 | Docker baseline exists; object binding, hardened profiles, and gVisor validation remain |
| MCP and network security | 62 | Manifest drift and basic SSRF controls are live; mandatory egress and rebinding controls remain |
| Audit integrity and evidence | 63 | Hash-chain behavior exists; external anchoring, privacy separation, and verifier maturity remain |
| Multi-tenancy and identity | 18 | Tenant labels exist, but authenticated tenant identity and forced RLS are not verified |
| Operational resilience | 28 | HA, backup/restore, upgrades, reconciliation, and incident evidence are not established |
| Developer and pilot experience | 45 | Demo works, but installer, stable SDKs, policy onboarding, and operator UX remain |
| Release assurance | 52 | Canonical specs are detailed, but provenance, signed artifacts, and fixed-commit evidence need completion |

The legacy numeric table below is retained only as a prioritization heuristic for Mode B. It is not reproducible from a fixed scoring rubric and must not be presented as a current release score. Product maturity changes only through named gate evidence.


### Top five priorities

1. **Implement the canonical governed-action state machine, transactional outbox, execution leasing, and reconciliation model.**
2. **Remove Cedar semantic overrides and finalize retry-safe decision-token, key, nonce, and emergency-revocation semantics.**
3. **Make approvals and hard budgets transactionally atomic, then prove them under concurrency and crash injection.**
4. **Introduce cryptographically authenticated identity, forced PostgreSQL RLS, and database-role separation.**
5. **Bind decisions to actual execution objects and enforce all governed network connections through the mandatory egress boundary.**

These five priorities precede broad UI expansion, connector growth, SCIM, Firecracker, or speculative autonomy work.

### Architectural refinement verdict

The second architectural review is directionally correct and materially improves the production plan. Its strongest contribution is identifying that several P0 items are not ordinary backlog features; they are **security-boundary design decisions**. However, three recommendations require qualification before becoming canonical:

| Proposal | Verdict | Required refinement |
|---|---|---|
| Replace Cedar CLI with Cedar WASM or Rust binding | **Accept the goal; refine the mechanism** | A direct evaluator is necessary, but WASM is not automatically safer or more deterministic. Prefer a dedicated Rust PDP using the official Cedar engine, with WASM/JS or N-API evaluated only through a conformance and failure-isolation benchmark. |
| Move SSRF enforcement to Envoy/Squid | **Accept as defense-in-depth** | The proxy must become the connection-time enforcement point, but application canonicalization and policy checks must remain. A generic proxy does not neutralize rebinding unless direct egress is blocked, DNS is controlled, IPs are validated at connect time, redirects are rechecked, and signed network grants are enforced. |
| Use atomic Postgres approval consumption | **Accept and strengthen** | Use one conditional SQL statement inside the same transaction that creates the resumed allow decision and audit event. Match approval ID, tenant, prior decision, scope, status, expiry, unused state, and token hash—not token hash alone. |
| Add PostgreSQL RLS | **Accept as mandatory before DPR** | RLS must use authenticated tenant context, `FORCE ROW LEVEL SECURITY`, non-owner runtime roles, transaction-local context, `USING` plus `WITH CHECK`, and cross-tenant tests. |
| Use Redis Lua for budgets | **Accept selectively** | Redis is well suited to high-throughput rate limits, but durable safety budgets should remain transactionally coupled to decisions in Postgres until scale requires a dual-store design. Redis must not become a fail-open source of truth. |
| Make the data plane stateless | **Accept as a target property, not a literal rule** | The data plane should be horizontally scalable and hold no authoritative identity/policy state. It may retain bounded execution-local state and caches; all durable approval, budget, idempotency, and audit state remains in trusted stores. |

---

## 1. Scope, Methodology, and Evidence Limits

### 1.1 Review scope

This review covers:

- Product positioning and category definition
- Current ActantOS architecture
- Decision and approval control paths
- Policy evaluation
- Sandbox execution
- Tool-result verification
- Audit-chain and session timeline behavior
- Pi guarded adapter workflow
- MCP gateway workflow
- Security posture and residual risks
- Technical debt and structural bottlenecks
- Operational and pilot readiness
- A versioned 12–15 month roadmap
- Business and stakeholder implications

### 1.2 Evidence basis

The primary evidence sources are:

- `implementation_spec.md` — canonical engineering specification and verified implementation handoff
- `strategic_roadmap.md` — canonical strategy and positioning
- `README.md` — canonical document precedence and decision log
- The prior `PROJECT_REVIEW.md`
- Orchestrator planning, briefing, progress, and handoff artifacts

The canonical document order is important:

1. `implementation_spec.md` controls technical contracts, schemas, decision semantics, sandbox constraints, and Week 1 behavior.
2. `strategic_roadmap.md` controls strategy and positioning.
3. Earlier `research.md` and `schedules.md` are historical and superseded where they conflict.

### 1.3 Evidence limitation

The July 12 audit had access to source, nested Git history, tests, status documents, and local release artifacts. However, the inspected `plan` and website repositories contained uncommitted work, so the snapshot is not independently reproducible from one commit SHA. Local unit/build evidence was rerun; public-artifact install, live Compose/demo, Cedar CLI conformance, adversarial security testing, and external production use were not all rerun.

- Fresh claims must cite §0.2 and distinguish pass, skip, historical evidence, and not run.
- The review is source-informed, but it is **not an independent security assessment**.
- A production or Proven Claim Gate review requires a clean fixed commit, immutable logs, artifact digests/signatures, and an independent rerun.

### 1.4 Status vocabulary

Every capability should use one of these labels:

| Label | Meaning |
|---|---|
| **VERIFIED** | Demonstrated through live HTTP/Postgres, Compose, integration, or documented passing tests |
| **IMPLEMENTED / LIMITED** | Present, but known limitations or insufficient production evidence remain |
| **DESIGNED** | Specified in canonical documents but not verified as active |
| **PLANNED** | Roadmap commitment, not current functionality |
| **CONDITIONAL** | Should be built only if customer demand or architecture requires it |

This vocabulary prevents planned enterprise capabilities from being presented as current product behavior.

---

## 2. Product and Strategic Assessment

### 2.1 Correct product definition

ActantOS should be positioned as:

> **A model-agnostic Agent Runtime Control Plane that evaluates and constrains AI-agent actions before those actions reach tools, APIs, files, databases, SaaS systems, shell commands, or MCP servers.**

The product is not primarily:

- An AI agent framework
- A chatbot platform
- An LLM gateway
- A prompt firewall
- A compliance dashboard
- A workflow orchestrator
- A model wrapper

ActantOS governs execution surfaces owned by other runtimes and frameworks.

### 2.2 Three-stage category language

| Stage | Recommended language | Why |
|---|---|---|
| Current wedge | Agent Permission Gateway | Concrete and easy to demonstrate |
| Product category | Agent Runtime Control Plane | Describes cross-runtime policy, approval, audit, and isolation |
| Long-term narrative | Agent OS for Governed Enterprise Autonomy | Appropriate only after identity, lifecycle, routing, sandboxing, and enterprise operations mature |

Calling the current kernel a full “Agent OS” is aspirational. The immediate product wins by proving reliable pre-execution control.

### 2.3 Dual wedge remains correct

The strategic combination is sound:

- **Pi adapter:** fastest concrete proof because file and shell tools create a visible control problem.
- **MCP gateway:** broader market wedge because it can govern heterogeneous clients and upstream tool servers.

The two should share one normalized decision contract, policy model, token model, and audit schema. They should not evolve into separate products.

### 2.4 Durable differentiation

ActantOS’s strongest differentiation is not a single policy language or sandbox technology. It is the combined execution contract:

```text
Every governed action becomes:
identity + normalized intent + resource + policy decision + approval state
+ execution constraints + result evidence + audit lineage
```

This creates value beyond:

- Identity-only systems that establish who the agent is
- Prompt-security systems that filter model inputs and outputs
- MCP gateways that only route or authenticate traffic
- GRC systems that document controls after the fact
- Agent frameworks that implement local tool hooks

### 2.5 Versioning and release-governance problem

The prior report used “Shipped (v1.1.0 Stage 3 Verified),” while other project artifacts describe a Week 1 kernel and a roadmap toward production. A public `v1.0.0` tag may exist for an open-core release, but that does not automatically mean the platform is enterprise-production qualified.

ActantOS needs two clearly separated concepts:

| Concept | Example |
|---|---|
| Product/package version | `actantosd 1.0.0` |
| Engineering maturity | Enforcement Kernel Verified / Pilot Ready / Production Qualified |

Recommended maturity labels:

1. **EKV — Enforcement Kernel Verified**
2. **DPR — Design Partner Ready**
3. **ESR — Enterprise Self-Host Ready**
4. **PQ — Production Qualified**

Do not use version numbers alone to imply security maturity.

---

## 3. Current Verified Baseline

### 3.1 Reported verification evidence

The implementation handoff reports the following green baseline:

```text
npm run typecheck                          -> pass
npm run build                              -> pass
npm test                                   -> 147 tests; 146 passed, 1 skipped (July 12 rerun)
PORT=3100 npm run dev                      -> daemon listens
Docker Compose actantosd + Postgres        -> healthy
npm run demo -- --url http://localhost:3100 -> 29 passed, 0 failed (historical; not rerun in this audit)
```

The verified endpoint is `http://localhost:3100`; port `3000` is reserved by the website in the referenced workspace.

### 3.2 Capability matrix

| Capability | Status | Current evidence | Important limitation |
|---|---|---|---|
| Tool-call interception | **VERIFIED** | Live HTTP/Postgres flow | Authentication and tenant isolation are not yet production-grade |
| Allow / deny / approval routing | **VERIFIED** | Demo and tests | Cedar compatibility shim affects evaluator confidence |
| Kill switch | **VERIFIED** | Live decision-path exercise | Distributed propagation and HA behavior not established |
| Idempotency | **VERIFIED baseline** | Request ID uniqueness and tests | Needs high-contention and retry-storm tests |
| Decision-token binding | **VERIFIED baseline** | Claims include decision, tenant, agent, session, tool call, scope, constraints, and expiry | HMAC key lifecycle and rotation require production design |
| Manual one-use approvals | **VERIFIED baseline** | Token consumption and lineage are implemented | Multi-user auth, channel identity, quorum, and escalation remain |
| Docker executor | **VERIFIED baseline** | Compose-backed execution | Hardened seccomp/AppArmor/gVisor profile not verified |
| Tool-result verification | **VERIFIED** | Token and persisted-decision checks | Distributed executor trust and attestation remain |
| Postgres hash-chain audit | **VERIFIED baseline** | Sequence parsing and timeline enrichment | No trusted external anchor or WORM export yet |
| Session event timeline | **VERIFIED** | Includes request, tool, decision, risk, approval, and result hash | UX and large-scale query performance not established |
| MCP gateway call path | **VERIFIED** | Live upstream SSE proof with request correlation | Production auth, transport breadth, and egress controls remain |
| MCP manifest drift | **VERIFIED** | Pending versions denied until approval | Admin identity and policy lifecycle remain basic |
| Basic URL SSRF blocklist | **IMPLEMENTED / LIMITED** | Loopback, metadata, and RFC-1918 examples denied | DNS rebinding, IPv6 completeness, redirect chains, and hostname resolution require hardening |
| Budgets and rate limits | **VERIFIED baseline** | Active Postgres provider, routes, policy regression, and passing tests | Atomic coupling to approval/job creation and high-contention evidence remain |
| Slack approvals | **PLANNED** | Roadmap only | Manual approval API is current baseline |
| OIDC / JWKS / SCIM | **PLANNED** | Roadmap only | Required before enterprise multi-user deployment |
| PostgreSQL RLS | **PLANNED** | Roadmap only | Current tenant ID is not a complete tenant isolation boundary |
| gVisor | **PLANNED** | Architecture target | Compatibility and performance not yet demonstrated |
| Firecracker | **CONDITIONAL** | Long-term architecture option | Requires demand, KVM infrastructure, and major operations investment |
| WORM audit export | **PLANNED** | Roadmap only | Hash chaining alone is not immutable storage |

### 3.3 Safe external claim

A supportable current statement is:

> ActantOS has a verified enforcement-kernel baseline in which Pi and MCP proof paths submit actions for deterministic decisions, high-risk actions can require one-use approval, allowed executions are token-bound, and decisions/results are correlated in Postgres-backed audit timelines.

Avoid claims such as:

- “All autonomous actions are guaranteed to be governed” without integration-boundary qualification.
- “Production-grade multi-tenant isolation.”
- “Absolute tamper-proof logging.”
- “Enterprise compliance achieved.”
- “gVisor or Firecracker is currently enforced.”

---

## 4. Architecture and Trust Boundaries

### 4.1 Current control path

```text
Agent Runtime / MCP Client
        |
        v
Guarded Adapter / ActantOS MCP Gateway
  - canonicalize and normalize
  - attach agent, user, session, resource
  - classify deterministic risk facts
        |
        v
POST /v1/intercept/tool-call
        |
        +--> idempotency
        +--> kill-switch check
        +--> budget/rate-limit check [active baseline; transactional hardening remains]
        +--> Cedar authorization
        +--> deterministic risk rules
        +--> approval-state verification
        |
        +--> deny
        +--> approval_required
        +--> allow + signed decision token
                    |
                    v
             Docker Executor
                    |
                    v
             POST /v1/tool-result
                    |
                    v
       Postgres event chain and session timeline
```

### 4.2 Core security invariant

The precise invariant should be:

> For a supported integration configured so that tool access is available only through the guarded adapter or ActantOS gateway, no governed action is executed by the reference executor without a valid ActantOS allow decision and decision token. Dependency errors must terminate the action rather than default to execution.

This wording is stronger than marketing language because it identifies the enforcement boundary and assumptions.

### 4.3 Trust model

| Component | Trust level | Main risks | Required controls |
|---|---|---|---|
| Agent/model | Untrusted | Prompt injection, hallucinated parameters, deliberate evasion | No direct credentials or tool access |
| Agent runtime | Semi-trusted | Bypass hooks, custom tools, direct shell/network | Locked tool registry, adapter integrity, process isolation |
| Guarded adapter | Trusted enforcement client | Tampering, request omission, token misuse | Signed distribution, version pinning, fail-closed contract |
| MCP client | Semi-trusted | Session theft, direct upstream access | Authenticated session, network routing restrictions |
| ActantOS gateway | Trusted | Parser errors, SSRF bypass, policy context corruption | Strict schemas, canonicalization, resolver protections |
| Policy evaluator | Trusted decision component | False permit/deny, parser/runtime bugs | Differential tests, stable evaluator, fail closed |
| Approval service | Trusted | Replay, scope escalation, approver spoofing | One-use token, TTL, scope binding, strong identity |
| Executor | High-trust / high-risk | Sandbox escape, token bypass, result forgery | Token validation, hardened runtime, minimal credentials |
| Postgres | Trusted state store | Cross-tenant reads, log rewriting, concurrency races | RLS, least privilege, backups, external evidence anchor |
| Upstream MCP server | Variable/untrusted | Tool poisoning, rug pull, data misuse | Registry, manifest pinning, scoped credentials |
| External resource | Protected target | Unauthorized mutation or exfiltration | Least privilege, target-bound credentials, audit |

### 4.4 Control-plane and data-plane separation

ActantOS should separate the planes **logically now** and **physically only where the security or scaling benefit is clear**. Prematurely splitting every module into a network service would add failure modes without automatically improving security.

#### Control plane — authoritative durable state

- Tenant, user, agent, owner, and workload identity
- Policy authoring, validation, signing, activation, and rollback
- Approval policy and durable approval state
- Budget definitions and durable consumption ledger
- Kill-switch configuration
- Audit, evidence checkpoints, retention, and export
- Administrative APIs and dashboard

#### Data plane — request-path enforcement

- Pi guarded adapter and MCP gateway
- Request authentication and normalized-context construction
- Canonicalization and deterministic risk classification
- Local call to the Cedar PDP
- Decision-token verification
- Sandbox execution and result capture
- Egress-proxy authorization and upstream routing
- Bounded caches for signed policy bundles, keys, and server manifests

#### Dedicated enforcement services

The target Design Partner Ready topology should include three small, tightly scoped enforcement components:

```text
                         CONTROL PLANE
       Identity / Policy Lifecycle / Approval / Budget / Audit
                              |
                signed bundles, keys, durable state
                              v
+------------------------------------------------------------------+
|                           DATA PLANE                              |
|                                                                  |
|  Adapter / MCP Gateway --> actantos-pdp --> Decision             |
|          |                    (Rust)          |                   |
|          |                                    v                   |
|          +--> Executor / MCP Forwarder --> Egress Proxy --> Target|
|                       |                         |                  |
|                       +------ Tool Result ------+                  |
+------------------------------------------------------------------+
```

- **`actantos-pdp`**: stateless Rust service using the pinned Cedar engine; local Unix-domain socket or loopback mTLS; no semantic overrides.
- **Executor**: ephemeral workload runner that accepts only scope-bound allow tokens.
- **Egress proxy**: the only permitted network path from governed workloads; consumes signed network grants and validates destination at connection time.

#### “Stateless data plane” qualification

The data plane should have no authoritative durable policy, tenant, approval, or audit state. It may still hold:

- In-flight request state
- Execution process handles
- Short-lived connection pools
- Signed policy/key/manifest caches
- Retry metadata bounded by request ID

All security-relevant durable transitions must be committed to Postgres or another designated authoritative store. Cache loss must reduce availability, never permit execution.

#### Migration sequence

1. Keep the current Fastify deployment but enforce module boundaries and interfaces.
2. Extract the Cedar PDP first because it removes the most critical semantic and crash coupling.
3. Add the egress proxy as a mandatory network chokepoint.
4. Separate executors when workload isolation or horizontal scaling requires it.
5. Split administrative control-plane APIs only after the interfaces and operational model are stable.

For enterprise deployments, data-plane enforcement should remain close to protected resources while policy administration may be centralized. Control-plane unavailability must not create a permissive path; deployments may either deny new actions or use explicitly bounded, signed, unexpired offline policy bundles for low-risk operations.


## 4.5 Canonical governed-action state machine

All adapters, gateways, services, workers, database rows, and audit events must use one state machine. No component may invent an implicit state.

```text
received
  -> validating
  -> evaluating
  -> denied
  -> approval_pending
  -> approval_granted
  -> authorized
  -> execution_queued
  -> execution_claimed
  -> executing
  -> executed | failed | timeout | cancelled
```

Exceptional states:

```text
authorization_expired
approval_expired
budget_reservation_expired
executor_lost
result_unknown
audit_reconciliation_required
policy_superseded
revoked_before_execution
```

### State-transition contract

Each transition must define:

- The only component allowed to perform it
- The exact required previous state
- The conditional SQL predicate
- Whether a budget reservation is created, committed, released, or expired
- Whether an approval is consumed
- The audit event written in the same transaction
- The idempotency key and retry response
- The timeout and recovery owner
- Whether a security-epoch or policy-version recheck is required

State regression is forbidden. A terminal state is immutable except for an append-only reconciliation annotation.

### Minimum transition table

| From | To | Owner | Atomic requirements |
|---|---|---|---|
| `received` | `evaluating` | Decision service | Persist canonical request and idempotency record |
| `evaluating` | `denied` | Decision service | Decision and audit commit together |
| `evaluating` | `approval_pending` | Decision service | Decision, approval row, expiry, and audit commit together |
| `approval_pending` | `approval_granted` | Approval service | Approver identity, displayed-scope hash, token hash, and audit commit together |
| `approval_granted` | `authorized` | Decision service | Consume approval, reserve budget, create allow decision, and audit atomically |
| `authorized` | `execution_queued` | Decision service | Persist immutable execution job/outbox record |
| `execution_queued` | `execution_claimed` | Executor worker | Atomic lease with owner and lease expiry |
| `execution_claimed` | `executing` | Executor worker | Revalidate token, epochs, resource binding, and constraints |
| `executing` | terminal | Result service | Result, budget settlement, job terminal state, and audit commit together |
| lease expired | `executor_lost` | Reconciler | Record uncertainty; never silently retry non-idempotent action |

## 4.6 Transactional outbox, execution leasing, and reconciliation

Authorization is a database transaction; external tool execution is not. ActantOS must not pretend these can be committed atomically.

### Transaction 1 — authorize and enqueue

Inside one PostgreSQL transaction:

1. Lock or conditionally consume the approval if required.
2. Reserve hard budget.
3. Create the allow decision and immutable token claims.
4. Create the `execution_jobs` row.
5. Create an outbox/audit event.
6. Commit.

### Worker execution

The worker:

1. Claims one job using `FOR UPDATE SKIP LOCKED` or an equivalent atomic lease.
2. Verifies lease ownership, decision token, security epochs, policy status, resource binding, and constraints.
3. Executes at most once when the operation is not safely idempotent.
4. Posts a terminal result with the job ID and execution nonce.

### Transaction 2 — settle result

Inside one PostgreSQL transaction:

1. Validate executor identity and execution nonce.
2. Move job to a terminal state.
3. Commit, release, or reconcile the budget reservation.
4. Store result hashes and redacted evidence.
5. Append the terminal audit event.
6. Commit.

### Reconciler responsibilities

A dedicated reconciler handles:

- Expired approval and budget reservations
- Expired worker leases
- Unknown results after worker failure
- Duplicate result submissions
- Stuck outbox rows
- Orphaned decisions/jobs
- Audit-chain gaps
- Mismatch between decision, execution, result, and budget ledgers

**Safety rule:** Unknown execution is never automatically retried when the action may have external side effects. It enters `result_unknown` and requires connector-specific reconciliation or human review.

## 4.7 Decision-token issuance, retries, and replay semantics

An allow response may be lost after the decision commits. Retrying the same `request_id` must not create a new decision, reservation, token lifetime, or execution opportunity.

Persist immutable token claims:

```text
decision_id
token_jti
kid
issued_at
expires_at
tenant_id
agent_id
session_id
tool_call_id
execution_job_id
execution_nonce
scope_hash
constraints_hash
policy_bundle_hash
security epochs
decision = allow
```

On idempotent retry:

- Return the existing decision.
- Recreate the same logical signed token from persisted claims or return an encrypted stored representation.
- Never extend `expires_at`.
- Never change the execution nonce.
- Never create a second budget reservation or execution job.

Executors reject:

- Reused execution nonce after a terminal result
- Missing or unknown `kid`
- Revoked key or stale security epoch
- Scope, constraint, policy, job, or resource-binding mismatch
- Token issued before a mandatory security epoch
- Expired token

## 4.8 Kill-switch and emergency revocation consistency

A kill switch must invalidate already-issued but not-yet-executed authorization.

Maintain monotonic epochs at these scopes:

```text
tenant_security_epoch
agent_security_epoch
session_security_epoch
tool_security_epoch
credential_security_epoch
```

Relevant epoch values are embedded in the allow token. Immediately before execution, the executor compares them with a trusted revocation snapshot or control-plane lookup.

Activation behavior:

- Increment the relevant epoch.
- Deny new decisions.
- Cancel queued but unclaimed jobs.
- Mark claimed jobs for immediate pre-execution rejection.
- Attempt connector-specific cancellation for actions already executing.
- Rotate or revoke credentials where possible.
- Write a high-priority audit event.

**Claim discipline:** ActantOS may claim bounded revocation before execution. It must not claim that an external side effect can always be reversed after an upstream system has accepted it.

## 4.9 Fail-closed and bounded-offline modes

### Default mode

```text
PDP, identity service, trusted revocation state, or authoritative database unavailable
-> deny all new governed actions
```

### Optional bounded-offline mode

This mode is disabled by default and requires tenant-admin opt-in. It permits only actions satisfying every condition:

- Read-only and preclassified low risk
- No credential access
- No network
- No mutation
- No approval requirement
- Signed policy bundle is valid
- Revocation snapshot is within the configured freshness window
- Security epochs are available
- Maximum offline duration has not elapsed
- Evidence is marked `decision_mode = bounded_offline`

Shell mutation, production access, external network operations, credentials, and destructive actions are never allowed offline.

## 4.10 Decision-to-execution object binding

Authorization must bind to the actual object used at execution time.

### File resources

Bind and revalidate:

- Canonical path
- Workspace/mount identity
- Device/inode where available
- File type and symlink policy
- Optional content hash for sensitive reads
- Open file descriptor or descriptor-relative path

On supported Linux hosts, use descriptor-relative operations and `openat2` resolution constraints rather than authorizing one path and reopening another.

### MCP resources

Bind:

- Server identity
- Approved manifest-version ID
- Tool schema and description hashes
- Transport and upstream endpoint
- Credential reference and audience

### Git resources

Bind:

- Repository identity
- Remote URL
- Ref/branch
- Commit SHA or expected tree state
- Exact operation

### HTTP resources

Bind:

- Scheme, host, port
- Method
- Normalized path/query policy
- Resolved destination set
- Credential reference
- Redirect policy
- Network-grant ID

Any material change requires a new decision and, when relevant, a new approval.

---


## 5. Detailed Backend and API Review

## 5.1 Decision API and orchestration pipeline

**Primary interface:** `POST /v1/intercept/tool-call`

### Responsibility

The decision API is the central Policy Enforcement Point. It validates the request, looks up runtime identity and state, produces a deterministic decision, persists evidence, and—only for an enforce-mode allow—issues a short-lived token for execution.

### Strengths

- Strict Zod/schema-oriented input design
- Opaque, retry-safe request IDs
- Explicit normalized facts rather than relying on raw command strings
- Three-way orchestration result: `allow`, `deny`, `approval_required`
- Stable machine-readable `reason_code`
- Explicit `decision_mode` for dry-run versus enforcement
- Decision tokens bound to scope and constraints
- Early kill-switch position
- Idempotency before repeated evaluation

### Material gaps

1. **Budget enforcement is active but not fully transaction-coupled.** The Postgres provider consumes configured limits and is covered by route, integration, and policy-regression tests; atomic reservation with approval/job creation and high-contention proof remain.
2. **Authentication is not yet sufficient for enterprise use.** Agent, subject, and session identity fields are context unless cryptographically authenticated.
3. **Tenant IDs are not a complete isolation boundary.** Without RLS and authenticated tenancy, they are labels, not enforcement.
4. **Policy-evaluator uncertainty can invalidate the entire decision path.** The Cedar shim must be removed.
5. **Failure-mode evidence is incomplete.** The report needs tests for DB timeout, policy timeout, malformed output, and process crash.

### Recommended improvements

- Add signed session identity with OIDC/JWKS-backed subject and agent claims.
- Implement a transaction-safe budget ledger rather than updating mutable counters without concurrency design.
- Add decision deadlines and explicit dependency failure reason codes.
- Define API version compatibility and deprecation policy.
- Generate and publish OpenAPI from the actual schemas.
- Add policy-decision explain output suitable for debugging without exposing sensitive internals.
- Add a deterministic policy-simulation endpoint isolated from enforcement.

### Acceptance gate

The component is pilot-ready when:

- No unauthenticated identity claim can influence an allow decision.
- Repeated and concurrent request IDs produce one effective decision.
- All dependency failures produce deny/error without execution.
- Decision-token claims are independently verified by the executor.
- Latency and throughput are measured under expected pilot load.

---

## 5.2 Cedar policy-decision service

**Current known module:** `src/cedar-cli-provider.ts`  
**Target component:** `actantos-pdp`

### Responsibility

The policy-decision point translates normalized ActantOS context into Cedar authorization input and returns the engine result without changing its semantics. Cedar remains responsible for authorization; risk routing, approval state, budgets, and kill switches remain orchestration concerns outside Cedar.

### Strengths of the current design

- Correct separation between authorization and workflow state
- `PolicyDecisionProvider` abstraction allows implementation replacement
- Policies consume stable normalized facts instead of raw shell text
- Default-deny behavior is understood
- Explicit safe permits are included for the proof workload

### Critical issue: compatibility shim

The current Cedar CLI path reportedly produces intermittent false denies or recursion diagnostics for logically equivalent non-credential requests. The provider contains a narrow override that preserves expected Week 1 behavior.

This is the highest-priority technical debt because application code can substitute a result for the authorization engine. No production path may convert a Cedar result into a different permit/forbid outcome.

### Evaluator architecture decision

The production recommendation is a dedicated, local **Rust Cedar PDP** rather than treating `cedar-wasm` or Node native bindings as an automatic fix.

| Option | Advantages | Risks | Recommendation |
|---|---|---|---|
| Rust PDP using official Cedar crate | Native engine integration, pinned dependency, process isolation, clear failure contract | Adds local IPC and a separately managed binary | **Preferred production path** |
| Official JavaScript/TypeScript authorization integration or WASM | Easier TypeScript packaging; no shell parsing | Runtime/package maturity, memory behavior, bundling, and semantic parity must be proven | Candidate for local/dev or production only after full conformance |
| Node N-API/Rust FFI module | Low call overhead | Native ABI lifecycle, process-crash coupling, memory-safety boundary, difficult upgrades | Secondary option if latency evidence requires it |
| Cedar CLI subprocess | Simple and transparent for development | Process overhead, output parsing, timeout/error ambiguity | Development fallback only; never with semantic override |

A direct in-process evaluator inside Fastify remains out-of-process from the agent, but it couples policy-engine crashes and memory pressure to the gateway. A small Rust PDP over a Unix-domain socket preserves the product’s out-of-agent boundary **and** creates a clearer failure-isolation boundary.

### `actantos-pdp` contract

```text
Input:
  request_id
  tenant_id
  policy_bundle_id + policy_bundle_hash
  principal / action / resource / normalized context
  evaluation_deadline

Output:
  cedar_result = permit | forbid
  determining_policy_ids
  diagnostics (bounded, non-sensitive)
  evaluator_version
  policy_bundle_hash
  evaluation_duration_us
```

Required properties:

- Loads only signed/approved policy bundles.
- Atomically swaps active bundles; never serves a partially loaded policy set.
- Returns no orchestration decision such as `approval_required`.
- Never changes a Cedar `forbid` to `permit`, or the reverse.
- Enforces request size, entity count, policy count, and deadline limits.
- Exposes readiness only after schema and bundle validation succeed.
- Fails closed on malformed input, timeout, crash, version mismatch, or bundle-hash mismatch.
- Records evaluator and bundle versions in decision evidence.

### Required verification

Create a differential and metamorphic policy corpus covering:

- Safe workspace reads
- Credential paths
- Production mutations
- Destructive actions
- Missing permits and explicit forbids
- Mixed permit/forbid cases
- Equivalent context/entity ordering
- Invalid policy and schema syntax
- Duplicate entities and extension values
- Maximum-size and adversarial requests
- Timeout, process crash, restart, and stale-bundle conditions
- Repeated evaluation across CLI, Rust PDP, and any proposed WASM/JS implementation

For each case, compare expected semantics, direct engine result, provider result, diagnostics, and repeated-run determinism.

### Migration plan

1. Freeze the existing policy/schema corpus and reproduce the shim-triggering cases.
2. Implement `RustCedarProvider` behind `PolicyDecisionProvider`.
3. Run CLI and Rust providers in shadow comparison mode with no effect on decisions.
4. Investigate every mismatch; do not whitelist unexplained differences.
5. Cut over only when the corpus and live shadow traffic show zero unexplained mismatch.
6. Remove the compatibility shim and CLI from the enforcement image.
7. Keep a separately packaged CLI diagnostic tool for operators.

### Exit gate

- Zero compatibility overrides in enforcement code.
- The Rust PDP is the sole production authorization source of truth.
- Policy corpus is deterministic over repeated runs and process restarts.
- PDP timeout/crash/unavailability produces no execution.
- Policy bundles are signed, versioned, validated, and atomically activated.
- Evaluator version, policy hash, and determining policy IDs are included in evidence.

## 5.3 Approval and authorization-resume flow

**Primary interface:** `POST /v1/approvals/{approval_id}/decide`

### Correct behavior

Approval must not bypass policy. The secure flow is:

1. Original request receives `approval_required`.
2. A random one-use approval token is generated only after authenticated approval.
3. Only a cryptographic token hash is stored.
4. The adapter creates a **new request ID** for execution resubmission.
5. It submits the prior decision ID, approval ID, token, and the exact reconstructed scope.
6. ActantOS re-runs kill-switch, identity, policy, and risk checks as required by the current bundle/version policy.
7. A single conditional database statement consumes the approval.
8. The resumed allow decision and its audit event are created in the same transaction.
9. A scope-bound decision token is issued for the executor.

### Why an atomic statement is required

A `SELECT` followed by an application-side `UPDATE` can race. The database must decide whether the approval is valid and unused at the moment of consumption.

The minimal safe condition is broader than `token_hash = $1 AND used_at IS NULL`. It must bind all relevant context:

```sql
WITH consumed AS (
  UPDATE approvals AS a
     SET used_at = now(),
         used_by_request_id = $new_request_id
   WHERE a.id = $approval_id
     AND a.tenant_id = $tenant_id
     AND a.decision_id = $prior_decision_id
     AND a.tool_call_id = $prior_tool_call_id
     AND a.status = 'approved'
     AND a.expires_at > now()
     AND a.used_at IS NULL
     AND a.scope_hash = $scope_hash
     AND a.one_use_token_hash = $submitted_token_hash
  RETURNING a.id, a.decision_id, a.tool_call_id, a.scope_hash
)
SELECT * FROM consumed;
```

No returned row means the approval is absent, wrong-scope, expired, denied, already consumed, or has the wrong token. The API should deliberately return one stable `invalid_approval` code rather than revealing which predicate failed.

### Transaction boundary

The approval consumption must occur in the same Postgres transaction as:

- Creation of the resumed `tool_calls` row
- Creation of the new `policy_decisions` allow row
- Any hard-budget reservation
- The approval-consumed audit event
- The allow-decision audit event

If the transaction rolls back, the token remains unused. After commit, retrying the same new request ID returns the existing allow decision through idempotency rather than attempting to consume the approval again.

### Strengths of the existing design

- Random token rather than deterministic derivation
- Raw token not stored
- Scope hash shared across approval, tool call, and decision token
- New request ID avoids replaying the old pending decision
- `used_at` provides one-use state
- Approval lineage is visible in the timeline

### Additional production controls

- Separate `approval_deadline` from `execution_deadline`.
- Bind approver identity to an OIDC subject, tenant, role, and approval-policy version.
- Require reason text for high-risk approvals.
- Support single approver, quorum, ordered stages, and escalation as explicit policies.
- Keep one-action scope as default; bounded temporary grants require exact action/resource limits.
- Record channel, authentication assurance, callback nonce, client metadata, and decision context.
- Store only token hashes produced by a versioned cryptographic scheme.
- Ensure the approval endpoint itself is idempotent and cannot regenerate multiple live tokens.

### Required tests

- 100–1,000 simultaneous consumers of one token: exactly one success.
- Same token with wrong tenant, request, prior decision, tool call, resource, or scope: zero successes.
- Approval and kill-switch race: kill switch wins before execution.
- Approval and policy-bundle change: behavior follows the documented reauthorization policy.
- Database disconnect between consume and decision creation: full transaction rollback.
- Retry after committed allow decision: idempotent return, no second consumption.

### Exit gate

- Exactly one concurrent resubmission can consume a token.
- Approval cannot be replayed across tenant, user, agent, session, tool, resource, or policy scope.
- Expired, denied, already-used, and mismatched approvals always deny.
- Consumption, budget reservation, resumed decision, and audit evidence are transactionally consistent.
- External approval channels are cryptographically authenticated and replay-protected.

## 5.4 Decision token, executor, and network enforcement

**Known module:** `src/docker-executor.ts`  
**Target supporting component:** mandatory egress proxy

### Responsibility

The executor verifies that ActantOS authorized the exact execution scope and constraints, launches the action in an isolated runtime, and allows network traffic only through the connection-time egress enforcement boundary.

### Strengths

- Execution requires an allow token.
- Token binds decision, tenant, agent, session, tool call, scope, constraints, and expiry.
- Expired tokens and constraint mismatches are rejected before runtime creation.
- Network mode is explicit: `none` or `egress_proxy`.
- Resource limits, read-only root, non-root user, dropped capabilities, and output limits are designed into the baseline.

### Risks

1. Docker is an MVP boundary, not sufficient for hostile multi-tenant arbitrary-code execution.
2. Workspace mounts remain exposed to symlink, ownership, executable-content, and loader attacks.
3. The Week 1 egress network is not a production destination-enforcement system.
4. HMAC key compromise permits token forgery unless key lifecycle and trust domains are constrained.
5. Executor-host compromise can bypass runtime controls or falsify results.
6. Interpreter and nested-process behavior require explicit syscall and image controls.

### Network architecture decision

Application-level URL parsing must remain, but it cannot be the final SSRF boundary. Governed workloads must have **no direct route** to arbitrary networks.

```text
Sandbox / MCP Forwarder
        |
        | only route permitted by namespace firewall
        v
ActantOS Egress Proxy
  - authenticates workload/executor
  - verifies signed network grant
  - resolves through controlled resolver
  - validates all A/AAAA/CNAME results
  - pins selected IP for the connection
  - validates Host/SNI/certificate relationship
  - rechecks every redirect
        |
        v
Approved external destination
```

Required layers:

1. **Gateway pre-check:** normalize scheme/hostname/port; reject malformed and ambiguous forms.
2. **Policy grant:** decision constraints contain destination identity, allowed protocol, port, methods, and expiry—not only a hostname string.
3. **Namespace enforcement:** nftables/iptables allows traffic only to the egress proxy and required local control endpoints.
4. **Proxy resolution:** proxy uses a controlled resolver and validates every IPv4/IPv6 result after resolution.
5. **Connection pinning:** the proxy connects to the validated IP and does not perform an uncontrolled second resolution.
6. **Redirect enforcement:** each redirect target receives a fresh grant check and resolution; downgrade and cross-host redirects deny by default.
7. **Protocol restriction:** initially support HTTP/HTTPS only; block arbitrary CONNECT, raw TCP, UDP, and DNS except explicit system paths.
8. **Observability:** log grant ID, hostname, resolved IP, SNI, port, method, status, byte counts, and denial reason without leaking secrets.

Denied destination classes must include loopback, link-local, private/ULA, cloud metadata, multicast, unspecified, benchmark/test ranges where appropriate, IPv4-mapped IPv6, and alternate numeric encodings. All DNS answers must be checked, not only the first.

A generic Envoy or Squid deployment is not sufficient by itself. The reference proxy must be configured or extended to consume ActantOS grants and must be tested for DNS cache behavior, connection reuse, redirects, HTTP CONNECT, and IPv6.

### Executor improvements

- Create a minimal, pinned sandbox image and SBOM.
- Add seccomp, AppArmor/SELinux, capability, cgroup, and filesystem tests.
- Enforce no host-home mount and explicit environment allowlist.
- Inject target-specific credentials only into the child execution context.
- Evaluate gVisor for single-tenant hosted workloads.
- Add executor workload identity and registration.
- Use key IDs and consider asymmetric tokens across separate executor trust domains.
- Bind each network grant to the decision token and execution nonce.
- Add terminal result state and attestation metadata.

### Exit gate

- Sandbox profile passes a documented escape/bypass corpus.
- No environment secret is exposed without an explicit credential reference.
- Governed workloads cannot route around the egress proxy.
- Proxy blocks the SSRF/DNS-rebinding corpus at connection time.
- Executor cannot expand network access beyond the signed grant.
- Timeout, output, PID, memory, and CPU limits are measured and enforced.
- gVisor compatibility is demonstrated before product claims are made.

## 5.5 Tool-result verification and request correlation

**Known module:** `src/tool-result-service.ts`

### Responsibility

The result service accepts execution outcomes only when the submitted decision token matches persisted decision and tool-call state. It correlates results with the same original request lineage.

### Strengths

- Executed/failed/timeout results require a token.
- Blocked results can be recorded without pretending execution occurred.
- Token claims are checked against persisted rows.
- MCP gateway now reuses the intercepted request ID rather than generating a new result request ID.
- Result hashes support compact evidence retention.

### Risks

- A compromised trusted executor can still report misleading output unless stronger attestation exists.
- Duplicate or reordered result submission semantics need explicit definition.
- Large output storage, redaction, and privacy retention require policy.
- Result hash algorithms and canonicalization must be stable and versioned.

### Recommended improvements

- Make result submission idempotent and define terminal-state transitions.
- Reject state regression, such as `executed` followed by `pending`.
- Record executor identity, sandbox image digest, policy version, and token key ID.
- Version the result-hash canonicalization format.
- Add optional signed executor receipt for distributed deployments.
- Add configurable retention classes for hashes, previews, and full encrypted payloads.

---

## 5.6 Hash-chain audit and session events

**Known module:** `src/session-events.ts`

### Responsibility

The audit layer records decisions, approvals, results, and security actions in a per-tenant sequence whose event hash includes the previous hash. The session timeline exposes operator-relevant context.

### Strengths

- Per-tenant sequence is persisted.
- Audit-chain writes serialize through `audit_chain_state`.
- Canonical JSON is required before hashing.
- Sequence is stored in event rows for independent recomputation.
- Session events include request, tool, decision, risk, approval, and result hash.
- Approval-resume lineage is recoverable.

### Important qualification

A database hash chain is **tamper-evident under a trust assumption**, not absolutely immutable. An attacker with sufficient database and application control may rewrite events and chain state unless an external trusted anchor exists.

### Recommended improvements

- Build an independent audit verifier CLI.
- Export signed chain checkpoints to external storage.
- Add S3 Object Lock or equivalent WORM only after retention/account-separation design is complete.
- Keep audit administration separate from application administration.
- Define redaction before persistence, not only at export.
- Add per-event schema version and hashing algorithm version.
- Test recovery, gaps, duplicate sequences, and corrupted rows.
- Add periodic checkpoint signatures using a managed key.

### Exit gate

- A fresh verifier can validate the event chain using exported data alone.
- Tampering produces a detectable and attributable verification failure.
- Chain checkpoints exist outside the mutable primary database.
- Redaction and retention policies pass privacy and security review.

---

## 5.7 MCP gateway, manifest lifecycle, and egress boundary

### Responsibility

The MCP gateway is the strategic cross-runtime enforcement point. It mediates client access to upstream servers, filters discovery, intercepts calls, authenticates server/tool identity, obtains policy decisions, routes permitted calls through the egress boundary, and records evidence.

### Current strengths

- Live upstream SSE proof is reported.
- `tools/list` and `tools/call` proof paths are exercised.
- Request correlation persists across decision and result records.
- First-seen manifest establishes a baseline.
- Drifted schema or description creates a pending version and fails closed.
- Admin approval can promote a pending version.
- Basic blocked URL classes are checked before policy evaluation.

### Security gaps

1. Basic URL blocklists do not prevent rebinding, connection-time changes, or direct-route bypass.
2. Upstream server identity and credentials are not yet enterprise-grade.
3. Tool hashing authenticates content only when the server identity and registry are trusted.
4. Prompt, resource, sampling, callback, and cancellation surfaces need explicit policies.
5. Direct client-to-upstream connections must be prevented by deployment networking.
6. Streaming and duplicate-delivery behavior must be reconciled with idempotency and audit.

### Target MCP request path

```text
MCP Client
   -> authenticated ActantOS session
   -> registry-approved server identity
   -> policy-filtered tools/list
   -> tools/call normalization
   -> Cedar PDP + risk/approval/budget pipeline
   -> signed upstream/network grant
   -> MCP forwarder through egress proxy
   -> result hash and evidence
```

### Required controls

- Register each upstream server with tenant, transport, endpoint identity, owner, and credential reference.
- Sign the approved registry configuration and manifest baseline.
- Filter `tools/list` before returning it to the client.
- Fail closed on tool name/schema/description/server identity drift.
- Never pass raw user OAuth tokens to arbitrary upstream servers.
- Use server-specific credentials bound to tenant, agent, session, target, audience, action, and TTL.
- Route all network MCP transports through the egress proxy.
- Apply the same destination validation to initial requests, redirects, callbacks, and server-provided URLs.
- Disable sampling and server-to-client callbacks until their policy and consent model is implemented.
- Surface the complete model-visible tool description in admin review to detect hidden instructions.
- Define cancellation, retries, duplicate responses, streaming partial results, and timeout semantics.

### Exit gate

- A supported MCP client only sees authorized tools.
- Manifest or server-identity drift fails closed.
- The SSRF/rebinding suite passes through the actual proxy path.
- Reference deployments prevent direct upstream routes.
- No end-user token is forwarded to an untrusted upstream.
- Duplicate/cancelled/streamed calls reconcile to one auditable request lineage.

## 5.8 Budget, rate-limit, and reservation architecture

### Distinguish three kinds of control

| Control | Required consistency | Recommended initial store |
|---|---|---|
| Hard safety budget: actions, shell seconds, protected mutations, monetary cap | Durable and transactionally coupled to authorization | **Postgres authoritative ledger** |
| High-throughput request rate limit | Atomic and low latency; short-lived state | Redis Lua/Functions or Redis 8.8 atomic counter where justified |
| Usage telemetry and analytics | Eventual consistency acceptable | Audit/event pipeline |

A Redis Lua script is an appropriate rate-limiting mechanism because the read/branch/write operation executes atomically. It should not automatically replace Postgres as the source of truth for hard budgets that must reconcile with decisions and audit evidence.

### Postgres reservation model

A hard budget should be reserved before an allow decision, then committed or released when the result is known.

```text
available = limit - committed - reserved

intercept:
  atomic reserve estimated_cost if available >= estimated_cost
  -> reservation_id included in decision token

tool result:
  commit actual_cost
  release unused reservation

blocked / expired / never executed:
  release reservation by timeout/reaper
```

Example conditional update:

```sql
UPDATE budgets
   SET reserved_value = reserved_value + $estimated_cost,
       updated_at = now()
 WHERE tenant_id = $tenant_id
   AND scope_type = $scope_type
   AND scope_id = $scope_id
   AND metric = $metric
   AND window_start = $window_start
   AND committed_value + reserved_value + $estimated_cost <= limit_value
RETURNING id, committed_value, reserved_value, limit_value;
```

The reservation, allow decision, and audit event belong in one database transaction. A missing returned row means `budget_exceeded`.

### Redis role at scale

Redis may become the authoritative mechanism for short-window request throttling, provided:

- The script/function is versioned and loaded at startup.
- All cluster keys use a compatible hash slot.
- Redis failure has an explicit fail-closed/fallback policy.
- Hard budgets still reconcile against Postgres.
- Rate-limit decisions carry the rule/version and are auditable.
- Clock/window semantics are tested across failover.

For DPR, keep the architecture minimal: Postgres for hard budgets; Redis only if measured load demonstrates need.

### Exit gate

- Concurrent requests cannot exceed a hard budget.
- Reservation leakage is recovered deterministically.
- Result retries cannot double-commit cost.
- Redis failure cannot create an unlimited execution path.
- Budget and decision records reconcile in the audit verifier.


## 5.9 Policy lifecycle and safe activation

Policies are executable security configuration. Production policy changes require this lifecycle:

```text
draft
-> parse
-> schema validation
-> unit corpus
-> negative corpus
-> historical-event simulation
-> impact report
-> independent approval
-> sign bundle
-> stage
-> canary/shadow evaluation
-> activate atomically
-> monitor
-> rollback or promote
```

Required controls:

- No direct editing of an active bundle
- Author and production approver separation
- Mandatory deny-path and default-deny tests
- Signed bundles with monotonic versions and trusted signer IDs
- Atomic active-version pointer update
- Maximum decision-delta thresholds during canary
- Emergency deny-only bundle path
- Rollback protection against unauthorized downgrade
- Explicit handling of outstanding approvals and unexecuted decisions after policy change

Default rule: approval resubmission evaluates under the current active policy. High-risk unexecuted allows are invalidated when an emergency policy epoch changes.

## 5.10 Human approval: “what is shown is what executes”

An approval is valid only for the exact canonical representation displayed to the approver.

The approval surface must display:

- Tenant, environment, agent, human owner, and session
- Canonical tool and operation
- Exact normalized command and argument list
- File diff or structured mutation preview
- Repository, remote, branch/ref, and commit where relevant
- Network method, destination, and redirect policy
- Credential class/reference without exposing the secret
- Resource scope, risk class, policy reason, and budget impact
- One-action versus time-bounded grant scope
- Expiry and approval nonce

The signed `approval_display_hash` covers the canonical displayed object. The resumed request must produce the same hash.

Required adversarial tests:

- Truncated or hidden arguments
- Unicode confusables and bidirectional controls
- Control characters
- Oversized previews
- Changed file diff
- Changed Git commit or remote
- Changed destination
- MCP description/manifest changes after approval

## 5.11 Evidence immutability, privacy, and deletion

Separate structural evidence from sensitive content.

### Immutable structural evidence

May contain:

- Event ID and timestamp
- Tenant-scoped pseudonymous identity references
- Policy/version hashes
- Decision, reason code, approval reference
- Tool/resource type
- Result hash
- Redaction metadata
- Chain and checkpoint hashes

### Encrypted, retention-controlled content

Store separately:

- Raw request arguments
- Output previews
- Full outputs
- Human-entered reasons
- Diffs
- PII and potential secrets

Requirements:

- Redact before persistence
- Tenant-scoped envelope-encryption keys
- Field-level retention classes
- Cryptographic erasure procedure
- Legal-hold rules
- Data-residency metadata
- Backup and WORM inclusion policy
- No raw secrets or complete tool output in WORM by default

## 5.12 Trusted software supply chain

Trusted ActantOS components include the adapter, gateway, PDP, executor, migrations, policy bundles, and release installer.

Controls begin in `v0.2.0`:

- Dependency lockfiles and pinned base-image digests
- SBOM for each released component
- Signed images, binaries, packages, policy bundles, and provenance
- Protected CI/release workflows
- Two-person release approval
- Secret, dependency, license, and container scanning
- Vulnerability remediation SLA
- Startup verification of expected artifact digests
- Runtime audit records include PDP, adapter, executor, image, policy, and migration versions

Release evidence should follow an incremental SLSA-aligned provenance program rather than making unsupported certification claims.

---


## 6. AI Agent Workflow Review

## 6.1 Pi guarded adapter workflow

**Known modules:**

- `packages/pi-adapter/src/guarded_read.ts`
- `packages/pi-adapter/src/guarded_bash.ts`

### Intended sequence

```text
Pi tool invocation
  -> adapter validates input
  -> canonical path / static argv normalization
  -> derive deterministic risk facts
  -> send interception request
  -> deny: raise guarded error
  -> approval_required: pause and expose approval reference
  -> allow: verify/use constraints and execute through reference executor
  -> submit result
  -> return safe output to Pi
```

### Strengths

- Path canonicalization is considered before decision and immediately before use.
- Credential-like file access is always denied rather than sent to approval.
- Shell commands prefer direct argv execution rather than `shell=true`.
- Ambiguous shell expressions are treated as high risk.
- Network mode is decision-controlled.

### Main bypass questions

Before production, the team must prove:

- Built-in unguarded tools are disabled.
- User shell shortcuts cannot bypass wrappers.
- Extensions cannot register a later unguarded tool with the same capability.
- Direct process/network APIs are not exposed elsewhere in the runtime.
- Custom tools follow the same interception contract.
- Adapter failure cannot fall back to native Pi execution.

### Required improvements

- Publish a supported Pi-version compatibility matrix.
- Sign and checksum adapter packages.
- Add an adapter self-test that confirms native risky tools are disabled.
- Expose health state that clearly indicates enforcement is active.
- Fail session startup when the adapter cannot establish the control path.
- Add contract tests for each supported guarded tool.
- Capture diff evidence for write/edit operations.

---

## 6.2 MCP governed workflow

### Intended sequence

```text
MCP client initializes through ActantOS
  -> session identity bound
  -> upstream server selected from registry
  -> tools/list filtered by policy and approved manifest
  -> client invokes tools/call
  -> arguments normalized
  -> SSRF and identity checks
  -> ActantOS decision pipeline
  -> optional approval
  -> forward with scoped server credential
  -> collect result
  -> verify/correlate result
  -> audit and return response
```

### Strengths

- Strategically broader than the Pi integration.
- Manifest hashing addresses tool poisoning and rug-pull changes.
- Policy-filtered discovery reduces overbroad tool exposure.
- Shared request correlation strengthens audit quality.

### Main workflow risks

- Long-lived MCP sessions may outlive user authorization.
- A tool can change behavior without changing schema or description.
- Malicious output can influence later model actions.
- Cancellation, retries, and duplicate calls can cause repeated side effects.
- Upstream server compromise can abuse scoped credentials.

### Required improvements

- Reauthenticate/reauthorize long-lived sessions.
- Add server software/artifact identity when available.
- Treat output as untrusted and apply output-size, content, and redaction policies.
- Define idempotency behavior for mutating upstream calls.
- Add short-lived, audience-bound upstream credentials.
- Record cancellation and timeout outcomes as first-class audit events.

---

## 7. Technical Debt and Risk Register

### Priority definitions

- **P0:** Blocks secure production use or can invalidate the enforcement guarantee.
- **P1:** Required for reliable pilots and enterprise self-hosting.
- **P2:** Important product quality, scale, or maintainability improvement.
- **P3:** Future optimization or conditional expansion.

### 7.1 P0 — security and correctness

| ID | Issue | Impact | Canonical remediation | Exit evidence |
|---|---|---|---|---|
| P0-01 | CLI compatibility shim can override Cedar result | Core authorization source of truth is compromised | Dedicated Rust `actantos-pdp`; signed bundles; shadow differential cutover; remove shim and CLI from enforcement image | Zero unexplained mismatch; no override code; PDP crash fails closed |
| P0-02 | Identity context is not cryptographically authenticated | Agent/user/session claims can be spoofed | OIDC/JWKS user identity, workload identity for adapters/executors, audience/session binding | Forged, stale, wrong-audience, and cross-session tokens rejected |
| P0-03 | Tenant ID is not database-enforced isolation | Cross-tenant read/write or policy leakage | Tenants model, Postgres RLS with `FORCE RLS`, non-owner runtime role, transaction-local tenant context | Automated cross-tenant suite and migration-policy coverage pass |
| P0-04 | Fail-closed behavior lacks complete chaos evidence | Dependency failure may produce undefined or permissive behavior | Fault injection for PDP, DB, Redis if used, executor, proxy, upstream, and key service | Zero execution without a committed allow decision and valid token |
| P0-05 | URL filtering is not a connection-time egress boundary | DNS rebinding, IPv6, redirects, metadata/internal service access | Mandatory egress proxy, namespace deny-all, controlled resolver, IP validation/pinning, redirect reauthorization | Full SSRF/rebinding corpus passes through real proxy path |
| P0-06 | Direct integration bypass is not fully proven | Agent or MCP client can avoid ActantOS | Disable native tools, signed adapter self-test, egress routing restrictions, upstream firewall | Reference deployments show no alternate tool or upstream path |
| P0-07 | Approval consumption is not yet proven transactionally atomic | Token double-use or inconsistent resumed decision | Single conditional `UPDATE ... RETURNING` plus resumed decision/budget/audit in one transaction | Exactly one winner across stress tests; rollback leaves token unused |
| P0-08 | HMAC key lifecycle not production-defined | Token forgery or unverifiable rotation after key compromise | KMS/HSM-backed keys, `kid`, overlap window, revocation, executor trust-domain analysis | Rotation, revocation, stale-key, and compromise drills pass |
| P0-09 | Audit chain lacks an external trust anchor | Privileged rewrite can reconstruct local history | Signed periodic checkpoints and WORM/external anchor with independent verifier | Historical mutation detected against external checkpoint |
| P0-10 | Hard budgets are inactive and lack reservation semantics | Runaway loops and overspend under concurrency | Postgres atomic reserve/commit/release ledger; Redis only for measured short-window rates | Concurrent requests stay within cap; retries do not double charge |
| P0-11 | Control/data plane boundaries are only conceptual | State leakage and failure coupling complicate security claims | Logical module contracts now; extract PDP and egress proxy first; keep durable state centralized | Component failure matrix and interface conformance suite pass |
| P0-12 | No canonical action state machine and dual-write recovery model | Crashes can consume approvals or budgets without a known execution outcome | Canonical states, execution jobs, transactional outbox, leases, terminal reconciliation | Crash-at-every-step suite produces no silent state or unsafe automatic replay |
| P0-13 | Token retry, issuance, and execution nonce semantics are incomplete | Lost responses can mint extra authorization windows or duplicate execution | Persist immutable claims, fixed expiry, stable JTI/nonce, idempotent response reconstruction | Retry never extends TTL, reserves twice, or creates a second job |
| P0-14 | Kill-switch propagation to issued tokens is undefined | A previously allowed action may execute after emergency revocation | Monotonic security epochs and pre-execution epoch validation | Issued-but-unexecuted actions are rejected after epoch increment |
| P0-15 | Decision-to-execution resource drift | Authorized object may differ from the object actually used | Resource identity binding and immediate pre-execution revalidation | File, MCP, Git, and HTTP drift corpus denies or requires a new decision |
| P0-16 | Offline behavior is ambiguous | Availability workarounds may become fail-open paths | Default deny plus tightly bounded, explicit read-only offline mode | Offline tests prove no credential, network, mutation, prod, or approval action executes |
| P0-17 | Unsafe policy activation lifecycle | Bad policy can create mass unsafe permits or operational outage | Validate, simulate, approve, sign, canary, atomically activate, and rollback | Historical replay and canary delta gates pass |
| P0-18 | Approval display may not exactly match execution | Approver can be misled by summaries or post-approval changes | Canonical display object and signed `approval_display_hash` | WYSIWYE adversarial suite passes |

### 7.2 P1 — pilot and enterprise readiness

| ID | Issue | Recommended action |
|---|---|---|
| P1-01 | No stable installer and upgrade path | Build signed packages, Compose bundle, migration tool, rollback procedure |
| P1-02 | Policy lifecycle is incomplete | Draft, validate, simulate, approve, activate, rollback, and audit bundles |
| P1-03 | No complete operational telemetry | Metrics, traces, structured logs, alerts, dashboards, SLOs |
| P1-04 | Backup and restore unverified | Automated backups and restore drills with RPO/RTO measurements |
| P1-05 | Approval channels not integrated | Slack/Teams adapters with signed callbacks and identity binding |
| P1-06 | gVisor not validated | Compatibility, performance, and failure tests on target workloads |
| P1-07 | Credential injection remains basic | Pluggable short-lived credential provider and target binding |
| P1-08 | API compatibility policy absent | Semantic versioning, OpenAPI, deprecation and migration guarantees |
| P1-09 | Audit access and export authorization are incomplete | Role/tenant-scoped audit queries, export approval, rate limits, and export audit events |
| P1-10 | Operator runbooks incomplete | Installation, incident, key rotation, policy rollback, recovery guides |
| P1-11 | Evidence retention, privacy, and deletion are incomplete | Separate immutable structural evidence from encrypted content; define retention and erasure |
| P1-12 | Release supply-chain assurance is incomplete | Signed artifacts, SBOM, provenance, pinned digests, protected release workflow |
| P1-13 | Capacity envelope and numeric release gates are absent | Freeze representative workloads and p50/p95/p99, throughput, contention, and soak thresholds |
| P1-14 | External security review occurs too late | Stage focused reviews after authorization and tenant/network milestones |

### 7.3 P2 — maintainability and product experience

| ID | Issue | Recommended action |
|---|---|---|
| P2-01 | Frontend styling/configuration ambiguity | Remove stale shadcn/Tailwind configuration or adopt it consistently |
| P2-02 | Potential layout-animation cost | Profile before changing; optimize based on measured traces |
| P2-03 | Third-party iframe hardening | Minimum sandbox permissions, CSP `frame-src`, referrer policy |
| P2-04 | Unused components and exports | Verify with TypeScript/ESLint/knip, then remove |
| P2-05 | Raw internal anchor navigation | Use framework routing where appropriate |
| P2-06 | `flushSync` usage needs justification | Profile and document; replace only if it causes measurable issues |
| P2-07 | Dashboard is demo-oriented | Build role-aware operational views and evidence export |
| P2-08 | Documentation can drift | Generate API and dashboard data from canonical schemas where possible |

### 7.4 P3 — conditional future work

- Firecracker multi-tenant execution tier
- Cryptographic memory governance
- Advanced policy marketplace
- Multi-region control plane
- Decentralized approval or policy consensus
- Broad compliance automation packs

These should not displace P0/P1 work.

---

## 8. Security Posture

### 8.1 Current security strengths

- Out-of-process control boundary
- Fail-closed design intent
- Deterministic authorization rather than LLM-as-judge
- Normalized structured facts
- Scope-bound decision tokens
- One-use approval tokens
- Explicit kill switch
- Manifest drift detection
- Basic SSRF denial
- Docker resource and network constraints
- Result-token verification
- Hash-chained event history

### 8.2 Highest residual risks

1. Authorization-engine reliability
2. Identity and tenant spoofing
3. Integration bypass
4. Sandbox escape or credential exposure
5. SSRF and upstream credential misuse
6. Approval-channel compromise
7. Audit rewriting by privileged actors
8. Operational failure and unsafe recovery
9. Policy misconfiguration
10. Unbounded or duplicated mutating actions

### 8.3 Required threat-model scenarios

The formal threat model should include at least:

- Prompt injection asks the agent to read `.env`.
- Agent changes command syntax to evade risk classification.
- Symlink target changes between policy check and execution.
- MCP server changes tool description after approval.
- Tool URL resolves to public IP during check and private IP during connect.
- Attacker reuses an approval token with another resource.
- Two workers consume the same approval simultaneously.
- Executor submits a result for another decision.
- ActantOS daemon becomes unavailable mid-call.
- Database is unavailable after decision but before audit commit.
- Policy bundle changes during a long-running session.
- Compromised admin attempts to rewrite event history.
- Agent tries direct network access around the gateway.
- Customer token is forwarded to the wrong MCP server.
- Tenant A queries Tenant B’s sessions or policies.

### 8.4 Marketing claim discipline

Use precise claims:

| Avoid | Use instead |
|---|---|
| “Absolute security” | “Deterministic pre-execution policy with documented trust assumptions” |
| “Tamper-proof logs” | “Hash-chained, independently verifiable audit evidence; WORM anchoring planned” |
| “All agent actions governed” | “Supported integrations fail closed when configured as the exclusive tool path” |
| “Compliance guaranteed” | “Produces runtime evidence that can support governance and audit programs” |
| “Firecracker sub-millisecond startup” | “Firecracker is under evaluation for a future multi-tenant isolation tier” |

---

## 9. Operational Readiness Review

### 9.1 Missing production capabilities

The following are necessary before production qualification:

- Authenticated administrators and agents
- Tenant isolation and RLS
- Database backup and tested restore
- Policy and schema migrations with rollback
- Key rotation and secret management
- Service health and dependency readiness
- Metrics, logs, traces, and alerting
- Capacity and performance benchmarks
- Incident response and forensic export
- Deployment upgrades without enforcement gaps
- HA and failover model
- Dependency pinning and SBOM
- Vulnerability scanning and patch process
- Support and compatibility policy


### 9.2 Capacity envelope and SLO framework

Before each release candidate, freeze a representative workload envelope:

```text
policies and entities per tenant
policy-bundle size
requests per second and burst
concurrent sessions and approvals
MCP servers and tools
audit events per day
maximum request/result size
database and proxy topology
decision deadline
```

Measure:

- PDP p50/p95/p99 and timeout rate
- End-to-end decision p50/p95/p99
- Sustained and burst throughput
- Database lock/contention and audit-chain throughput
- Proxy DNS and connection-setup latency
- Executor startup and queue latency
- Approval-resume latency
- Recovery after dependency restart
- Noisy-neighbor impact across tenants

Targets are frozen in each release candidate’s evidence package. A target may not be invented after test results are known.

| SLI | Required pilot property |
|---|---|
| Fail-closed correctness | 0 execution without committed allow decision, valid token, and current epochs |
| Audit correlation completeness | 100% governed executions link request, decision, job, budget, and terminal result |
| Approval replay | 0 successful replay or double-consumption |
| Cross-tenant access | 0 successful unauthorized operation |
| Manifest/object drift | 100% material unapproved drift denied |
| Recovery | RPO/RTO measured through real restore and failover drills |
| Upgrade safety | No enforcement gap during upgrade or rollback |
| Reconciliation | All stuck/unknown jobs reach an explained terminal or review state |

### 9.3 Staged external security review

External review is progressive:

1. **After v0.2.0:** authorization semantics, tokens, approval/budget transactions, state/outbox model.
2. **After v0.3.1:** identity, RLS, security epochs, egress proxy, SSRF, resource binding.
3. **Before production data in design-partner workflows:** targeted penetration test.
4. **Before v1.0:** full architecture, source, deployment, and operational assessment.

Critical findings block progression to the next maturity label.

### 9.4 Release evidence package

Every release should contain:

```text
release version and maturity label
commit SHA and dependency lockfiles
OpenAPI/schema snapshot
policy bundle and hash
migration list
SBOM and vulnerability scan
unit/integration/E2E results
fault-injection results
performance results
threat scenarios covered
known limitations
upgrade and rollback instructions
audit event samples and verifier output
reviewer/approver sign-off
```

---



## 10. Versioned 12–15 Month Production Roadmap

The roadmap starts from the EKV baseline on **July 12, 2026**. Dates are planning windows, not promises. A version ships only when all evidence gates pass.

### Dependency chain

```text
v0.2.0 state/authorization integrity
  -> v0.3.0 authenticated identity and RLS
  -> v0.3.1 mandatory network boundary
  -> v0.4.0 MCP design-partner package
  -> v0.5.0 enterprise self-host operations
  -> v0.7.0 credentials and ecosystem
  -> v1.0.0 production qualification
```

## v0.2.0 — Authorization and Transactional Integrity

**Target window:** July–August 2026  
**Primary owner:** Enforcement-kernel lead  
**Required reviewers:** Policy/Cedar reviewer, database-security reviewer, release-security reviewer  
**Goal:** Establish one authoritative state machine and remove ambiguity from policy, tokens, approvals, budgets, execution jobs, and evidence.

### Entry criteria

- EKV behavior is reproduced at a fixed commit.
- Test logs, images, lockfiles, policy bundle, and environment are captured.
- Cedar shim-triggering cases are reproducible.
- Existing request, decision, approval, result, and audit schemas are frozen as the migration baseline.

### Deliverables

- Canonical governed-action state machine and database transition constraints
- `execution_jobs`, transactional outbox, worker leasing, and reconciler
- Cedar evaluator ADR and conformance benchmark
- Preferred `actantos-pdp` implementation using a pinned Cedar engine
- Signed/versioned policy bundles and safe activation lifecycle
- Removal of CLI semantic override after shadow parity
- Immutable token claims, stable retry behavior, `kid`, JTI, execution nonce, and security epochs
- Atomic approval consumption, hard-budget reservation, resumed decision, job creation, and audit transaction
- Hard-budget reserve/commit/release/expiry model in PostgreSQL
- Independent audit and ledger verifier
- Initial SBOM, signed artifacts, and release provenance
- Generated OpenAPI and stable reason-code contract

### Security and correctness gates

- Cedar result is never semantically overridden.
- Zero unexplained differential mismatch remains across the approved corpus.
- Crash at every transaction/worker boundary produces a known reconcilable state.
- Exactly one approval consumer and one execution job win.
- Retry never extends token expiry or duplicates a reservation/job.
- Issued tokens reject scope, constraint, job, epoch, policy, key, nonce, and resource mismatch.
- Hard budgets cannot exceed the declared cap in the tested concurrency envelope.
- Unsigned trusted components fail release verification.

### Non-goals

- OIDC/SCIM
- Production multi-tenancy
- Broad MCP connector catalog
- Mandatory gVisor
- Redis as authoritative budget store
- Bounded-offline execution
- Firecracker

### Exit evidence

- Fixed commit, policy hash, migration version, and artifact digests
- Unit, integration, concurrency, crash-point, and replay logs
- PDP ADR, benchmark, differential, and failure-isolation report
- State-machine invariant and reconciliation report
- Approval/budget/outbox stress report
- Audit verifier output
- SBOM, signatures, and provenance
- Focused authorization/transaction external or independent review

## v0.3.0 — Authenticated Identity and Tenant Boundary

**Target window:** September 2026  
**Primary owner:** Identity/tenancy lead  
**Required reviewers:** IAM reviewer, PostgreSQL/RLS reviewer, application-security reviewer  
**Goal:** Make tenant, user, agent, executor, and approver identities cryptographically trustworthy and database-enforced.

### Entry criteria

- v0.2.0 gates pass.
- Token claims and security-epoch model are stable.
- Every tenant-scoped table and API route is inventoried.
- Runtime, migration, backup, and administration database roles are defined.

### Deliverables

- OIDC/JWKS user and administrator authentication
- Workload identity for adapters, gateways, PDP clients, and executors
- Issuer, audience, tenant, session, workload, and purpose binding
- `tenants`, memberships, groups, and role model
- PostgreSQL RLS on every tenant-scoped table
- `ENABLE` and `FORCE ROW LEVEL SECURITY`
- Non-owner runtime roles without `BYPASSRLS`
- Transaction-local tenant context
- `USING` and `WITH CHECK` policies
- Connection-pool reset and isolation controls
- Administration/migration/backup role separation
- Security-epoch service and emergency-revocation propagation

### Security and correctness gates

- Forged, expired, wrong-issuer, wrong-audience, wrong-session, and wrong-workload tokens are rejected.
- Cross-tenant read, insert, update, delete, export, audit, policy, and approval tests pass.
- Request-body identity cannot override authenticated identity.
- Connection pooling cannot leak tenant state.
- Table ownership and backup roles are documented and tested.
- Issued-but-unexecuted authorization is rejected after epoch increment.

### Non-goals

- SCIM
- Multiple enterprise IdPs
- Managed SaaS tenancy
- Network egress redesign
- Advanced approval quorum

### Exit evidence

- Identity threat-test report
- RLS policy inventory and migration coverage
- Database-role and connection-pool tests
- Cross-tenant adversarial suite
- Emergency-revocation drill
- Independent identity/RLS review

## v0.3.1 — Mandatory Network Enforcement Boundary

**Target window:** October 2026  
**Primary owner:** Runtime/network-security lead  
**Required reviewers:** Infrastructure-security reviewer, protocol reviewer, penetration tester  
**Goal:** Ensure governed network access is constrained at connection time, not only classified in application code.

### Entry criteria

- v0.3.0 gates pass.
- Gateway and executor workload identities are available.
- Network-grant claims and HTTP/MCP object-binding schemas are frozen.
- Reference deployment topology identifies every possible direct route.

### Deliverables

- Mandatory authenticated egress proxy
- Deny-all direct egress from gateway and sandbox namespaces
- Signed network grants bound to decision, job, identity, protocol, method, host, port, and expiry
- Controlled DNS resolver
- IPv4/IPv6 private, loopback, link-local, multicast, and metadata denial
- Connection-time IP validation and pinning
- Host/SNI validation
- Redirect and CONNECT reauthorization
- Network-grant and proxy audit records
- Proxy outage and stale-grant behavior
- HTTP resource binding and drift tests

### Security and correctness gates

- No direct route to upstream services exists in the reference deployment.
- DNS rebinding, redirect, alternate-IP, IPv6, metadata, and proxy-bypass corpus passes.
- Proxy cannot forward an untrusted end-user token.
- Destination drift requires a new decision.
- Proxy, resolver, identity, or grant failure denies.
- Network audit records reconcile with decision and execution jobs.

### Non-goals

- General-purpose enterprise service mesh
- Customer-managed arbitrary proxy plugins
- Broad DLP inspection
- Offline network access

### Exit evidence

- Network topology and firewall proof
- Proxy configuration and signed-grant examples
- SSRF/rebinding/redirect test report
- Proxy fault-injection report
- Network latency and capacity baseline
- Focused network-boundary assessment

## v0.4.0 — MCP Design Partner Ready

**Target window:** November–December 2026  
**Primary owner:** MCP/integration lead  
**Required reviewers:** MCP protocol reviewer, product-security reviewer, design-partner operator  
**Goal:** A design partner deploys one governed MCP or Pi workflow without changing ActantOS core.

### Entry criteria

- v0.3.1 gates pass.
- Supported MCP transports and protocol versions are explicitly selected.
- Connector idempotency/cancellation matrix is documented.
- One candidate design-partner workflow is threat-modeled.

### Deliverables

- Authenticated MCP server registry
- Policy-filtered `tools/list`
- Manifest version, diff, promotion, rollback, and rug-pull handling
- Exact tool/server/object binding before forwarding
- Connector-specific idempotency, cancellation, and unknown-result semantics
- Short-lived audience-bound credential-reference abstraction
- Signed CLI/package installer and Compose reference deployment
- Dry-run onboarding and policy simulation
- WYSIWYE approval UI
- Minimal role-aware dashboard
- Operator, incident, privacy, and reconciliation runbooks

### Product gates

- Two design partners install from documentation.
- At least one real workflow per partner is governed end-to-end.
- No partner-specific core fork exists.
- Time to first governed action, coverage, denial quality, and approval burden are measured.

### Security and correctness gates

- Unapproved server, tool, or manifest change denies.
- Direct upstream MCP route is blocked.
- WYSIWYE adversarial tests pass.
- Unknown external outcome enters reconciliation rather than automatic unsafe retry.
- Raw end-user credentials never reach arbitrary MCP servers.
- Targeted authorization/identity/network/MCP assessment has no unresolved critical issue.

### Non-goals

- Hundreds of connectors
- Full SCIM
- Multi-region control plane
- Arbitrary multi-tenant code execution
- Natural-language policy as source of truth

### Exit evidence

- Reproducible installer and upgrade logs
- 24-hour protocol/workflow soak test
- Design-partner onboarding report
- MCP manifest and object-drift corpus
- Credential and cancellation tests
- Signed DPR evidence package and partner acceptance

## v0.5.0 — Enterprise Self-Host Ready

**Target window:** January–March 2027  
**Primary owner:** Platform-operations lead  
**Required reviewers:** SRE reviewer, enterprise-security reviewer, customer operator  
**Goal:** Operate ActantOS reliably inside a customer-controlled environment.

### Entry criteria

- DPR evidence package is accepted.
- Real pilot workload envelope is measured.
- Backup, restore, upgrade, and rollback objectives are approved.
- Observability data classification is defined.

### Deliverables

- HA reference architecture
- Backup, restore, migration, and rollback automation
- Slack and Teams approvals with signed callbacks and identity binding
- Policy lifecycle UI, simulator, canary, and rollback
- Audit checkpoints and privacy-safe export
- Metrics, traces, structured logs, alerts, and SLO dashboards
- Capacity envelope and representative load profiles
- Optional hardened gVisor profile after compatibility benchmark
- Signed upgrades and rollback verification
- Vulnerability management and patch SLA

### Security and correctness gates

- Dependency and node failures do not fail open.
- Approval channels pass identity, replay, display-binding, and expiry tests.
- Upgrade and rollback never create an enforcement gap.
- Backup/restore preserves or explicitly reconciles evidence and security epochs.
- Pilot workload meets frozen latency, throughput, contention, and soak thresholds.

### Non-goals

- Managed multi-region SaaS
- Firecracker by default
- Broad compliance certification claims
- Unbounded log retention

### Exit evidence

- RPO/RTO and disaster-recovery drill
- HA/failover and upgrade/rollback report
- Capacity, noisy-neighbor, and endurance results
- Targeted penetration test
- Operator acceptance and runbook exercise
- ESR release evidence package

## v0.7.0 — Credentials, Ecosystem, and Enterprise Integration

**Target window:** April–June 2027  
**Primary owner:** Enterprise-integration lead  
**Required reviewers:** Cloud/IAM reviewer, privacy reviewer, SDK maintainer  
**Goal:** Integrate ActantOS into enterprise identity, secret, evidence, and observability systems.

### Entry criteria

- ESR gates pass.
- `CredentialProvider` threat model and interface are stable.
- Pilot demand justifies each selected provider and adapter.
- Privacy/retention model is operational.

### Deliverables

- Pluggable `CredentialProvider`
- AWS STS first implementation; Azure/GCP/Vault-compatible contract
- Short-lived target, audience, action, agent, session, and tenant binding
- SCIM and multiple-IdP federation in enterprise tier
- S3 Object Lock or equivalent structural-evidence export
- Splunk and Datadog integrations
- Stable TypeScript and Python SDKs
- Additional runtime adapters based on customer evidence
- Advanced approval quorum and bounded grants
- Privacy/retention administration

### Security and correctness gates

- Raw end-user credentials never reach arbitrary tools.
- Credentials cannot be replayed across target, audience, action, session, or tenant.
- WORM structural evidence reconciles with checkpoints without copying raw sensitive content by default.
- Every SDK and adapter passes the same enforcement conformance suite.
- Credential-provider outage and revocation fail closed for protected operations.

### Non-goals

- Credential support without customer need
- Universal compliance mapping
- Firecracker solely for marketing
- LLM-generated authorization policies without deterministic review

### Exit evidence

- Credential-provider security and revocation report
- SDK compatibility/conformance matrix
- SCIM/IdP lifecycle tests
- SIEM/WORM reconciliation evidence
- Privacy and deletion exercise

## v1.0.0-production — Production Qualification

**Target window:** July–September 2027  
**Primary owner:** Engineering lead  
**Required reviewers:** Independent security assessor, operations approver, product executive, customer representatives  
**Goal:** Declare production maturity only from independently reviewable evidence.

### Entry criteria

- ESR and v0.7.0 gates pass.
- Production deployment envelope and support matrix are frozen.
- All known P0 items are closed.
- High-risk exceptions have formal owners, expiry, and compensating controls.

### Deliverables

- Full independent architecture, source, deployment, and operational assessment
- Remediation or explicit time-bounded acceptance of findings
- Scale, endurance, noisy-neighbor, and recovery tests
- Compatibility, support, upgrade, and deprecation policies
- Disaster-recovery and incident evidence
- Production operator documentation
- Signed release evidence package
- Paid pilot conversion and referenceable production users
- Firecracker tier only if customer demand and isolation analysis justify it

### Security and correctness gates

- No unresolved critical security issue.
- High findings are remediated or formally accepted with compensating controls and expiry.
- Published SLOs are achieved within the declared deployment envelope.
- Backup, restore, failover, key rotation, revocation, upgrade, and rollback are verified.
- Supply-chain artifacts and policy bundles are signed and provenance-backed.
- Independent assessor and accountable owner sign off.

### Non-goals unless evidence changes

- Decentralized policy consensus
- Generic agent-memory platform
- Broad workflow orchestration
- Multi-region SaaS by default
- Natural-language or LLM authorization as source of truth
- Claims of formal verification beyond properties actually proved
- Firecracker before validated multi-tenant demand

### Exit evidence

- Independent assessment and remediation ledger
- Complete performance and resilience package
- Production support/compatibility matrix
- Customer acceptance from at least two production users
- Signed go/no-go record
- Final `v1.0.0-production` evidence bundle

---

## 11. Team, Ownership, Effort, and Dependency Model

Every security-sensitive milestone must name a responsible owner, accountable approver, independent reviewer, rollback owner, and evidence custodian.

### Workstream RACI

| Workstream | Responsible | Accountable | Independent reviewer | Key outputs |
|---|---|---|---|---|
| State and transactions | Enforcement engineer | Technical lead | Database/security reviewer | State machine, outbox, budgets, idempotency |
| Policy/PDP | Policy engineer | Security architect | Cedar-independent reviewer | Evaluator, bundles, simulation, activation |
| Identity/tenancy | Identity engineer | Security architect | Postgres/IAM reviewer | OIDC, workload identity, RLS |
| Runtime/network | Runtime security engineer | Technical lead | Infrastructure security reviewer | Sandbox, egress, resource binding |
| MCP/adapters | Integration engineer | Product engineering lead | Protocol/security reviewer | Gateway, Pi, SDK conformance |
| Evidence/privacy | Evidence engineer | Security lead | Privacy/compliance reviewer | Audit, verifier, retention, export |
| Platform operations | SRE/release engineer | Engineering lead | Operations reviewer | HA, recovery, observability, releases |
| Product experience | Product engineer | Product lead | Design-partner representative | Approvals, dashboard, onboarding |
| Security assurance | Security lead | Executive sponsor | External assessor | Threat model, tests, review program |

### Indicative effort and critical dependencies

These are capacity-planning estimates, not delivery promises.

| Milestone | Indicative focused effort | Critical dependency |
|---|---:|---|
| v0.2.0 | 10–16 engineer-weeks | State machine and PDP ADR |
| v0.3.0 | 8–12 engineer-weeks | Stable token/identity contract |
| v0.3.1 | 8–12 engineer-weeks | Workload identity and network-grant contract |
| v0.4.0 | 12–18 engineer-weeks | Identity, RLS, and egress gates |
| v0.5.0 | 16–24 engineer-weeks | Design-partner operational evidence |
| v0.7.0 | 16–28 engineer-weeks | Stable provider/SDK interfaces |
| v1.0 | 12–20 engineer-weeks plus external assessment | Completed production evidence |

A solo founder should not interpret these as elapsed calendar weeks. Parallel execution requires multiple experienced owners.

### Weekly governance

- Monday: dependency and gate review
- Midweek: threat/evidence review for active security boundary
- Friday: demo from fixed commit and evidence-index update
- Every architecture change: ADR plus canonical-spec update
- Every release candidate: go/no-go review with rollback owner present

---

## 12. Business and Stakeholder Review

### 12.1 Near-term ideal customer

The best design partners are teams that:

- Already run coding or operational agents with real tool access.
- Have a clear security owner.
- Can route one workflow through ActantOS.
- Need approvals and evidence but do not require a complete global governance platform on day one.
- Can tolerate self-hosted early-product operations.

Good examples:

- AI-native development tool companies
- Mid-market SaaS platform/security teams
- Regulated internal automation teams with one bounded workflow

### 12.2 Avoid overly broad initial sales

Do not begin with customers requiring:

- Multi-region mission-critical availability
- Arbitrary untrusted multi-tenant code execution
- Full enterprise IAM and compliance certification on day one
- Hundreds of connectors
- Natural-language policy authoring as an authorization source

### 12.3 Pilot success metrics

| Metric | Target question |
|---|---|
| Time to deploy | Can a partner install without core-team code changes? |
| Time to first governed action | How quickly does value become visible? |
| Coverage | What percentage of target tool actions are actually in-path? |
| Decision quality | How many incorrect denies, unsafe permits, and unnecessary approvals occur? |
| Approval burden | Does governance create operational fatigue? |
| Incident evidence | Can the team reconstruct exactly what happened? |
| Integration effort | How many adapter-specific changes were needed? |
| Willingness to pay | Does the control solve a budgeted security/platform problem? |


### 12.4 Open-core boundary

Security correctness must not be a paid-only feature.

#### Open and secure baseline

- Core decision service and policy-provider interface
- Cedar local/PDP reference implementation
- Basic local/admin authentication
- OIDC/JWKS support
- Workload identity contract
- Postgres RLS and tenant isolation
- Pi adapter and basic MCP gateway
- Docker executor reference
- Basic approval flow
- Audit chain and verifier
- Key rotation and signed-upgrade capability
- Starter policies and conformance suite

#### Paid enterprise capabilities

- Managed control plane and HA operations
- SCIM and multiple identity-provider federation
- Advanced approval quorum and policy workflows
- Managed credential-provider integrations
- SIEM and WORM integrations
- Private-cloud and hardened managed execution tiers
- Long-term evidence retention
- Enterprise policy packs, support, and assurance services

ActantOS should monetize operational assurance, integrations, managed reliability, and support—not withholding foundational security controls or reselling model tokens.


---

## 13. Frontend and Documentation Review

Frontend issues are useful but secondary to the enforcement path.

### 13.1 Configuration hygiene

If `components.json` references Tailwind/shadcn paths while the project uses custom styles, choose one architecture:

- Remove stale configuration, or
- Adopt and document the intended Tailwind version and build setup.

Do not leave a misleading partial configuration.

### 13.2 Animation performance

Animating `height: auto` may create layout work, but it should be classified as a **profiling candidate**, not a confirmed bottleneck. Capture Chrome performance traces under mobile throttling before refactoring.

### 13.3 Calendly iframe

Treat the missing `sandbox` as a defense-in-depth review item, not automatically a critical vulnerability. Determine the minimum functioning permissions and add:

- `sandbox` with least privilege
- `referrerPolicy`
- CSP `frame-src`
- Restricted `allow` attributes

### 13.4 Dead code and links

Verify unused components/exports with compiler and static-analysis tools before deletion. Replace internal raw anchors with framework navigation where it improves client transitions and accessibility.

### 13.5 Documentation drift

The website should consume release and capability data from a structured canonical source where possible. Every public capability should include a maturity label to prevent marketing pages from getting ahead of the implementation.

---

## 14. Verification Strategy

The previous verification list was too frontend-focused. The production program requires the following test families.

| Test family | Mandatory coverage |
|---|---|
| Schema and API | Valid, malformed, unknown fields, version compatibility |
| Policy | Permit/forbid corpus, default deny, evaluator failure, repeated determinism |
| Identity | Forged JWT, wrong audience, expired token, cross-tenant subject |
| Idempotency | Duplicate sequential and concurrent request IDs |
| Approval | Expiry, replay, double-use race, scope mismatch, wrong approver |
| Decision token | Invalid signature, wrong key, expiry, altered scope/constraints |
| Budget | Atomic increments, concurrency, windows, threshold boundary |
| Sandbox | Mount, capabilities, process, network, timeout, output, escape attempts |
| MCP | Drift, hidden tools, SSRF, redirects, DNS rebinding, cancellation, duplicate calls |
| Tool result | Forgery, duplicate result, state regression, wrong executor |
| Audit | Sequence, canonical hash, corruption, missing row, external checkpoint |
| Multi-tenancy | Cross-tenant DB/API/policy/audit attempts |
| Failure injection | DB, evaluator, Docker, network, upstream, partial transaction |
| Operations | Backup, restore, upgrade, rollback, restart, failover |
| Performance | p50/p95/p99 decision latency, throughput, connection and DB contention |

### Definition of done for a security-sensitive feature

A feature is complete only when it has:

- Threat scenario
- Design contract
- Unit tests
- Integration tests
- Negative tests
- Failure-mode tests
- Audit evidence
- Operator documentation
- Known limitations
- Named owner and reviewer

---

## 15. Governance of Project Artifacts

### 15.1 Current coordination inconsistency

Earlier coordination artifacts disagreed about completion. The current `progress.md`, `task_plan.md`, and `forward_steps/STATUS.md` now agree that the local/self-hosted scenario is complete and external validation is optional/inactive; `pilot-1-status.md` still carries external-pilot language and should be reconciled after the Mode A/Mode B decision.

Recommended correction:

```text
M1–M4 artifacts complete.
Final delivery status: complete only after parent acknowledgement is recorded.
```

### 15.2 Required evidence index

Add an `EVIDENCE.md` file with entries such as:

```text
finding_id
capability
source file and line/function
commit SHA
test command
test result/log path
audit event IDs
reviewer
confidence
known limitation
```

### 15.3 Decision-log discipline

New technical decisions should be recorded in:

1. The canonical implementation specification
2. The decision log in `README.md`
3. Any affected API/schema files
4. The release evidence package

Do not silently change semantics only in website copy or roadmap text.

---


## 16. Conditional 30-Day Production-Qualification Plan (Mode B Only)

This section is **not active under the current Mode A repository status**. Activate it only through an ADR that names the owner, budget, target maturity gate, and superseded freeze decisions. If activated, the first month is dedicated to security-boundary hardening; do not begin broad UI, connector, SCIM, or Firecracker work.

### Week 1 — freeze contracts and prove the current baseline

- Freeze repository commit, environment, lockfiles, images, and policy bundle
- Re-run all unit, integration, Compose, and live demo evidence
- Create `EVIDENCE.md` and link every verified claim
- Approve canonical state machine, terminal states, and invariants
- Approve token retry/JTI/nonce/expiry contract
- Reproduce all Cedar shim-triggering cases
- Complete evaluator ADR test plan
- Inventory every external side-effecting connector and its idempotency properties

**Gate:** No ambiguity remains about current behavior or the authoritative schema.

### Week 2 — implement transactional safety

- Add execution jobs/outbox and worker lease model
- Implement atomic approval consumption, hard-budget reservation, allow decision, job, and audit transaction
- Add result settlement and reservation release
- Add reconciler for expired leases, unknown results, abandoned reservations, and audit mismatch
- Add crash injection after every durable step
- Add high-concurrency idempotency, approval, and budget tests

**Gate:** Every crash produces a known state; no unsafe automatic replay.

### Week 3 — stabilize authorization and revocation

- Benchmark Rust PDP, official JS/WASM option, and process-isolated alternatives against the corpus
- Approve ADR and implement preferred PDP
- Add signed policy bundles and safe activation pipeline
- Run shadow differential evaluation
- Add key IDs, immutable token claims, security epochs, and pre-execution revocation check
- Remove compatibility override after zero unexplained mismatch

**Gate:** Cedar is authoritative, deterministic under the corpus, and fail-closed.

### Week 4 — bind execution and package evidence

- Implement file/MCP/Git/HTTP resource-binding structures
- Add WYSIWYE approval display hash
- Add audit structural/content separation design
- Generate SBOM, signed artifacts, and provenance
- Publish audit/ledger verifier
- Run final v0.2.0 chaos, concurrency, replay, and recovery suite
- Conduct focused internal or external security review

**Gate:** v0.2.0 release candidate has a complete signed evidence package.

### 30-day completion criteria

- Canonical state machine is enforced by database/application invariants
- Outbox, execution lease, terminal result, and reconciler operate
- No Cedar semantic override remains
- Retry never extends or duplicates authorization
- Exactly one approval consumer and one execution job win
- Hard budgets cannot be exceeded under the tested concurrency envelope
- Security epoch invalidates issued-but-unexecuted authorization
- Resource drift requires a new decision
- All release artifacts are identified, signed, and included in SBOM/provenance
- Focused review has no unresolved critical issue

---

## 17. Final Assessment

ActantOS has moved beyond a slideware idea. The supplied evidence indicates a real enforcement kernel with live decision, approval, Docker, MCP, token, and audit behavior. That is a meaningful achievement and a defensible basis for continued development.

The next stage should be disciplined rather than expansive. The project’s success depends on proving that its enforcement guarantee survives:

- Broken dependencies
- Malicious inputs
- Concurrent requests
- Identity spoofing
- Tenant boundaries
- Approval replay
- Sandbox and network attacks
- Operator mistakes
- Upgrades and recovery

The product should therefore prioritize **trustworthy enforcement and pilot operability** over speculative autonomy features.

### Final recommendation

Proceed with ActantOS as an Agent Runtime Control Plane, using Pi for demonstrable developer workflows and MCP as the strategic interoperability wedge. Treat the current implementation as **Enforcement Kernel Verified**, not yet enterprise-production qualified. Before Design Partner Ready, ActantOS must prove the canonical action state machine and reconciliation model; a shim-free authoritative Cedar path; immutable retry-safe token and revocation semantics; atomic approval and hard-budget transitions; authenticated identity with forced RLS; decision-to-execution object binding; mandatory connection-time egress enforcement; privacy-safe independently anchored evidence; and signed, provenance-backed trusted components.

---

## Appendix A — Current Evidence Summary

```text
Reported verified commands:
- npm run typecheck
- npm run build
- npm test                     (147 tests; 146 passed, 1 skipped on July 12)
- docker compose up -d --build
- npm run demo -- --url http://localhost:3100  (29 passed, 0 failed; historical, not rerun July 12)

Reported verified capabilities:
- decision allow / deny / approval_required
- one-use approval resume
- decision-token scope and constraint binding
- Docker execution and tool-result verification
- kill switch
- Postgres audit chain
- enriched session timeline
- live MCP upstream call and request correlation
- MCP manifest drift denial and promotion
- basic SSRF denial

Highest-priority known limitation:
- cedar-policy-cli 4.11.2 compatibility shim in src/cedar-cli-provider.ts
```

## Appendix B — Existing Canonical Semantics That Must Not Drift

1. Cedar is the default policy engine behind `PolicyDecisionProvider`.
2. Manual approval API is the verified baseline; Slack is a later integration.
3. Stack: TypeScript, Fastify, Zod, Postgres, Kysely.
4. Sandbox progression: Docker → gVisor → Firecracker only if required.
5. `network_mode` values: `none` and `egress_proxy`.
6. Dry run returns the real decision with `decision_mode="dry_run"`; it never executes or consumes approval tokens.
7. Credential access is denied, not approval-routed.
8. Approval execution resubmission uses a new request ID.
9. Execution requires a valid, unexpired allow decision token.
10. Planned capabilities must not be described as current verified behavior.


## Appendix C — Final Canonical Architectural Decisions

1. **Cedar authority:** Cedar remains the default authorization engine behind `PolicyDecisionProvider`; production provider code may not semantically override a Cedar result.
2. **Evaluator deployment:** Rust PDP is the preferred design hypothesis, but the final mechanism is selected by ADR using conformance, failure isolation, latency, packaging, and operations evidence.
3. **Canonical state machine:** Every governed action uses the states and transitions in §4.5; state regression and implicit states are forbidden.
4. **Transactional execution:** Approval consumption, hard-budget reservation, allow decision, execution job, and audit commit atomically; external execution uses leased jobs, terminal settlement, and reconciliation.
5. **Idempotent authorization:** Retrying the same request returns the same logical authorization window, JTI, execution nonce, reservation, and job; expiry is never extended.
6. **Emergency revocation:** Monotonic security epochs invalidate issued-but-unexecuted tokens and jobs.
7. **Hard budgets:** PostgreSQL is the initial authoritative reserve/commit/release ledger. Redis may accelerate short-window rate limits but may not become a fail-open hard-budget source.
8. **Tenant isolation:** Authenticated identity—not request body—defines tenant context. Runtime roles do not own tables or bypass RLS; tenant tables use `ENABLE` and `FORCE ROW LEVEL SECURITY`, `USING`, and `WITH CHECK`.
9. **Network boundary:** Application validation remains, but all governed egress crosses an authenticated connection-time enforcement proxy; direct routes are denied.
10. **Resource binding:** A decision and approval bind to the exact file, MCP manifest/tool, Git object, HTTP destination, credential reference, and execution job used.
11. **Approval WYSIWYE:** The canonical representation shown to the approver is hashed and must match the resumed execution.
12. **Policy lifecycle:** Production bundles are validated, simulated, approved, signed, staged, canaried, atomically activated, monitored, and rollback-capable.
13. **Evidence architecture:** Structural evidence is append-only and externally anchored; sensitive content is separately encrypted, retention-controlled, and erasable.
14. **Supply-chain trust:** Trusted components and policy bundles are versioned, signed, SBOM-listed, provenance-backed, and digest-verified.
15. **Offline behavior:** Default is fail-closed. Optional bounded-offline mode is explicit, read-only, credential-free, network-free, non-production, time-limited, and audited.
16. **Plane separation:** Control plane owns durable identity, policy, approval, budget, revocation, and evidence state. Data-plane components enforce requests and hold only bounded local/lease state.
17. **Maturity discipline:** EKV, DPR, ESR, and production labels are earned only from their defined evidence gates.
18. **Security baseline availability:** Foundational identity, RLS, verification, and secure upgrade capabilities remain available in the open secure baseline; advanced managed operations and integrations may be commercial.

## Appendix D — Planning Quality Checklist

A plan revision is complete only if every answer is “yes.”

### Product and scope

- Is the product category unambiguous?
- Are current, planned, and conditional capabilities separated?
- Are non-goals explicit?
- Is the target design partner defined?

### Architecture

- Are trust boundaries and authoritative stores named?
- Is the action state machine explicit?
- Are all dual-write boundaries handled?
- Are offline and dependency-failure behaviors explicit?
- Is resource identity bound through execution?

### Security

- Is authorization deterministic and shim-free?
- Are token retries, keys, revocation, and epochs defined?
- Are approvals atomic and WYSIWYE?
- Are tenant boundaries enforced by identity and RLS?
- Is egress connection-time enforced?
- Are hard budgets authoritative and atomic?
- Is policy activation safe?
- Are evidence privacy and retention defined?
- Are trusted artifacts signed and traceable?

### Execution

- Does every milestone have entry criteria?
- Does every milestone have deliverables, non-goals, and exit evidence?
- Are owners, reviewers, dependencies, effort, and rollback roles named?
- Are performance and capacity envelopes frozen before release?
- Are external reviews staged before architecture becomes expensive to change?

### Evidence

- Can every “verified” claim be tied to commit, command, logs, and reviewer?
- Can an independent verifier reconcile request, decision, approval, job, budget, result, and audit?
- Is product readiness scored only from evidence?

The checklist is a review gate, not a score. The July 12 audit found several answers that remain “no” until the product mode, clean evidence commit, release/maturity source, and status reconciliation are completed.

## Appendix E — Standard Release Gate Template

```markdown
# Release <version> Gate

## Maturity label
EKV | DPR | ESR | Production

## Fixed inputs
- Commit SHA:
- Policy bundle hash:
- Schema/migration version:
- Container/package digests:
- Deployment topology:

## Entry criteria
- ...

## Deliverables
- ...

## Security invariants
- ...

## Non-goals
- ...

## Workload envelope
- ...

## Required tests
- Unit:
- Integration:
- Concurrency:
- Fault injection:
- Adversarial:
- Performance:
- Recovery:

## Evidence
- Log locations:
- Audit event/checkpoint IDs:
- SBOM/provenance:
- External review:

## Known limitations
- ...

## Go/no-go
- Responsible owner:
- Security reviewer:
- Rollback owner:
- Evidence custodian:
- Decision:
```

## Appendix F — Primary Technical References

- Cedar security and production Rust implementation: https://docs.cedarpolicy.com/other/security.html
- Cedar policy/schema validation: https://docs.cedarpolicy.com/policies/validation.html
- PostgreSQL row-security behavior and `FORCE ROW LEVEL SECURITY`: https://www.postgresql.org/docs/current/ddl-rowsecurity.html
- Envoy dynamic forward proxy: https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/dynamic_forward_proxy_filter
- Redis rate limiting and atomic Lua patterns: https://redis.io/docs/latest/develop/use-cases/rate-limiter/
- Transactional outbox design rationale: https://docs.aws.amazon.com/prescriptive-guidance/latest/cloud-design-patterns/transactional-outbox.html
- SLSA software-supply-chain framework: https://slsa.dev/

These references validate design patterns. ActantOS-specific correctness still requires the fixed-commit tests and evidence gates defined above.
