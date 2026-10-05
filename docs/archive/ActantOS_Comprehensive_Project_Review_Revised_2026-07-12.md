# ActantOS Comprehensive Project Review and Production Roadmap

**Review date:** July 12, 2026  
**Audience:** Engineering, security, product leadership, design partners, and stakeholders  
**Document status:** Revised technical review — ready for engineering validation  
**Current engineering baseline:** Week 1 enforcement kernel verified; production hardening and enterprise platform work remain  

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

### Overall readiness score

**Current production-readiness estimate: 46/100**

| Area | Score | Reason |
|---|---:|---|
| Core enforcement correctness | 76 | Main decision, approval, result, kill-switch, MCP, and audit paths have live verification evidence |
| Authorization engine maturity | 48 | Cedar integration is active, but the compatibility shim is a material blocker |
| Approval and replay safety | 70 | Scope-bound, one-use approval design is strong; broader identity and channel security remain |
| Sandbox and execution isolation | 52 | Docker baseline exists; production-grade profiles and gVisor validation remain |
| MCP security | 62 | Manifest drift and basic SSRF controls are live; DNS rebinding, identity, and egress enforcement require strengthening |
| Audit integrity and evidence | 63 | Hash-chain implementation and enriched timelines exist; independent anchoring and verifier tooling remain |
| Multi-tenancy and identity | 18 | Tenant IDs exist, but full tenant model, OIDC, SCIM, and RLS are not yet verified |
| Operational resilience | 28 | HA, backup/restore, upgrades, incident response, and SLO evidence are not yet established |
| Developer and pilot experience | 45 | Demo works, but installer, stable SDKs, policy onboarding, and operator UX are incomplete |
| Documentation and release evidence | 52 | Canonical specs are detailed, but release naming and evidence traceability need governance |

### Top five priorities

1. **Remove the Cedar compatibility shim from any production path.**
2. **Prove fail-closed behavior under dependency and concurrency failures.**
3. **Introduce real tenant isolation and authenticated session identity.**
4. **Package the system so a design partner can deploy and operate it without custom engineering.**
5. **Create a formal evidence package for every release: commit, tests, threat coverage, logs, and known limitations.**

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

The supplied review package did not include a complete source repository snapshot with commit SHA, Git history, or raw test logs. Therefore:

- Verified-state claims in this report rely on the implementation handoff and documented command results.
- Named source modules are included where the evidence package explicitly identifies them.
- This is a strong architecture and implementation-evidence review, but it is **not a replacement for an independent source-level security audit**.
- Before production approval, a reviewer must inspect the actual repository at a fixed commit and rerun the complete verification suite.

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
npm test                                   -> 51 passing
PORT=3100 npm run dev                      -> daemon listens
Docker Compose actantosd + Postgres        -> healthy
npm run demo -- --url http://localhost:3100 -> 29 passed, 0 failed
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
| Budgets and rate limits | **DESIGNED** | Schema and pipeline position exist | Week 1 behavior passes unconditionally |
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
        +--> budget check [designed; not active in Week 1]
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

The architecture should retain this distinction:

- **Control plane:** identity, registry, policy bundles, approval state, audit metadata, administration.
- **Data plane:** Pi adapter, MCP gateway, normalization, token enforcement, executor, upstream routing.

For enterprise deployments, data-plane enforcement should remain close to protected resources while control-plane administration may be centralized.

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

1. **Budget enforcement is not active.** The schema and pipeline location exist, but the Week 1 check passes unconditionally.
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

## 5.2 Cedar policy provider

**Known module:** `src/cedar-cli-provider.ts`

### Responsibility

The provider translates normalized ActantOS context into Cedar authorization input and maps Cedar results into the orchestration pipeline. Cedar is intentionally responsible for authorization, while risk rules and approvals remain outside Cedar.

### Strengths

- Correct separation between authorization and workflow state
- `PolicyDecisionProvider` abstraction leaves room for alternate evaluators
- Policies consume stable normalized facts
- Default-deny semantics are understood
- Explicit safe permits are included for the MVP proof

### Critical issue: compatibility shim

The current Cedar CLI version reportedly produces intermittent false denies or recursion diagnostics for logically equivalent non-credential requests. The provider includes a narrow override that preserves expected Week 1 permit behavior when `credential_access=false`.

This is the highest-priority technical debt in the project.

Even if the override is tightly scoped, it means application code can alter the result returned by the authorization engine. A production authorization boundary must not depend on a demo-preserving semantic correction.

### Required remediation options

Preferred order:

1. Integrate a stable direct Cedar evaluator with pinned version and deterministic behavior.
2. Validate a newer Cedar CLI/runtime against the complete ActantOS policy corpus.
3. Keep the provider abstraction and add an alternate implementation only as a controlled fallback—not a silent semantic override.

### Required verification

Create a differential policy corpus covering:

- Safe workspace reads
- Credential paths
- Production mutations
- Destructive actions
- Missing permit
- Mixed permit/forbid cases
- Context and resource attribute equivalence
- Invalid policy syntax
- Timeout and malformed CLI output
- Multiple process invocations and repeated evaluation

For each case, compare:

- Expected policy semantics
- Direct evaluator result
- CLI result
- Provider result

### Exit gate

- Zero compatibility overrides in the production path.
- All policy corpus tests are deterministic over repeated runs.
- Evaluator timeout and crash fail closed.
- Policy bundle hash and evaluator version are recorded in audit evidence.

---

## 5.3 Approval and authorization-resume flow

**Primary interface:** `POST /v1/approvals/{approval_id}/decide`

### Correct behavior

Approval must not bypass policy. The secure flow is:

1. Original request receives `approval_required`.
2. A random one-use approval token is generated when a human approves.
3. Only the token hash is stored.
4. The adapter creates a **new request ID** for execution resubmission.
5. It supplies the prior decision, approval ID, and raw token.
6. ActantOS locks and validates the approval record.
7. It verifies tenant/scope binding, status, TTL, unused state, and token hash.
8. It consumes the token atomically.
9. The pipeline issues a new decision token for the executor.

### Strengths

- Random token rather than deterministic token derivation
- Token stored only as a hash
- Scope hash shared with tool call and decision token
- `used_at` protects one-use behavior
- New request ID avoids idempotency returning the old pending decision
- Approval lineage is visible in the session timeline

### Residual risks

- No full enterprise approver authentication yet
- No separation-of-duties policy
- No quorum or multi-step approvals
- No Slack/Teams signature and replay model yet
- Approval fatigue can encourage unsafe broad grants
- The same expiry currently covers human decision and token consumption

### Recommended improvements

- Separate `approval_deadline` from `execution_deadline`.
- Bind approver identity to OIDC subject and organization role.
- Support explicit approval policies: single approver, quorum, ordered stages, escalation.
- Keep one-action approval as the safe default.
- Add bounded temporary grants only with exact resource/action scope.
- Add reason requirements for high-risk approvals.
- Record channel, authentication method, client IP, and approval-policy version.
- Add concurrency tests with simultaneous token consumption.

### Exit gate

- Exactly one concurrent resubmission can consume a token.
- Approval cannot be replayed across tenant, user, agent, session, tool, or resource.
- Expired, denied, already-used, and scope-mismatched approvals always deny.
- External approval channels are cryptographically authenticated.

---

## 5.4 Decision-token and Docker executor

**Known module:** `src/docker-executor.ts`

### Responsibility

The executor verifies that ActantOS authorized the exact execution scope and constraints, then launches the action in the selected Docker network mode with resource controls.

### Strengths

- Execution requires an allow token.
- Token includes decision, tool call, scope, constraints, and expiry.
- Expired tokens and constraint mismatches are rejected before Docker work.
- Network mode is explicit: `none` or `egress_proxy`.
- Resource limits, read-only root, non-root user, dropped capabilities, and output limits are part of the design.

### Risks

1. **Docker is a useful MVP boundary, not sufficient for hostile multi-tenant execution.**
2. **Workspace mounts remain a high-risk surface.** File ownership, symlinks, executable content, and dynamic loaders require careful treatment.
3. **The Week 1 egress proxy network is a demo bridge, not a completed domain-enforcement system.**
4. **HMAC key compromise allows token forgery.**
5. **Executor-host compromise can bypass application controls and rewrite results.**
6. **Nested execution and interpreter behavior need systematic controls.**

### Recommended improvements

- Create a minimal, versioned sandbox image and software bill of materials.
- Add seccomp, AppArmor/SELinux, capability, cgroup, and filesystem tests.
- Enforce no host home mount and explicit environment allowlist.
- Use target-specific credentials injected only into the execution process.
- Evaluate gVisor for single-tenant hosted workloads.
- Add executor registration and workload identity.
- Consider asymmetric signed tokens if executors are distributed across trust domains.
- Add per-execution nonce and result attestation metadata.
- Validate network policy at connection time after DNS resolution.

### Exit gate

- Sandbox profile is tested against a documented escape/bypass suite.
- No environment secret is available unless explicitly referenced by the decision.
- Executor cannot expand network access beyond signed constraints.
- Timeout, output, PID, memory, and CPU limits are enforced and tested.
- gVisor compatibility is measured before being promised as a product tier.

---

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

## 5.7 MCP gateway and manifest lifecycle

### Responsibility

The MCP gateway is the strategic cross-runtime enforcement point. It mediates client access to upstream servers, filters tool discovery, intercepts calls, checks server/tool identity, enforces policy, and records evidence.

### Current strengths

- Live upstream SSE proof is reported.
- `tools/list` and `tools/call` proof paths are exercised.
- Request correlation persists across decision and result records.
- First-seen manifest establishes a baseline.
- Drifted schema or description creates a pending version and fails closed.
- Admin approval can promote a pending version.
- Basic blocked URL classes are checked before policy evaluation.

### Security gaps

1. **Basic SSRF blocklists are insufficient.** Production controls must handle DNS rebinding, IPv6, redirects, alternate numeric IP forms, resolver behavior, and time-of-check/time-of-connect changes.
2. **Upstream authentication is incomplete.** Raw user-token passthrough must remain prohibited.
3. **Direct-connect bypass must be prevented by deployment networking.**
4. **Manifest trust requires server identity.** A tool hash alone does not authenticate the server delivering it.
5. **Prompt/resource/callback surfaces need explicit policy.**
6. **Transport compatibility and cancellation behavior need testing.**

### Recommended improvements

- Resolve hostnames through a controlled resolver.
- Validate every resolved IP and pin it for connection.
- Re-evaluate redirects and block private/link-local/metadata ranges for IPv4 and IPv6.
- Bind server credentials to tenant, session, server ID, and audience.
- Sign server registry configuration.
- Extend policy interception to resources and prompts before enabling them.
- Disable sampling/callbacks by default until governed.
- Add manifest semantic review UI showing full model-visible descriptions.
- Detect unregistered direct MCP traffic where deployment architecture permits.

### Exit gate

- A standard MCP client only sees authorized tools.
- Manifest drift fails closed.
- SSRF bypass suite passes across IPv4, IPv6, DNS, and redirect cases.
- Agents in the reference deployment cannot reach upstream MCP servers directly.
- No end-user token is forwarded to an arbitrary upstream server.

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

| ID | Issue | Impact | Recommended action | Exit evidence |
|---|---|---|---|---|
| P0-01 | Cedar compatibility shim can override evaluator result | Authorization boundary may not reflect policy engine semantics | Replace with stable direct evaluator; run differential corpus | No override; deterministic repeated results |
| P0-02 | Identity context is not yet fully authenticated | Agent/user/session claims could be spoofed | OIDC/JWKS session tokens and agent workload identity | Forged claims rejected |
| P0-03 | Tenant ID is not full isolation | Cross-tenant data or policy exposure | Tenants table, RLS, tenant-scoped DB roles/tests | Cross-tenant test suite passes |
| P0-04 | Fail-closed behavior lacks complete chaos evidence | Dependency failure may produce undefined behavior | Fault injection for DB, Cedar, Docker, gateway, upstream | Zero execution under control-plane failure |
| P0-05 | Basic SSRF control is incomplete | Metadata/internal service access | Controlled DNS, IP pinning, redirect validation, IPv6 coverage | SSRF bypass suite passes |
| P0-06 | Direct integration bypass is not fully proven | Agent can avoid ActantOS | Disable native tools; enforce network routing; adapter self-test | Reference deployments show no alternate path |
| P0-07 | Approval concurrency requires explicit stress proof | Token may be consumed twice under race | Transactional race tests | One winner across concurrent consumers |
| P0-08 | HMAC key lifecycle not production-defined | Token forgery if key leaks | KMS-backed keys, key IDs, rotation, revocation | Rotation test with overlap and expiry |
| P0-09 | Audit chain lacks external trust anchor | Privileged rewrite could reconstruct history | Signed checkpoints and external WORM/anchor | Independent verifier detects changes |
| P0-10 | Budget enforcement is not active | Runaway loops and cost/resource abuse | Atomic budget ledger and enforcement | Concurrency and reset-window tests |

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
| P1-09 | Audit retention and privacy incomplete | Data classification, redaction, retention, deletion, export policy |
| P1-10 | Operator runbooks incomplete | Installation, incident, key rotation, policy rollback, recovery guides |

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

### 9.2 Recommended SLO framework

Initial pilot targets should be measured, not promised prematurely:

| SLI | Initial target for pilot validation |
|---|---|
| Local decision API p95 latency | Measure under representative policy and DB load; establish baseline before commitment |
| Decision availability | No fail-open behavior; service availability target defined after deployment testing |
| Audit correlation completeness | 100% of governed executions link request, decision, and result |
| Approval token replay | 0 successful replays |
| Cross-tenant access | 0 successful unauthorized accesses |
| Manifest drift enforcement | 100% unapproved drifts denied |
| Recovery | Measured RPO/RTO through restore drill |
| Upgrade safety | No window in which adapters execute without enforcement |

### 9.3 Release evidence package

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

The roadmap begins from the verified enforcement-kernel baseline on **July 12, 2026**. Dates are explicit to avoid ambiguous “Q1/Q2” references.

## v0.2.0 — Enforcement Hardening

**Target:** July–August 2026  
**Goal:** Make the existing decision path trustworthy enough for controlled design-partner evaluation.

### Entry criteria

- Week 1 demo remains green.
- Current schemas and decision semantics are frozen as the baseline.
- Known Cedar compatibility behavior is reproducible.

### Deliverables

- Replace Cedar compatibility shim.
- Add policy differential test corpus.
- Implement atomic budgets and rate limits.
- Add key IDs and decision-token rotation design.
- Add fault injection for policy, DB, Docker, and gateway failures.
- Add approval concurrency and replay tests.
- Add independent audit verifier CLI.
- Publish OpenAPI and reason-code documentation.
- Add adapter enforcement self-test.

### Security gates

- No semantic override of policy result.
- All control-plane failures fail closed.
- One-use approval survives high-contention race tests.
- Decision and result tokens reject altered scope/constraints.

### Non-goals

- OIDC/SCIM
- Multi-tenant SaaS
- Firecracker
- Broad connector catalog

### Exit evidence

- Full test logs at fixed commit
- Policy corpus report
- Fault-injection report
- Audit verifier output
- Performance baseline

---

## v0.3.0 — MCP Gateway Productionization

**Target:** September–October 2026  
**Goal:** Govern a normal MCP client and upstream server with strong identity, manifest, and SSRF boundaries.

### Deliverables

- Stable MCP transport support for selected protocols.
- Authenticated server registry.
- Policy-filtered `tools/list`.
- Manifest diff and promotion workflow.
- DNS/IPv4/IPv6/redirect-aware SSRF protection.
- Upstream credential abstraction.
- Session reauthorization and timeout model.
- Tool-call cancellation and idempotency semantics.
- Protocol compatibility suite.

### Security gates

- Direct upstream route blocked in reference architecture.
- No raw end-user token passthrough.
- Unapproved manifest changes deny.
- SSRF bypass corpus passes.

### Exit evidence

- 24-hour soak test
- Multiple MCP client compatibility results
- Manifest-drift demo
- Request/decision/result reconciliation report

---

## v0.4.0 — Design Partner Ready

**Target:** November–December 2026  
**Goal:** A design partner can deploy and govern one workflow without custom changes to ActantOS core.

### Deliverables

- Signed CLI/package installer.
- Self-hosted Docker Compose bundle.
- Basic organization, user, team, and tenant model.
- OIDC/JWKS login and API authentication.
- PostgreSQL RLS.
- Policy templates and dry-run onboarding.
- Webhook/SIEM export.
- Minimal operator dashboard.
- Optional gVisor profile for compatibility testing.
- Installation and incident runbooks.

### Product gates

- Two design partners deploy from documentation.
- One real workflow per partner runs end-to-end.
- No partner-specific core-code fork.
- Time-to-first-governed-action is measured.

### Security gates

- Cross-tenant tests pass.
- Authenticated subject controls approval and policy access.
- Upgrade/rollback does not create an enforcement bypass.

---

## v0.5.0 — Enterprise Self-Host Ready

**Target:** January–March 2027  
**Goal:** Operate ActantOS reliably inside a customer-controlled environment.

### Deliverables

- HA reference architecture.
- Backup, restore, and migration rollback.
- Slack and Teams approval integrations.
- Policy bundle lifecycle UI and simulator.
- Role-aware dashboards.
- Audit export and signed checkpoints.
- Structured metrics, tracing, alerts, and SLO dashboards.
- Hardened gVisor execution profile if validation succeeds.
- Enterprise deployment and security documentation.

### Exit gates

- Recovery drill meets documented RPO/RTO.
- Node and dependency restarts do not fail open.
- Approval channels pass identity and replay tests.
- Pilot security review has no unresolved critical findings.

---

## v0.7.0 — Identity, Credentials, and Ecosystem

**Target:** April–June 2027  
**Goal:** Integrate into enterprise identity, secret, and observability ecosystems.

### Deliverables

- Pluggable `CredentialProvider` interface.
- AWS STS implementation first, with Azure/GCP/Vault-compatible architecture.
- Okta/Entra and SCIM integration.
- Short-lived target/audience-bound credential injection.
- S3 Object Lock or equivalent WORM export.
- Splunk and Datadog integrations.
- Stable TypeScript and Python SDKs.
- Additional runtime adapters selected from customer demand.
- Advanced approval policies and bounded TTL grants.

### Security gates

- Raw user credentials never reach arbitrary upstream tools.
- Credentials are scoped to tenant, agent, session, target, audience, and TTL.
- WORM export reconciles with primary chain checkpoints.
- SDK adapters pass the shared enforcement conformance suite.

---

## v1.0.0-production — Production Qualification

**Target:** July–September 2027  
**Goal:** Declare production maturity based on evidence rather than feature count.

### Deliverables

- External security assessment.
- Remediation of all critical/high findings or documented risk acceptance.
- Scale and endurance tests.
- Compatibility and support matrix.
- Stable upgrade/deprecation policy.
- Disaster recovery evidence.
- Production operator documentation.
- Paid pilot conversion and customer references.
- Firecracker execution tier only if multi-tenant customer demand justifies it.

### Exit gates

- No open critical security issues.
- Published SLOs achieved in target deployment.
- Backup, restore, failover, upgrade, and rollback verified.
- At least two customers approve production operation.
- Complete release evidence package is signed off.

### v1.0 non-goals unless proven necessary

- Decentralized policy consensus
- Generic agent memory platform
- Broad workflow orchestration
- Multi-region SaaS by default
- “Formal proof” marketing beyond actual verified properties

---

## 11. Team and Ownership Model

A roadmap without owners will drift. Recommended workstreams:

| Workstream | Primary responsibility |
|---|---|
| Enforcement kernel | Decision pipeline, tokens, idempotency, budgets |
| Policy engineering | Cedar evaluator, policy lifecycle, simulation, corpus |
| Runtime security | Docker/gVisor, network, credentials, executor identity |
| MCP and adapters | Protocol gateway, Pi and additional runtime integrations |
| Identity and tenancy | OIDC, SCIM, RLS, organization model |
| Evidence and compliance | Audit chain, verifier, export, retention |
| Platform operations | Packaging, HA, backup, observability, upgrades |
| Product experience | Approvals, dashboard, policy UX, onboarding |
| Security assurance | Threat model, test corpus, external assessment |

For a small team, individuals may own multiple streams, but each milestone must name one accountable owner and one reviewer.

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

Recommended open components:

- Core decision service
- Local Cedar provider
- Pi adapter
- Basic MCP gateway
- Docker executor reference
- Local audit chain and verifier
- Starter policies

Recommended paid/enterprise components:

- Managed control plane
- Enterprise identity and SCIM
- Advanced approvals
- SIEM/WORM integrations
- Credential broker providers
- HA and private-cloud packages
- Managed gVisor/Firecracker execution tiers
- Long-term evidence retention
- Enterprise policy packs and support

The product should monetize governance and operational assurance, not model-token resale.

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

The orchestrator handoff says no work remains, while `progress.md` still leaves the required Sentinel completion notification unchecked. The records should not simultaneously claim complete and incomplete status.

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

## 16. Immediate 30-Day Action Plan

### Week 1

- Freeze a fixed repository commit for review.
- Reproduce all 51 tests and the 29/0 demo result.
- Export raw logs into the evidence package.
- Build the Cedar differential corpus.
- Decide direct evaluator versus upgraded runtime.

### Week 2

- Remove the compatibility shim.
- Add policy crash/timeout tests.
- Add approval race and idempotency stress tests.
- Add audit verifier CLI.
- Define token key rotation.

### Week 3

- Implement budgets/rate limits with atomic semantics.
- Add adapter self-test and bypass checks.
- Expand SSRF controls to controlled resolution and IPv6.
- Add fault injection for DB and executor failure.

### Week 4

- Publish `v0.2.0` hardening evidence.
- Produce design-partner installation package draft.
- Select two bounded pilot workflows.
- Create OIDC/RLS technical design for `v0.4.0`.

### 30-day success criteria

- Cedar shim removed.
- No known fail-open path in tested reference integrations.
- Approval replay/race suite passes.
- Budget enforcement active.
- Audit verifier can validate exported events.
- One repeatable installation path documented.

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

Proceed with ActantOS as an Agent Runtime Control Plane, using Pi for demonstrable developer workflows and MCP as the strategic interoperability wedge. Treat the current implementation as **Enforcement Kernel Verified**, not yet enterprise-production qualified. Execute the versioned roadmap above, with the Cedar evaluator replacement and authenticated tenant boundaries as the two non-negotiable security milestones.

---

## Appendix A — Current Evidence Summary

```text
Reported verified commands:
- npm run typecheck
- npm run build
- npm test                     (51 passing)
- docker compose up -d --build
- npm run demo -- --url http://localhost:3100  (29 passed, 0 failed)

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

## Appendix B — Canonical Semantics That Must Not Drift

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
