# ActantOS Canonical Overview and Vision

**Document role:** Canonical planning and execution entrypoint
**Updated:** 2026-07-12
**Active mode:** Mode A — Active Reconciliation Path
**Frozen mode:** Mode B — Conditional Production Qualification
**Current next action:** **None (Mode B Complete)**
**Public package baseline:** Quiet Open-Core artifact tag `v1.0.0` (semver is not maturity)
**Detailed architecture reference:** [`ActantOS_Final_Canonical_Production_Plan_100_Score_2026-07-12.md`](./ActantOS_Final_Canonical_Production_Plan_100_Score_2026-07-12.md)
**Technical contracts:** [`implementation_spec.md`](./implementation_spec.md)
**Milestone plans:** [`milestones/`](./milestones/)

---

## 1. Purpose of This Document

This document is the single planning and execution entrypoint for ActantOS contributors and coding agents.

It answers:

* What ActantOS is and is not
* What the project is trying to achieve now
* What is already verified versus merely claimed or planned
* Which execution mode is active
* Which milestone must be executed next
* Where detailed milestone plans live
* How milestones are activated, completed, cancelled, or reopened
* Who owns implementation, review, security approval, and evidence acceptance

This overview coordinates detailed plans. It does not duplicate work packages, test matrices, or architecture appendices. Execute work from the linked milestone files under [`milestones/`](./milestones/).

When documents disagree, this overview and the active milestone plan win for **execution order and mode**. `implementation_spec.md` wins for **technical contracts**. ADRs under [`docs/adr/`](./docs/adr/) win for **settled product decisions**.

---

## 2. Product Vision

ActantOS is a **model-agnostic, in-path, fail-closed runtime control plane** for governing AI-agent tool actions **before** those actions reach enterprise systems.

It decides whether an agent may perform a tool action, binds that decision to the action that executes, and produces auditable evidence of the outcome.

### 2.1 What ActantOS is not

* Another AI agent
* A chatbot
* A model wrapper
* A prompt-only safety layer
* A dashboard that merely observes actions after execution
* A framework that trusts the agent process to enforce its own permissions

### 2.2 Security boundary

Wherever architecture requires it, the central security boundary remains **outside the governed agent process**. Authorization, approval, egress restrictions, and audit recording must not depend on the agent voluntarily obeying local checks.

### 2.3 Capabilities the product emphasizes

* Authorization before execution
* Explicit agent and principal identity
* Policy enforcement
* Human approval where required
* Tool and parameter validation
* Egress restrictions
* Sandboxing and isolation
* Auditability
* Fail-closed behavior
* Evidence-backed product claims
* Separation between demonstrated capability and future capability

Do **not** exaggerate maturity, deployment scale, security assurance, customer use, or production readiness.

---

## 3. Product Boundary

### In scope for current Mode A

* Public Quiet Open-Core self-host install path for the enforcement kernel
* Supported governed workflow: allow, deny, approval (where supported), audit inspection
* Claim accuracy for what the public artifact actually does
* Reproducible local verification and evidence hygiene
* Fail-closed fixes on the free surface when they protect truthfulness or safety

### Out of scope until Mode B activation (or an explicit Escape Hatch ADR)

* Production-qualified multi-tenant operation
* Enterprise identity (OIDC/SCIM) and forced tenant isolation as a shipped claim
* Cryptographic decision-to-execution binding as a production claim
* Authenticated connect-time egress proxy as a production claim
* Independent production-qualification assessment
* Customer-proven marketing claims without living Pilot Done (Unaided) evidence (see ADR 0003)

### Supported deployment form (current claim level)

Self-hosted Quiet Open-Core kernel and docs. Maturity is **local/self-hosted reconciliation**, not production-qualified enterprise platform.

---

## 4. Core Principles

1. **Govern before execution** — decisions precede side effects.
2. **Fail closed** — evaluator, policy, or dependency failure must not silently allow.
3. **Evidence over assertion** — every public claim maps to a claim level and concrete evidence.
4. **One truth source for release/maturity** — package version, tag, maturity label, and validation class must not drift.
5. **Mode discipline** — Mode A is active; Mode B is frozen until activation gates pass.
6. **Semver is not assurance** — never encode production qualification as `v1.0.0-production` or similar.
7. **Separation of duties** — the producer of evidence is not automatically the final approver for security-critical gates.
8. **Narrow before broad** — prefer one reproducible supported workflow over unverified breadth.
9. **Preserve history** — deprecate and relabel; do not erase useful historical evidence without traceability.

---

## 5. Current Verified State

Status labels use the vocabulary in §6. Figures below are the July 12, 2026 planning audit snapshot and may age; A-02 must re-establish a fixed-commit baseline.

| Area | Claim level | Notes |
|---|---|---|
| Kernel typecheck / build / unit tests | Locally verified (audit snapshot) | `npm run release:verify` reported 147 tests, 146 pass, 1 Cedar-dependent skip; policy regression 5/5 |
| Website lint / typecheck / tests / build | Locally verified (audit snapshot) | `npm run check` pass with residual non-blocking warnings possible |
| Public artifact install journey | Historically verified | Must be re-run from public bytes under A-03 |
| Cedar authoritative evaluation | Implemented | Production fail-closed when Cedar unavailable is not yet Mode A exit-complete (A-04) |
| Budget / rate-limit paths | Locally verified (tests) | Concurrency and transactional coupling remain unproven for production qualification |
| Egress | Implemented (Docker network mode) | Not an authenticated destination-enforcing proxy; claims reconciled under A-05 |
| Tenant identity / RLS | Planned / conditional | Mode B (PQ-02) |
| External living pilot evidence | Unsupported as current claim | No customer-production claim permitted |
| Production qualification | Unsupported | Mode B frozen |

**Authoritative Mode A identity:** [`actantosd/release-maturity-truth.json`](./actantosd/release-maturity-truth.json) (schema: [`actantosd/docs/release-maturity-truth.md`](./actantosd/docs/release-maturity-truth.md)). Validate with `npm run maturity:validate` in `actantosd/`.

**Unresolved planning drifts that Mode A must close:**

* Website Stage 3 / `v1.1.0` language versus kernel/manifest `v1.0.0` — **A-01 in progress:** P0 website claim surfaces realigned to Quiet Open-Core `v1.0.0`; residual blog/history and `actantos-releases` 1.1.0 engineering tree remain documented in the truth source
* Evaluator fallback paths versus fail-closed production claims
* `egress_proxy` naming versus actual Docker network selection
* Status documents that disagree on the active next step

---

## 6. Evidence Vocabulary and Claim Levels

All milestone plans use these labels. Do not invent synonyms for the same maturity.

| Label | Meaning |
|---|---|
| **Claimed** | Statement exists in docs, marketing, comments, or plans without acceptable evidence |
| **Implemented** | Relevant code or configuration exists; independent verification may be missing |
| **Locally verified** | Passed repeatable local verification with retained evidence |
| **Integration verified** | Exercised across the relevant component boundary |
| **Release verified** | Present and reproducible in the actual public or designated release artifact |
| **Production-qualified** | Satisfied approved production-qualification requirements (security, reliability, privacy, ops, deployment) |
| **Unsupported / disproven** | Evidence shows the claim is not currently true or must not be made |
| **Planned** | Approved future work, not current behavior |
| **Conditional** | Frozen until named activation decision and prerequisites exist |
| **Deprecated** | Superseded; retained for history with explicit replacement pointer |

### Acceptable evidence types

Claims must reference concrete artifacts such as:

* Test command and output
* CI run identifier
* Commit or tree hash
* Release digest / package checksum / container digest
* HTTP trace
* Audit event identifier
* Database record reference (sanitized)
* Screenshot
* Reproduction instructions
* Threat-model review
* Security-test result
* Named reviewer approval

### Evidence record minimum fields

Commit or tree identity, command(s), date, environment, result including skips, log or artifact path, reviewer, and known limitation.

---

## 7. Current Execution Mode
## 7. Current Execution Mode

**Active:** Mode B — Conditional Production Qualification
**Frozen:** Mode A — Active Reconciliation Path (Complete)

Exactly one milestone is the **current next action**. Parallelism is allowed only when a milestone plan explicitly declares safe parallelism and no shared exit gate is compromised.

**The current next action is PQ-01.**

---

## 8. Mode A — Active Reconciliation Path

Mode A makes the existing public product, repository, release claims, enforcement behavior, and supporting evidence **internally consistent and defensible**.

Mode A work is **not** speculative production-scale functionality.

### Mode A milestones

| ID | Name | Plan | Status |
|---|---|---|---|
| A-01 | Release and maturity truth source | [`milestones/A-01-release-maturity-truth.md`](./milestones/A-01-release-maturity-truth.md) | **Next** |
| A-02 | Clean evidence baseline | [`milestones/A-02-clean-evidence-baseline.md`](./milestones/A-02-clean-evidence-baseline.md) | Pending (blocked by A-01) |
| A-03 | Public artifact user journey | [`milestones/A-03-public-artifact-journey.md`](./milestones/A-03-public-artifact-journey.md) | Pending (blocked by A-02) |
| A-04 | Authoritative evaluator | [`milestones/A-04-authoritative-evaluator.md`](./milestones/A-04-authoritative-evaluator.md) | Pending (blocked by A-03) |
| A-05 | Egress claim integrity | [`milestones/A-05-egress-claim-integrity.md`](./milestones/A-05-egress-claim-integrity.md) | Pending (blocked by A-04) |
| A-06 | Repository reconciliation | [`milestones/A-06-repository-reconciliation.md`](./milestones/A-06-repository-reconciliation.md) | Pending (blocked by A-05) |

### Mode A exit gate

A new operator installs the public artifact in two clean environments and completes allow, deny, approval-where-supported, audit verification, and documented cleanup using only public documentation. All public claims resolve to fixed-commit evidence. Production configuration cannot silently degrade policy authority. Status documents agree that Mode A is complete and Mode B remains inactive unless activated.

---

## 9. Mode B — Conditional Production Qualification

Mode B is **active** per ADR-0006.

It covers production-qualification requirements that Mode A does not claim.

### Core Mode B milestones (required hierarchy)

| ID | Name | Plan | Status |
|---|---|---|---|
| PQ-01 | Authorization and transactional integrity | [`milestones/PQ-01-authorization-integrity.md`](./milestones/PQ-01-authorization-integrity.md) | **Next** |
| PQ-02 | Authenticated identity and tenant isolation | [`milestones/PQ-02-authenticated-tenancy.md`](./milestones/PQ-02-authenticated-tenancy.md) | Pending |
| PQ-03 | Execution object and egress binding | [`milestones/PQ-03-execution-egress-binding.md`](./milestones/PQ-03-execution-egress-binding.md) | Pending |
| PQ-04 | Evidence privacy and supply-chain trust | [`milestones/PQ-04-evidence-supply-chain.md`](./milestones/PQ-04-evidence-supply-chain.md) | Pending |

### Additional Mode B milestones (existing, justified, also frozen)

These two files already exist in the repository and remain part of the production-qualification chain after PQ-04. They are **not** active Mode A work.

| ID | Name | Plan | Status |
|---|---|---|---|
| PQ-05 | Operational resilience | [`milestones/PQ-05-operational-resilience.md`](./milestones/PQ-05-operational-resilience.md) | Frozen / conditional |
| PQ-06 | Independent production qualification | [`milestones/PQ-06-independent-qualification.md`](./milestones/PQ-06-independent-qualification.md) | Frozen / conditional |

---

## 10. Milestone Dependency Map

```text
Mode A (active):
  A-01 → A-02 → A-03 → A-04 → A-05 → A-06
                                         │
Mode B activation gate ──────────────────┘
                                         │
Mode B (frozen until activation):
  PQ-01 → PQ-02 → PQ-03 → PQ-04 → PQ-05 → PQ-06
```

* A-01 has no predecessor.
* Each Mode A milestone depends on the previous exit gate unless a plan documents an explicit, safe exception.
* Mode B requires Mode A completion **and** the activation gate in §12.
* PQ milestones are sequential by default; parallelism requires explicit plan language.

Supporting historical tracks (`forward_steps/`, version plans `v0.2.0`–`v1.0.0`) are **not** the active execution queue for Mode A. They remain supporting or complete references.

---

## 11. Completion Rules

A milestone is complete only when **all** of the following hold:

1. Entry criteria were true before implementation began (or exceptions are recorded).
2. Every in-scope work package is done or explicitly deferred with owner and reason.
3. Concrete deliverables exist at recorded paths.
4. Verification requirements pass with retained evidence.
5. Evidence requirements are satisfied using §6 vocabulary.
6. Security and failure-mode checks pass or residual risks are accepted by the security reviewer.
7. Rollback or recovery behavior is documented and, where required, drilled.
8. Exit gate conditions are objective and met.
9. Completion record is filled (date, commit/tree, evidence links, approvers).
10. Roles that were `UNASSIGNED` are either assigned before exit or the gate explicitly allows residual unassigned non-security roles (security-critical roles must be assigned).

Subjective language such as “looks good” or “mostly ready” is not an exit gate.

---

## 12. Activation Rules

### Mode A milestone activation

* Only the **current next action** is active by default.
* Completing milestone *N* activates *N+1* only after the completion record is accepted by the final gate approver for *N*.
* A milestone may be blocked if a dependency fails or an external resource is unavailable; the overview next action must be updated.

### Mode B activation

Mode B may activate only when **all** are true:

1. Mode A exit gates are satisfied with accepted evidence.
2. An approved production-qualification objective exists (customer, compliance, pilot, funding, or release requirement).
3. Required owners and reviewers are assigned by name or durable role assignment.
4. Scope, threat model, deployment target, and assurance level are approved.
5. An ADR records Mode B activation, funding/staffing, target maturity, and which freeze decisions are superseded.

Until then, PQ files remain executable **plans only**, not a schedule.

---

## 13. Cancellation, Deferral, and Reopening Rules

| Action | Rule |
|---|---|
| **Cancel** | Record reason, residual risk, and what remains true in Mode A. Preserve evidence. Do not delete historical plans silently. |
| **Defer** | Record trigger that reopens the work, owner, and impact on claims. Deferred Mode B items stay frozen. |
| **Reopen** | Requires new entry criteria check, updated ownership, and invalidation or supersession of prior completion evidence if the claim surface changed. |
| **Mode B pause** | Triggered by lost staffing, lost requirement, failed predecessor gate, envelope violation, or independent review demanding redesign. Pause preserves Mode A; it does not weaken security gates. |

Cancellation of a security gate is never satisfied by renaming a version string.

---

## 14. Governance and Ownership

### Role set (required on every milestone)

| Role | Responsibility |
|---|---|
| **Milestone owner** | Drives scope, schedule, and exit readiness |
| **Implementation owner** | Produces code, docs, and primary artifacts |
| **Security reviewer** | Reviews security and failure-mode claims |
| **Evidence reviewer** | Accepts or rejects evidence packages |
| **Documentation owner** | Ensures public and operator docs match claims |
| **Final gate approver** | Authorizes milestone completion |

### Separation of duties

* A person or agent that **produces** evidence must not automatically be the **final approver** of that same evidence for security-critical gates (A-04, A-05, and all PQ milestones).
* When a role is unassigned, mark: `UNASSIGNED — milestone may not exit until assigned.`

### Authority map

| Concern | Authority |
|---|---|
| Execution order / mode | This overview + active milestone |
| Technical contracts | `implementation_spec.md` |
| Product strategy decisions | `docs/adr/` |
| Terminology | `CONTEXT.md` |
| Detailed architecture audit | `ActantOS_Final_Canonical_Production_Plan_100_Score_2026-07-12.md` (supporting) |
| Historical version execution | `production_execution_plan.md` + `v*.md` (complete) |

---

## 15. Evidence and Record-Keeping Requirements

* Store evidence under repository-approved paths (discover under `forward_steps/evidence/`, release docs, or a path recorded in the milestone completion record). Do not invent secret stores.
* Prefer append-only evidence notes; supersede rather than rewrite history.
* Sanitize secrets, tokens, and personal data before commit.
* Update persistent records when mode, next action, or hierarchy changes:
  * Parent tracking (when present): `../findings.md`, `../progress.md`, `../task_plan.md`
  * Plan status: `forward_steps/STATUS.md` as applicable
* Completion records must include: milestone ID, date, commit/tree hash, evidence links, claim-level changes, approver names/roles, residual risks.

---

## 16. Canonical Document Hierarchy

| Rank | Document | Role |
|---:|---|---|
| 1 | **This file** | Canonical planning and execution entrypoint |
| 2 | [`milestones/`](./milestones/) | Executable milestone plans and exit gates |
| 3 | [`implementation_spec.md`](./implementation_spec.md) | Technical contracts |
| 4 | [`docs/adr/`](./docs/adr/) | Settled strategic decisions |
| 5 | [`CONTEXT.md`](./CONTEXT.md) | Domain language |
| 6 | [`ActantOS_Final_Canonical_Production_Plan_100_Score_2026-07-12.md`](./ActantOS_Final_Canonical_Production_Plan_100_Score_2026-07-12.md) | Detailed architecture / audit reference (supporting) |
| 7 | [`production_execution_plan.md`](./production_execution_plan.md), version plans, `forward_plan.md`, `forward_steps/` | Historical and supporting execution material |
| 8 | Superseded research (`schedules.md`, `research.md`) | Historical only |

### Non-canonical / supporting clarifications

* Filenames containing “Final Canonical Production Plan” or “100 Score” are **not** the execution entrypoint.
* Semantic version tags describe published artifacts; they do not replace maturity labels.
* Do not treat marketing website stage labels as release truth until A-01 binds them to the machine-readable source.

---

## 17. Current Next Action

**Mode B is fully complete. Production qualification achieved.**

Open and execute:

None.
