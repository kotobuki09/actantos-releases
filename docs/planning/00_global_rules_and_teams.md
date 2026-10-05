# ActantOS Agent-Team Execution Plan — Global Rules

> **Prerequisites:** Read this file first before reading any version-specific plan file.
>
> **Domain language & strategy:** `CONTEXT.md` and `docs/adr/`. When a ticket conflicts with Pilot Freeze or claim language, ADRs win.

## Current phase (authoritative)

```text
1. Quiet Open-Core Release → v1.0.0_plan.md  ✅ complete / shipped
2. Forward execution       → forward_plan.md + forward_steps/  🟡 active
3. Design Partner Window   → design_partner_window_plan.md  (living pilots, freeze, unaided done)
```

Historical milestones **v0.2.0–v0.7.0** are **complete**. Do not create tickets against those files unless fixing docs-only drift.

Local engineering and public release for v1 are complete: typecheck/build/test verification, fresh-install smoke, artifacts, frozen `/v1` API, public tag, and release surface. Remaining work is **living validation through `forward_plan.md`**, not publishing or rebuilding the kernel.

Core promise:

> **No agent action executes without an ActantOS decision.**

---

## 0. Team lanes

Use these lanes for every version.

| Lane | Team                    | Responsibility                                                         |
| ---- | ----------------------- | ---------------------------------------------------------------------- |
| A0   | Release Captain         | Version scope, PR ordering, release evidence, changelog, tag, freeze   |
| A1   | Core API/DB             | Fastify routes, Zod schemas, Kysely/Postgres, migrations               |
| A2   | Policy/Budget           | Cedar provider, policy bundles, risk rules, dry-run, budgets           |
| A3   | Pi Adapter              | Guarded tools, canonicalization, fail-closed adapter behavior          |
| A4   | MCP Gateway             | MCP registry, manifest drift, SSRF, tools/list filtering, tools/call   |
| A5   | Security/QA             | Red-team tests, token tests, replay tests, fail-closed tests           |
| A6   | Approvals/Slack         | Slack integration, approval token flow, replay/expiry/signature checks |
| A7   | Console/UI              | Minimal operator console, evidence views, timeline, kill switch UI     |
| A8   | DevOps/CLI/Docs         | Docker Compose, CLI, OpenAPI, setup docs, backup/restore               |
| A9   | Pilot/Customer Workflow | Pilot scripts, onboarding playbooks, Success Package, evidence         |

### Phase focus (Design Partner Window)

| Lane | Default focus now |
| ---- | ----------------- |
| A0   | Forward-plan gates, claim hygiene, Escape Hatch approval |
| A3   | Pi pilot-blocking fixes only |
| A4   | MCP optional; no pilot-gating work unless hatch |
| A9   | Warm Pilot #1, Fit Checklist, Success Package, unaided done |
| A2   | Balanced default + Strict opt-in templates only |
| Others | P0/P1 and pilot-blocking only |

---

## 1. Global rules for every agent

Every agent must follow this rule:

```text
No feature is complete unless it has:
1. implementation
2. unit tests
3. integration tests where relevant
4. fail-closed behavior
5. audit event coverage
6. docs or operator notes
7. evidence attached to release package
```

**Pilot Freeze (ADR 0002):** During the design partner window, do not implement OIDC, gVisor, Firecracker, credential broker, SCIM, WORM product, multi-tenant SaaS, or new adapters unless a **written Escape Hatch** is approved first. Prefer docs/template fixes and pilot-blocking bugs.

**Claims (ADR 0003):** Do not write release notes or README language that implies living-customer proof until Proven Claim Gate. Tag is `v1.0.0` (open-core), not “proven production at customers.”

**Pi primary (ADR 0004):** Design Partner Pilot success is measured on Pi Primary Path. MCP remains supported and optional.

Required verification commands for every release:

```bash
npm run typecheck
npm run build
npm test
docker compose up -d --build
npm run demo -- --url http://localhost:3100
```

Prefer when available:

```bash
npm run release:verify
npm run smoke:fresh-install
npm run release:artifacts
```

If the version changes API behavior, also run:

```bash
npm run test:schemas
npm run test:migrations
npm run test:compat
```

---

## 2. Dependency order

### Historical (complete — do not restart)

```text
1. v0.2 Redaction, Slack, guarded tools, console, Cedar
2. v0.3 MCP registry/drift/SSRF
3. v0.4 Self-host/auth/CLI
4. v0.5 Policy bundle/budget/dry-run
5. v0.6 Chaos/token/audit verifier/red-team
6. v0.7 Evidence export/SIEM/onboarding playbooks
7. v1.0 local regression/artifacts/go (code Go)
```

### Current (execute in this order)

```text
1. FWD-001–005 readiness: status, measurement, claims, public artifact, provenance
2. FWD-006–009 living Pilot #1 sourcing, Fit, and acceptance
3. FWD-010 Success Package (2 weeks) on public artifact
4. FWD-011 Pilot Done (Unaided) or Auto-Kill ≤ 4 weeks from install
5. FWD-012 freeze-allowed fixes only from living evidence
6. FWD-013 Clone Pilot #2 after #1 unaided
7. FWD-014 day-90 decision and Proven Claim Gate updates
```

---

## 3. Recommended ticket format for agents

Use this template for every ticket:

```text
Ticket ID:
Version: (v1.0.0 | design-partner-window)
Priority:
Owner:
Reviewer:
Security reviewer:

Goal:
Pilot-blocking? (yes/no — if no, justify or reject under freeze)
Escape Hatch ref: (if any)
Files likely touched:
Dependencies:
Implementation steps:
Tests required:
Docs required:
Audit events required:
Failure behavior:
Evidence to attach:
Definition of done:
```

---

## 4. Version plan files

| Version / phase | File | Summary | Status |
| --- | --- | --- | --- |
| v0.2.0 | `v0.2.0_plan.md` | Demo Hardening MVP | ✅ Complete |
| v0.3.0 | `v0.3.0_plan.md` | MCP Hardening Beta | ✅ Complete |
| v0.4.0 | `v0.4.0_plan.md` | Self-Host Alpha | ✅ Complete |
| v0.5.0 | `v0.5.0_plan.md` | Policy & Budget Beta | ✅ Complete |
| v0.6.0 | `v0.6.0_plan.md` | Security Beta | ✅ Complete |
| v0.7.0 | `v0.7.0_plan.md` | Pilot Readiness Beta | ✅ Complete (eng) |
| v1.0.0 | `v1.0.0_plan.md` | Quiet Open-Core Release | ✅ Complete — shipped |
| Forward plan | `forward_plan.md` | Living validation → repeatability → gated platform | 🟡 Active |
| Design partner | `design_partner_window_plan.md` | Living pilot operating runbook | 🟡 Current |

---

## 5. First forward tickets to create now

```text
FWD-001 Reconcile canonical statuses and Pilot #1 must-hit language
FWD-002 Create pilot scorecard, support log, and friction taxonomy
FWD-003 Correct website claims and open-core pricing language
FWD-004 Verify public artifact from a clean environment
FWD-005 Decide artifact/image signing path
FWD-006 Build warm list and begin Pilot #1 outreach
FWD-007 Complete Fit interviews and accept one living candidate
```

Do **not** recreate v0.2 redaction/Slack tickets — those streams are complete.
