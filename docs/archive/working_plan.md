# ActantOS Production Completion Plan

## 0. Current state

ActantOS already has a green Week 1 enforcement kernel. The current verified build includes `typecheck`, `build`, `51` passing tests, Docker Compose with Postgres, `demo.ts` passing with `29 passed, 0 failed`, stronger `decision_token` binding, `/v1/tool-result` verification, MCP gateway result logging, session timeline enrichment, MCP manifest drift enforcement, SSRF denial, and real HTTP/Postgres-backed verification.

The core product goal remains:

> **No agent action executes without an ActantOS decision.**

Production completion means ActantOS is no longer only a demo kernel. It must become a reliable self-hostable control plane that can govern a real Pi or MCP workflow for a design partner.

## 0.1 Current execution focus

> **Canonical status:** `production_execution_plan.md` · **Forward execution:** `forward_plan.md` · **Pilot runbook:** `design_partner_window_plan.md` · **Language/ADRs:** `CONTEXT.md`, `docs/adr/`.

Milestones 0–6 and local `V1-01`–`V1-10` engineering are complete. Baseline now includes `typecheck`, `build`, `145` tests, `policy:regression`, `smoke:fresh-install`, STRIDE threat model, fail-closed coverage, token/approval/SSRF/audit hardening, SBOM, pilot onboarding docs, frozen `/v1` API, `v0.7`→`v1` migration path, policy templates, MCP client docs, and release artifact generation. Local go/no-go (2026-07-08): **Go** for code/package.

**Do not restart v0.2–v0.7 ticket streams.**

### Historical transition phase (superseded by `forward_plan.md`)

```text
1) Quiet Open-Core Release — tag public v1.0.0 (no launch campaign) ✅ shipped
   - claim hygiene: not "battle-tested at customers"
   - Self-Host Free Surface: kernel + web approval + basic dashboard + optional Slack
   - Balanced Coding default; Strict opt-in
   - Pi Primary Path; MCP Optional

2) Internal dogfood validation ✅ complete
   - Pilot #1: coding team, Pi primary, Success Package (2 weeks)
   - Pilot Done (Unaided): second engineer, public docs only, ≤4 weeks
   - Pilot Freeze + one Escape Hatch max
   - Clone Pilot #2 only after #1 unaided
   - 90-day must-hit: public v1.0.0 + Pilot #1 unaided
```

```text
Current operating state:
- simple local/self-hosted solution verified
- internal dogfood scenario complete
- external pilot and Proven Claim Gate are optional future tracks, not active requirements
```

---

# 1. Production target

## Production v1 definition

ActantOS v1 is complete for the current scope when the published self-hosted artifact installs and governs a local agent workflow through verified allow, deny, approval, and audit paths.

Production v1 must support:

```text
1. Self-hosted deployment
2. Agent/session identity
3. Pi guarded adapter
4. MCP gateway
5. Cedar policy enforcement
6. Risk rules
7. Allow / deny / approval_required
8. Slack or web approval
9. Docker sandbox execution
10. Rate limits and budgets
11. Kill switch
12. Tamper-evident audit log
13. Minimal dashboard
14. CLI installer
15. Policy templates
16. SIEM/webhook export
17. Production documentation
18. Regression test suite
19. Security hardening baseline
20. Design partner pilot playbook
```

## Do not build Firecracker, full OIDC/SCIM, advanced credential broker, complex compliance packs, or multi-tenant SaaS before this. The spec explicitly separates MVP/Days 1–60 from later enterprise features and notes that gVisor/Firecracker, full SaaS deployment, credential broker, and OIDC are not Week 1 goals.

# 2. Team structure

Use 10 agent teams.

| Team                | Owner                  | Mission                                                          |
| ------------------- | ---------------------- | ---------------------------------------------------------------- |
| A0 Release Captain  | PM agent               | Break work into tickets, track gates, merge order, release notes |
| A1 Core API/DB      | Backend agent          | Fastify APIs, Kysely/Postgres, migrations, idempotency           |
| A2 Policy Engine    | Security/backend agent | Cedar provider, policy bundles, risk rules, decision pipeline    |
| A3 Pi Adapter       | TypeScript agent       | guarded_read/write/edit/bash/ls/grep/find/http/github            |
| A4 MCP Gateway      | Protocol agent         | MCP tools/list, tools/call, manifest drift, SSRF                 |
| A5 Sandbox Executor | Runtime/security agent | Docker execution, token checks, output limits, redaction         |
| A6 Approval System  | Integration agent      | Web approval, Slack approval, one-use token flow                 |
| A7 Dashboard/UI     | Frontend agent         | Agents, sessions, decisions, approvals, audit timeline           |
| A8 QA/Security      | Test/red-team agent    | Regression, attack tests, fail-closed, audit verification        |
| A9 Docs/DevEx       | Docs/CLI agent         | CLI, setup, demo, deployment docs, policy templates              |

Rule: every team must open a PR with tests and update the production checklist.

---

# 3. Release milestones

## Milestone 0 — Freeze current kernel

Version: `v0.1.0-week1-kernel`
Goal: protect the verified base before adding production features.

### Tasks

| ID    | Team | Task                      | Done when                          |
| ----- | ---- | ------------------------- | ---------------------------------- |
| M0-01 | A0   | Create release branch/tag | `v0.1.0-week1-kernel` exists       |
| M0-02 | A8   | Run baseline verification | typecheck/build/test/demo all pass |
| M0-03 | A0   | Create release notes      | Known issues documented            |
| M0-04 | A8   | Lock Week 1 tests         | T1–T12 run in CI                   |
| M0-05 | A9   | Update README quickstart  | Fresh setup works                  |

### Required commands

```bash
cd plan/actantosd
npm run typecheck
npm run build
npm test
docker compose up -d --build
npm run demo -- --url http://localhost:3100
```

### Exit gate

```text
- 51 tests pass
- demo passes
- Docker/Postgres path works
- Week 1 acceptance matrix passes
- current Cedar CLI provider behavior is verified without a non-credential fallback shim
```

The Week 1 acceptance matrix already defines the base done-state: safe read allowed, `.env` denied, path traversal denied, symlink secret denied, idempotency, approval resume, approval token reuse denial, kill switch, tool-result token rejection, and dry-run behavior.

---

## Milestone 1 — Demo-grade MVP

Version: `v0.2.0-demo-grade-mvp`
Target: 1–2 weeks
Goal: make ActantOS demoable to design partners.

### Product scope

```text
- Web approval page
- Slack approval
- guarded_write
- guarded_edit
- guarded_ls
- guarded_grep
- guarded_find
- Docker output limits
- Redaction
- Basic dashboard
- Stronger CLI demo
```

### Task breakdown

| ID    | Team | Task                   | Details                                           | Done when                                       |
| ----- | ---- | ---------------------- | ------------------------------------------------- | ----------------------------------------------- |
| M1-01 | A6   | Pending approvals page | List pending approvals with approve/deny          | Approval can be completed from UI               |
| M1-02 | A6   | Slack approval         | Send Slack message with approve/deny buttons      | `git push --dry-run` can be approved from Slack |
| M1-03 | A6   | Approval expiry job    | Mark pending approvals expired                    | Expired approvals cannot be consumed            |
| M1-04 | A3   | `guarded_write`        | Canonicalize parent path, deny credential targets | Safe workspace write works                      |
| M1-05 | A3   | `guarded_edit`         | Capture before/after hash and redacted diff       | Edit audit contains diff preview                |
| M1-06 | A3   | `guarded_ls`           | Workspace-only list                               | Traversal denied                                |
| M1-07 | A3   | `guarded_grep`         | Workspace-only grep with max output               | Secret paths denied                             |
| M1-08 | A3   | `guarded_find`         | Workspace-only find                               | `/workspace2` denied                            |
| M1-09 | A5   | Output limiter         | Enforce `max_output_bytes`                        | Large output truncated and hashed               |
| M1-10 | A5   | Secret redaction       | Scrub API keys, tokens, private keys              | Audit stores redacted preview only              |
| M1-11 | A7   | Dashboard v0           | Agents, Sessions, Decisions, Approvals, Audit     | Demo can show full flow                         |
| M1-12 | A9   | Demo script update     | 7-step demo with Slack option                     | New user can run under 10 minutes               |

### Dashboard screens

```text
1. Agents
2. Sessions
3. Decisions
4. Pending Approvals
5. Audit Timeline
```

The current architecture already expects approval_required to use manual API in Week 1 and Slack in Weeks 2–4.

### Exit gate

```text
- Week 1 tests still pass
- Slack approval works
- guarded_read/write/edit/bash/ls/grep/find pass
- dashboard shows every demo step
- audit timeline shows decision before execution
- no unredacted secrets in audit previews
```

---

## Milestone 2 — Production-shaped MCP gateway

Version: `v0.3.0-mcp-alpha`
Target: weeks 3–4
Goal: make MCP the strategic wedge, not just a proof.

### Product scope

```text
- MCP server registry
- MCP tools/list filtering
- MCP tools/call enforcement
- MCP manifest diff review
- MCP SSRF tests
- MCP approval flow
- MCP audit evidence
```

### Task breakdown

| ID    | Team  | Task                     | Details                                         | Done when                            |
| ----- | ----- | ------------------------ | ----------------------------------------------- | ------------------------------------ |
| M2-01 | A4    | MCP server registry      | CRUD for upstream MCP servers                   | Servers can be registered/disabled   |
| M2-02 | A4    | Approved tool baseline   | First manifest becomes approved baseline        | First clean call works               |
| M2-03 | A4    | Manifest drift detection | Schema/description hash drift stored as pending | Drifted tool call denied             |
| M2-04 | A7    | Manifest diff UI         | Show old vs new schema/description              | Admin can approve new version        |
| M2-05 | A4    | `tools/list` filtering   | Hide unauthorized or drifted tools              | Client sees only allowed tools       |
| M2-06 | A4    | `tools/call` enforcement | Every call goes through `/intercept/tool-call`  | No direct upstream call before allow |
| M2-07 | A4/A5 | URL-bearing SSRF checks  | Block localhost, metadata, RFC-1918             | SSRF tests pass                      |
| M2-08 | A6    | MCP approval routing     | Mutating MCP call can require approval          | Approval resume works                |
| M2-09 | A8    | MCP attack test suite    | Tool poisoning, rug pull, SSRF, shadow tool     | All MCP red-team tests pass          |
| M2-10 | A9    | MCP setup docs           | Cursor/Claude/custom client examples            | Fresh MCP demo works                 |

### MCP gateway responsibilities

The spec defines the MCP gateway as the trusted enforcement point responsible for authenticating identity, verifying manifest hashes, filtering `tools/list`, intercepting `tools/call`, enforcing SSRF blocklist, injecting scoped credentials, routing approval, executing in sandbox, and logging results.

### MCP test matrix

```text
MCP-T1: first manifest establishes approved baseline
MCP-T2: unchanged manifest allows
MCP-T3: schema hash drift denied
MCP-T4: description hash drift denied
MCP-T5: admin approves pending version
MCP-T6: approved version becomes new baseline
MCP-T7: localhost URL denied
MCP-T8: 127.0.0.1 denied
MCP-T9: 169.254.169.254 denied
MCP-T10: RFC-1918 IP denied
MCP-T11: mutating MCP tool requires approval
MCP-T12: unauthorized tool hidden from tools/list
```

### Exit gate

```text
- Normal MCP client connects through ActantOS
- Agent only sees policy-approved tools
- Drifted tools are disabled until admin approval
- URL SSRF attempts fail closed
- Every MCP call creates policy decision + tool result + audit event
```

---

## Milestone 3 — Self-hosted alpha

Version: `v0.4.0-self-host-alpha`
Target: weeks 5–6
Goal: deployable by a technical design partner.

### Product scope

```text
- Production Docker Compose
- Environment config
- Migration runner
- Health checks
- API key authentication
- Tenant model
- User/team basics
- CLI installer
- Backup/restore docs
```

### Task breakdown

| ID    | Team  | Task                  | Details                                 | Done when                          |
| ----- | ----- | --------------------- | --------------------------------------- | ---------------------------------- |
| M3-01 | A1    | Add `tenants` table   | Replace plain demo tenant behavior      | Tenant created during setup        |
| M3-02 | A1    | Add `users` table     | Admin/user roles                        | Approval records link to users     |
| M3-03 | A1    | Add API keys          | Hashed API keys, scoped to tenant       | Adapter authenticates with API key |
| M3-04 | A1    | Migration runner      | `npm run migrate`                       | Fresh DB migrates cleanly          |
| M3-05 | A9    | CLI `actantos init`   | Generate config, policy, compose files  | New project initializes            |
| M3-06 | A9    | CLI `actantos verify` | Check daemon, DB, Docker, policy        | Local health report works          |
| M3-07 | A0/A9 | Production compose    | `actantosd`, Postgres, dashboard, proxy | One command starts stack           |
| M3-08 | A1    | Health endpoints      | `/healthz`, `/readyz`, `/version`       | Compose health checks pass         |
| M3-09 | A1    | Backup docs           | Postgres backup/restore                 | Backup and restore tested          |
| M3-10 | A8    | Install smoke test    | Fresh machine install                   | Passes in under 15 minutes         |

### Exit gate

```text
- Fresh self-host install works
- No hardcoded `t_demo` required in production mode
- API keys protect all write/decision endpoints
- Migrations are repeatable
- Rollback instructions exist
- Health checks work
```

---

## Milestone 4 — Policy and budget productionization

Version: `v0.5.0-policy-budget-beta`
Target: weeks 7–8
Goal: make the policy layer useful for real pilot teams.

### Product scope

```text
- Policy bundle management
- Policy templates
- Risk rules editor/file loader
- Budget enforcement
- Rate limits
- Dry-run onboarding
- Policy test command
```

### Task breakdown

| ID    | Team  | Task                    | Details                                              | Done when                                      |
| ----- | ----- | ----------------------- | ---------------------------------------------------- | ---------------------------------------------- |
| M4-01 | A2    | Policy bundle CRUD      | Create, activate, rollback                           | Active policy switch works                     |
| M4-02 | A2    | Policy validation       | Cedar syntax validation before activation            | Bad policy rejected                            |
| M4-03 | A2    | Cedar compatibility fix | Remove or isolate shim                               | Non-credential permit is stable                |
| M4-04 | A2    | Risk rules loader       | JSON rules from DB/file                              | `git push`, `npm publish`, mutation rules work |
| M4-05 | A1/A2 | Budget enforcement      | Enforce `budgets` table                              | Exceeded budget returns `budget_exceeded`      |
| M4-06 | A1/A2 | Rate limits             | Tenant/agent/session/tool limits                     | Runaway loop blocked                           |
| M4-07 | A2/A9 | `actantos policy test`  | Test policy against sample requests                  | CLI shows allow/deny/approval                  |
| M4-08 | A2    | Dry-run mode            | Real decision, `decision_mode=dry_run`, no execution | Onboarding logs without execution              |
| M4-09 | A7    | Policy UI basic         | View active bundle, upload new bundle                | Admin can switch policy                        |
| M4-10 | A8    | Policy regression suite | Safe, denied, approval, budget, dry-run              | All pass                                       |

### Important dry-run rule

Dry-run must return the real decision with `decision_mode="dry_run"`, issue no decision token, consume no approval token, and execute nothing. There is no separate `would_deny` decision.

### Exit gate

```text
- Policy bundles can be activated and rolled back
- Bad Cedar policy cannot break production
- Budget/rate limits block runaway agents
- Dry-run onboarding works
- Policy tests run in CI
```

---

## Milestone 5 — Security hardening beta

Version: `v0.6.0-security-beta`
Target: weeks 9–10
Goal: become credible for security review.

### Product scope

```text
- Threat model
- Fail-closed test suite
- Audit hash-chain verifier
- Sandbox hardening
- Secret redaction test suite
- SBOM/dependency scanning
- Security docs
```

### Task breakdown

| ID    | Team | Task                      | Details                                                 | Done when                          |
| ----- | ---- | ------------------------- | ------------------------------------------------------- | ---------------------------------- |
| M5-01 | A8   | Threat model              | STRIDE-style document                                   | Top threats and mitigations mapped |
| M5-02 | A8   | Fail-closed tests         | Daemon down, timeout, bad response, bad token           | All block execution                |
| M5-03 | A5   | Sandbox constraints audit | Confirm non-root, no privileged, cap drop, network mode | Runtime test verifies flags        |
| M5-04 | A5   | Seccomp/AppArmor plan     | Phase 2 hardening target                                | Documented and partially tested    |
| M5-05 | A8   | Audit chain verifier      | Recompute event hashes from DB                          | Tamper detection works             |
| M5-06 | A8   | Redaction fuzz tests      | Tokens, keys, private keys, env secrets                 | No secret in preview               |
| M5-07 | A8   | Dependency scan           | npm audit/SBOM                                          | No critical unresolved vulns       |
| M5-08 | A8   | MCP attack tests          | Tool poisoning, rug pull, SSRF, manifest drift          | All pass                           |
| M5-09 | A0   | Security review checklist | Pre-pilot checklist                                     | No P0/P1 open                      |
| M5-10 | A9   | Security docs             | Fail-closed, sandbox, audit, approval docs              | Reviewed by team                   |

### Hardening guidance

Phase 2/3 hardening includes noexec mounts, dynamic loader restrictions, seccomp, AppArmor/SELinux, eBPF execve monitoring, stdin interception, distroless images, gVisor for single-tenant hosted, and Firecracker for multi-tenant SaaS.

### Exit gate

```text
- No known P0/P1 security issues
- Fail-closed tests pass
- Audit chain verifier works
- SSRF tests pass
- Sandbox config is automatically tested
- Redaction tests pass
```

---

## Milestone 6 — Pilot-ready production beta

Version: `v0.7.0-pilot-beta`
Target: weeks 11–12
Goal: ready for 2–3 design partners.

### Product scope

```text
- Stable self-host package
- Pilot onboarding guide
- Pilot policy templates
- Webhook/SIEM export
- Usage metrics
- Incident export
- Support runbook
```

### Task breakdown

| ID    | Team  | Task                   | Details                                         | Done when                     |
| ----- | ----- | ---------------------- | ----------------------------------------------- | ----------------------------- |
| M6-01 | A9    | Pilot onboarding guide | Install, configure, run first agent             | External user can follow      |
| M6-02 | A9/A2 | Policy templates       | Dev coding agent, MCP readonly, GitHub approval | Templates included            |
| M6-03 | A1    | Webhook export         | Send audit/security events                      | Receiver gets signed events   |
| M6-04 | A1/A7 | Usage metrics          | Decisions, denies, approvals, tool results      | Dashboard shows totals        |
| M6-05 | A7    | Incident export        | Export session/audit as JSON/CSV                | Security review package works |
| M6-06 | A0    | Support runbook        | Logs, restart, backup, common failures          | Operator can recover          |
| M6-07 | A8    | Pilot acceptance test  | Fresh install + real Pi/MCP workflow            | Passes                        |
| M6-08 | A0    | Pilot feedback form    | Capture blocker/feature/risk                    | Feedback process exists       |
| M6-09 | A0    | Release notes          | Known limitations clear                         | Customer-safe notes           |
| M6-10 | A0    | Go/no-go review        | Team signs off                                  | Pilot starts                  |

### Pilot acceptance scenario

```text
1. Install ActantOS self-host.
2. Register one Pi or MCP agent.
3. Start session.
4. Safe read is allowed.
5. Secret read is denied.
6. Risky action requires approval.
7. Approval resumes execution.
8. Kill switch blocks next action.
9. Audit timeline proves decision before execution.
10. Export evidence package.
```

The official demo flow already uses exactly this story: safe read, credential block, approval-required `git push --dry-run`, one-use approval, audit timeline, and kill switch.

### Exit gate

```text
- Design partner can install without founder intervention
- One real workflow runs end-to-end
- All audit evidence exportable
- All production docs complete
- No critical security gaps
```

---

## Milestone 7 — Quiet Open-Core v1 + design partners

Version: **`v1.0.0`** (Quiet Open-Core artifact tag — **not** “proven at customers”)  
Target: public tag soon; living unaided pilot within 90 days  
Goal: ship installable open-core; prove one coding pilot without founder forever.

> Detail tickets: `v1.0.0_plan.md` and `design_partner_window_plan.md`. ADR 0003 separates tag from Proven Claim Gate.

### Required for Quiet Open-Core tag `v1.0.0`

```text
- API schemas frozen (/v1)
- Migration compatibility tested (v0.7 → v1)
- Backup/restore tested
- Audit verifier tested (lab/fixture OK)
- Local regression + smoke:fresh-install green
- Release artifacts prepared
- Claim hygiene docs (open-core stage language)
- Balanced default + Strict opt-in documented
- Public tag v1.0.0 + quiet release surface upload
```

### Required for Proven Claim Gate (after tag)

```text
- Pilot #1 Pilot Done (Unaided) on Pi Primary Path
- Living evidence package (not fixture-only)
- Clone Pilot #2 for repeatability claims (stretch / second bar)
- Pricing: free self-host + Success Package (first 1–2 may waive)
```

### v1 task breakdown

| ID | Team | Task | Status / done when |
|---|---|---|---|
| V1-01 | A0 | API freeze | ✅ Versioned `/v1` API documented |
| V1-02 | A1 | Migration compatibility | ✅ Upgrade from v0.7 to v1 works |
| V1-03 | A8 | Full regression | ✅ Local suite/smoke green |
| V1-04 | A8 | Security regression | ✅ Fail-closed, SSRF, token, audit tests pass |
| V1-05 | A9 | Production docs | ✅ Install/upgrade/backup/security; 🟡 claim hygiene |
| V1-06 | A0 | Release artifacts | 🟡 Generate OK; ⬜ public tag + upload |
| V1-07 | A7 | Dashboard polish | ✅ Usable free-surface console |
| V1-08 | A2 | Policy template pack | 🟡 Ensure Balanced default + Strict opt-in |
| V1-09 | A4 | MCP stable docs | ✅ Supported; mark optional for pilots |
| V1-10 | A0 | Quiet Open-Core go/no-go | ✅ Public `v1.0.0` shipped |
| V1-11 | A9 | Living Pilot #1 unaided | ⬜ `design_partner_window_plan.md` |

---

# 4. Master dependency order

Do not let agents build randomly.

### Historical (complete)

```text
1. Freeze current kernel
2. CI and acceptance matrix
3. Approval UX
4. More guarded Pi tools
5. Docker/redaction hardening
6. Dashboard
7. MCP registry + manifest diff
8. Self-host deployment
9. Tenant/user/API key model
10. Policy bundle management
11. Budget/rate limit enforcement
12. Security hardening
13. Webhook/SIEM export
14. Pilot docs / playbooks
15. v1 local regression and artifacts
```

### Current

```text
16. Quiet Open-Core claim hygiene + tag v1.0.0
17. Warm Pilot #1 (coding, Pi) + Success Package
18. Pilot Done (Unaided) + freeze-allowed fixes only
19. Clone Pilot #2
20. Proven Claim Gate language
```

---

# 5. Production quality gates

## Gate A — Enforcement gate

```text
PASS if:
- every execution path requires allow decision_token
- denied action never executes
- approval_required action never executes before approval
- expired/reused approval token denied
- daemon down means fail closed
```

## Gate B — Audit gate

```text
PASS if:
- every request creates audit event
- every decision has reason_code
- every execution result has hash
- audit chain verifier passes
- tampering is detected
```

## Gate C — Sandbox gate

```text
PASS if:
- no host HOME mounted
- non-root user
- no privileged container
- capabilities dropped
- memory/cpu/pids limits enforced
- network none by default
- egress_proxy only by policy
- output size limit enforced
```

The MVP Docker constraints require workspace-only mounting, non-root user, read-only root where possible, no privileged mode, dropped capabilities, resource limits, default-deny egress, env allowlist, timeout, and output byte limit.

## Gate D — MCP gate

```text
PASS if:
- tools/list is filtered
- tools/call is intercepted
- manifest drift disables tool
- SSRF blocklist works
- raw user tokens are not passed upstream
- every MCP result logs back to same request_id
```

## Gate E — Pilot gate

```text
PASS if:
- fresh self-host setup works
- one real agent workflow works
- customer can approve/deny
- customer can export audit evidence
- support runbook covers common failures
```

---

# 6. Tickets to create immediately

Create these tickets in Plane/Jira/GitHub Projects.

## Epic E0 — Release Management

```text
E0-01 Tag v0.1.0-week1-kernel
E0-02 Add CI for typecheck/build/test/demo
E0-03 Add acceptance matrix runner
E0-04 Create release notes
E0-05 Create production checklist
```

## Epic E1 — Approval UX

```text
E1-01 Pending approvals API
E1-02 Pending approvals page
E1-03 Approve/deny page actions
E1-04 Slack app setup
E1-05 Slack approval message
E1-06 Slack callback verification
E1-07 Approval expiry job
E1-08 Approval audit events
```

## Epic E2 — Pi Adapter Expansion

```text
E2-01 guarded_write
E2-02 guarded_edit
E2-03 guarded_ls
E2-04 guarded_grep
E2-05 guarded_find
E2-06 guarded_http
E2-07 GitHub command classifier
E2-08 Adapter fail-closed test suite
```

## Epic E3 — Sandbox Runtime

```text
E3-01 Docker runtime config tests
E3-02 Output max byte enforcement
E3-03 Timeout enforcement
E3-04 Redacted preview
E3-05 stdout/stderr hashing
E3-06 egress_proxy mode test
E3-07 sandbox_unavailable handling
```

## Epic E4 — MCP Gateway

```text
E4-01 MCP server registry
E4-02 MCP tool baseline
E4-03 MCP manifest drift persistence
E4-04 MCP manifest approval route
E4-05 MCP diff UI
E4-06 tools/list filtering
E4-07 tools/call enforcement
E4-08 MCP SSRF test suite
E4-09 MCP mutating tool approval
```

## Epic E5 — Dashboard

```text
E5-01 Agents page
E5-02 Sessions page
E5-03 Decisions page
E5-04 Pending approvals page
E5-05 Audit timeline page
E5-06 Kill switch button
E5-07 Evidence export button
```

## Epic E6 — Self-host Deployment

```text
E6-01 Production docker-compose
E6-02 .env.example
E6-03 Migration runner
E6-04 Health endpoints
E6-05 API key auth
E6-06 Tenant table
E6-07 User table
E6-08 Backup/restore docs
E6-09 Fresh install test
```

## Epic E7 — Policy Productionization

```text
E7-01 Policy bundle CRUD
E7-02 Policy validation
E7-03 Policy activation/rollback
E7-04 Risk rules CRUD/file loader
E7-05 Budget enforcement
E7-06 Rate limits
E7-07 Dry-run onboarding mode
E7-08 actantos policy test
E7-09 Cedar compatibility fix
```

## Epic E8 — Security and QA

```text
E8-01 Threat model
E8-02 Fail-closed tests
E8-03 Token verification tests
E8-04 Approval replay tests
E8-05 SSRF tests
E8-06 Audit chain verifier
E8-07 Redaction fuzz tests
E8-08 Dependency scan
E8-09 SBOM
E8-10 Production security checklist
```

## Epic E9 — Docs and DevEx

```text
E9-01 actantos init
E9-02 actantos verify
E9-03 actantos run pi
E9-04 actantos demo
E9-05 Quickstart docs
E9-06 MCP client setup docs
E9-07 Pi adapter docs
E9-08 Policy template docs
E9-09 Pilot onboarding guide
E9-10 Support runbook
```

---

# 7. Agent prompts for each team

## A0 Release Captain prompt

```text
You are the ActantOS release captain. Your job is to coordinate production completion from v0.1.0-week1-kernel to v1.0. Maintain the release checklist, enforce milestone gates, block merges that break typecheck/build/tests/demo, and create release notes. Do not implement features unless needed to unblock release hygiene.
```

## A1 Core API/DB prompt

```text
You own ActantOS backend API and Postgres schema. Implement migrations, tenant/user/API-key model, health endpoints, policy bundle storage, budget/rate-limit tables, and webhook export. Preserve idempotency and hash-chain audit guarantees. Every schema change must include migration, rollback note, and tests.
```

## A2 Policy Engine prompt

```text
You own Cedar policy enforcement, risk rules, dry-run semantics, and budget/rate-limit decision logic. Cedar handles authorization only; ActantOS orchestration returns allow, deny, or approval_required. Never use LLM-as-judge for authorization. Add policy validation, policy test CLI support, and fix or isolate the current Cedar CLI compatibility shim.
```

## A3 Pi Adapter prompt

```text
You own packages/pi-adapter. Expand guarded tools: read, write, edit, bash, ls, grep, find, http, and GitHub operations. Every tool must canonicalize input before decision and before execution, fail closed on daemon errors, and never execute without an allow decision_token.
```

## A4 MCP Gateway prompt

```text
You own the MCP gateway. Implement server registry, tools/list filtering, tools/call interception, manifest hashing, manifest drift approval, SSRF blocking, and MCP audit evidence. The gateway is the trusted enforcement point; upstream MCP servers are variable trust.
```

## A5 Sandbox Executor prompt

```text
You own Docker execution. Verify decision_token before any work, enforce timeout, memory/cpu/pids, non-root, cap-drop, network mode, output byte limit, stdout/stderr hash, and redacted preview. Execution must fail closed on invalid token, expired token, constraint mismatch, or sandbox unavailable.
```

## A6 Approval System prompt

```text
You own human approval. Implement web approval and Slack approval using the existing one-use token design. Approval tokens must be random, stored only as hash, scoped by scope_hash, expire, and be consumed atomically once. Add approval audit events and replay/expiry tests.
```

## A7 Dashboard/UI prompt

```text
You own the minimal operator dashboard. Build only five screens first: Agents, Sessions, Decisions, Pending Approvals, Audit Timeline. Add kill switch and evidence export. Do not build analytics or enterprise UI until production gates pass.
```

## A8 QA/Security prompt

```text
You own regression, security tests, and production gates. Maintain T1–T12 and add MCP, fail-closed, token replay, SSRF, audit tamper, and redaction tests. No release passes with P0/P1 security failures.
```

## A9 Docs/DevEx prompt

```text
You own CLI, docs, setup, and pilot onboarding. Build actantos init, verify, demo, run pi, and policy test docs. A new developer should complete self-host setup and demo in under 15 minutes.
```

---

# 8. Daily execution rhythm

Every day:

```text
1. A0 posts current milestone board.
2. Each team works one ticket only.
3. Every PR includes tests.
4. A8 runs regression after merges.
5. Broken main is highest priority.
6. A0 updates release checklist.
```

Merge order:

```text
1. DB/API contracts
2. Backend service logic
3. Adapter/gateway logic
4. Sandbox execution
5. UI
6. CLI/docs
7. Security tests
```

Do not merge UI before API contracts stabilize.

---

# 9. Final production path

Use this production ladder:

```text
v0.1.0-week1-kernel
  Current verified base.

v0.2.0-demo-grade-mvp
  Slack approval, more guarded Pi tools, dashboard, redaction.

v0.3.0-mcp-alpha
  MCP registry, tools/list filtering, manifest drift, SSRF.

v0.4.0-self-host-alpha
  Production Compose, tenant/user/API key model, CLI init/verify.

v0.5.0-policy-budget-beta
  Policy bundles, validation, budget/rate limits, dry-run.

v0.6.0-security-beta
  Threat model, fail-closed tests, audit verifier, hardening.

v0.7.0-pilot-beta
  Docs, SIEM/webhook export, evidence export, pilot onboarding.

v1.0.0 (Quiet Open-Core)
  Public tag/ship and local/self-hosted validation complete; external Pilot #1 is optional.
```

Recommended immediate command for the agent team:

```text
Start with Milestone 0 and do not begin feature work until v0.1.0-week1-kernel is tagged and CI protects the current passing demo.
```
