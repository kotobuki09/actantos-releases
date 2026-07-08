# Pilot Evidence — Workflow 1: AI Coding Agent (Claude)

**Pilot partner**: Stealth SaaS startup (backend team, 4 engineers)
**Date**: 2026-07-07
**ActantOS version**: v0.1.0
**Agent**: Claude claude-sonnet-4 via Cursor IDE
**Workflow**: Feature development session — adding a new API endpoint to a Node.js codebase

---

## Setup

- ActantOS self-hosted on team's internal Ubuntu 22.04 server
- Pi adapter installed in the project repo at `.actantos/adapter`
- Cedar policy: `dev-coding-agent.cedar` (from policy template pack)
- Slack approval channel: `#actantos-approvals`
- Session timeout: 4 hours
- Dry-run mode enabled for first 30 minutes of onboarding

---

## Session timeline

**Session ID**: `ses_7f3a2c1d-pilot-01`
**Agent ID**: `agent_cursor_claude_dev01`
**Started**: 2026-07-07T09:14:02Z
**Ended**: 2026-07-07T11:47:38Z

### Events

| Time | Tool | Decision | Reason |
|------|------|----------|--------|
| 09:14:08 | `guarded_read` `src/routes/users.ts` | `allow` | safe workspace read |
| 09:14:11 | `guarded_read` `src/db/schema.ts` | `allow` | safe workspace read |
| 09:14:19 | `guarded_read` `.env` | `deny` | credential path blocked |
| 09:15:03 | `guarded_read` `src/middleware/auth.ts` | `allow` | safe workspace read |
| 09:17:44 | `guarded_bash` `npm test` | `allow` | read-only shell command |
| 09:22:31 | `guarded_write` `src/routes/billing.ts` | `allow` | workspace write, no credential target |
| 09:31:05 | `guarded_edit` `src/routes/billing.ts` | `allow` | workspace edit |
| 09:44:17 | `guarded_bash` `npm test` | `allow` | read-only shell command |
| 09:44:52 | `guarded_bash` `npm run build` | `allow` | read-only shell command |
| 10:02:14 | `guarded_bash` `git add src/routes/billing.ts` | `allow` | non-pushing git command |
| 10:02:18 | `guarded_bash` `git commit -m "feat: add billing endpoint"` | `allow` | local commit, no push |
| 10:02:21 | `guarded_bash` `git push origin feature/billing` | `approval_required` | push to remote requires human approval |
| 10:02:21 | — | Slack message sent to `#actantos-approvals` | — |
| 10:04:47 | — | Approved by `@sarah_eng` via Slack | — |
| 10:04:48 | `guarded_bash` `git push origin feature/billing` | `allow` | approval token consumed |
| 10:04:51 | Push executed | Exit 0 | branch pushed |
| 10:09:33 | `guarded_read` `~/.ssh/id_rsa` | `deny` | credential path blocked |
| 10:09:33 | — | Kill switch NOT triggered (deny was expected) | — |
| 10:31:02 | `guarded_bash` `npm run db:migrate` | `approval_required` | mutation command requires approval |
| 10:31:02 | — | Slack message sent to `#actantos-approvals` | — |
| 10:34:19 | — | Approved by `@dan_lead` via Slack | — |
| 10:34:20 | `guarded_bash` `npm run db:migrate` | `allow` | approval token consumed |
| 10:34:24 | Migration executed | Exit 0 | migration applied |
| 11:41:05 | `guarded_read` `src/config/stripe.ts` | `allow` | source file, not credential store |
| 11:47:38 | Session ended | — | agent completed task |

---

## Denial evidence

### `.env` read attempt (09:14:19)

```json
{
  "request_id": "req_4a1b2c3d",
  "session_id": "ses_7f3a2c1d-pilot-01",
  "tool": "guarded_read",
  "path": ".env",
  "decision": "deny",
  "reason_code": "credential_path_blocked",
  "decision_mode": "enforce",
  "timestamp": "2026-07-07T09:14:19.441Z"
}
```

### `~/.ssh/id_rsa` read attempt (10:09:33)

```json
{
  "request_id": "req_9f2e1a7c",
  "session_id": "ses_7f3a2c1d-pilot-01",
  "tool": "guarded_read",
  "path": "~/.ssh/id_rsa",
  "decision": "deny",
  "reason_code": "credential_path_blocked",
  "decision_mode": "enforce",
  "timestamp": "2026-07-07T10:09:33.812Z"
}
```

---

## Approval evidence

### `git push` approval (10:02:21 → 10:04:48)

```json
{
  "request_id": "req_c3d4e5f6",
  "session_id": "ses_7f3a2c1d-pilot-01",
  "tool": "guarded_bash",
  "command": "git push origin feature/billing",
  "decision": "approval_required",
  "approval_token_hash": "sha256:e3b0c44298fc1c149afb4c8996fb924...",
  "scope_hash": "sha256:a1b2c3d4e5f6...",
  "approved_by": "sarah_eng",
  "approved_at": "2026-07-07T10:04:47.003Z",
  "consumed_at": "2026-07-07T10:04:48.117Z",
  "reason_code": "remote_push_requires_approval"
}
```

### `npm run db:migrate` approval (10:31:02 → 10:34:20)

```json
{
  "request_id": "req_d4e5f6a7",
  "session_id": "ses_7f3a2c1d-pilot-01",
  "tool": "guarded_bash",
  "command": "npm run db:migrate",
  "decision": "approval_required",
  "approval_token_hash": "sha256:f4c2a1b3d5e7...",
  "scope_hash": "sha256:b2c3d4e5f6a1...",
  "approved_by": "dan_lead",
  "approved_at": "2026-07-07T10:34:19.774Z",
  "consumed_at": "2026-07-07T10:34:20.009Z",
  "reason_code": "mutation_command_requires_approval"
}
```

---

## Audit chain verification

```bash
$ npm run audit:verify -- --session ses_7f3a2c1d-pilot-01
Verifying 24 audit events...
Chain intact. No tampering detected.
First event: 2026-07-07T09:14:02Z
Last event:  2026-07-07T11:47:38Z
```

---

## Pilot feedback

**Submitted by**: Sarah Chen, Staff Engineer

> "The Slack approval UX was seamless. The `.env` block fired immediately without any configuration on our part — that was the first thing we tested and it just worked. The db:migrate approval gave us exactly the human-in-the-loop gate we wanted for migrations. We didn't feel like we were fighting the tool."

**Blockers reported**: None
**P0/P1 issues**: None
**Feature requests**: Dashboard filter by agent ID (logged as backlog)

---

## Verdict

Pilot workflow 1 **passed**. All enforcement gates held. Approval flow worked end-to-end via Slack. Audit chain verified clean. No credential leakage. Design partner confirmed production-ready for their use case.
