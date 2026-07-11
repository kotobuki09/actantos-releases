# Pilot Onboarding Guide

Last updated: `2026-07-09`  
**Stage:** Quiet Open-Core / Design Partner  
**Primary path:** **Pi Primary Path** (coding agents via guarded tools)  
**Secondary:** **MCP Optional Path** — supported, **not** required for Design Partner Pilot success

This guide gets one governed **coding** agent workflow running without live founder support. Use the [Design Partner kit](./design-partner-kit.md) for Fit Checklist and Success Package terms.

## What you need

- Node.js `22+`
- Docker Desktop with Compose
- One free local port for `actantosd` on `3100`
- A long random value for `HMAC_SECRET`
- Optional: an operator API key for the dashboard and admin endpoints
- Optional: Slack app credentials if you want Slack Approval (web Approval works without Slack)

## Path overview

```text
1. Start self-host stack
2. Verify install (smoke or demo)
3. Load Balanced Coding Policy (default) — or Strict opt-in
4. Connect Pi guarded tools (PRIMARY)
5. Exercise Pilot Workflow: allow / deny / approval_required
6. Optional later: MCP gateway (OPTIONAL)
7. Export evidence
```

---

## 1. Start the stack

From the `actantosd` package root:

```bash
cp .env.example .env
```

Set at least:

- `HMAC_SECRET`
- `ACTANTOS_API_KEY` if you want the operator plane protected from day one

Then start the stack:

```bash
docker compose up -d --build
```

Wait for readiness:

```bash
curl http://localhost:3100/health/ready
```

Expected response:

```json
{ "status": "ready", "database": "connected" }
```

## 2. Verify the fresh install path

```bash
npm run smoke:fresh-install
```

That command:

1. creates `.env` if needed  
2. installs dependencies  
3. builds the service  
4. starts Compose  
5. waits for `/health/ready`  
6. runs the end-to-end demo against `http://localhost:3100`  

Prefer installing from the public **`v1.0.0`** Quiet Open-Core artifact when available (see [release checklist](./release-checklist-v1.md)).

## 3. Confirm the first governed workflow (Pi Primary Path)

The demo **is** the coding Pilot Workflow story:

```bash
npm run demo -- --url http://localhost:3100
```

Expected story:

1. seeded agent/session/operator context exists  
2. safe file read is **allow**  
3. secret / credential read is **deny**  
4. `git push --dry-run` is **approval_required**  
5. Approval resumes execution with a one-use token  
6. audit timeline proves the Decision happened before execution  
7. kill switch blocks the next action  
8. evidence export returns the review package  

Optional Slack Approval:

```bash
npm run demo -- --url http://localhost:3100 --approval-mode slack
```

Web Approval remains on the Self-Host Free Surface without Slack.

### Connect a real coding agent (Pi Primary Path)

1. Install/configure the Pi guarded adapter so file/shell tools call `POST /v1/intercept/tool-call` before execution.  
2. Point the adapter at your `actantosd` base URL and API key.  
3. Keep ActantOS **on** during real feature work (not toggled off for speed).  
4. Approvers use the dashboard pending Approvals page and/or Slack.

Pi is pilot-gating. Do **not** block first success on MCP.

## 4. Load Balanced (default) or Strict (opt-in)

See [`docs/pilot-policy-templates.md`](./pilot-policy-templates.md).

| Posture | When |
| --- | --- |
| **Balanced Coding Policy** | Default Design Partner Pilot |
| **Strict Coding Policy** | Opt-in if the team wants more Approvals on mutations |

Pair Cedar templates with the default risk rules so `git push`, publish, and similar side effects stay `approval_required`.

## 5. Operator surfaces

Primary operator pages:

- `http://localhost:3100/dashboard?tenant_id=t_demo`
- `http://localhost:3100/dashboard/policy?tenant_id=t_demo`
- `http://localhost:3100/dashboard/metrics?tenant_id=t_demo`

If `ACTANTOS_API_KEY` is enabled, append `?api_key=...` in the browser or use the `x-actantos-api-key` header for API calls.

Useful endpoints:

- `GET /v1/policy-bundles?tenant_id=t_demo`
- `POST /v1/policy-bundles`
- `GET /v1/risk-rules?tenant_id=t_demo`
- `PUT /v1/risk-rules`
- `GET /v1/evidence/export?tenant_id=t_demo&session_id=s_demo`
- `POST /v1/webhooks/evidence`

## 6. MCP Optional Path (not required)

Only if the team already uses MCP clients and wants the gateway:

- Read [`docs/mcp-gateway-stable.md`](./mcp-gateway-stable.md)
- Point the MCP client at ActantOS, not directly at upstream servers
- Design Partner Pilot **success does not require** this path

## 7. Pilot success check (install quality)

The product is correctly installed when:

- `/health/ready` returns `200`
- `npm run demo -- --url http://localhost:3100` ends with `0 failed`
- the operator dashboard loads
- policy bundles can be listed
- evidence export downloads a JSON package

**Living pilot success** (Pilot Done Unaided) is defined in the [Design Partner kit](./design-partner-kit.md) — a second engineer, public docs only, multi-day use. Lab demo green is not Proven Claim Gate proof.

## 8. If something fails

Use [`docs/support-runbook.md`](./support-runbook.md) for the first response path.
