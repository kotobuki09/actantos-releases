# Pilot Onboarding Guide

Last updated: `2026-07-07`

This guide is the Milestone 6 operator path for getting one governed agent workflow running without live support.

## What you need

- Node.js `22+`
- Docker Desktop with Compose
- One free local port for `actantosd` on `3100`
- A long random value for `HMAC_SECRET`
- Optional: an operator API key for the dashboard and admin endpoints

## 1. Start the stack

From `plan/actantosd`:

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

Run the smoke flow once:

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

## 3. Confirm the first governed workflow

Run:

```bash
npm run demo -- --url http://localhost:3100
```

The demo is the pilot acceptance story:

1. seeded agent/session/operator context exists
2. safe file read is allowed
3. secret read is denied
4. `git push --dry-run` requires approval
5. approval resumes execution with a one-use token
6. audit timeline proves the decision happened before execution
7. kill switch blocks the next action
8. evidence export returns the review package

## 4. Operator surfaces

Primary operator pages:

- `http://localhost:3100/dashboard?tenant_id=t_demo`
- `http://localhost:3100/dashboard/policy?tenant_id=t_demo`
- `http://localhost:3100/dashboard/metrics?tenant_id=t_demo`

If `ACTANTOS_API_KEY` is enabled, append `?api_key=...` in the browser or use the `x-actantos-api-key` header for API calls.

## 5. Policy and runtime controls

Useful starting endpoints:

- `GET /v1/policy-bundles?tenant_id=t_demo`
- `POST /v1/policy-bundles`
- `GET /v1/risk-rules?tenant_id=t_demo`
- `PUT /v1/risk-rules`
- `GET /v1/budgets?tenant_id=t_demo`
- `POST /v1/budgets`
- `GET /v1/rate-limits?tenant_id=t_demo`
- `PUT /v1/rate-limits`
- `GET /v1/metrics/usage?tenant_id=t_demo`
- `GET /v1/evidence/export?tenant_id=t_demo&session_id=s_demo`
- `POST /v1/webhooks/evidence`

Policy template starting points are in [`docs/pilot-policy-templates.md`](./pilot-policy-templates.md).

## 6. Pilot success check

The pilot is correctly installed when all of these are true:

- `/health/ready` returns `200`
- `npm run demo -- --url http://localhost:3100` ends with `0 failed`
- the operator dashboard loads
- policy bundles can be listed
- metrics return decision and tool-result counts
- evidence export downloads a JSON package
- webhook delivery returns a signed event to a receiver you control

## 7. If something fails

Use [`docs/support-runbook.md`](./support-runbook.md) for the first response path.
