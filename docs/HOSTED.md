# Stage 2 hosted / single-tenant path

**Ship rule:** built + tests pass = done.

## What this is

Single-tenant self-host or hosted control plane install using Docker Compose:

- `actantosd` enforcement + operator APIs  
- Postgres for sessions, decisions, approvals, budgets, policy bundles  
- Health probes for orchestration  

Not multi-tenant SaaS. Not Firecracker isolation (Stage 3).

## Install (single tenant)

```bash
cd actantosd
cp .env.example .env   # if present; otherwise export vars below
docker compose up -d --build
```

### Required env

| Variable | Purpose |
|----------|---------|
| `DATABASE_URL` | Postgres DSN (compose default provided) |
| `PORT` | API port (default `3100`) |
| `HMAC_SECRET` | Decision token signing |
| `ACTANTOS_API_KEY` | Optional ops API key gate |

### Optional Stage 2 identity

| Variable | Purpose |
|----------|---------|
| `ACTANTOS_OIDC_ISSUER` | OIDC issuer URL |
| `ACTANTOS_OIDC_AUDIENCE` | Expected audience |
| `ACTANTOS_OIDC_CLIENT_SECRET` | HS256 shared secret (dev/Stage 2) |

When OIDC env is set, operator routes require `Authorization: Bearer <token>`. Runtime intercept (`/v1/intercept/tool-call`, `/v1/tool-result`) stays open for adapters.

## Health

| Endpoint | Meaning |
|----------|---------|
| `GET /health/live` | Process up |
| `GET /health/ready` | Ready when DB connected (or `not_configured` in memory mode) |

Compose `healthcheck` probes `/health/ready` on the actantosd service.

```bash
curl -sf http://127.0.0.1:3100/health/live
curl -sf http://127.0.0.1:3100/health/ready
```

## Operator surfaces

| Path | Role |
|------|------|
| `/dashboard` | Agents, sessions, decisions (filters), approvals, audit |
| `/dashboard/metrics` | Ops home rates, kill switch, budgets |
| `/dashboard/policy` | Bundle upload/activate/dry-run |

## Smoke checklist

1. `docker compose up -d --build`  
2. `/health/ready` returns `status: ready`  
3. `npm run demo` or portable quickstart against the instance  
4. `GET /v1/metrics/usage?tenant_id=t_demo` returns `ops_home` rates  
5. Policy dry-run: `POST /v1/policy-bundles/:id/test`  
