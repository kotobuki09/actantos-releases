# Support Runbook

## Basic health checks

Run in order:

```bash
curl http://localhost:3100/health/live
curl http://localhost:3100/health/ready
docker compose ps
```

Expected:

- `live` returns `200`
- `ready` returns `200` with `database: "connected"` when Postgres is enabled
- both `actantosd` and `postgres` are up in Compose

## Common recovery steps

`/health/ready` returns `503`

- inspect Postgres container logs
- confirm `.env` values for `POSTGRES_*` and `DATABASE_URL`
- rerun `docker compose up -d --build`

Demo or smoke path fails

- make sure the target URL is `http://localhost:3100`
- clear stale state with `docker compose down -v`
- restart Compose and rerun `npm run smoke:fresh-install`

Dashboard returns `401`

- provide `x-actantos-api-key`
- or append `?api_key=...` in the browser if `ACTANTOS_API_KEY` is enabled

Policy bundle upload fails

- validate Cedar syntax with `npm run policy:test`
- if using a real Cedar binary, inspect the parse error surfaced by `/v1/policy-bundles`

Webhook delivery fails

- confirm the receiver URL is reachable from the host running `actantosd`
- retry `POST /v1/webhooks/evidence`
- inspect the receiver for `x-actantos-event` and `x-actantos-signature`

## Backup and restore

Backup:

```bash
docker compose exec postgres pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" > actantosd-backup.sql
```

Restore:

```bash
cat actantosd-backup.sql | docker compose exec -T postgres psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"
```

## Audit and incident evidence

Use:

- `GET /v1/sessions/:session_id/events`
- `GET /v1/evidence/export?tenant_id=...&session_id=...`
- `GET /v1/metrics/usage?tenant_id=...`

These are the first-stop artifacts for pilot review and incident reconstruction.
