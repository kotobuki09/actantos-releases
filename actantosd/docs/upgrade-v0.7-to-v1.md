# Upgrade Guide: `v0.7.0-pilot-beta` to `v1.0.0-production`

This guide defines the supported upgrade path from the pilot release to the production `v1` release.

## What changed

- `tenants` became a first-class table
- `users` became a first-class table
- tenant-scoped `risk_rule_sets` were introduced
- tenant-scoped `rate_limits` were introduced
- the seeded demo policy bundle is backfilled from the old placeholder `fake` source to the checked-in Cedar source

## Supported source state

The supported upgrade source is a database created from the `v0.7.0-pilot-beta` schema shape:

- core `001_day1_core.sql` tables exist
- pilot tenant data is already stored directly on the core tables
- no `tenants`, `users`, `risk_rule_sets`, or `rate_limits` tables exist yet

That source state is exercised by `src/migration-compatibility.test.ts`.

## Upgrade steps

1. Back up the current pilot database.
2. Stop write traffic to `actantosd`.
3. Deploy the `v1.0.0-production` image or package.
4. Run:

```bash
DATABASE_URL=postgres://... npm run db:migrate
```

5. Reseed the demo tenant only if you rely on the local demo fixtures:

```bash
DATABASE_URL=postgres://... npm run db:seed-demo
```

6. Verify:

```bash
curl http://localhost:3100/health/ready
npm run policy:regression
```

## Expected post-upgrade state

- `tenants` contains the existing pilot tenants
- `users` contains backfilled owners, session users, and approval actors
- the demo policy bundle contains the checked-in Cedar source, not the old `fake` placeholder
- existing sessions, decisions, approvals, and audit history remain queryable through the same `/v1` surfaces
