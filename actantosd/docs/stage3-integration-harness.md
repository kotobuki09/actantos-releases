# Stage 3 integration harness

The default `npm run stage3:preflight` is deterministic and offline. It performs no external calls.

`npm run stage3:preflight:optional` reports dependency health without blocking local work. `npm run stage3:preflight:required` is the hardened release lane: missing or malformed configuration exits 2; unavailable, timed-out, or marker-mismatched dependencies exit 1.

Required configuration:

- `DATABASE_URL` for a disposable PostgreSQL database
- `AWS_REGION`, `STAGE3_AWS_ACCOUNT_ID`, and `STAGE3_S3_BUCKET`
- `STAGE3_SPLUNK_HEC_URL`
- `STAGE3_WEBHOOK_URL` and `STAGE3_WEBHOOK_READY_MARKER`

Every invocation performs fresh bounded probes. No probe result is cached. Successful exit requires stdout, after trimming surrounding whitespace, to equal the dependency-specific marker exactly. Prefixes, suffixes, and embedded markers fail even when the command exits zero.

Load `sql/fixtures/stage3-two-tenant-rls.sql` after migrations to create deterministic alpha and beta tenant records. Run `psql "$DATABASE_URL" -f sql/fixtures/stage3-rls-preflight.sql` as a non-superuser to validate PostgreSQL RLS semantics independently of application policies. The preflight transaction rolls back all probe objects.
