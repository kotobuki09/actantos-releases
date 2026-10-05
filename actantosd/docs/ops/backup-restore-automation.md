# Backup and Restore Automation

## Backup Strategy
- **Database:** `pg_dump` daily to encrypted object storage.
- **Audit Logs:** Immutable audit chain synced in real-time.

## Restore Drill
1. Provision a new Postgres instance.
2. Download latest `pg_dump` snapshot.
3. Run `pg_restore -d actantos snapshot.sql`.
4. Run `npm run audit:verify` to check the chain integrity.
