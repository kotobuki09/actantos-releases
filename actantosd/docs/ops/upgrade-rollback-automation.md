# Upgrade and Rollback Automation

## Upgrade
- Zero-downtime upgrades via rolling restarts (min 2 instances).
- Database migrations run using `-- actantos-pg-only` transactional locks.

## Rollback
- If an upgrade fails (e.g., error rate > 1%), automatically route traffic to the previous version.
- Note: Database schema downgrades are currently manual and require incident commander intervention. Rollback code version only if it's compatible with the new schema.
