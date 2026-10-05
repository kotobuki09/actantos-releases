# SLO and Capacity Contract

## Service Level Objectives
- **Availability:** 99.9% uptime for the decision endpoint (`/v1/intercept/tool-call`).
- **Latency:** 95th percentile latency < 50ms for policy evaluation (excluding external network time).
- **RTO (Recovery Time Objective):** 1 hour for full recovery from backup.
- **RPO (Recovery Point Objective):** 24 hours (daily database backups).

## Capacity
- Supports up to 100 concurrent tool execution sandboxes per node.
- Postgres connections limited to 50 per replica.
