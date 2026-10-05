# Observability and Alert Set

## Key Metrics (Prometheus/Grafana)
- `actantos_decision_latency_ms`: Policy evaluation latency.
- `actantos_sandbox_restarts_total`: Number of failed or restarted Docker executors.
- `actantos_authz_denies_total`: Total number of denied tool calls.

## Alerts
- **HighLatency:** `actantos_decision_latency_ms{quantile="0.95"} > 50` for 5m.
- **HighErrorRate:** HTTP 5xx rate > 1% for 5m.
- **AuditChainBroken:** Fired if the background verification job fails.
