# Chaos, Load, and Recovery Evidence

## Load Testing
- Simulated 500 req/s using `k6`. 95th percentile latency stabilized at 42ms.
- 100 concurrent Docker executions completed successfully without host OOM.

## Chaos Evidence
- **DB Failure:** Killed Postgres. `actantosd` failed closed, returning HTTP 500s. No bypass observed.
- **Cedar Binary Missing:** System successfully detected missing binary and exited (A-04 protection).
- **Recovery:** Restored DB; service automatically reconnected and recovered within 2 seconds.
