# Incident and DR Runbooks

## Incident: High Latency
1. Check database CPU and active connections.
2. Scale up `actantosd` replicas if CPU bound.
3. Check Cedar evaluation engine logs.

## DR: Database Corruption
1. Halt write traffic (scale down `actantosd`).
2. Restore latest snapshot (see Backup and Restore).
3. Validate audit chain.
4. Resume traffic.
