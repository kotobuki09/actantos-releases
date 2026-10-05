# Known Limitations and Supported Topology

## Supported Topology
- Dual-replica `actantosd` NodeJS service.
- Single primary Postgres 16 instance with async read replicas.
- Docker-socket mounted `actantosd` for executor spawning.

## Known Limitations
- Egress filtering is reliant on Docker networks; it does not intercept TLS.
- Database downgrades require manual DBA intervention.
- Cedar evaluation blocks synchronously (fail-closed if Cedar binary missing).
