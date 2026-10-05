# Rollback Readiness Confirmation

The rollback strategy has been tested. In the event of a critical failure post-deployment, we will scale down the new `actantosd` replicas, scale up the previous version replicas, and manually verify the database schema compatibility. The on-call engineer has access to the runbook.
