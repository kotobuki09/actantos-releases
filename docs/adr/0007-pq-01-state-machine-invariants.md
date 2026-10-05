# 7. PQ-01 State Machine Invariants

Date: 2026-07-12

## Status

Accepted

## Context

To achieve Production Qualification (Mode B), we must guarantee authorization and transactional integrity for tool calls. Currently, state transitions in `tool_calls` are implicit and updated via arbitrary SQL `UPDATE` statements without transition safeguards. We need a defined state machine with legal transitions to prevent double-execution, approval consumption races, and incomplete recovery from crashes.

## Decision

We are adopting a rigid state machine for `tool_calls` with the following states and legal transitions enforced at the database level:

### States

*   `pending`: Initial request received.
*   `decision_created`: Policy evaluated to allow.
*   `approval_pending`: Policy evaluated to require approval.
*   `approved`: Human approval granted and consumed.
*   `denied`: Policy evaluated to deny, or approval rejected.
*   `blocked`: Execution was prevented.
*   `executing`: Tool action is actively executing under a worker lease.
*   `executed`: Tool action completed successfully.
*   `failed`: Tool action completed with an error.
*   `timeout`: Tool action execution timed out.

### Legal Transitions

*   `pending` -> `decision_created` | `approval_pending` | `denied`
*   `approval_pending` -> `approved` | `denied`
*   `decision_created` -> `executing` | `blocked`
*   `approved` -> `executing` | `blocked`
*   `executing` -> `executed` | `failed` | `timeout`
*   *(Terminal states: `denied`, `blocked`, `executed`, `failed`, `timeout`)*

### Invariants

1.  **Atomicity:** Creating a job for execution must atomically transition the tool call to `executing` (or `approved` -> `executing`).
2.  **Idempotency:** Re-submitted requests with the same `request_id` must return the existing state and must not advance the state machine or create duplicate execution leases.
3.  **Approval Races:** Approval consumption must be atomic with the transition from `approval_pending` to `approved`.
4.  **Leases:** Transitions out of `executing` must settle the worker lease.

## Consequences

*   We must introduce a PostgreSQL migration (e.g., using a trigger) to reject illegal state transitions in `tool_calls`.
*   We must update `intercept-service.ts` and `tool-result-service.ts` to respect transaction boundaries and outbox/lease patterns.
*   A new worker lease and settlement mechanism must be implemented to manage the `executing` state.
