# Task 1 verification

## Focused contract suite

Command: `node --test scripts/validate-stage3-ledger.test.mjs`

Result: 5 tests passed, 0 failed. This covers the Stage 2 inventory characterization, valid Stage 3 ledger, misleading aggregate rejection, malformed/missing-ID rejection, and the CLI surface.

## Real CLI manual QA

Command: `npm run stage3:validate`

```text
Stage 3 ledger valid: 5 capabilities, aggregate active
```

Invalid-fixture command: `node scripts/validate-stage3-ledger.mjs ../.omo/evidence/task-1-stage3-governed-enterprise-autonomy/invalid-aggregate-ledger.json`

```text
aggregateStatus must be active for the recorded capability states
INVALID_EXIT_STATUS=1
```

The invalid fixture proves copied or misleading success text cannot replace the process exit status.

## Full regression suite

After `npm ci`, `npm test` completed with 163 tests passed, 0 failed, 0 skipped. It was run from PowerShell so the existing release-artifact test used Windows tar correctly; the earlier Git Bash run was environmentally invalid because Git tar interpreted the Windows drive prefix as a remote host.

## Adversarial review

- Malformed input: covered by test.
- Stale aggregate: covered by test and real CLI invalid fixture.
- Dirty worktree exclusions: generated release artifacts from the full test were restored and are not included.
- Misleading success output: CLI failure returns exit code 1; covered by manual QA.
- Network, concurrency, tenant isolation, credential leakage, and service degradation: N/A because this ledger validator performs local, read-only file validation and has no network, persistence, tenant, secret, or concurrent execution surface.
