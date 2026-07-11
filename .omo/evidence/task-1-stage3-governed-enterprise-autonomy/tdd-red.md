# TDD red evidence

Command: `node --test scripts/validate-stage3-ledger.test.mjs`

Observed before implementation:

```text
Error [ERR_MODULE_NOT_FOUND]: Cannot find module '.../scripts/validate-stage3-ledger.mjs'
tests 1
pass 0
fail 1
```

The failure was caused by the intentionally absent validator, before production implementation was added.
