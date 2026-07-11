# Task 2 verification evidence

- Focused tests: `node --test scripts/stage3-preflight.test.mjs`
- Full tests: `npm test`
- Type check: `npm run typecheck`
- Offline manual lane: `node scripts/stage3-preflight.mjs --mode=offline` exits 0
- Required manual lane without configuration: `node scripts/stage3-preflight.mjs --mode=required` exits 2 with an explicit missing-key reason

Adversarial coverage includes malformed configuration, unavailable commands, hung probes, stale-cache avoidance through per-run execution, and misleading exit-zero output without the exact readiness marker. Flaky-test behavior is prevented by injected runners and no sleeps. Dirty-worktree isolation is handled by the dedicated worktree. Product-feature and live-cloud failure modes are not applicable to this infrastructure-only task.
