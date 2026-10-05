# Evaluator mode (A-04)

ActantOS uses Cedar as the authoritative policy evaluator in production.

## Modes

| Mode | How selected | Missing Cedar CLI |
|---|---|---|
| `production` | `ACTANTOS_EVALUATOR_MODE=production`, or `ACTANTOS_REQUIRE_CEDAR=1`, or `NODE_ENV=production` | **Fail closed** — process refuses FakeCedar silent fallback |
| `development` | default when not production/test | FakeCedar allowed for local DX |
| `test` | `NODE_ENV=test` or `ACTANTOS_EVALUATOR_MODE=test` | FakeCedar allowed for unit tests |

## Operators

```bash
# Production / Quiet Open-Core self-host (recommended)
export ACTANTOS_REQUIRE_CEDAR=1
export CEDAR_CLI_PATH=/path/to/cedar   # if not on PATH
export CEDAR_POLICY_PATH=/path/to/policies/default.cedar
npm start
```

If startup prints `AuthoritativeEvaluatorUnavailableError` / FATAL about FakeCedar:

1. Install the Cedar CLI or mount the vendored binary used by Docker.
2. Set `CEDAR_CLI_PATH` correctly.
3. Do **not** set `ACTANTOS_EVALUATOR_MODE=development` in production.

## Verify

```bash
# Development (FakeCedar allowed if cedar missing)
node -e "import('./src/cedar-provider.ts').then(m => console.log(m.resolveEvaluatorMode(), m.createConfiguredCedarProvider({mode:'development'}).constructor.name))"

# Production probe (must throw if cedar missing)
ACTANTOS_EVALUATOR_MODE=production node --experimental-strip-types -e "import { createConfiguredCedarProvider } from './src/cedar-provider.ts'; createConfiguredCedarProvider({probeBinary:()=>false})"
```
