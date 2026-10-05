#!/usr/bin/env node
// Run the substrate-gated tests against a real external dependency.
//
// Why this exists rather than a plain npm script: several test files migrate and seed the same
// database, and Node runs test files concurrently. With DATABASE_URL exported, a plain
// `npm test` therefore deadlocks on DDL locks. This runner sets the opt-in flag and forces
// serial execution, so the substrate tests either run properly or skip cleanly.
//
// It also refuses to run without DATABASE_URL. A green run against no database would be a worse
// outcome than a clear failure, because the skip count would still look green.

import { spawnSync } from "node:child_process"
import path from "node:path"
import { fileURLToPath } from "node:url"

const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..")

if (!process.env["DATABASE_URL"]) {
  console.error(
    "test:substrate requires DATABASE_URL.\n" +
      "Start a PostgreSQL instance and export a connection string, for example:\n" +
      "  docker run -d --name actantos-sec-pg -p 55433:5432 " +
      "-e POSTGRES_USER=actantos -e POSTGRES_PASSWORD=actantos_sec_pw " +
      "-e POSTGRES_DB=actantos_sec postgres:16-alpine\n" +
      "  DATABASE_URL=postgresql://actantos:actantos_sec_pw@127.0.0.1:55433/actantos_sec npm run test:substrate",
  )
  process.exit(1)
}

const result = spawnSync(
  process.execPath,
  [
    "--experimental-strip-types",
    // One file at a time. The whole point of this script.
    "--test-concurrency=1",
    "--test",
    "src/v2/replay-store.test.ts",
    "src/v2/effect-gateway-replay.test.ts",
    "src/v2/evidence-store.test.ts",
    "src/v2/effect-commit.test.ts",
    "src/tenant-isolation.test.ts",
    "src/docker-executor-substrate.test.ts",
    "../packages/pi-adapter/src/shell_executor_substrate.test.ts",
    "scripts/security-fabric-state.test.mjs",
  ],
  {
    cwd: rootDir,
    stdio: "inherit",
    env: { ...process.env, ACTANTOS_SUBSTRATE_TESTS: "1" },
  },
)

process.exit(result.status ?? 1)