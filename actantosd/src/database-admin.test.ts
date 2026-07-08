import assert from "node:assert/strict"
import test from "node:test"

import { parseDatabaseAdminCommand } from "./database-admin.ts"

test("parseDatabaseAdminCommand accepts supported database admin commands", () => {
  assert.equal(parseDatabaseAdminCommand("migrate"), "migrate")
  assert.equal(parseDatabaseAdminCommand("seed-demo"), "seed-demo")
})

test("parseDatabaseAdminCommand rejects unsupported database admin commands", () => {
  assert.throws(
    () => parseDatabaseAdminCommand("unknown"),
    /Expected a database command: migrate \| seed-demo/,
  )
})
