import assert from "node:assert/strict"
import { mkdir, mkdtemp, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import path from "node:path"
import test from "node:test"

import { parsePgBigInt, runSqlDirectory } from "./database.ts"
import { createTestDatabase } from "./test-database.ts"

test("parsePgBigInt accepts Postgres bigint strings without string concatenation semantics", () => {
  assert.equal(parsePgBigInt("0"), 0n)
  assert.equal(parsePgBigInt("9") + 1n, 10n)
  assert.equal(parsePgBigInt(12), 12n)
})

test("runSqlDirectory applies sql files in lexical order", async () => {
  const tempRoot = await mkdtemp(path.join(tmpdir(), "actantosd-sql-"))
  const sqlDirectory = path.join(tempRoot, "sql")
  const executedSql: string[] = []

  await mkdir(sqlDirectory)
  await writeFile(path.join(sqlDirectory, "002_second.sql"), "select 2;")
  await writeFile(path.join(sqlDirectory, "001_first.sql"), "select 1;")
  await writeFile(path.join(sqlDirectory, "ignore.txt"), "skip")

  await runSqlDirectory(
    {
      async query(sql) {
        executedSql.push(sql)
        return []
      },
    },
    "sql",
    { rootDirectory: tempRoot },
  )

  assert.deepEqual(executedSql, ["select 1;", "select 2;"])
})

test("createTestDatabase seeds the demo tenant row", async () => {
  const database = await createTestDatabase()

  try {
    const rows = await database.query<{ id: string; status: string }>(
      "SELECT id, status FROM tenants WHERE id = $1",
      ["t_demo"],
    )

    assert.deepEqual(rows, [{ id: "t_demo", status: "active" }])
  } finally {
    await database.close()
  }
})

test("createTestDatabase seeds the demo user row", async () => {
  const database = await createTestDatabase()

  try {
    const rows = await database.query<{ id: string; role: string; status: string }>(
      "SELECT id, role, status FROM users WHERE tenant_id = $1 AND id = $2",
      ["t_demo", "u_demo"],
    )

    assert.deepEqual(rows, [{ id: "u_demo", role: "operator", status: "active" }])
  } finally {
    await database.close()
  }
})
