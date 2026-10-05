import assert from "node:assert/strict"
import test from "node:test"

import { canonicalCommandHash, commandFromRequest } from "./decision-command.ts"

test("commandFromRequest reads argv and the declared host workspace from the request", () => {
  const command = commandFromRequest({
    action: { args: { argv: ["rm", "-rf", "x"], host_workspace_path: "/srv/work" } },
    resource: { path: "/workspace" },
  })

  assert.deepEqual(command.argv, ["rm", "-rf", "x"])
  assert.equal(command.workspacePath, "/srv/work")
})

test("commandFromRequest falls back to the directory holding the resource", () => {
  // A file is not a workspace. Falling back to the whole resource path meant
  // `/workspace/README.md` was offered to policy as a workspace, and a policy comparing it to an
  // approved root refused every ordinary file request.
  const command = commandFromRequest({
    action: { args: { argv: ["ls"] } },
    resource: { path: "/workspace/README.md" },
  })

  assert.equal(command.workspacePath, "/workspace")
})

test("commandFromRequest returns an empty argv rather than throwing on a malformed request", () => {
  // Fail closed at the digest, not with an exception from an unrelated tool call.
  const cases: readonly unknown[] = [
    {},
    { action: {} },
    { action: { args: {} } },
    { action: { args: { argv: "not-an-array" } } },
    { action: { args: { argv: ["ok", 42] } } },
    { action: { args: { argv: [null] } } },
  ]

  for (const request of cases) {
    const command = commandFromRequest(request as Parameters<typeof commandFromRequest>[0])
    assert.deepEqual(command.argv, [])
    assert.equal(command.workspacePath, "")
  }
})

test("the digest changes when any element of the argv changes", () => {
  const baseline = canonicalCommandHash(["printf", "hello"], "/workspace")

  const different = [
    canonicalCommandHash(["printf", "goodbye"], "/workspace"),
    canonicalCommandHash(["printf"], "/workspace"),
    canonicalCommandHash(["echo", "hello"], "/workspace"),
    canonicalCommandHash(["printf", "hello", "extra"], "/workspace"),
    canonicalCommandHash(["printf", "HELLO"], "/workspace"),
  ]

  for (const digest of different) {
    assert.notEqual(digest, baseline)
  }
})

test("the digest changes when the workspace changes", () => {
  assert.notEqual(
    canonicalCommandHash(["printf", "hello"], "/workspace"),
    canonicalCommandHash(["printf", "hello"], "/etc"),
  )
})

test("argv order is significant, so reordering produces a different digest", () => {
  assert.notEqual(
    canonicalCommandHash(["rm", "-rf", "x"], "/workspace"),
    canonicalCommandHash(["rm", "-x", "-rf"], "/workspace"),
  )
})

test("the digest is stable across calls and independent of the input array", () => {
  const argv = ["printf", "hello"]
  const first = canonicalCommandHash(argv, "/workspace")
  argv.push("mutated")
  const second = canonicalCommandHash(argv, "/workspace")

  assert.notEqual(first, second)
  assert.equal(second, canonicalCommandHash(["printf", "hello", "mutated"], "/workspace"))
})

test("empty argv and empty workspace are hashed, not skipped", () => {
  assert.equal(typeof canonicalCommandHash([], ""), "string")
  assert.notEqual(canonicalCommandHash([], ""), canonicalCommandHash([], "/workspace"))
  assert.notEqual(canonicalCommandHash([], ""), canonicalCommandHash([""], ""))
})
