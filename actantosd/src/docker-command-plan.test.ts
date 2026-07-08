import assert from "node:assert/strict"
import test from "node:test"

import { DEFAULT_IMAGE, GIT_IMAGE, planDockerCommand } from "./docker-command-plan.ts"

test("planDockerCommand preserves non-git argv for the default image", () => {
  const plan = planDockerCommand(["printf", "hello"])

  assert.equal(plan.image, DEFAULT_IMAGE)
  assert.deepEqual(plan.containerArgv, ["printf", "hello"])
  assert.deepEqual(plan.dockerFlags, [])
})

test("planDockerCommand strips the git family token for the git image entrypoint", () => {
  const plan = planDockerCommand(["git", "push", "--dry-run", "origin", "main"])

  assert.equal(plan.image, GIT_IMAGE)
  assert.deepEqual(plan.containerArgv, [
    "-lc",
    "git config --global --add safe.directory \"*\" && exec git \"$@\"",
    "sh",
    "push",
    "--dry-run",
    "origin",
    "main",
  ])
  assert.deepEqual(plan.dockerFlags, [
    "--entrypoint",
    "sh",
    "--env",
    "HOME=/tmp",
  ])
})

test("planDockerCommand rejects an empty argv list", () => {
  assert.throws(
    () => {
      planDockerCommand([])
    },
    /argv must not be empty/u,
  )
})
