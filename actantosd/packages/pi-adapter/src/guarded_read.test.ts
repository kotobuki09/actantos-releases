import assert from "node:assert/strict"
import test from "node:test"
import * as fs from "node:fs"
import * as os from "node:os"
import * as path from "node:path"

import {
  canonicalizeReadPath,
  isCredentialPath,
  GuardedAccessDenied,
} from "./guarded_read.ts"
import { shlexSplit } from "./guarded_bash.ts"

// ---------------------------------------------------------------------------
// Set up a temporary workspace for path tests
// ---------------------------------------------------------------------------

const tmpDir = os.tmpdir()
const workspaceRoot = fs.mkdtempSync(path.join(tmpDir, "actantos-test-"))
const outsideDir = fs.mkdtempSync(path.join(tmpDir, "actantos-outside-"))

// Create test files
fs.writeFileSync(path.join(workspaceRoot, "README.md"), "# Hello")
fs.writeFileSync(path.join(workspaceRoot, ".env"), "SECRET=hunter2")
fs.writeFileSync(path.join(outsideDir, "outside.txt"), "sensitive data")

// ---------------------------------------------------------------------------
// T3: Path traversal ../../outside → deny, canonicalization_failed
// ---------------------------------------------------------------------------

test("T3: path traversal ../../outside → canonicalization_failed", () => {
  // Attempt to escape workspace via ../..
  const userInput = `../../${path.basename(outsideDir)}/outside.txt`
  const result = canonicalizeReadPath(userInput, workspaceRoot, workspaceRoot)

  assert.equal(result.ok, false)
  if (!result.ok) {
    assert.ok(
      result.reason.includes("outside workspace") || result.reason.includes("does not exist"),
      `Expected workspace boundary error, got: ${result.reason}`,
    )
  }
})

// ---------------------------------------------------------------------------
// T4: Symlink to .env → deny
// ---------------------------------------------------------------------------

test("T4: symlink-to-.env → credential_access=true detected", () => {
  const symlinkPath = path.join(workspaceRoot, "link-to-env")

  // Ensure no previous symlink
  try { fs.unlinkSync(symlinkPath) } catch { /* ignore */ }

  // Create symlink inside workspace pointing to .env inside workspace
  fs.symlinkSync(path.join(workspaceRoot, ".env"), symlinkPath)

  const result = canonicalizeReadPath(symlinkPath, workspaceRoot, workspaceRoot)

  assert.equal(result.ok, true)
  if (result.ok) {
    // The canonical path should resolve to the real .env file
    const credentialCheck = isCredentialPath(result.path)
    assert.ok(credentialCheck, `Expected isCredentialPath=true, got false for path: ${result.path}`)
  }

  // Cleanup
  fs.unlinkSync(symlinkPath)
})

// ---------------------------------------------------------------------------
// T4b: Symlink to external .env → deny (outside workspace)
// ---------------------------------------------------------------------------

test("T4b: symlink escaping workspace boundary → canonicalization_failed", () => {
  const externalEnv = path.join(outsideDir, ".env")
  fs.writeFileSync(externalEnv, "SECRET=externalvalue")

  const symlinkPath = path.join(workspaceRoot, "bad-link")

  // Ensure no previous symlink
  try { fs.unlinkSync(symlinkPath) } catch { /* ignore */ }

  // Create symlink inside workspace pointing to external .env
  fs.symlinkSync(externalEnv, symlinkPath)

  const result = canonicalizeReadPath(symlinkPath, workspaceRoot, workspaceRoot)

  // The symlink target is outside workspace → should fail
  assert.equal(result.ok, false)
  if (!result.ok) {
    assert.ok(
      result.reason.includes("outside workspace"),
      `Expected 'outside workspace' error, got: ${result.reason}`,
    )
  }

  // Cleanup
  fs.unlinkSync(symlinkPath)
})

// ---------------------------------------------------------------------------
// T5: Workspace2 (different workspace) → deny, canonicalization_failed
// ---------------------------------------------------------------------------

test("T5: path in different workspace root → canonicalization_failed", () => {
  // workspaceRoot is the valid workspace
  // outsideDir is a different workspace — reading from it should fail
  const userInput = path.join(outsideDir, "outside.txt")

  const result = canonicalizeReadPath(userInput, workspaceRoot, workspaceRoot)

  assert.equal(result.ok, false)
  if (!result.ok) {
    assert.ok(
      result.reason.includes("outside workspace"),
      `Expected 'outside workspace', got: ${result.reason}`,
    )
  }
})

// ---------------------------------------------------------------------------
// T1 (unit): Workspace file → canoniocalization ok, no credential path
// ---------------------------------------------------------------------------

test("T1 (unit): README.md in workspace → canonicalization ok", () => {
  const result = canonicalizeReadPath(
    "README.md",
    workspaceRoot,
    workspaceRoot,
  )

  assert.equal(result.ok, true)
  if (result.ok) {
    assert.ok(result.path.includes("README.md"))
    assert.equal(isCredentialPath(result.path), false)
  }
})

// ---------------------------------------------------------------------------
// T2 (unit): .env → credential path detected
// ---------------------------------------------------------------------------

test("T2 (unit): .env path → isCredentialPath=true", () => {
  assert.equal(isCredentialPath("/workspace/.env"), true)
  assert.equal(isCredentialPath("/workspace/.env.production"), true)
  assert.equal(isCredentialPath("/home/user/.ssh/id_rsa"), true)
  assert.equal(isCredentialPath("/workspace/.aws/credentials"), true)
  assert.equal(isCredentialPath("/workspace/README.md"), false)
  assert.equal(isCredentialPath("/workspace/src/index.ts"), false)
})

// ---------------------------------------------------------------------------
// Shell tokenizer tests
// ---------------------------------------------------------------------------

test("shlexSplit: simple command", () => {
  assert.deepEqual(shlexSplit("git push origin main"), ["git", "push", "origin", "main"])
})

test("shlexSplit: single-quoted args", () => {
  assert.deepEqual(
    shlexSplit("echo 'hello world'"),
    ["echo", "hello world"],
  )
})

test("shlexSplit: double-quoted args", () => {
  assert.deepEqual(
    shlexSplit('echo "hello world"'),
    ["echo", "hello world"],
  )
})

test("shlexSplit: unclosed quote → returns empty", () => {
  assert.deepEqual(shlexSplit("echo 'unclosed"), [])
})

test("shlexSplit: escaped space", () => {
  assert.deepEqual(shlexSplit("echo hello\\ world"), ["echo", "hello world"])
})
