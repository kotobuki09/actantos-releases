import assert from "node:assert/strict"
import { mkdtempSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { after, test } from "node:test"
import { execFileSync } from "node:child_process"

import { EvidenceChain } from "./v2/evidence.ts"
import { ed25519 } from "./v2/signature.ts"

/**
 * The CLI is the offline verification boundary: it must work with no running ActantOS, so it
 * is tested as a subprocess against files on disk rather than through an in-process call.
 */

const keyPair = ed25519.generateKeyPair()
const ISSUER = "issuer-primary"

const workdir = mkdtempSync(join(tmpdir(), "actant-verify-"))

after(() => {
  rmSync(workdir, { recursive: true, force: true })
})

const writeBundle = (name: string, bundle: unknown): string => {
  const path = join(workdir, name)
  writeFileSync(path, JSON.stringify(bundle))
  return path
}

const keysPath = join(workdir, "keys.json")
writeFileSync(
  keysPath,
  JSON.stringify({ [ISSUER]: keyPair.publicKeyPem }),
)

const buildChain = (): EvidenceChain => {
  const chain = new EvidenceChain({
    tenantId: "t_demo",
    issuerId: ISSUER,
    keyPair,
  })

  chain.append("delegation", {
    delegator: "spiffe://actantos.local/tenant/t_demo/agent/orchestrator",
    delegatee: "spiffe://actantos.local/tenant/t_demo/agent/reviewer-1",
    scope: ["grant://github/org/repo/issues/read"],
  })

  chain.append("effect_execution", { permit_id: "permit-1", ok: true })

  return chain
}

const runCli = (
  bundlePath: string,
  extraArgs: string[] = [],
  trustedKeysPath = keysPath,
) => {
  try {
    const stdout = execFileSync(
      process.execPath,
      [
        "--experimental-strip-types",
        "src/cli-verify-evidence.ts",
        bundlePath,
        "--keys",
        trustedKeysPath,
        ...extraArgs,
      ],
      { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
    )

    return { status: 0, stdout, stderr: "" }
  } catch (error) {
    const failure = error as { status?: number; stdout?: string; stderr?: string }

    return {
      status: failure.status ?? 1,
      stdout: failure.stdout ?? "",
      stderr: failure.stderr ?? "",
    }
  }
}

test("actant verify: a genuine bundle verifies with exit code 0", () => {
  const bundlePath = writeBundle("valid.json", buildChain().export())
  const result = runCli(bundlePath)

  assert.equal(result.status, 0, result.stderr)
  assert.match(result.stdout, /Verified 2 evidence records/)
})

test("actant verify: reports the record count as JSON when asked", () => {
  const bundlePath = writeBundle("valid-json.json", buildChain().export())
  const result = runCli(bundlePath, ["--json"])

  assert.equal(result.status, 0, result.stderr)
  assert.deepEqual(JSON.parse(result.stdout), { valid: true, recordCount: 2 })
})

test("actant verify: a tampered payload fails with exit code 1", () => {
  const bundle = buildChain().export() as unknown as {
    records: { payload: unknown }[]
  }
  bundle.records[1]!.payload = { permit_id: "permit-1", ok: false }

  const bundlePath = writeBundle("tampered.json", bundle)
  const result = runCli(bundlePath)

  assert.equal(result.status, 1)
  assert.match(result.stderr, /Evidence verification FAILED/)
  assert.match(result.stderr, /record_hash_mismatch/)
})

test("actant verify: a removed record breaks the chain", () => {
  const bundle = buildChain().export() as unknown as {
    records: unknown[]
  }
  bundle.records.splice(0, 1)

  const bundlePath = writeBundle("truncated.json", bundle)
  const result = runCli(bundlePath, ["--json"])

  assert.equal(result.status, 1)
  const parsed = JSON.parse(result.stdout) as { valid: boolean; issues: unknown[] }
  assert.equal(parsed.valid, false)
  assert.ok(parsed.issues.length > 0)
})

test("actant verify: a signature from an untrusted issuer is rejected", () => {
  const otherKeysPath = join(workdir, "other-keys.json")
  // The right key, under an issuer id the verifier has never been told to trust.
  writeFileSync(
    otherKeysPath,
    JSON.stringify({ "issuer-not-trusted": keyPair.publicKeyPem }),
  )

  const bundlePath = writeBundle("untrusted.json", buildChain().export())
  const result = runCli(bundlePath, [], otherKeysPath)

  assert.equal(result.status, 1)
  assert.match(result.stderr, /untrusted_issuer/)
})

test("actant verify: the wrong key for a known issuer is rejected", () => {
  const wrongKeyPath = join(workdir, "wrong-key.json")
  writeFileSync(
    wrongKeyPath,
    JSON.stringify({ [ISSUER]: ed25519.generateKeyPair().publicKeyPem }),
  )

  const bundlePath = writeBundle("wrong-key-bundle.json", buildChain().export())
  const result = runCli(bundlePath, [], wrongKeyPath)

  assert.equal(result.status, 1)
  assert.match(result.stderr, /invalid_signature/)
})

test("actant verify: verification needs no running ActantOS and no database", () => {
  // The bundle is the only input. This test is the assertion: the CLI opens no connection and
  // reads no environment beyond its two file arguments, so it runs on an auditor's machine.
  const bundlePath = writeBundle("offline.json", buildChain().export())

  const result = execFileSync(
    process.execPath,
    [
      "--experimental-strip-types",
      "src/cli-verify-evidence.ts",
      bundlePath,
      "--keys",
      keysPath,
    ],
    {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      env: { PATH: process.env["PATH"] ?? "" },
    },
  )

  assert.match(result, /Verified 2 evidence records/)
})

test("actant verify: missing arguments exit with code 2", () => {
  try {
    execFileSync(
      process.execPath,
      ["--experimental-strip-types", "src/cli-verify-evidence.ts"],
      { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
    )
    assert.fail("expected the CLI to reject missing arguments")
  } catch (error) {
    assert.equal((error as { status?: number }).status, 2)
  }
})