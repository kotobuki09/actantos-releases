import assert from "node:assert/strict"
import { execFileSync } from "node:child_process"
import { createHash, createHmac, randomUUID } from "node:crypto"
import test from "node:test"

import { canonicalCommandHash, executeShellCommand } from "./shell_executor.ts"
import { InMemoryDecisionNonceStore } from "../../../actantosd/src/decision-nonce-store.ts"

/**
 * The pi-adapter executor, proven against a real container.
 *
 * `shell_executor.test.ts` asserts the planned argv against a recorded command, which proves the
 * executor *decided* to refuse. It cannot show that a running container is subject to that
 * decision. These tests start real containers, so the claim is about the substrate — and they
 * are the reason `pi-adapter-shell-executor` can claim REAL_SUBSTRATE rather than SIMULATED.
 *
 * The point of running the fork on a real substrate is drift. Two executors written separately
 * agreeing on recorded argv can still disagree about what Docker actually receives. These tests
 * hold the same claims as `actantosd/src/docker-executor-substrate.test.ts`, so if one path
 * changes a flag the other does not, the runtime behaviour diverges visibly here.
 *
 * Gated behind `ACTANTOS_SUBSTRATE_TESTS=1` and run by actantosd's `npm run test:substrate`,
 * because they need a working Docker daemon and pull an image.
 *
 * What these tests do NOT establish: anything about gVisor. `checkRunsc` is stubbed to false
 * throughout, so the sandbox runtime stays out of the picture and these tests measure only the
 * command binding, the container hardening, and single-use tokens.
 */

const SUBSTRATE_PASS = process.env["ACTANTOS_SUBSTRATE_TESTS"] === "1"
const dockerAvailable = (() => {
  if (!SUBSTRATE_PASS) {
    return false
  }
  try {
    execFileSync("docker", ["version", "--format", "{{.Server.Version}}"], { stdio: "ignore" })
    return true
  } catch {
    return false
  }
})()

const skip = !dockerAvailable
const todo = skip
  ? "run `npm run test:substrate` on a host with a working Docker daemon — this needs real containers"
  : undefined

const secret = "pi-shell-executor-substrate-secret"
const WORKSPACE = process.cwd().replace(/\\/gu, "/")

const CONSTRAINTS = {
  max_output_bytes: 4_000,
  network_allowlist: [] as readonly string[],
  network_mode: "none",
  timeout_ms: 20_000,
} as const

/** Sorted-key JSON, matching the actantosd canonical form; see the drift guards. */
const sortJson = (value: unknown): unknown => {
  if (Array.isArray(value)) return value.map(sortJson)
  if (typeof value === "object" && value !== null) {
    const sorted: Record<string, unknown> = {}
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      sorted[key] = sortJson((value as Record<string, unknown>)[key])
    }
    return sorted
  }
  return value
}

const canonicalHash = (value: unknown): string =>
  createHash("sha256").update(JSON.stringify(sortJson(value)), "utf8").digest("hex")

const mintToken = (argv: readonly string[], overrides: Record<string, unknown> = {}): string => {
  const payload = JSON.stringify({
    request_id: "req_pi_substrate",
    tenant_id: "t_substrate",
    agent_id: "pi_substrate",
    session_id: "s_substrate",
    tool_name: "guarded_bash",
    scope_hash: "scope-substrate",
    constraints_hash: canonicalHash(CONSTRAINTS),
    command_hash: canonicalCommandHash(argv, WORKSPACE),
    nonce: randomUUID(),
    exp: Math.floor(Date.now() / 1_000) + 600,
    ...overrides,
  })

  return `${Buffer.from(payload, "utf8").toString("base64url")}.${createHmac("sha256", secret).update(payload).digest("base64url")}`
}

const baseRequest = (argv: readonly string[]) =>
  ({
    decisionToken: mintToken(argv),
    hmacSecret: secret,
    requestId: "req_pi_substrate",
    tenantId: "t_substrate",
    agentId: "pi_substrate",
    sessionId: "s_substrate",
    toolName: "guarded_bash",
    workspacePath: WORKSPACE,
    argv,
    networkMode: "none",
    timeoutMs: CONSTRAINTS.timeout_ms,
    maxOutputBytes: CONSTRAINTS.max_output_bytes,
  }) as Parameters<typeof executeShellCommand>[0]

/** The real Docker daemon, with runsc stubbed off so gVisor is not in the picture. */
const deps = (nonceStore = new InMemoryDecisionNonceStore()) => ({
  checkRunsc: () => false,
  nonceStore,
})

test("pi substrate: the authorized command really runs in the container", { skip: todo }, async () => {
  const argv = ["printf", "actantos-pi-substrate-ok"]

  const result = await executeShellCommand(baseRequest(argv), deps())

  assert.equal(result.status, "executed")
  assert.match(result.stdout, /actantos-pi-substrate-ok/u)
})

test("pi substrate: a substituted command is refused with Docker live behind it", { skip: todo }, async () => {
  // The claim `shell_executor.test.ts` cannot make. There, the refusal is observed against a
  // recorded command; here a real daemon is waiting, so this shows the decision is actually load
  // bearing for what runs.
  const authorized = ["printf", "authorized"]
  const substituted = ["printf", "actantos-pi-substituted"]

  await assert.rejects(
    () =>
      executeShellCommand(
        { ...baseRequest(authorized), argv: substituted } as Parameters<typeof executeShellCommand>[0],
        deps(),
      ),
    /decision token command mismatch/u,
  )
})

test("pi substrate: --network none leaves no name resolution in the container", { skip: todo }, async () => {
  const argv = ["nslookup", "example.com"]

  const result = await executeShellCommand(baseRequest(argv), deps()).catch(
    (error: unknown) => error as Error,
  )

  // Either the lookup fails inside the container, or alpine lacks nslookup. Both show the point:
  // no resolution succeeded. What must never happen is a successful answer.
  if (typeof result === "object" && "status" in result) {
    assert.equal(result.status, "failed")
    assert.doesNotMatch(result.stdout, /Address:?\s+\d+\.\d+\.\d+\.\d+/u)
  } else {
    assert.match(result.message, /nslookup|not found|image/u)
  }
})

test("pi substrate: the container runs as a non-root user", { skip: todo }, async () => {
  // `id -u` for real. The recorded-argv suite asserts `--user 1001:1001` was passed; this asserts
  // the container honoured it.
  const result = await executeShellCommand(baseRequest(["id", "-u"]), deps())

  assert.equal(result.status, "executed")
  assert.equal(result.stdout.trim(), "1001", "container ran as root")
})

test("pi substrate: the container root filesystem is read-only", { skip: todo }, async () => {
  // The probe location is chosen carefully, because both wrong choices pass silently.
  //
  // Writing to `/` fails for a non-root user whether or not the filesystem is read-only, so it
  // tests `--user`, not `--read-only`. Writing to `/tmp` always succeeds, because the executor
  // mounts a writable tmpfs there. An earlier version of this test used `/` and passed even with
  // `--read-only` deleted from the executor.
  //
  // `/etc` is the discriminating location: the reason differs. With `--read-only` the write fails
  // "Read-only file system"; without it, it fails "Permission denied" because of the uid. Both
  // give rc=1, so the exit code cannot tell them apart — the message is what proves the flag is
  // doing the work.
  // `2>&1` is load-bearing: the executor captures stderr separately, so without it the reason
  // string never reaches stdout and the assertion below cannot see it.
  const result = await executeShellCommand(
    baseRequest(["sh", "-c", "touch /etc/read-only-probe 2>&1; echo rc=$?"]),
    deps(),
  )

  assert.equal(result.status, "executed")
  assert.match(
    result.stdout,
    /Read-only file system/u,
    "the write failed without that message, so the refusal came from the uid rather than the read-only flag",
  )
})

test("pi substrate: an expired token starts no container", { skip: todo }, async () => {
  const argv = ["printf", "actantos-pi-expired"]
  const request = {
    ...baseRequest(argv),
    decisionToken: mintToken(argv, { exp: Math.floor(Date.now() / 1_000) - 1 }),
  } as Parameters<typeof executeShellCommand>[0]

  const before = Date.now()
  await assert.rejects(() => executeShellCommand(request, deps()), /decision token expired/u)

  // Refused in well under the image-inspect timeout, so nothing was started and no pull began.
  assert.ok(
    Date.now() - before < 1_000,
    "expiry rejection was slow enough to suggest it contacted Docker",
  )
})

test("pi substrate: a forged signature starts no container", { skip: todo }, async () => {
  const argv = ["printf", "actantos-pi-forged"]
  const valid = baseRequest(argv).decisionToken
  const [payload] = valid.split(".")
  assert.ok(payload !== undefined)

  // A payload the policy engine never signed, signed with the wrong key.
  const forgedPayload = JSON.stringify({
    request_id: "req_pi_substrate",
    tenant_id: "t_substrate",
    agent_id: "pi_substrate",
    session_id: "s_substrate",
    tool_name: "guarded_bash",
    scope_hash: "scope-substrate",
    constraints_hash: canonicalHash(CONSTRAINTS),
    command_hash: canonicalCommandHash(argv, WORKSPACE),
    nonce: randomUUID(),
    decision: "allow",
    exp: Math.floor(Date.now() / 1_000) + 600,
  })
  const forged = `${Buffer.from(forgedPayload, "utf8").toString("base64url")}.${createHmac("sha256", "not-the-secret").update(forgedPayload).digest("base64url")}`

  await assert.rejects(
    () =>
      executeShellCommand(
        { ...baseRequest(argv), decisionToken: forged } as Parameters<typeof executeShellCommand>[0],
        deps(),
      ),
    /invalid decision token/u,
  )
})

test("pi substrate: one token yields one container, and a replay starts nothing", { skip: todo }, async () => {
  // S9 on a live substrate. The same claim `docker-executor-substrate.test.ts` makes on the
  // canonical executor; running both is what keeps the fork honest.
  const argv = ["printf", "actantos-pi-replay-probe"]
  const request = baseRequest(argv)
  const nonceStore = new InMemoryDecisionNonceStore()

  const first = await executeShellCommand(request, deps(nonceStore))
  assert.equal(first.status, "executed")
  assert.match(first.stdout, /actantos-pi-replay-probe/u)

  const before = Date.now()
  await assert.rejects(
    () => executeShellCommand(request, deps(nonceStore)),
    /decision token already used/u,
  )

  assert.ok(
    Date.now() - before < 1_000,
    "replay rejection was slow enough to suggest it started something",
  )
})