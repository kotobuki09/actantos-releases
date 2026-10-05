import assert from "node:assert/strict"
import { createHash, createHmac, randomUUID } from "node:crypto"
import { EventEmitter } from "node:events"
import test from "node:test"

import { executeShellCommand } from "./shell_executor.ts"
import {
  canonicalCommandHash,
  dockerRegistersRunsc,
  type DecisionNonceEntry,
  type DecisionNonceStore,
  EGRESS_CELL_NETWORK,
  resolveSandboxRuntimeFlags,
  SandboxRuntimeUnavailableError,
  verifyDecisionTokenWith,
} from "./shell_executor.ts"
import { canonicalCommandHash as canonicalCommandHashServer } from "../../../actantosd/src/decision-command.ts"
import { canonicalHash as serverCanonicalHash } from "../../../actantosd/src/hash.ts"
import { EGRESS_CELL_NETWORK as serverEgressCellNetwork } from "../../../actantosd/src/v2/egress-cell.ts"
import {
  InMemoryDecisionNonceStore,
  ReplayStoreDecisionNonceStore,
} from "../../../actantosd/src/decision-nonce-store.ts"
import type { ReplayConsumeOutcome, ReplayStore } from "../../../actantosd/src/v2/replay-store.ts"
import {
  dockerRegistersRunsc as serverDockerRegistersRunsc,
  resolveSandboxRuntimeFlags as serverResolveSandboxRuntimeFlags,
} from "../../../actantosd/src/sandbox-runtime.ts"
import {
  signDecisionTokenEd25519 as serverSignDecisionTokenEd25519,
  verifyDecisionTokenEd25519 as serverVerifyDecisionTokenEd25519,
} from "../../../actantosd/src/decision-token-signature.ts"
import { ed25519 as serverEd25519 } from "../../../actantosd/src/v2/signature.ts"

const secret = "shell-executor-test-secret"

/**
 * A ReplayStore that answers `consume` from a script instead of a database.
 *
 * pi-adapter has no database, so the durable adapter cannot be exercised for real here. What can
 * be checked — and is what these drift tests are for — is that the adapter translates outcomes
 * faithfully: every outcome that is not an explicit `"consumed"` must become a refusal.
 */
const createRecordingReplayStore = (script: readonly string[]): ReplayStore => {
  const consumed = new Set<string>()
  let index = 0

  return {
    async consume(entry): Promise<ReplayConsumeOutcome> {
      const scripted = script[index] ?? "unavailable"
      index += 1

      if (scripted === "unavailable") {
        return { outcome: "unavailable", error: "database is down" }
      }

      if (scripted === "replay") {
        return { outcome: "replayed", reason: "nonce_already_consumed" }
      }

      consumed.add(`${entry.tenantId} ${entry.nonce}`)

      return { outcome: "consumed" }
    },
    async isConsumed(query): Promise<boolean> {
      return consumed.has(`${query.tenantId} ${query.nonce ?? ""}`)
    },
    async cleanupExpired(): Promise<number> {
      return 0
    },
  }
}

class FakeStream extends EventEmitter {
  setEncoding(): this {
    return this
  }
}

class FakeChildProcess extends EventEmitter {
  readonly stdout = new FakeStream()
  readonly stderr = new FakeStream()
  kill(): boolean {
    return true
  }
}

type SpawnCall = {
  readonly command: string
  readonly args: readonly string[]
}

/**
 * Records every docker invocation and lets a test decide each exit code.
 *
 * The default (all succeed) matches an environment where the image and network already
 * exist. Tests that exercise the creation branches pass an `exitFor` override.
 */
const createSpawnStub = (
  calls: SpawnCall[],
  exitFor: (call: SpawnCall) => number = () => 0,
) =>
  ((
    command: string,
    args: readonly string[],
  ): FakeChildProcess => {
    const call = { command, args } as SpawnCall
    calls.push(call)
    const child = new FakeChildProcess()
    queueMicrotask(() => {
      child.emit("exit", exitFor(call))
    })
    return child
  }) as never

/** Mirrors the server-side mint: HMAC over the raw payload string, same secret. */
const mintToken = (payload: Record<string, unknown>): string => {
  const raw = JSON.stringify(payload)
  const encoded = Buffer.from(raw, "utf8").toString("base64url")
  const signature = createHmac("sha256", secret).update(raw).digest("base64url")
  return `${encoded}.${signature}`
}

const AUTHORIZED_ARGV = ["printf", "hello"] as const
const AUTHORIZED_WORKSPACE = "/workspace"
const AUTHORIZED_NETWORK_MODE = "none" as const
const AUTHORIZED_TIMEOUT_MS = 1_000
const AUTHORIZED_MAX_OUTPUT_BYTES = 32

const sortJson = (value: unknown): unknown => {
  if (Array.isArray(value)) {
    return value.map(sortJson)
  }
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

/** Claims a real server-side mint would produce for the authorised command. */
const authorizedClaims = (): Record<string, unknown> => ({
  request_id: "req_shell_001",
  tenant_id: "t_demo",
  agent_id: "pi_demo",
  session_id: "s_demo",
  tool_name: "guarded_bash",
  scope_hash: "scope-demo",
  constraints_hash: canonicalHash({
    max_output_bytes: AUTHORIZED_MAX_OUTPUT_BYTES,
    network_allowlist: [],
    network_mode: AUTHORIZED_NETWORK_MODE,
    timeout_ms: AUTHORIZED_TIMEOUT_MS,
  }),
  command_hash: canonicalCommandHash(AUTHORIZED_ARGV, AUTHORIZED_WORKSPACE),
  // S9: a real server-side mint generates one per token, so a captured token is single-use.
  nonce: randomUUID(),
  exp: Math.floor(Date.now() / 1_000) + 600,
})

const createRequest = (overrides: Record<string, unknown> = {}) => ({
  decisionToken: mintToken(authorizedClaims()),
  hmacSecret: secret,
  requestId: "req_shell_001",
  tenantId: "t_demo",
  agentId: "pi_demo",
  sessionId: "s_demo",
  toolName: "guarded_bash",
  workspacePath: AUTHORIZED_WORKSPACE,
  argv: AUTHORIZED_ARGV,
  networkMode: AUTHORIZED_NETWORK_MODE,
  timeoutMs: AUTHORIZED_TIMEOUT_MS,
  maxOutputBytes: AUTHORIZED_MAX_OUTPUT_BYTES,
  ...overrides,
})

/**
 * Calls the real executor with a fresh nonce store, so tests that are not about S9 do not have to
 * think about it. A test that is about S9 passes its own store to observe reuse directly.
 */
const runShellCommand = (
  request: Parameters<typeof executeShellCommand>[0],
  dependencies: Partial<Parameters<typeof executeShellCommand>[1]> = {},
) => executeShellCommand(request, { nonceStore: new InMemoryDecisionNonceStore(), ...dependencies })

test("S8: a token issued for one command must not authorise a substituted destructive command", async () => {
  const calls: SpawnCall[] = []

  await assert.rejects(
    () =>
      runShellCommand(
        createRequest({
          argv: ["rm", "-rf", "/workspace/important"],
        }) as Parameters<typeof executeShellCommand>[0],
        { spawnCommand: createSpawnStub(calls) },
      ),
    /decision token command mismatch/u,
  )

  // The substituted command must never have reached a spawn.
  assert.deepEqual(calls, [])
})

test("S8: changing only a trailing argument invalidates the token", async () => {
  await assert.rejects(
    () =>
      runShellCommand(
        createRequest({ argv: ["printf", "goodbye"] }) as Parameters<
          typeof executeShellCommand
        >[0],
        { spawnCommand: createSpawnStub([]) },
      ),
    /decision token command mismatch/u,
  )
})

test("S8: reordering argv is a different command", async () => {
  await assert.rejects(
    () =>
      runShellCommand(
        createRequest({ argv: ["printf", "b", "a"] }) as Parameters<
          typeof executeShellCommand
        >[0],
        { spawnCommand: createSpawnStub([]) },
      ),
    /decision token command mismatch/u,
  )
})

test("S8: a token is rejected when the mounted workspace changes", async () => {
  await assert.rejects(
    () =>
      runShellCommand(
        createRequest({ workspacePath: "/etc" }) as Parameters<
          typeof executeShellCommand
        >[0],
        { spawnCommand: createSpawnStub([]) },
      ),
    /decision token command mismatch/u,
  )
})

test("S8: the authorised command still executes when nothing changed", async () => {
  const calls: SpawnCall[] = []
  const result = await runShellCommand(
    createRequest() as Parameters<typeof executeShellCommand>[0],
    { spawnCommand: createSpawnStub(calls) },
  )

  assert.equal(result.status, "executed")
  assert.ok(calls.some((call) => call.args.includes("printf")))
})

test("S9: an expired decision token is refused", async () => {
  await assert.rejects(
    () =>
      runShellCommand(
        createRequest({
          decisionToken: mintToken({
            ...authorizedClaims(),
            exp: Math.floor(Date.now() / 1_000) - 1,
          }),
        }) as Parameters<typeof executeShellCommand>[0],
        { spawnCommand: createSpawnStub([]) },
      ),
    /decision token expired/u,
  )
})

test("S9: the execution envelope is bound, so raising max_output_bytes is refused", async () => {
  await assert.rejects(
    () =>
      runShellCommand(
        createRequest({ maxOutputBytes: 10_000_000 }) as Parameters<
          typeof executeShellCommand
        >[0],
        { spawnCommand: createSpawnStub([]) },
      ),
    /decision token constraints mismatch/u,
  )
})

test("S9: widening the network mode after authorization is refused", async () => {
  await assert.rejects(
    () =>
      runShellCommand(
        createRequest({ networkMode: "egress_proxy" }) as Parameters<
          typeof executeShellCommand
        >[0],
        { spawnCommand: createSpawnStub([]) },
      ),
    /decision token constraints mismatch/u,
  )
})

/* -------------------------------------------------------------------------------------------- */
/* Drift guards                                                                                     */
/*                                                                                                  */
/* pi-adapter cannot import actantosd, so the canonical hash and runtime resolution are restated  */
/* here. These tests import the originals and assert the two agree, so a change on either side     */
/* fails rather than silently producing a digest the other side cannot reproduce.                   */
/* -------------------------------------------------------------------------------------------- */

test("drift guard: this file's command digest matches the canonical actantosd implementation", () => {
  const cases: readonly (readonly [readonly string[], string])[] = [
    [["printf", "hello"], "/workspace"],
    [["rm", "-rf", "/workspace/important"], "/workspace"],
    [["printf", "b", "a"], "/workspace"],
    [[], ""],
    [["git", "push", "--force"], "/srv/repo"],
    [["echo", "ünïcödé", "😀"], "/workspace"],
  ]

  for (const [argv, workspacePath] of cases) {
    assert.equal(
      canonicalCommandHash(argv, workspacePath),
      canonicalCommandHashServer(argv, workspacePath),
      `digest differs for ${JSON.stringify(argv)}`,
    )
  }
})

test("drift guard: the constraints digest matches the canonical actantosd hash", () => {
  // createDecisionConstraints defaults: network_allowlist is always [] on this path, which is
  // why the restated object can hardcode it.
  const cases: readonly {
    readonly networkMode: "none" | "egress_proxy"
    readonly timeoutMs: number
    readonly maxOutputBytes: number
  }[] = [
    { networkMode: "none", timeoutMs: 1000, maxOutputBytes: 32 },
    { networkMode: "egress_proxy", timeoutMs: 30_000, maxOutputBytes: 200_000 },
  ]

  for (const options of cases) {
    const restated = createHash("sha256")
      .update(
        JSON.stringify({
          max_output_bytes: options.maxOutputBytes,
          network_allowlist: [],
          network_mode: options.networkMode,
          timeout_ms: options.timeoutMs,
        }),
      )
      .digest("hex")

    assert.equal(
      restated,
      serverCanonicalHash({
        timeout_ms: options.timeoutMs,
        max_output_bytes: options.maxOutputBytes,
        network_mode: options.networkMode,
        network_allowlist: [],
      }),
    )
  }
})

test("drift guard: the egress cell network name matches actantosd", () => {
  assert.equal(EGRESS_CELL_NETWORK, serverEgressCellNetwork)
})

test("drift guard: sandbox runtime resolution matches actantosd across the whole probe matrix", () => {
  // Every combination of the two probes, compared against the actantosd implementation. Comparing
  // one case left the whole "binary present but daemon unregistered" row uncovered, which is
  // precisely the row the actantosd change was about.
  const previous = process.env["ACTANTOS_USE_GVISOR"]
  const outcome = (
    resolve: (binary: () => boolean, registry: () => boolean) => unknown,
    binaryAvailable: boolean,
    registryAvailable: boolean,
  ): unknown => {
    try {
      return resolve(() => binaryAvailable, () => registryAvailable)
    } catch (error) {
      return error instanceof Error ? `${error.name}: ${error.message}` : String(error)
    }
  }

  try {
    for (const binaryAvailable of [true, false]) {
      for (const registryAvailable of [true, false]) {
        process.env["ACTANTOS_USE_GVISOR"] = "true"
        assert.deepEqual(
          outcome(resolveSandboxRuntimeFlags, binaryAvailable, registryAvailable),
          outcome(serverResolveSandboxRuntimeFlags, binaryAvailable, registryAvailable),
          `binary=${binaryAvailable} registry=${registryAvailable}`,
        )
      }
    }

    delete process.env["ACTANTOS_USE_GVISOR"]
    assert.deepEqual(resolveSandboxRuntimeFlags(() => false), [])
  } finally {
    if (previous === undefined) {
      delete process.env["ACTANTOS_USE_GVISOR"]
    } else {
      process.env["ACTANTOS_USE_GVISOR"] = previous
    }
  }
})

test("drift guard: the daemon runtime registry is parsed the same way as in actantosd", () => {
  // `.Runtimes` is an object keyed by the name `--runtime` accepts, verified against a live
  // `docker info`. If either side drifts back to guessing the shape, this fails.
  const payloads: readonly string[] = [
    JSON.stringify({ "io.containerd.runc.v2": { path: "runc" }, runc: { path: "runc" } }),
    JSON.stringify({ runc: { path: "runc" }, runsc: { path: "/usr/local/bin/runsc" } }),
    JSON.stringify({ runc: { path: "/usr/bin/runsc-wrapper" } }),
    "not json",
    "null",
    "[]",
    '"runsc"',
    "",
    '{"__proto__":{"runsc":{}}}',
  ]

  for (const payload of payloads) {
    assert.equal(
      dockerRegistersRunsc(payload),
      serverDockerRegistersRunsc(payload),
      `payload: ${payload}`,
    )
  }

  assert.equal(serverDockerRegistersRunsc(payloads[0] ?? ""), false)
  assert.equal(serverDockerRegistersRunsc(payloads[1] ?? ""), true)
})

test("S12: runsc on PATH but unregistered by the daemon still refuses, naming the fix", () => {
  const previous = process.env["ACTANTOS_USE_GVISOR"]
  try {
    process.env["ACTANTOS_USE_GVISOR"] = "true"
    assert.throws(
      () => resolveSandboxRuntimeFlags(() => true, () => false),
      (error: unknown) =>
        error instanceof SandboxRuntimeUnavailableError &&
        /daemon has no runtime registered/u.test(error.message),
    )
    // A host with neither must not be told to edit daemon.json when the binary is simply absent.
    assert.throws(
      () => resolveSandboxRuntimeFlags(() => false, () => false),
      /not found on PATH/u,
    )
  } finally {
    if (previous === undefined) {
      delete process.env["ACTANTOS_USE_GVISOR"]
    } else {
      process.env["ACTANTOS_USE_GVISOR"] = previous
    }
  }
})

test("S12: a host requiring gVisor without runsc refuses rather than degrading", async () => {
  const previous = process.env["ACTANTOS_USE_GVISOR"]
  const calls: SpawnCall[] = []
  try {
    process.env["ACTANTOS_USE_GVISOR"] = "true"
    await assert.rejects(
      () =>
        runShellCommand(createRequest() as Parameters<typeof executeShellCommand>[0], {
          spawnCommand: createSpawnStub(calls),
          checkRunsc: () => false,
        }),
      SandboxRuntimeUnavailableError,
    )
    assert.deepEqual(calls, [])
  } finally {
    if (previous === undefined) {
      delete process.env["ACTANTOS_USE_GVISOR"]
    } else {
      process.env["ACTANTOS_USE_GVISOR"] = previous
    }
  }
})

test("S2: the egress cell is created internal, so the workload has no route off the host", async () => {
  const calls: SpawnCall[] = []
  // Re-mint the token for the egress_proxy envelope, as the server would.
  await runShellCommand(
    createRequest({
      networkMode: "egress_proxy",
      decisionToken: mintToken({
        ...authorizedClaims(),
        constraints_hash: canonicalHash({
          max_output_bytes: AUTHORIZED_MAX_OUTPUT_BYTES,
          network_allowlist: [],
          network_mode: "egress_proxy",
          timeout_ms: AUTHORIZED_TIMEOUT_MS,
        }),
      }),
    }) as Parameters<typeof executeShellCommand>[0],
    {
      // The cell does not exist yet, so inspect fails and create is attempted.
      spawnCommand: createSpawnStub(calls, (call) =>
        call.args[0] === "network" && call.args[1] === "inspect" ? 1 : 0,
      ),
      checkRunsc: () => false,
    },
  )

  const createCall = calls.find(
    (call) => call.command === "docker" && call.args[0] === "network" && call.args[1] === "create",
  )
  assert.ok(createCall, "expected the cell network to be created")
  assert.ok(
    createCall.args.includes("--internal"),
    `cell network must be created --internal, got ${JSON.stringify(createCall.args)}`,
  )
  assert.ok(createCall.args.includes(EGRESS_CELL_NETWORK))

  const runCall = calls.find((call) => call.args[0] === "run")
  assert.ok(runCall)
  assert.equal(runCall.args[runCall.args.indexOf("--network") + 1], EGRESS_CELL_NETWORK)
})

// --- S9: single-use decision tokens ---------------------------------------
//
// These use a recorded-argv stub, so they prove the executor *decided* to refuse. The matching
// claim against a live container is `actantosd/src/docker-executor-substrate.test.ts`.

test("S9: a decision token authorises one execution, and a replay spawns nothing", async () => {
  const nonceStore = new InMemoryDecisionNonceStore()
  const calls: SpawnCall[] = []
  const request = createRequest() as Parameters<typeof executeShellCommand>[0]

  const first = await runShellCommand(request, { spawnCommand: createSpawnStub(calls), nonceStore })
  assert.equal(first.status, "executed")
  const spawnsAfterFirst = calls.length
  assert.ok(spawnsAfterFirst > 0)

  await assert.rejects(
    () => runShellCommand(request, { spawnCommand: createSpawnStub(calls), nonceStore }),
    /decision token already used/u,
  )

  // No additional spawn of any kind: not docker run, not even an image inspect.
  assert.equal(calls.length, spawnsAfterFirst)
})

test("S9: a token with no nonce is refused rather than treated as exempt", async () => {
  const calls: SpawnCall[] = []
  const claims = authorizedClaims()
  delete claims["nonce"]

  await assert.rejects(
    () =>
      runShellCommand(
        { ...createRequest(), decisionToken: mintToken(claims) } as Parameters<
          typeof executeShellCommand
        >[0],
        { spawnCommand: createSpawnStub(calls) },
      ),
    /invalid decision token claims/u,
  )

  assert.deepEqual(calls, [])
})

test("S9: a token whose nonce is empty is refused", async () => {
  const calls: SpawnCall[] = []
  const claims = { ...authorizedClaims(), nonce: "" }

  await assert.rejects(
    () =>
      runShellCommand(
        { ...createRequest(), decisionToken: mintToken(claims) } as Parameters<
          typeof executeShellCommand
        >[0],
        { spawnCommand: createSpawnStub(calls) },
      ),
    /invalid decision token claims/u,
  )

  assert.deepEqual(calls, [])
})

test("S9: two independently issued tokens for the same command both execute", async () => {
  // The control. Single-use must not degenerate into "this command may run once, ever".
  const nonceStore = new InMemoryDecisionNonceStore()

  for (const _ of [1, 2]) {
    const calls: SpawnCall[] = []
    const result = await runShellCommand(createRequest() as Parameters<typeof executeShellCommand>[0], {
      spawnCommand: createSpawnStub(calls),
      nonceStore,
    })
    assert.equal(result.status, "executed")
  }
})

test("S9: the replay refusal names the nonce, not the command", async () => {
  // Asserting the exact reason matters. "already used" and "command mismatch" are different
  // failures, and a test that accepted either would pass even if the command binding broke.
  const nonceStore = new InMemoryDecisionNonceStore()
  const request = createRequest() as Parameters<typeof executeShellCommand>[0]

  await runShellCommand(request, { spawnCommand: createSpawnStub([]), nonceStore })

  await assert.rejects(
    () => runShellCommand(request, { spawnCommand: createSpawnStub([]), nonceStore }),
    (error: unknown) => {
      assert.ok(error instanceof Error)
      assert.equal(error.message, "decision token already used")
      return true
    },
  )
})

test("S9 drift: the actantosd nonce store satisfies the pi-adapter store interface", async () => {
  // pi-adapter restates the store type because it does not depend on actantosd. That restatement
  // is only safe while the actantosd classes keep satisfying it, so assert that directly for both
  // the in-memory and the durable adapter: a caller must be able to wire either one to both
  // executors without an adapter of its own.
  const entry = (nonce: string): DecisionNonceEntry => ({
    tenantId: "t1",
    permitId: "d1",
    nonce,
    expiresAt: new Date("2026-01-01T00:00:00Z"),
  })

  const memory: DecisionNonceStore = new InMemoryDecisionNonceStore()
  const durable: DecisionNonceStore = new ReplayStoreDecisionNonceStore(
    createRecordingReplayStore(["consumed", "replay", "consumed", "unavailable"]),
  )

  for (const store of [memory, durable]) {
    assert.equal(await store.consume(entry("n1")), true)
    assert.equal(await store.consume(entry("n1")), false)
    assert.equal(await store.consume(entry("n2")), true)
    assert.equal(await store.isConsumed(entry("n1")), true)
    assert.equal(await store.isConsumed(entry("never-seen")), false)
  }
})

test("S12 drift: the durable actantosd store refuses when the database cannot answer", async () => {
  // The restated interface promises "anything that is not an explicit success is a refusal". The
  // actantosd adapter is where that promise is actually kept, so pin the `unavailable` case here
  // too: pi-adapter must not be satisfiable by a store that lets a database outage through.
  const store: DecisionNonceStore = new ReplayStoreDecisionNonceStore(
    createRecordingReplayStore(["unavailable"]),
  )

  assert.equal(
    await store.consume({
      tenantId: "t1",
      permitId: "d1",
      nonce: "n1",
      expiresAt: new Date("2026-01-01T00:00:00Z"),
    }),
    false,
  )
})

// --- S7: the verifier must not also be the issuer ---------------------------
//
// pi-adapter restates Ed25519 verification because it does not depend on actantosd. The first
// two tests are drift guards: a token minted by the actantosd implementation must verify here,
// and the refusal must match.

test("S7 drift: a token signed by actantosd verifies through the pi-adapter implementation", () => {
  const keys = serverEd25519.generateKeyPair()
  const payload = JSON.stringify({ decision: "allow", command_hash: "abc" })

  const token = serverSignDecisionTokenEd25519(payload, keys.privateKeyPem)

  const result = verifyDecisionTokenWith(token, {
    kind: "ed25519",
    publicKeyPem: keys.publicKeyPem,
  })

  assert.equal(result.valid, true)
  assert.equal(result.valid ? result.payload : undefined, payload)
})

test("S7 drift: pi-adapter refuses a tampered token that the actantosd implementation refuses", () => {
  const keys = serverEd25519.generateKeyPair()
  const payload = JSON.stringify({ decision: "allow", command_hash: "abc" })
  const token = serverSignDecisionTokenEd25519(payload, keys.privateKeyPem)
  const [, encodedPayload, signature] = token.split(".")
  // Tamper at the byte level and re-encode, rather than editing the base64url text.
  //
  // Two earlier attempts edited characters and both could be no-ops. Replacing the last two
  // characters with "AA" changes nothing whenever a random signature already ends in "AA" -- about
  // once in four thousand runs. Changing the final character to a different letter is not enough
  // either: a 64-byte signature encodes to 86 base64url characters, and the last character carries
  // only 2 significant bits, so 16 different characters decode to the same final byte. Both
  // versions left the "forged" token bit-for-bit genuine on some runs, and it then verified
  // correctly and failed for reasons unrelated to either implementation.
  //
  // Flipping a bit in the decoded bytes is unambiguous: the signature differs whatever the
  // encoding does with it.
  const signatureBytes = Buffer.from(signature ?? "", "base64url")
  assert.ok(signatureBytes.length > 0, "expected a signature to tamper with")
  signatureBytes[0] = (signatureBytes[0] as number) ^ 0x01
  const tampered = `ed25519.${encodedPayload ?? ""}.${signatureBytes.toString("base64url")}`

  const local = verifyDecisionTokenWith(tampered, { kind: "ed25519", publicKeyPem: keys.publicKeyPem })
  const server = serverVerifyDecisionTokenEd25519(tampered, keys.publicKeyPem)

  assert.equal(local.valid, false)
  assert.equal(server.valid, false, "the two implementations disagreed on a forged token")
})

test("S7: an Ed25519-configured executor refuses an HMAC token", async () => {
  const keys = serverEd25519.generateKeyPair()
  const claims = authorizedClaims()
  const edToken = serverSignDecisionTokenEd25519(JSON.stringify(claims), keys.privateKeyPem)
  const hmacToken = mintToken(claims)

  // The asymmetric route is accepted, so the configuration is live and not merely present.
  const accepted = await runShellCommand(
    { ...createRequest(), decisionToken: edToken } as Parameters<typeof executeShellCommand>[0],
    { spawnCommand: createSpawnStub([]), tokenVerification: { kind: "ed25519", publicKeyPem: keys.publicKeyPem } },
  )
  assert.equal(accepted.status, "executed")

  // The downgrade is refused. If both were accepted, configuring Ed25519 would be cosmetic.
  await assert.rejects(
    () =>
      runShellCommand(
        { ...createRequest(), decisionToken: hmacToken } as Parameters<typeof executeShellCommand>[0],
        { spawnCommand: createSpawnStub([]), tokenVerification: { kind: "ed25519", publicKeyPem: keys.publicKeyPem } },
      ),
    /invalid decision token/u,
  )
})

test("S7: a token signed by an untrusted key is refused", async () => {
  const trusted = serverEd25519.generateKeyPair()
  const attacker = serverEd25519.generateKeyPair()
  const forged = serverSignDecisionTokenEd25519(
    JSON.stringify(authorizedClaims()),
    attacker.privateKeyPem,
  )

  await assert.rejects(
    () =>
      runShellCommand(
        { ...createRequest(), decisionToken: forged } as Parameters<typeof executeShellCommand>[0],
        { spawnCommand: createSpawnStub([]), tokenVerification: { kind: "ed25519", publicKeyPem: trusted.publicKeyPem } },
      ),
    /invalid decision token/u,
  )
})
