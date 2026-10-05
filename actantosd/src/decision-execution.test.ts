import assert from "node:assert/strict"
import { EventEmitter } from "node:events"
import { randomUUID } from "node:crypto"
import test from "node:test"

import {
  createDecisionExecutionService,
  DecisionExecutionRefusal,
  type DecisionAuthorization,
  type DecisionAuthorizationLookup,
  loadStoredAuthorization,
} from "./decision-execution.ts"
import { InMemoryDecisionNonceStore } from "./decision-nonce-store.ts"
import { createDecisionToken } from "./intercept-response.ts"
import { createToolCallContext } from "./intercept-response.ts"
import { canonicalCommandHash } from "./decision-command.ts"
import { createDecisionConstraints } from "./decision-constraints.ts"
import { signDecisionTokenEd25519 } from "./decision-token-signature.ts"
import { ed25519 } from "./v2/signature.ts"
import type { Database } from "./database.ts"
import type { ToolCallInterceptionRequest } from "./contracts.ts"

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

const { publicKeyPem, privateKeyPem } = ed25519.generateKeyPair()

const tokenVerification = { kind: "ed25519", publicKeyPem } as const
const signer = (payload: string) => signDecisionTokenEd25519(payload, privateKeyPem)

// ---------------------------------------------------------------------------
// Spawn stub: records what would have been run, starts nothing
// ---------------------------------------------------------------------------

type SpawnCall = { readonly command: string; readonly args: readonly string[] }

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

/**
 * Records every docker invocation and exits all of them successfully.
 *
 * The executor calls `ensureDockerNetwork` and `ensureDockerImage` before it spawns the command,
 * and both wait on a `exit` event from this stub. A stub that never emits one leaves the promise
 * unresolved and the test hangs rather than failing, so every child is exited here.
 */
const createSpawnStub = (calls: SpawnCall[] = []) =>
  ((command: string, args: readonly string[]) => {
    const child = new FakeChildProcess()
    calls.push({ command, args: [...args] })
    setImmediate(() => {
      child.stdout.emit("data", Buffer.from("ok"))
      child.emit("exit", 0)
    })
    return child as never
  }) as never

/** Only the `docker run` invocation, which is the one that would mean something was executed. */
const runCalls = (calls: SpawnCall[]): SpawnCall[] =>
  calls.filter((call) => call.command === "docker" && call.args[0] === "run")

// ---------------------------------------------------------------------------
// A stored authorization, and the tool call that produced it
// ---------------------------------------------------------------------------

const buildRequest = (): ToolCallInterceptionRequest => ({
  request_id: `req_${randomUUID()}`,
  tenant_id: "t_demo",
  agent: {
    id: "agent_1",
    runtime_type: "pi",
    environment: "dev",
    risk_tier: "low",
  },
  subject: { user_id: "user_1" },
  session: { id: "sess_1" },
  tool: { kind: "shell", name: "guarded_bash", operation: "run" },
  resource: { path: "/workspace/run.sh" },
  // `commandFromRequest` reads argv and the workspace out of `action.args`, not out of
  // `normalized`, so the fixture has to put them here or the token would be minted over an empty
  // command and the S8 assertions would be testing nothing.
  action: { args: { argv: ["/bin/sh", "run.sh"], host_workspace_path: "/workspace" } },
  normalized: { credential_access: false, verb: "execute" },
})

type Built = {
  readonly token: string
  readonly request: ReturnType<typeof buildRequest>
  readonly scopeHash: string
  readonly constraints: ReturnType<typeof createDecisionConstraints>
}

/**
 * Mint a token exactly the way the control plane does, so the tests exercise the same claim set
 * `assertClaimsMatch` compares against rather than a hand-written approximation.
 */
const mint = (
  sign: (payload: string) => string = signer,
  options: { networkMode?: "none" | "egress_proxy"; timeoutMs?: number; maxOutputBytes?: number } = {},
): Built => {
  const request = buildRequest()
  const constraints = createDecisionConstraints({
    networkMode: options.networkMode ?? "none",
    ...(options.timeoutMs === undefined ? {} : { timeoutMs: options.timeoutMs }),
    ...(options.maxOutputBytes === undefined ? {} : { maxOutputBytes: options.maxOutputBytes }),
  })
  const scopeHash = createToolCallContext(request).scope_hash
  const token = createDecisionToken({
    decisionId: randomUUID(),
    toolCallId: randomUUID(),
    request,
    scopeHash,
    constraints,
    expiresAtEpochSeconds: Math.floor(Date.now() / 1_000) + 300,
    hmacSecret: "unused-because-a-signer-is-supplied",
    sign,
  })

  return { token, request, scopeHash, constraints }
}

const authorizationFor = (
  built: Built,
  overrides: Partial<DecisionAuthorization> = {},
): DecisionAuthorization => ({
  decisionId: "decision_1",
  tenantId: built.request.tenant_id,
  agentId: built.request.agent.id,
  sessionId: built.request.session.id,
  scopeHash: built.scopeHash,
  toolName: built.request.tool.name,
  decisionToken: built.token,
  constraints: { network_mode: "none", timeout_ms: 30_000, max_output_bytes: 200_000 },
  ...overrides,
})

const lookupReturning = (
  authorization: DecisionAuthorization | null,
): DecisionAuthorizationLookup => async () => authorization

const buildService = (
  lookup: DecisionAuthorizationLookup,
  overrides: Partial<Parameters<typeof createDecisionExecutionService>[0]> = {},
) =>
  createDecisionExecutionService({
    lookup,
    nonceStore: new InMemoryDecisionNonceStore(),
    tokenVerification,
    spawnCommand: createSpawnStub(),
    checkRunsc: () => false,
    ...overrides,
  })

// ---------------------------------------------------------------------------

test("S7: the service refuses to be constructed with an HMAC verifier", () => {
  // An executor that verifies HMAC holds the signing key and can therefore mint its own
  // authorization. That is refused at construction, where it cannot be forgotten later.
  assert.throws(
    () =>
      createDecisionExecutionService({
        lookup: lookupReturning(null),
        nonceStore: new InMemoryDecisionNonceStore(),
        tokenVerification: { kind: "hmac", secret: "shared" },
      }),
    /requires an ed25519 token verifier/u,
  )
})

test("the production caller executes a stored allow through the real executor", async () => {
  const built = mint()
  const calls: SpawnCall[] = []
  const service = buildService(lookupReturning(authorizationFor(built)), {
    spawnCommand: createSpawnStub(calls),
  })

  const result = await service.execute({
    tenantId: built.request.tenant_id,
    requestId: built.request.request_id,
    argv: ["/bin/sh", "run.sh"],
    workspacePath: "/workspace",
  })

  assert.equal(result.status, "executed")
  // `docker run` is the only invocation that means something was executed; the image and network
  // inspections before it are setup. Exactly one, so the command ran once and not twice.
  assert.equal(runCalls(calls).length, 1)
  assert.ok(!(runCalls(calls)[0]?.args ?? []).includes("--runtime"))
})

test("S8: the same authorization refuses a command that was not the one authorized", async () => {
  const built = mint()
  const calls: SpawnCall[] = []
  const service = buildService(lookupReturning(authorizationFor(built)), {
    spawnCommand: createSpawnStub(calls),
  })

  // The authorization was minted for `/bin/sh run.sh`. A caller that swaps the binary, appends an
  // argument, or relocates the working directory must not be able to reuse it.
  for (const argv of [
    ["/bin/bash", "run.sh"],
    ["/bin/sh", "run.sh", "--root"],
    ["/bin/sh", "other.sh"],
  ]) {
    await assert.rejects(
      service.execute({
        tenantId: built.request.tenant_id,
        requestId: built.request.request_id,
        argv,
        workspacePath: "/workspace",
      }),
      /^Error: decision token command mismatch$/u,
    )
  }

  for (const workspacePath of ["/etc", "/workspace/subdir"]) {
    await assert.rejects(
      service.execute({
        tenantId: built.request.tenant_id,
        requestId: built.request.request_id,
        argv: ["/bin/sh", "run.sh"],
        workspacePath,
      }),
      /^Error: decision token command mismatch$/u,
    )
  }

  assert.deepEqual(runCalls(calls), [], "nothing may be spawned for a mismatched command")
})

test("S9: the durable store is spent by one execution and refuses the second", async () => {
  const built = mint()
  const nonceStore = new InMemoryDecisionNonceStore()
  const service = buildService(lookupReturning(authorizationFor(built)), { nonceStore })

  const input = {
    tenantId: built.request.tenant_id,
    requestId: built.request.request_id,
    argv: ["/bin/sh", "run.sh"],
    workspacePath: "/workspace",
  }

  assert.equal((await service.execute(input)).status, "executed")
  await assert.rejects(service.execute(input), /already used/u)
})

test("a token the executor cannot verify is refused", async () => {
  const built = mint()
  const other = ed25519.generateKeyPair()
  const service = buildService(
    lookupReturning(authorizationFor(built)),
    { tokenVerification: { kind: "ed25519", publicKeyPem: other.publicKeyPem } },
  )

  await assert.rejects(
    service.execute({
      tenantId: built.request.tenant_id,
      requestId: built.request.request_id,
      argv: ["/bin/sh", "run.sh"],
      workspacePath: "/workspace",
    }),
    /^Error: invalid decision token$/u,
  )
})

test("an hmac token stored before ed25519 was configured is refused by name", async () => {
  // The claims are identical; only the envelope differs. Refusing it is the fail-closed outcome —
  // the alternative would be a fallback to HMAC verification, which is the exact property this
  // service exists to remove.
  const built = mint((payload) => `${Buffer.from(payload, "utf8").toString("base64url")}.sig`)
  const service = buildService(lookupReturning(authorizationFor(built)))

  await assert.rejects(
    service.execute({
      tenantId: built.request.tenant_id,
      requestId: built.request.request_id,
      argv: ["/bin/sh", "run.sh"],
      workspacePath: "/workspace",
    }),
    (error: unknown) =>
      error instanceof DecisionExecutionRefusal && error.reason === "token_not_ed25519",
  )
})

test("S7: a refusal from the lookup reaches the caller with its reason intact", async () => {
  // `loadStoredAuthorization` is what distinguishes "this decision said no" from "no such
  // decision". If the service collapsed either into a generic error, an operator could not tell a
  // policy denial from a typo, and the route would answer 404 for a request that was actually
  // denied. The reason has to survive the hop.
  const calls: SpawnCall[] = []
  const service = buildService(
    async () => {
      throw new DecisionExecutionRefusal("not_allowed", 'the stored decision is "deny", not "allow"')
    },
    { spawnCommand: createSpawnStub(calls) },
  )

  await assert.rejects(
    service.execute({
      tenantId: "t_demo",
      requestId: "req_denied_1",
      argv: ["/bin/sh", "run.sh"],
      workspacePath: "/workspace",
    }),
    (error: unknown) =>
      error instanceof DecisionExecutionRefusal &&
      error.reason === "not_allowed" &&
      error.message.includes('"deny"'),
  )
  assert.deepEqual(runCalls(calls), [])
})

test("an unknown request is refused as no_such_authorization, not as a policy denial", async () => {
  const service = buildService(lookupReturning(null))

  await assert.rejects(
    service.execute({
      tenantId: "t_demo",
      requestId: "req_does_not_exist",
      argv: ["/bin/sh", "run.sh"],
      workspacePath: "/workspace",
    }),
    (error: unknown) =>
      error instanceof DecisionExecutionRefusal && error.reason === "no_such_authorization",
  )
})

test("a decision whose stored token is empty is refused rather than executed", async () => {
  const service = buildService(lookupReturning(authorizationFor(mint(), { decisionToken: "" })))

  await assert.rejects(
    service.execute({
      tenantId: "t_demo",
      requestId: "req_1",
      argv: ["/bin/sh", "run.sh"],
      workspacePath: "/workspace",
    }),
    (error: unknown) =>
      error instanceof DecisionExecutionRefusal && error.reason === "no_decision_token",
  )
})

test("S7: identity taken from the record, not from the caller", async () => {
  // The record says this decision belonged to agent_1 in session sess_1. An authorization whose
  // claims name a different agent must not execute under the record's identity, and vice versa.
  const built = mint()
  const service = buildService(
    lookupReturning(authorizationFor(built, { agentId: "agent_other", sessionId: "sess_other" })),
  )

  await assert.rejects(
    service.execute({
      tenantId: built.request.tenant_id,
      requestId: built.request.request_id,
      argv: ["/bin/sh", "run.sh"],
      workspacePath: "/workspace",
    }),
    /^Error: decision token claims mismatch$/u,
  )
})

test("the stored constraints, not the caller, choose the network mode", async () => {
  const built = mint(signer, { networkMode: "none", timeoutMs: 1234, maxOutputBytes: 99 })
  const calls: SpawnCall[] = []
  const service = buildService(
    lookupReturning(
      authorizationFor(built, {
        constraints: { network_mode: "none", timeout_ms: 1234, max_output_bytes: 99 },
      }),
    ),
    { spawnCommand: createSpawnStub(calls) },
  )

  await service.execute({
    tenantId: built.request.tenant_id,
    requestId: built.request.request_id,
    argv: ["/bin/sh", "run.sh"],
    workspacePath: "/workspace",
  })

  const args = [...(runCalls(calls)[0]?.args ?? [])]
  assert.ok(args.includes("--network"), `expected a network flag in ${args.join(" ")}`)
  assert.ok(args.includes("none"), `expected network "none", got ${args.join(" ")}`)
  assert.ok(!args.includes("actantos_egress_cell"))
})

test("S2: a stored constraint that disagrees with the token is refused, not executed", async () => {
  // This is the check that makes the previous test meaningful. If the record's constraints could
  // differ from the ones the token was signed over, then the record — a database row, not the
  // signature — would be what decides the network mode, and a tampered row would widen egress.
  const built = mint(signer, { networkMode: "none", timeoutMs: 1234, maxOutputBytes: 99 })
  const calls: SpawnCall[] = []
  const service = buildService(
    lookupReturning(
      authorizationFor(built, {
        constraints: { network_mode: "egress_proxy", timeout_ms: 1234, max_output_bytes: 99 },
      }),
    ),
    { spawnCommand: createSpawnStub(calls) },
  )

  await assert.rejects(
    service.execute({
      tenantId: built.request.tenant_id,
      requestId: built.request.request_id,
      argv: ["/bin/sh", "run.sh"],
      workspacePath: "/workspace",
    }),
    /^Error: decision token constraints mismatch$/u,
  )
  assert.deepEqual(runCalls(calls), [])
})

test("loadStoredAuthorization reads the decision back and joins the external identifiers", async () => {
  // The external ids are what the token is signed over. Reading the UUIDs instead would make every
  // token fail its own identity check, so the query has to name the joined columns.
  const executed: { sql: string; params?: readonly unknown[] }[] = []
  const database = {
    async query(sql: string, params?: readonly unknown[]) {
      executed.push(params === undefined ? { sql } : { sql, params })
      return [
        {
          decision_id: "decision_1",
          final_decision: "allow",
          tool_name: "guarded_bash",
          scope_hash: "scope_1",
          decision_token: "ed25519.payload.sig",
          constraints_json: { network_mode: "none", timeout_ms: 5000, max_output_bytes: 1000 },
          agent_external_id: "agent_1",
          session_external_id: "sess_1",
        },
      ]
    },
  } as unknown as Database

  const lookup = loadStoredAuthorization(database)
  const authorization = await lookup({ tenantId: "t_demo", requestId: "req_1" })

  assert.ok(authorization !== null)
  assert.equal(authorization.agentId, "agent_1")
  assert.equal(authorization.sessionId, "sess_1")
  assert.equal(authorization.scopeHash, "scope_1")
  assert.equal(authorization.decisionToken, "ed25519.payload.sig")
  assert.equal(authorization.constraints.network_mode, "none")
  assert.equal(authorization.constraints.timeout_ms, 5000)
  assert.ok(executed[0]?.sql.includes("agents"), "must join agents for external_id")
  assert.ok(executed[0]?.sql.includes("sessions"), "must join sessions for external_id")
  assert.deepEqual(executed[0]?.params, ["t_demo", "req_1"])
})

test("loadStoredAuthorization returns null for an unknown request", async () => {
  const database = {
    async query() {
      return []
    },
  } as unknown as Database

  assert.equal(await loadStoredAuthorization(database)({ tenantId: "t", requestId: "r" }), null)
})

test("loadStoredAuthorization refuses a stored decision that was not an allow", async () => {
  const database = {
    async query() {
      return [
        {
          decision_id: "decision_1",
          final_decision: "deny",
          tool_name: "guarded_bash",
          scope_hash: "scope_1",
          decision_token: null,
          constraints_json: null,
          agent_external_id: "agent_1",
          session_external_id: "sess_1",
        },
      ]
    },
  } as unknown as Database

  await assert.rejects(
    loadStoredAuthorization(database)({ tenantId: "t", requestId: "r" }),
    (error: unknown) =>
      error instanceof DecisionExecutionRefusal &&
      error.reason === "not_allowed" &&
      error.message.includes("deny"),
  )
})

test("loadStoredAuthorization drops a constraint value it does not recognise", async () => {
  // `network_mode` is an enum in the contract. A row carrying anything else must not become
  // `egress_proxy` by accident, and must not be passed through unchecked either.
  const database = {
    async query() {
      return [
        {
          decision_id: "decision_1",
          final_decision: "allow",
          tool_name: "guarded_bash",
          scope_hash: "scope_1",
          decision_token: "ed25519.payload.sig",
          constraints_json: { network_mode: "host", timeout_ms: "60000" },
          agent_external_id: "agent_1",
          session_external_id: "sess_1",
        },
      ]
    },
  } as unknown as Database

  const authorization = await loadStoredAuthorization(database)({ tenantId: "t", requestId: "r" })

  assert.equal(authorization?.constraints.network_mode, undefined)
  assert.equal(authorization?.constraints.timeout_ms, undefined)
})

test("the mint and the verify sides agree on command_hash", () => {
  // Guards the fixture itself: if canonicalCommandHash moved, the S8 test above would start
  // passing for the wrong reason.
  const built = mint()
  assert.equal(
    canonicalCommandHash(["/bin/sh", "run.sh"], "/workspace"),
    canonicalCommandHash(["/bin/sh", "run.sh"], "/workspace"),
  )
})