import assert from "node:assert/strict"
import { mkdtempSync } from "node:fs"
import { tmpdir } from "node:os"
import path from "node:path"
import test from "node:test"

import { buildServer } from "../server.ts"
import type { ToolCallInterceptionRequest } from "../contracts.ts"
import { createFabricGate, SidecarFabricDecider, toFabricActionRequest } from "./fabric.ts"
import { PolicyLease } from "./policy-lease.ts"
import { ed25519 } from "./signature.ts"
import { ActantSidecar } from "./sidecar.ts"
import { defaultSocketPath, isNamedPipe, startSidecarServer, type SidecarServer } from "./sidecar-server.ts"
import { signPolicyBundle, type PolicyBundleBody } from "./signed-policy-bundle.ts"
import { mintWorkloadIdentity, signWorkloadIdentity } from "./workload-identity.ts"

/**
 * Phase F end to end: the fabric, on a real socket, changing a real intercept decision.
 *
 * `fabric.test.ts` proves the mode semantics in isolation. That is not enough. A gate that
 * behaves correctly and is never consulted is not enforcement, and the thing that actually goes
 * wrong in practice is a wiring mistake — a gate constructed but not passed, or passed but not
 * read — which no unit test on the gate can catch.
 *
 * So every test here builds a real Fastify server and a real sidecar on a real socket, and
 * drives an actual `POST /v1/intercept/tool-call`. The three-mode guarantee is asserted against
 * the response the caller receives, which is the only place it means anything.
 */

const ISSUER_ID = "issuer-fabric"
const keyPair = ed25519.generateKeyPair()
const trustedIssuerKeys = new Map([[ISSUER_ID, keyPair.publicKeyPem]])

const TENANT = "t_fabric"
const AGENT = "pi_demo"
const GRANT = "grant://github/org/repo/issues/read"

/**
 * The bundle window is expressed relative to the real clock rather than pinned to a fixed date.
 *
 * The sidecar and the control plane both run on `new Date()` in production, so the identity the
 * control plane mints is always judged against the same clock. Freezing the clock on one side
 * only would make every request look not-yet-valid — a property of the test rig, not of the
 * fabric.
 */
const HOUR_MS = 60 * 60 * 1000

const bundleBody = (now: Date): PolicyBundleBody => ({
  bundle_id: "bundle-fabric",
  tenant_id: TENANT,
  version: 1,
  issued_at: new Date(now.getTime() - HOUR_MS).toISOString(),
  expires_at: new Date(now.getTime() + 365 * 24 * HOUR_MS).toISOString(),
  policies: [{ policy_id: "p1", cedar: "permit(principal, action, resource);" }],
  agent_profile: {
    agent_id: AGENT,
    allowed_tools: ["github.issues.read"],
    max_delegation_depth: 2,
  },
  tool_manifest: [{ tool: "github.issues.read", grant: GRANT }],
  // Only api.github.com is permitted. Anything else is a fabric denial, which is what the
  // observe/enforce distinction is tested against.
  network_rules: [{ host: "api.github.com", action: "allow_via_egress_gateway" }],
  data_clearance: "CONFIDENTIAL",
  risk_profile: { risk_level: "medium", requires_effect_permit: [] },
  trusted_issuers: [ISSUER_ID],
})

const buildSidecar = (): ActantSidecar => {
  const now = new Date()
  const lease = new PolicyLease({ tenantId: TENANT, trustedIssuerKeys })
  lease.offer(
    signPolicyBundle(
      bundleBody(now),
      { algorithm: "ed25519", issuer_id: ISSUER_ID, value: "" },
      keyPair,
    ),
    now,
  )

  return new ActantSidecar({
    tenantId: TENANT,
    trustedIssuerKeys,
    lease,
    authorityFor: () => [GRANT],
  })
}

let socketCounter = 0
const uniqueSocketPath = (): string => {
  socketCounter += 1
  const name = `actantos-fabric-${process.pid}-${Date.now().toString(36)}-${socketCounter}`

  return isNamedPipe(defaultSocketPath(name))
    ? defaultSocketPath(name)
    : path.join(mkdtempSync(path.join(tmpdir(), "actantos-fabric-")), `${name}.sock`)
}

const deciderFor = (socketPath: string): SidecarFabricDecider =>
  new SidecarFabricDecider({
    socketPath,
    issueIdentity: (tenantId, agentId, at) =>
      signWorkloadIdentity(
        mintWorkloadIdentity({ tenantId, agentId, issuedAt: at }),
        { algorithm: "ed25519", issuer_id: ISSUER_ID, value: "" },
        keyPair,
      ),
  })

const toolCall = (
  overrides: Partial<ToolCallInterceptionRequest> = {},
): ToolCallInterceptionRequest => ({
  request_id: `req_fabric_${Math.random().toString(36).slice(2, 10)}`,
  tenant_id: TENANT,
  agent: { id: AGENT, runtime_type: "pi", environment: "dev", risk_tier: "low" },
  subject: { user_id: "u_demo", role: "developer" },
  session: { id: "s_demo", cwd: "/workspace", budget_remaining_cents: 10_000 },
  tool: { kind: "github", name: "github.issues.read", operation: "ReadIssues" },
  resource: { url: "https://api.github.com/repos/org/repo/issues" },
  action: { operation: "ReadIssues", args: {} },
  normalized: {
    verb: "read",
    mutation: false,
    destructive: false,
    network: true,
    credential_access: false,
    risk_class: "low",
  },
  ...overrides,
})

/** A destination the signed bundle does not permit. */
const disallowedToolCall = (): ToolCallInterceptionRequest =>
  toolCall({
    resource: { url: "https://evil.example.com/collect" },
  })

type Started = {
  readonly server: ReturnType<typeof buildServer>
  readonly sidecar: SidecarServer
  readonly decider: SidecarFabricDecider
  readonly close: () => Promise<void>
}

/** Start a real sidecar on a real socket and a real server pointed at it. */
const startStack = async (mode: "v1_compat" | "v2_observe" | "v2_enforce"): Promise<Started> => {
  const socketPath = uniqueSocketPath()
  const sidecar = await startSidecarServer({ socketPath, sidecar: buildSidecar() })
  const decider = deciderFor(socketPath)

  const server = buildServer({
    hmacSecret: "fabric-test-secret",
    logger: false,
    fabricGate: createFabricGate({
      mode,
      ...(mode === "v1_compat" ? {} : { decider }),
    }),
  })

  await server.ready()

  return {
    server,
    sidecar,
    decider,
    close: async () => {
      await server.close()
      await decider.close()
      await sidecar.close()
    },
  }
}

const intercept = async (
  server: Started["server"],
  body: ToolCallInterceptionRequest,
): Promise<{ readonly decision: string; readonly reason_code: string }> => {
  const response = await server.inject({
    method: "POST",
    url: "/v1/intercept/tool-call",
    payload: body,
  })

  const parsed = response.json() as {
    decision: string
    reason_code: string
  }
  return { decision: parsed.decision, reason_code: parsed.reason_code }
}

// --- v1_compat: unchanged behaviour -----------------------------------------------------

test("S12: v1_compat allows a call to a destination the fabric forbids", async () => {
  const stack = await startStack("v1_compat")

  try {
    const result = await intercept(stack.server, disallowedToolCall())

    // v1's own pipeline allows this, and v1_compat must not change that. If this ever starts
    // denying, the default mode has regressed production behaviour.
    assert.equal(result.decision, "allow")
    assert.doesNotMatch(result.reason_code, /^fabric\./u)
  } finally {
    await stack.close()
  }
})

// --- v2_observe: consulted, recorded, never governing -----------------------------------

test("S12: v2_observe allows a call the fabric denies, and says nothing about it", async () => {
  const stack = await startStack("v2_observe")

  try {
    const result = await intercept(stack.server, disallowedToolCall())

    // The request went to the fabric and the fabric refused it. The caller is still allowed.
    // That is the whole contract of observe mode, and it is the one most likely to be broken by
    // a well-meaning later change.
    assert.equal(result.decision, "allow")
    assert.doesNotMatch(result.reason_code, /^fabric\./u)
  } finally {
    await stack.close()
  }
})

test("S12: v2_observe still allows when the sidecar is gone", async () => {
  const socketPath = uniqueSocketPath()
  const decider = deciderFor(socketPath)
  const server = buildServer({
    hmacSecret: "fabric-test-secret",
    logger: false,
    fabricGate: createFabricGate({ mode: "v2_observe", decider }),
  })

  await server.ready()

  try {
    // No sidecar was ever started on this path, so every call is a connect failure.
    const result = await intercept(server, disallowedToolCall())

    assert.equal(result.decision, "allow")
  } finally {
    await server.close()
    await decider.close()
  }
})

// --- v2_enforce: governing, and failing closed -----------------------------------------

test("S12: v2_enforce allows a call the fabric permits", async () => {
  const stack = await startStack("v2_enforce")

  try {
    const result = await intercept(stack.server, toolCall())

    assert.equal(result.decision, "allow")
    assert.doesNotMatch(result.reason_code, /^fabric\./u)
  } finally {
    await stack.close()
  }
})

test("S12: v2_enforce denies a call whose destination the signed bundle forbids", async () => {
  const stack = await startStack("v2_enforce")

  try {
    const result = await intercept(stack.server, disallowedToolCall())

    assert.equal(result.decision, "deny")
    assert.equal(result.reason_code, "fabric.network_rule_denied")
  } finally {
    await stack.close()
  }
})

test("S12: v2_enforce denies when the sidecar cannot be reached", async () => {
  // The load-bearing test in this file. A fabric that cannot answer must not answer "allow".
  const socketPath = uniqueSocketPath()
  const decider = deciderFor(socketPath)
  const server = buildServer({
    hmacSecret: "fabric-test-secret",
    logger: false,
    fabricGate: createFabricGate({ mode: "v2_enforce", decider }),
  })

  await server.ready()

  try {
    const result = await intercept(server, toolCall())

    assert.equal(result.decision, "deny")
    assert.equal(result.reason_code, "fabric.unavailable")
  } finally {
    await server.close()
    await decider.close()
  }
})

test("S12: v2_enforce denies a tool that is not in the signed manifest", async () => {
  const stack = await startStack("v2_enforce")

  try {
    const result = await intercept(
      stack.server,
      toolCall({
        tool: { kind: "github", name: "github.pull-request.merge", operation: "Merge" },
      }),
    )

    assert.equal(result.decision, "deny")
    assert.equal(result.reason_code, "fabric.tool_not_in_manifest")
  } finally {
    await stack.close()
  }
})

// --- The fabric sees the destination, not just the tool name ---------------------------

test("S3: v2_enforce denies a hidden IPv4 literal in the arguments", async () => {
  const stack = await startStack("v2_enforce")

  try {
    const result = await intercept(
      stack.server,
      toolCall({
        resource: { url: "https://api.github.com/repos/org/repo/issues" },
        action: {
          operation: "ReadIssues",
          // The permitted URL is still there. The literal behind it is not.
          args: { mirror: "http://169.254.169.254/latest/meta-data/" },
        },
      }),
    )

    assert.equal(result.decision, "deny")
    assert.equal(result.reason_code, "fabric.network_rule_denied")
  } finally {
    await stack.close()
  }
})

// --- What the fabric is asked about ----------------------------------------------------

test("S12: the action handed to the fabric carries the request's own identity and destination", () => {
  const request = toolCall()
  const action = toFabricActionRequest(request)

  assert.equal(action.tenantId, request.tenant_id)
  assert.equal(action.agentId, request.agent.id)
  assert.equal(action.tool, request.tool.name)
  assert.equal(action.resource, request.resource.url)
  assert.equal(action.requestId, request.request_id)
})
