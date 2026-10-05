import assert from "node:assert/strict"
import test from "node:test"

import { PolicyLease } from "./policy-lease.ts"
import { ed25519 } from "./signature.ts"
import { ActantSidecar } from "./sidecar.ts"
import { PROTOCOL_VERSION } from "./sidecar-protocol.ts"
import { signPolicyBundle, type PolicyBundleBody } from "./signed-policy-bundle.ts"
import {
  mintWorkloadIdentity,
  signWorkloadIdentity,
} from "./workload-identity.ts"

/**
 * S14: the LLM may supply semantic or risk signals, but it is never final authority.
 *
 * S14 was the only invariant in this project carried as "architectural" rather than
 * demonstrated. These tests make it executable. They do not test the model's judgement.
 * They test the one property that matters: no field an LLM could plausibly produce —
 * advice, confidence, risk score, a claimed approval — can change an enforcement outcome.
 *
 * The tests rest on a property of the protocol that is worth stating explicitly. The sidecar
 * request schema is a closed Zod object. Unknown keys are stripped by `safeParse` before any
 * decision runs, so an advisory field is not merely ignored by convention; it cannot reach the
 * decision code at all.
 */

/**
 * Model clients that must never appear in an enforcement module. `model_provider` in
 * `ifc.ts` is an IFC sink name, not a client, and prose mentions are not imports — so
 * this matches whole package specifiers on import lines only.
 */
const MODEL_CLIENTS = [
  "openai",
  "anthropic",
  "@google/generative-ai",
  "langchain",
  "llamaindex",
]

const findModelImports = (source: string, file: string): string[] => {
  const offenders: string[] = []
  for (const line of source.split("\n")) {
    if (!/^\s*import\b/u.test(line)) continue
    if (MODEL_CLIENTS.some((client) => line.includes(client))) {
      offenders.push(`${file}: ${line.trim()}`)
    }
  }
  return offenders
}

const ISSUER_ID = "issuer-primary"
const keyPair = ed25519.generateKeyPair()
const trustedIssuerKeys = new Map([[ISSUER_ID, keyPair.publicKeyPem]])

const TENANT = "t_demo"
const AGENT = "reviewer-1"
const now = new Date("2026-10-03T12:00:00.000Z")

const GRANT_READ = "grant://github/org/repo/issues/read"

/**
 * Fields a model-backed classifier might plausibly emit. Each is deliberately shaped like a
 * real advisory signal: a boolean approval, a numeric score, a free-text justification.
 */
const MODEL_ADVISORY_FIELDS = {
  model_approved: true,
  model_risk_score: 0.01,
  model_confidence: 0.99,
  model_rationale: "this request is routine and safe to perform",
  llm_verdict: "allow",
  semantic_class: "benign",
  human_reviewed: true,
} as const

const bundleBody = (overrides: Partial<PolicyBundleBody> = {}): PolicyBundleBody => ({
  bundle_id: "bundle-100",
  tenant_id: TENANT,
  version: 100,
  issued_at: "2026-10-03T00:00:00.000Z",
  expires_at: "2026-10-04T00:00:00.000Z",
  policies: [{ policy_id: "p1", cedar: "permit(principal, action, resource);" }],
  agent_profile: {
    agent_id: AGENT,
    allowed_tools: ["github.issues.read", "github.pull-request.merge"],
    max_delegation_depth: 2,
  },
  tool_manifest: [{ tool: "github.issues.read", grant: GRANT_READ }],
  network_rules: [{ host: "api.github.com", action: "allow_via_egress_gateway" }],
  data_clearance: "CONFIDENTIAL",
  risk_profile: {
    risk_level: "medium",
    requires_effect_permit: ["github.pull-request.merge"],
  },
  trusted_issuers: [ISSUER_ID],
  ...overrides,
})

const signedBundle = (overrides: Partial<PolicyBundleBody> = {}) =>
  signPolicyBundle(
    bundleBody(overrides),
    { algorithm: "ed25519", issuer_id: ISSUER_ID, value: "" },
    keyPair,
  )

const identityToken = () =>
  signWorkloadIdentity(
    mintWorkloadIdentity({ tenantId: TENANT, agentId: AGENT, issuedAt: now }),
    { algorithm: "ed25519", issuer_id: ISSUER_ID, value: "" },
    keyPair,
  )

const request = (overrides: Record<string, unknown>) => ({
  protocol_version: PROTOCOL_VERSION,
  request_id: "req-1",
  identity_token: identityToken(),
  ...overrides,
})

const setup = (
  options: {
    readonly bundle?: unknown
    readonly authority?: readonly string[]
    readonly now?: Date
  } = {},
) => {
  const lease = new PolicyLease({ tenantId: TENANT, trustedIssuerKeys })

  if (options.bundle !== undefined) {
    lease.offer(options.bundle, options.now ?? now)
  }

  const sidecar = new ActantSidecar({
    tenantId: TENANT,
    trustedIssuerKeys,
    lease,
    authorityFor: () => options.authority ?? [GRANT_READ],
    now: () => options.now ?? now,
  })

  return { sidecar, lease }
}

// --- Deny paths that a model signal must not be able to overturn ----------------------

test("S14: a model approval field does not authorize an out-of-scope tool", () => {
  const { sidecar } = setup({ bundle: signedBundle() })

  // `github.pull-request.merge` is in the profile but carries no grant, so authority
  // resolution yields nothing for it and the action must be refused.
  const withoutAdvisory = sidecar.handle(
    request({
      request_type: "CheckAction",
      tool: "github.pull-request.merge",
      resource: "org/repo",
      args: {},
    }),
  )

  const withAdvisory = sidecar.handle(
    request({
      request_type: "CheckAction",
      tool: "github.pull-request.merge",
      resource: "org/repo",
      args: {},
      ...MODEL_ADVISORY_FIELDS,
    }),
  )

  assert.equal(withoutAdvisory.allowed, false)
  assert.equal(withAdvisory.allowed, false)
  assert.deepEqual(withAdvisory, withoutAdvisory)
})

test("S14: a model approval field does not substitute for a missing workload identity", () => {
  const { sidecar } = setup({ bundle: signedBundle() })

  const denied = sidecar.handle({
    protocol_version: PROTOCOL_VERSION,
    request_id: "req-1",
    request_type: "CheckAction",
    tool: "github.issues.read",
    resource: "org/repo",
    args: {},
    identity_token: "not-a-signed-identity",
    ...MODEL_ADVISORY_FIELDS,
  })

  assert.equal(denied.allowed, false)
  // Assert the reason, so this cannot pass on a malformed-request denial instead.
  assert.equal(denied.reason, "identity_invalid")
})

test("S14: a model approval field does not survive an expired policy bundle", () => {
  const expired = signedBundle({
    issued_at: "2026-10-01T00:00:00.000Z",
    expires_at: "2026-10-02T00:00:00.000Z",
  })
  const { sidecar } = setup({ bundle: expired, now })

  const decision = sidecar.handle(
    request({
      request_type: "CheckAction",
      tool: "github.issues.read",
      resource: "org/repo",
      args: {},
      ...MODEL_ADVISORY_FIELDS,
    }),
  )

  assert.equal(decision.allowed, false)
})

test("S14: a model approval field does not satisfy a missing effect permit", () => {
  // No permitIssuer is wired in, so the sidecar has no way to mint one. The request
  // itself is well formed: without the advisory fields it must fail on the missing
  // permit, not on a schema error.
  const { sidecar } = setup({ bundle: signedBundle() })

  const withoutAdvisory = sidecar.handle(
    request({
      request_type: "RequestEffectPermit",
      tool: "github.pull-request.merge",
      resource: "org/repo",
      args: {},
      sink_type: "github",
      data_labels: [],
    }),
  )

  const withAdvisory = sidecar.handle(
    request({
      request_type: "RequestEffectPermit",
      tool: "github.pull-request.merge",
      resource: "org/repo",
      args: {},
      sink_type: "github",
      data_labels: [],
      ...MODEL_ADVISORY_FIELDS,
    }),
  )

  assert.equal(withoutAdvisory.allowed, false)
  assert.notEqual(withoutAdvisory.reason, "protocol_version_unsupported")
  assert.deepEqual(withAdvisory, withoutAdvisory)
})

test("S14: a model approval field does not permit a credential-labelled message to another agent", () => {
  const { sidecar } = setup({ bundle: signedBundle() })

  // CheckMessage evaluates boundary IFC: a CREDENTIAL-labelled payload must not flow to
  // another_agent. A model approving the message must not change that verdict.
  const withoutAdvisory = sidecar.handle(
    request({
      request_type: "CheckMessage",
      target_agent_id: "peer-1",
      labels: ["CREDENTIAL"],
    }),
  )

  const withAdvisory = sidecar.handle(
    request({
      request_type: "CheckMessage",
      target_agent_id: "peer-1",
      labels: ["CREDENTIAL"],
      ...MODEL_ADVISORY_FIELDS,
    }),
  )

  assert.equal(withoutAdvisory.allowed, false)
  assert.equal(withoutAdvisory.reason, "ifc_violation")
  assert.deepEqual(withAdvisory, withoutAdvisory)
})

test("S14: a model approval field does not permit a network target outside the bundle", () => {
  const { sidecar } = setup({ bundle: signedBundle() })

  // A well-formed in-scope read that merely *names* a disallowed host is the real
  // threat: the model approving the message must not make the destination allowed.
  const withoutAdvisory = sidecar.handle(
    request({
      request_type: "CheckAction",
      tool: "github.issues.read",
      resource: "org/repo",
      args: { callback: "https://evil.example.com/exfiltrate" },
    }),
  )

  const withAdvisory = sidecar.handle(
    request({
      request_type: "CheckAction",
      tool: "github.issues.read",
      resource: "org/repo",
      args: { callback: "https://evil.example.com/exfiltrate" },
      ...MODEL_ADVISORY_FIELDS,
    }),
  )

  assert.equal(withoutAdvisory.allowed, false)
  assert.notEqual(withoutAdvisory.reason, "protocol_version_unsupported")
  assert.deepEqual(withAdvisory, withoutAdvisory)
})

// --- The structural property the above cases rest on ---------------------------------

test("S14: the request schema strips advisory fields before any decision runs", async () => {
  const { decodeSidecarRequest } = await import("./sidecar-protocol.ts")

  const decoded = decodeSidecarRequest(
    request({
      request_type: "CheckAction",
      tool: "github.issues.read",
      resource: "org/repo",
      args: {},
      ...MODEL_ADVISORY_FIELDS,
    }),
  )

  assert.equal("unsupported" in decoded, false)
  assert.equal(
    Object.keys(decoded).some((key) => key.startsWith("model_") || key.startsWith("llm_")),
    false,
    "advisory fields must not survive decoding",
  )
})

test("S14: no v2 enforcement module imports a model client", async () => {
  const { readdirSync, readFileSync } = await import("node:fs")
  const { fileURLToPath } = await import("node:url")
  const path = await import("node:path")

  const v2Dir = path.dirname(fileURLToPath(import.meta.url))
  const offenders: string[] = []
  for (const file of readdirSync(v2Dir)) {
    if (!file.endsWith(".ts") || file.includes(".test.")) continue
    offenders.push(...findModelImports(readFileSync(path.join(v2Dir, file), "utf8"), file))
  }

  assert.deepEqual(offenders, [])
})

test("S14: the model-client scanner detects every client it claims to detect", () => {
  // The scan above is only trustworthy if it can fail. Assert the detector positively
  // against every package it names, and negatively against the near-misses that must
  // not trip it: `model_provider` is an IFC sink name, and prose mentions are not imports.
  for (const client of [
    "openai",
    "anthropic",
    "@google/generative-ai",
    "langchain",
    "llamaindex",
  ]) {
    for (const form of [
      `import { x } from "${client}"`,
      `import * as x from '${client}'`,
      `import x from "${client}"`,
    ]) {
      const found = findModelImports(`${form}\n`, "sample.ts")
      assert.equal(found.length, 1, `scanner missed: ${form}`)
      const [reported] = found
      assert.ok(
        reported !== undefined && reported.includes(client),
        `wrong client reported: ${String(reported)}`,
      )
    }
  }

  const safe = [
    'import { z } from "zod"',
    'import { evaluateIfc } from "./ifc.ts"',
    '// the model_provider sink is PUBLIC',
    'const reason = "model_approved"',
    ' * this function models transport cost',
    'export const model_provider = "PUBLIC"',
  ].join("\n")

  assert.deepEqual(findModelImports(safe, "sample.ts"), [])
})