import assert from "node:assert/strict"
import { test } from "node:test"

import {
  createFabricGate,
  DEFAULT_FABRIC_MODE,
  FABRIC_MODES,
  fabricDenial,
  isFabricMode,
  resolveFabricMode,
  toFabricActionRequest,
  type FabricActionRequest,
  type FabricAssessment,
  type FabricDecider,
} from "./fabric.ts"

/**
 * Runtime wiring for the fabric (phase F), S12 at the configuration boundary.
 *
 * The properties under test are almost all negative ones, and that is the point. A fabric that
 * is wired in but configured wrongly is worse than one that is absent, because an operator
 * believes it is enforcing something. So the tests below are about what the fabric must *not*
 * do:
 *
 *   - an unrecognised mode must not fall back to a permissive default
 *   - `v2_observe` must not be able to deny, however loudly the fabric objects
 *   - `v2_enforce` must deny when the fabric cannot be reached, not allow
 *   - `v2_compat` must not consult the fabric at all
 */

const REQUEST: FabricActionRequest = {
  tenantId: "t_demo",
  agentId: "reviewer-1",
  requestId: "req-fabric-1",
  tool: "github.issues.read",
  resource: "org/repo",
  args: {},
}

const deciderReturning = (decision: {
  readonly allowed: boolean
  readonly reason: string
}): FabricDecider => ({
  check: async () => decision,
})

const deciderThrowing = (message: string): FabricDecider => ({
  check: async () => {
    throw new Error(message)
  },
})

// --- Mode resolution fails closed ------------------------------------------------------

test("S12: an unset mode is v1_compat, which changes nothing", () => {
  assert.equal(resolveFabricMode(undefined), DEFAULT_FABRIC_MODE)
  assert.equal(resolveFabricMode(""), DEFAULT_FABRIC_MODE)
  assert.equal(resolveFabricMode("   "), DEFAULT_FABRIC_MODE)
  assert.equal(DEFAULT_FABRIC_MODE, "v1_compat")
})

test("S12: every declared mode round-trips through the resolver", () => {
  for (const mode of FABRIC_MODES) {
    assert.equal(resolveFabricMode(mode), mode)
    assert.ok(isFabricMode(mode))
  }
})

test("S12: mode resolution tolerates surrounding whitespace and case", () => {
  // An operator setting this through a shell or a Helm value should not be defeated by a
  // trailing space, which would otherwise throw and look like a crash rather than a config.
  assert.equal(resolveFabricMode("  v2_enforce  "), "v2_enforce")
  assert.equal(resolveFabricMode("V2_Enforce"), "v2_enforce")
})

test("S12: an unrecognised mode refuses to resolve rather than defaulting", () => {
  // The dangerous case is a typo like "v2_enforc". Falling back to v1_compat would silently
  // disable enforcement on a deployment whose operator believes it is enforcing.
  for (const typo of ["v2_enforc", "enforce", "v2", "true", "1", "v1compat"]) {
    assert.throws(
      () => resolveFabricMode(typo),
      /ACTANTOS_FABRIC_MODE/u,
      `expected "${typo}" to be rejected rather than silently defaulted`,
    )
  }
})

test("S12: a v2 mode without a decider refuses to construct", () => {
  // Enforcing with nothing to consult would answer every request by saying nothing, which the
  // pipeline reads as an allow.
  for (const mode of ["v2_observe", "v2_enforce"] as const) {
    assert.throws(() => createFabricGate({ mode }), /no fabric decider/u)
  }
})

// --- v1_compat does not consult the fabric ---------------------------------------------

test("S12: v1_compat never evaluates and cannot produce a denial", async () => {
  let consulted = false
  const gate = createFabricGate({
    mode: "v1_compat",
    decider: {
      check: async () => {
        consulted = true
        return { allowed: false, reason: "network_rule_denied" }
      },
    },
  })

  assert.equal(gate.evaluates, false)

  const assessment = await gate.evaluate(REQUEST)

  assert.equal(consulted, false, "v1_compat must not reach the fabric at all")
  assert.equal(assessment.outcome, "not_evaluated")
  assert.equal(fabricDenial(assessment), null)
})

// --- v2_observe records but never governs ----------------------------------------------

test("S12: v2_observe records a denial but does not block", async () => {
  const seen: FabricAssessment[] = []
  const gate = createFabricGate({
    mode: "v2_observe",
    decider: deciderReturning({ allowed: false, reason: "network_rule_denied" }),
    onAssessment: (assessment) => seen.push(assessment),
  })

  assert.equal(gate.evaluates, true)

  const assessment = await gate.evaluate(REQUEST)

  // The verdict is recorded, so the divergence is measurable...
  assert.equal(assessment.outcome, "denied")
  assert.equal(seen.length, 1)
  assert.equal(seen[0]?.outcome, "denied")

  // ...and it changes nothing. This is the single most important assertion in the file.
  assert.equal(fabricDenial(assessment), null)
})

test("S12: v2_observe does not block when the fabric is unreachable", async () => {
  const gate = createFabricGate({
    mode: "v2_observe",
    decider: deciderThrowing("connection refused"),
  })

  const assessment = await gate.evaluate(REQUEST)

  assert.equal(assessment.outcome, "unavailable")
  assert.equal(
    fabricDenial(assessment),
    null,
    "observe mode must survive an outage; that is the point of observe mode",
  )
})

test("S12: v2_observe does not block when the decider itself is missing at evaluation time", async () => {
  // Belt and braces. The constructor already refuses this, but the guarantee that observe mode
  // never governs is about the mode, not about the current wiring.
  const gate = createFabricGate({
    mode: "v2_observe",
    decider: deciderThrowing("no route to host"),
  })

  assert.equal(fabricDenial(await gate.evaluate(REQUEST)), null)
})

// --- v2_enforce governs, and fails closed ----------------------------------------------

test("S12: v2_enforce turns a fabric denial into a denial", async () => {
  const gate = createFabricGate({
    mode: "v2_enforce",
    decider: deciderReturning({ allowed: false, reason: "network_rule_denied" }),
  })

  const denial = fabricDenial(await gate.evaluate(REQUEST))

  assert.ok(denial !== null)
  assert.equal(denial.reasonCode, "fabric.network_rule_denied")
  assert.match(denial.reason, /network_rule_denied/u)
})

test("S12: v2_enforce allows when the fabric allows", async () => {
  const gate = createFabricGate({
    mode: "v2_enforce",
    decider: deciderReturning({ allowed: true, reason: "action_allowed" }),
  })

  assert.equal(fabricDenial(await gate.evaluate(REQUEST)), null)
})

test("S12: v2_enforce denies when the fabric cannot be reached", () => {
  // The fail-closed case. An unreachable fabric that answers "allow" converts an outage into a
  // bypass, which is strictly worse than having no fabric.
  return (async () => {
    const gate = createFabricGate({
      mode: "v2_enforce",
      decider: deciderThrowing("connect ECONNREFUSED"),
    })

    const denial = fabricDenial(await gate.evaluate(REQUEST))

    assert.ok(denial !== null, "an unreachable fabric must not produce an allow in enforce mode")
    assert.equal(denial.reasonCode, "fabric.unavailable")
    assert.match(denial.reason, /could not be consulted/u)
    assert.match(denial.reason, /ECONNREFUSED/u)
  })()
})

test("S12: an unavailable assessment is distinguishable from a policy denial", async () => {
  // "The sidecar is down" and "the policy forbids this" are different events and an operator
  // reading a decision row has to be able to tell them apart.
  const unavailable = createFabricGate({
    mode: "v2_enforce",
    decider: deciderThrowing("boom"),
  })
  const denied = createFabricGate({
    mode: "v2_enforce",
    decider: deciderReturning({ allowed: false, reason: "tool_not_in_manifest" }),
  })

  const a = fabricDenial(await unavailable.evaluate(REQUEST))
  const b = fabricDenial(await denied.evaluate(REQUEST))

  assert.equal(a?.reasonCode, "fabric.unavailable")
  assert.equal(b?.reasonCode, "fabric.tool_not_in_manifest")
  assert.notEqual(a?.reasonCode, b?.reasonCode)
})

test("S12: a fabric denial reason is namespaced away from a v1 policy_forbid", async () => {
  // The v1 and v2 pipelines are independent and their denials mean different things. An
  // operator reading an audit row must be able to tell which one produced it.
  const gate = createFabricGate({
    mode: "v2_enforce",
    decider: deciderReturning({ allowed: false, reason: "policy_forbid" }),
  })

  const denial = fabricDenial(await gate.evaluate(REQUEST))

  assert.equal(denial?.reasonCode, "fabric.policy_forbid")
  assert.notEqual(denial?.reasonCode, "policy_forbid")
})

test("S12: a non-Error thrown by the decider still fails closed with a usable message", async () => {
  const gate = createFabricGate({
    mode: "v2_enforce",
    decider: {
      check: async () => {
        throw "a bare string, not an Error"
      },
    },
  })

  const denial = fabricDenial(await gate.evaluate(REQUEST))

  assert.equal(denial?.reasonCode, "fabric.unavailable")
  assert.match(denial?.reason ?? "", /a bare string/u)
})

// --- The action the fabric is asked about ----------------------------------------------

test("S12: the fabric action carries the tenant, agent and tool from the request", () => {
  const action = toFabricActionRequest({
    request_id: "req-42",
    tenant_id: "t_acme",
    agent: { id: "reviewer-1" },
    tool: { name: "github.issues.read" },
    resource: { url: "https://api.github.com/repos/org/repo/issues" },
    action: { state: "open" },
  } as never)

  assert.equal(action.tenantId, "t_acme")
  assert.equal(action.agentId, "reviewer-1")
  assert.equal(action.tool, "github.issues.read")
  assert.deepEqual(action.args, { state: "open" })
})

test("S12: the resource URL is passed to the fabric intact, not normalised away", () => {
  // checkNetworkTargets reads its targets out of this string. Shortening or dropping the URL
  // here would remove the destination from the S3 check rather than merely tidy it.
  const url = "https://api.github.com/repos/org/repo/issues"
  const action = toFabricActionRequest({
    request_id: "req-43",
    tenant_id: "t_acme",
    agent: { id: "a" },
    tool: { name: "github.issues.read" },
    resource: { url },
    action: {},
  } as never)

  assert.equal(action.resource, url)
})

test("S12: an absent resource still yields a non-empty one", () => {
  // The sidecar protocol requires a non-empty resource, and an empty string would be a way to
  // slip past the destination check by omitting the destination.
  const action = toFabricActionRequest({
    request_id: "req-44",
    tenant_id: "t_acme",
    agent: { id: "a" },
    tool: { name: "shell.exec" },
    resource: {},
    action: {},
  } as never)

  assert.ok(action.resource.length > 0)
  assert.equal(action.resource, "shell.exec")
})
