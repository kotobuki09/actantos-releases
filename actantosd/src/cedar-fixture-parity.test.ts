import assert from "node:assert/strict"
import { spawnSync } from "node:child_process"
import { readFileSync } from "node:fs"
import { join } from "node:path"
import test from "node:test"

import { buildCedarAuthorizeInput, CedarCliProvider } from "./cedar-cli-provider.ts"
import { FakeCedarProvider } from "./fake-cedar-provider.ts"
import {
  approvedWorkspaceShellRequest,
  credentialAccessShellRequest,
  mcpToolCallRequest,
} from "./fake-cedar-fixtures.ts"

/**
 * Every fixture that stands in for an authorization decision is checked against the real policy.
 *
 * ## The defect this exists to prevent
 *
 * Seven v1 suites run their requests through `FakeCedarProvider`, which permits anything that is
 * not a credential access. Each builds an "allow" as a *precondition* and then asserts something
 * else about it — that the audit chain links, that the budget check short-circuits, that the tool
 * result is recorded. None of those assertions is about Cedar.
 *
 * That arrangement is safe only while the fixture's "allow" is one the real policy would also
 * give. It was not. `commandFromRequest` derives the workspace as `dirname(resource.path)`, so a
 * fixture with `resource.path = "/workspace"` derives the workspace `"/"`, and the shipped policy
 * permits only `resource.path == "" || resource.workspace_path == "/workspace"`. Those fixtures
 * asserted an allow that `cedar-policy-cli` refuses. They passed because the fake is more
 * permissive than production, and the divergence was invisible for as long as nobody ran the real
 * binary over them.
 *
 * The failure mode is not a false alarm. It is a test suite certifying "an allowed tool call is
 * audited" on the strength of an authorization that cannot occur.
 *
 * ## Why the fixtures are imported, not re-declared
 *
 * The first version of this file re-declared each shape inline. That guard was worthless: deleting
 * `host_workspace_path` from the real fixture left it green, because it was checking its own copy.
 * The fixtures now live in `./fake-cedar-fixtures.ts`, which the suites import, so this file
 * evaluates the objects production code actually sees.
 *
 * The real-Cedar half is skipped when the binary is absent, the same gate `cedar-provider.test.ts`
 * uses. That skip is registered as gated coverage in `scripts/security-fabric-state.mjs` rather
 * than left implicit, so the report says these did not run on a host without Cedar.
 */

const DAEMON_ROOT = join(import.meta.dirname, "..")
const POLICY_PATH = join(DAEMON_ROOT, "policies", "default.cedar")
const MCP_TEMPLATE_POLICY_PATH = join(
  DAEMON_ROOT,
  "policies",
  "templates",
  "mcp-readonly.cedar",
)

/**
 * Timeouts for the real CLI, which is a subprocess and not a function call.
 *
 * `CedarCliProvider` defaults `timeoutMs` to 1,000, which is a deliberate fail-closed bound and
 * is not changed here. It is simply too tight to be reliable when the whole suite is running at
 * once: this file spawns a real `cedar` process per evaluation, `node --test` runs files
 * concurrently, and on a loaded host process start plus policy load can exceed a second. That was
 * measured, not guessed — these two tests failed intermittently in full-suite runs and never in
 * isolation, always with the provider's own timeout.
 *
 * So the tests below pass a bound they do not care about, and the provider's default is left to
 * mean what it says. The availability probe gets the same treatment for a different reason: a
 * 1,000 ms window on `cedar --version` turns a slow moment into a *skip*, which is worse than a
 * failure because it silently removes coverage and still reports green.
 */
const CLI_TIMEOUT_MS = 20_000

const canRunCedarCli = (): boolean =>
  spawnSync(process.env["CEDAR_CLI_PATH"] ?? "cedar", ["--version"], {
    stdio: "ignore",
    timeout: CLI_TIMEOUT_MS,
  }).status === 0

const realProvider = (): CedarCliProvider =>
  new CedarCliProvider({
    binaryPath: process.env["CEDAR_CLI_PATH"] ?? "cedar",
    policyPath: POLICY_PATH,
    timeoutMs: CLI_TIMEOUT_MS,
  })

const defaultPolicyProvider = realProvider

test("the shared shell fixture's allow is an allow under the shipped policy, not only under the fake", async (t) => {
  if (!canRunCedarCli()) {
    t.skip("cedar CLI is unavailable in this environment — parity is unverified here")
    return
  }

  // The exact object audit-chain-verifier and tool-result-service build their "allow" on.
  const context = approvedWorkspaceShellRequest()
  const real = (await realProvider().evaluate(context)).decision
  const fake = (await new FakeCedarProvider().evaluate(context)).decision

  assert.equal(
    fake,
    real,
    `FakeCedarProvider says ${fake} and the shipped policy says ${real}. These suites assert ` +
      "things about an allowed call — audit chaining, result recording — and that allow must be " +
      "one production can actually issue. Check host_workspace_path in ./fake-cedar-fixtures.ts.",
  )
})

test("the fake's credential rule agrees with the shipped policy", async (t) => {
  // The one rule the fake encodes is `credential_access` denies. Checked against the real policy
  // rather than assumed, because a policy edit could quietly stop honouring it.
  if (!canRunCedarCli()) {
    t.skip("cedar CLI is unavailable in this environment")
    return
  }

  const context = credentialAccessShellRequest()

  assert.equal((await new FakeCedarProvider().evaluate(context)).decision, "forbid")
  assert.equal((await realProvider().evaluate(context)).decision, "forbid")
})

test("the shipped default policy denies every MCP tool call, and that is deliberate", async (t) => {
  // `mcp-gateway.ts` derives a resource path under `/mcp/<server>/tools/`, which the shipped
  // policy confines to the approved workspace and so never permits. That is the fail-closed
  // side of an explicit decision, not an oversight: a deployment that has not chosen to grant MCP
  // access gets a deny.
  //
  // The fake permits it, which is the divergence. It is safe here precisely because the default
  // refuses, and the next test shows the opt-in path that does work.
  if (!canRunCedarCli()) {
    t.skip("cedar CLI is unavailable in this environment")
    return
  }

  const context = mcpToolCallRequest()

  assert.equal((await new FakeCedarProvider().evaluate(context)).decision, "permit")
  assert.equal(
    (await defaultPolicyProvider().evaluate(context)).decision,
    "forbid",
    "the shipped default now permits MCP resource paths. That is a deliberate widening of what " +
      "the fabric accepts and must not happen by accident: update the cedar-fake-provider note in " +
      "scripts/security-fabric-state.mjs in the same commit.",
  )
})

test("the opt-in MCP template permits a read-only call and refuses every other shape", async (t) => {
  // The closure. `policies/templates/mcp-readonly.cedar` shipped inert: it gated on
  // `Action::"ReadFile"`, which the gateway never emits, and it could not have consulted the
  // mutation flag even then, because `buildCedarAuthorizeInput` did not put it on the entity.
  // Both are fixed and both are checked here against the real CLI.
  //
  // The narrowness is the point, so every refusal is asserted rather than the happy path alone:
  // a deployment opting into MCP must still get a deny for a credential-reading tool, for a
  // mutating tool, and for a tool whose `readOnlyHint` lied about a destructive operation.
  if (!canRunCedarCli()) {
    t.skip("cedar CLI is unavailable in this environment")
    return
  }

  const provider = new CedarCliProvider({
    binaryPath: process.env["CEDAR_CLI_PATH"] ?? "cedar",
    policyPath: MCP_TEMPLATE_POLICY_PATH,
  })

  const shaped = (normalized: { mutation: boolean; destructive: boolean; credential_access: boolean }) => {
    const base = mcpToolCallRequest()
    return { ...base, normalized: { ...base.normalized, ...normalized } }
  }

  const readOnly = { mutation: false, destructive: false, credential_access: false }

  assert.equal((await provider.evaluate(shaped(readOnly))).decision, "permit")
  assert.equal(
    (await provider.evaluate(shaped({ ...readOnly, credential_access: true }))).decision,
    "forbid",
    "a credential-reading MCP tool is permitted; that is the rule the template exists to keep",
  )
  assert.equal(
    (await provider.evaluate(shaped({ ...readOnly, mutation: true }))).decision,
    "forbid",
    "a mutating MCP tool is permitted by the read-only template",
  )
  assert.equal(
    (await provider.evaluate(shaped({ ...readOnly, destructive: true }))).decision,
    "forbid",
    "a destructive tool is permitted despite readOnlyHint; the flag cannot be trusted alone",
  )
})

test("an undetermined mutation status denies rather than permits", async (t) => {
  // The fail-open trap. `mutation` and `destructive` are both optional in the request schema, so
  // a caller can omit them. Defaulting an absent value to "does not mutate" would make
  // `resource.mutation == false` permit a call whose mutation status nobody determined — the
  // read-only template would then grant access it was never told about.
  //
  // This asserts the absent case specifically. A test whose fixtures always set the field passes
  // against both readings, which is exactly what happened the first time this was written.
  if (!canRunCedarCli()) {
    t.skip("cedar CLI is unavailable in this environment")
    return
  }

  const base = mcpToolCallRequest()
  const { mutation: _m, destructive: _d, ...withoutVerdicts } = base.normalized
  const context = { ...base, normalized: { ...withoutVerdicts } }

  // Prove the field really is absent rather than defaulted upstream.
  assert.equal("mutation" in context.normalized, false)
  assert.equal("destructive" in context.normalized, false)

  const provider = new CedarCliProvider({
    binaryPath: process.env["CEDAR_CLI_PATH"] ?? "cedar",
    policyPath: MCP_TEMPLATE_POLICY_PATH,
  })

  assert.equal(
    (await provider.evaluate(context)).decision,
    "forbid",
    "a tool call with no mutation verdict was permitted by the read-only template",
  )
})

test("the mutation and destructive verdicts actually reach the policy engine", () => {
  // Without this the template's `resource.mutation == false` term is unbacked: Cedar treats a
  // missing attribute on a request as no decision, so a template referring to an attribute the
  // input never carried would silently stop permitting anything.
  const context = mcpToolCallRequest()
  const file = buildCedarAuthorizeInput(context).entities[2]

  assert.equal(file?.attrs["mutation"], false)
  assert.equal(file?.attrs["destructive"], false)
  assert.equal(file?.attrs["credential_access"], false)
})

test("the divergence is registered, not merely described in a test name", () => {
  // A guard on the guard. If the MCP divergence is ever resolved, this names the place that must
  // change with it, so the resolution cannot be recorded in only one of the two.
  const state = readFileSync(join(DAEMON_ROOT, "scripts", "security-fabric-state.mjs"), "utf8")

  assert.ok(
    state.includes("mcp-gateway.ts"),
    "the MCP divergence is asserted by a test but absent from the substrate registry note",
  )
})