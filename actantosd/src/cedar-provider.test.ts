import assert from "node:assert/strict"
import { spawnSync } from "node:child_process"
import { mkdtemp, rm, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import path from "node:path"
import test from "node:test"

import { buildCedarAuthorizeInput, CedarCliProvider } from "./cedar-cli-provider.ts"
import { commandFromRequest } from "./decision-command.ts"
import {
  createConfiguredCedarPolicyValidator,
  createConfiguredCedarProvider,
  resolveEvaluatorMode,
} from "./cedar-provider.ts"
import { FakeCedarProvider } from "./fake-cedar-provider.ts"

const canRunCedarCli = (): boolean =>
  spawnSync("cedar", ["--version"], {
    stdio: "ignore",
    timeout: 1_000,
  }).status === 0

const safeReadContext = {
  request_id: "req_00000001",
  tenant_id: "t_demo",
  agent: {
    id: "pi_demo",
    runtime_type: "pi",
    environment: "dev",
    risk_tier: "low",
  },
  subject: {
    user_id: "u_demo",
  },
  session: {
    id: "s_demo",
    cwd: "/workspace",
  },
  tool: {
    kind: "file",
    name: "guarded_read",
    operation: "ReadFile",
    schema_hash: "",
  },
  action: {
    operation: "ReadFile",
    args: {
      path: "/workspace/README.md",
    },
  },
  resource: {
    id: "/workspace/README.md",
    kind: "file",
    path: "/workspace/README.md",
  },
  normalized: {
    verb: "read",
    mutation: false,
    destructive: false,
    network: false,
    credential_access: false,
    risk_class: "low",
  },
  scope_hash: "scope-demo",
} as const

const withCustomPolicyFile = async <T>(
  callback: (policyPath: string) => Promise<T>,
): Promise<T> => {
  const directoryPath = await mkdtemp(path.join(tmpdir(), "cedar-provider-test-"))
  const policyPath = path.join(directoryPath, "custom.cedar")

  await writeFile(policyPath, "permit(principal, action, resource) when { true };", "utf8")

  try {
    return await callback(policyPath)
  } finally {
    await rm(directoryPath, { recursive: true, force: true })
  }
}

test("createConfiguredCedarProvider falls back to FakeCedarProvider when cedar is unavailable in development", () => {
  const provider = createConfiguredCedarProvider({
    probeBinary: () => false,
    mode: "development",
  })

  assert.ok(provider instanceof FakeCedarProvider)
})

test("createConfiguredCedarProvider falls back to FakeCedarProvider when cedar is unavailable in test mode", () => {
  const provider = createConfiguredCedarProvider({
    probeBinary: () => false,
    mode: "test",
  })

  assert.ok(provider instanceof FakeCedarProvider)
})

test("createConfiguredCedarProvider fails closed in production when cedar is unavailable", () => {
  assert.throws(
    () =>
      createConfiguredCedarProvider({
        probeBinary: () => false,
        mode: "production",
      }),
    (error: unknown) => {
      assert.ok(error instanceof Error)
      assert.match(error.message, /Refusing FakeCedar silent fallback/)
      assert.match(error.message, /mode=production/)
      return true
    },
  )
})

test("createConfiguredCedarProvider selects CedarCliProvider when cedar is available", () => {
  const provider = createConfiguredCedarProvider({
    probeBinary: () => true,
    mode: "production",
  })

  assert.ok(provider instanceof CedarCliProvider)
})

test("createConfiguredCedarPolicyValidator fails closed in production when cedar is unavailable", async () => {
  const validator = createConfiguredCedarPolicyValidator({
    probeBinary: () => false,
    mode: "production",
  })
  const result = await validator("permit(principal, action, resource);")
  assert.equal(result.ok, false)
  if (!result.ok) {
    assert.match(result.message, /Authoritative Cedar policy validator unavailable/)
  }
})

test("createConfiguredCedarPolicyValidator accepts Cedar source when check-parse succeeds", async () => {
  const validator = createConfiguredCedarPolicyValidator({
    probeBinary: () => true,
    runCheckParse: () => ({
      status: 0,
      stdout: "",
      stderr: "",
    }),
  })

  const result = await validator("permit(principal, action, resource);")

  assert.deepEqual(result, { ok: true })
})

test("createConfiguredCedarPolicyValidator returns a readable parse error when Cedar rejects the source", async () => {
  const validator = createConfiguredCedarPolicyValidator({
    probeBinary: () => true,
    runCheckParse: () => ({
      status: 1,
      stdout: "",
      stderr: "parse error at line 1, column 8",
    }),
  })

  const result = await validator("permit(principal action, resource);")

  assert.deepEqual(result, {
    ok: false,
    message: "parse error at line 1, column 8",
  })
})

test("buildCedarAuthorizeInput carries the canonical resource attributes Cedar evaluates", () => {
  const authorizeInput = buildCedarAuthorizeInput(safeReadContext)

  assert.deepEqual(authorizeInput.request.context, {})
  assert.equal(authorizeInput.entities[2]?.attrs["credential_access"], false)
  assert.equal(authorizeInput.entities[2]?.attrs["path"], "/workspace/README.md")
  assert.equal(authorizeInput.request.resource, "File::\"/workspace/README.md\"")
  // No host_workspace_path in the fixture, so this falls back to the directory holding the
  // resource. A file is not a workspace, and an absent workspace must not become the empty string,
  // which a policy could treat as "no workspace declared" and permit.
  assert.equal(authorizeInput.entities[2]?.attrs["workspace_path"], "/workspace")
})

test("buildCedarAuthorizeInput exposes the workspace the command will actually be mounted with", () => {
  // The gap this closes: policy could see the file path but not the directory the executor binds.
  // A caller could therefore be authorized for File::"/workspace/README.md" while mounting an
  // unrelated host directory.
  const context = {
    ...safeReadContext,
    action: {
      ...safeReadContext.action,
      args: { ...safeReadContext.action.args, host_workspace_path: "/workspace" },
    },
  }

  const authorizeInput = buildCedarAuthorizeInput(context)

  assert.equal(authorizeInput.entities[2]?.attrs["workspace_path"], "/workspace")
  // The resource path is unchanged, so every existing policy means what it meant before.
  assert.equal(authorizeInput.entities[2]?.attrs["path"], "/workspace/README.md")
})

test("buildCedarAuthorizeInput exposes a workspace outside the authorized resource path", () => {
  // The interesting case, and the reason the attribute exists. Nothing in the input stops a caller
  // declaring /etc while asking to touch a file under /workspace; making that visible is what lets
  // a policy refuse it.
  const context = {
    ...safeReadContext,
    action: {
      ...safeReadContext.action,
      args: { ...safeReadContext.action.args, host_workspace_path: "/etc" },
    },
  }

  const authorizeInput = buildCedarAuthorizeInput(context)

  assert.equal(authorizeInput.entities[2]?.attrs["workspace_path"], "/etc")
  assert.notEqual(authorizeInput.entities[2]?.attrs["workspace_path"], authorizeInput.entities[2]?.attrs["path"])
})

test("the workspace attribute matches the one the command digest binds", () => {
  // If these two derivations ever disagreed, a policy could authorize one workspace while the
  // token binds another, which would reopen the hole the digest closes.
  for (const hostWorkspacePath of ["/workspace", "/srv/project", "/etc"]) {
    const context = {
      ...safeReadContext,
      action: {
        ...safeReadContext.action,
        args: { ...safeReadContext.action.args, host_workspace_path: hostWorkspacePath },
      },
    }

    const fromPolicy = buildCedarAuthorizeInput(context).entities[2]?.attrs["workspace_path"]
    const fromCommand = commandFromRequest(context).workspacePath

    assert.equal(fromPolicy, fromCommand)
  }
})

test("CedarCliProvider evaluates the default policy directly for a safe read", async (t) => {
  if (!canRunCedarCli()) {
    t.skip("cedar CLI is unavailable in this environment")
    return
  }

  const provider = new CedarCliProvider()

  const result = await provider.evaluate(safeReadContext)

  assert.equal(result.decision, "permit")
})

test("CedarCliProvider denies credential access under the default policy", async (t) => {
  if (!canRunCedarCli()) {
    t.skip("cedar CLI is unavailable in this environment")
    return
  }

  const provider = new CedarCliProvider()

  const result = await provider.evaluate({
    ...safeReadContext,
    request_id: "req_00000002",
    resource: {
      id: "/workspace/.env",
      kind: "file",
      path: "/workspace/.env",
    },
    action: {
      operation: "ReadFile",
      args: {
        path: "/workspace/.env",
      },
    },
    normalized: {
      ...safeReadContext.normalized,
      credential_access: true,
      risk_class: "critical",
    },
  })

  assert.equal(result.decision, "forbid")
})

test("CedarCliProvider retries transient recursion-limit failures before returning the decision", async () => {
  await withCustomPolicyFile(async (policyPath) => {
    let attempts = 0
    const provider = new CedarCliProvider({
      policyPath,
      maxAttempts: 2,
      authorizeCommand: async () => {
        attempts += 1
        if (attempts === 1) {
          return {
            exitCode: 2,
            stdout: "\nDENY\n\nerror while evaluating policy `policy0`: recursion limit reached\n",
            stderr: "",
          }
        }

        return {
          exitCode: 0,
          stdout: "\nALLOW\n",
          stderr: "",
        }
      },
    })

    const result = await provider.evaluate(safeReadContext)

    assert.equal(result.decision, "permit")
    assert.equal(attempts, 2)
  })
})

test("CedarCliProvider rejects non-zero Cedar exits even when stdout begins with DENY", async () => {
  await withCustomPolicyFile(async (policyPath) => {
    const provider = new CedarCliProvider({
      policyPath,
      maxAttempts: 1,
      authorizeCommand: async () => ({
        exitCode: 2,
        stdout: "\nDENY\n\nerror while evaluating policy `policy0`: recursion limit reached\n",
        stderr: "",
      }),
    })

    await assert.rejects(
      provider.evaluate(safeReadContext),
      /cedar exited with code 2/u,
    )
  })
})

// ---------------------------------------------------------------------------
// A-04: Evaluator-mode contract tests
// ---------------------------------------------------------------------------

test("resolveEvaluatorMode returns production when NODE_ENV=production", () => {
  assert.equal(resolveEvaluatorMode({ NODE_ENV: "production" }), "production")
})

test("resolveEvaluatorMode returns test when NODE_ENV=test", () => {
  assert.equal(resolveEvaluatorMode({ NODE_ENV: "test" }), "test")
})

test("resolveEvaluatorMode returns development when NODE_ENV is unset", () => {
  assert.equal(resolveEvaluatorMode({}), "development")
})

test("resolveEvaluatorMode respects ACTANTOS_EVALUATOR_MODE override over NODE_ENV", () => {
  assert.equal(
    resolveEvaluatorMode({ NODE_ENV: "production", ACTANTOS_EVALUATOR_MODE: "development" }),
    "development",
  )
})

test("resolveEvaluatorMode respects ACTANTOS_REQUIRE_CEDAR=1 as production override", () => {
  assert.equal(
    resolveEvaluatorMode({ NODE_ENV: "development", ACTANTOS_REQUIRE_CEDAR: "1" }),
    "production",
  )
})

test("A-04 bypass: fake provider cannot be selected via default production config (Cedar unavailable → throws)", () => {
  // Attempting production mode without Cedar must throw — no silent allow-on-error path
  assert.throws(
    () =>
      createConfiguredCedarProvider({
        probeBinary: () => false,
        mode: "production",
      }),
    (err: unknown) => {
      assert.ok(err instanceof Error)
      assert.match(err.message, /Refusing FakeCedar silent fallback/)
      assert.match(err.message, /mode=production/)
      return true
    },
  )
})

test("A-04 bypass: invalid/zero-length ACTANTOS_EVALUATOR_MODE falls back to NODE_ENV logic", () => {
  // An empty or unknown value must not silently default to development in production env
  assert.equal(
    resolveEvaluatorMode({ NODE_ENV: "production", ACTANTOS_EVALUATOR_MODE: "" }),
    "production",
  )
  assert.equal(
    resolveEvaluatorMode({ NODE_ENV: "production", ACTANTOS_EVALUATOR_MODE: "unknown-value" }),
    "production",
  )
})

test("CedarCliProvider enforces a policy that constrains the workspace", async (t) => {
  // Requires the real CLI: the built-in evaluator answers the shipped policy in-process, so
  // without the binary this would prove nothing about Cedar.
  if (!canRunCedarCli()) {
    t.skip("cedar CLI is unavailable in this environment")
    return
  }

  const withWorkspace = (hostWorkspacePath: string) => ({
    ...safeReadContext,
    action: {
      ...safeReadContext.action,
      args: { ...safeReadContext.action.args, host_workspace_path: hostWorkspacePath },
    },
  })

  // The shipped policy constrains the workspace, so this is the claim under test.
  const shipped = new CedarCliProvider()

  assert.equal(
    (await shipped.evaluate(withWorkspace("/etc"))).decision,
    "forbid",
    "the shipped policy must refuse a workspace outside the approved root",
  )
  assert.equal((await shipped.evaluate(withWorkspace("/workspace"))).decision, "permit")

  // A custom policy, to show the constraint is policy-driven rather than hard-wired.
  const constrained = new CedarCliProvider()
  // No unconditional forbid: in Cedar an explicit forbid outranks a permit, so adding one would
  // deny the permitted case too and the test would pass for the wrong reason. With no permit
  // matching, the decision is already Deny.
  constrained.reloadPolicy(
    `permit(principal, action, resource) when { resource.workspace_path == "/workspace" };`,
  )

  assert.equal((await constrained.evaluate(withWorkspace("/workspace"))).decision, "permit")
  assert.equal((await constrained.evaluate(withWorkspace("/etc"))).decision, "forbid")
})

test("the built-in evaluator and the real cedar CLI never disagree", async (t) => {
  // `evaluateBuiltInPolicy` answers the three known policies in-process so the daemon works
  // without the cedar binary installed. That is a second implementation of the same decision, and
  // the two drifting apart is how a host with no binary would quietly enforce something different
  // from the policy it ships. These contexts are run through both and must agree exactly.
  if (!canRunCedarCli()) {
    t.skip("cedar CLI is unavailable in this environment")
    return
  }

  const withWorkspace = (hostWorkspacePath: string | undefined) => ({
    ...safeReadContext,
    action: {
      ...safeReadContext.action,
      args: {
        ...safeReadContext.action.args,
        ...(hostWorkspacePath === undefined ? {} : { host_workspace_path: hostWorkspacePath }),
      },
    },
  })

  const withCredentialAccess = (credentialAccess: boolean) => ({
    ...safeReadContext,
    normalized: { ...safeReadContext.normalized, credential_access: credentialAccess },
  })

  const contexts = [
    withWorkspace("/workspace"),
    withWorkspace("/etc"),
    withWorkspace("/workspace/nested"),
    withCredentialAccess(true),
    { ...withCredentialAccess(true), ...withWorkspace("/etc") },
    withWorkspace(undefined),
    // The network-call shape: a `url` resource with no path. The workspace constraint must not
    // apply to it, and applying it denied every outbound call in the v2 runtime suite.
    { ...safeReadContext, resource: { kind: "url", url: "https://api.github.com/repos/org/repo" } },
  ]

  for (const [index, context] of contexts.entries()) {
    // The built-in answer, taken with the CLI stubbed so nothing can reach a real cedar.
    const builtIn = new CedarCliProvider({
      authorizeCommand: async () => {
        throw new Error("the built-in evaluator must not invoke cedar")
      },
    })

    // The same shipped policy through the real binary. No options: the default policyPath is
    // policies/default.cedar, which is the file under test.
    const viaCli = new CedarCliProvider()

    assert.equal(
      (await builtIn.evaluate(context)).decision,
      (await viaCli.evaluate(context)).decision,
      `built-in and cedar disagree on context ${String(index)}`,
    )
  }
})
