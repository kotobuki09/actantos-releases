import assert from "node:assert/strict"
import { spawnSync } from "node:child_process"
import { mkdtemp, rm, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import path from "node:path"
import test from "node:test"

import { buildCedarAuthorizeInput, CedarCliProvider } from "./cedar-cli-provider.ts"
import {
  createConfiguredCedarPolicyValidator,
  createConfiguredCedarProvider,
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

test("createConfiguredCedarProvider falls back to FakeCedarProvider when cedar is unavailable", () => {
  const provider = createConfiguredCedarProvider({
    probeBinary: () => false,
  })

  assert.ok(provider instanceof FakeCedarProvider)
})

test("createConfiguredCedarProvider selects CedarCliProvider when cedar is available", () => {
  const provider = createConfiguredCedarProvider({
    probeBinary: () => true,
  })

  assert.ok(provider instanceof CedarCliProvider)
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
})

test("CedarCliProvider evaluates the default policy directly for a safe read", async (t) => {
  if (!canRunCedarCli()) {
    t.skip("cedar CLI is unavailable in this environment")
    return
  }

  const provider = new CedarCliProvider()

  const result = await provider.evaluate(safeReadContext)

  assert.equal(result, "permit")
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

  assert.equal(result, "forbid")
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

    assert.equal(result, "permit")
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
