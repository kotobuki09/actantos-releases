import assert from "node:assert/strict"
import { mkdtemp, rm, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import path from "node:path"
import test from "node:test"

import { safeReadRequest } from "./intercept-test-fixtures.ts"
import {
  parsePolicyTestCommand,
  runPolicyTestCommand,
} from "./policy-test.ts"
import { createTestDatabase } from "./test-database.ts"

const defaultPolicySource = `permit (
  principal,
  action,
  resource
)
when {
  resource.credential_access == false
};
`

const writeRequestFixture = async (
  directoryPath: string,
  fileName: string,
  request: unknown,
): Promise<string> => {
  const filePath = path.join(directoryPath, fileName)
  await writeFile(filePath, JSON.stringify(request, null, 2), "utf8")
  return filePath
}

const gitPushRequest = (requestId: string) => ({
  ...safeReadRequest(requestId),
  tool: {
    kind: "shell",
    name: "guarded_bash",
    operation: "ExecuteShellCommand",
    schema_hash: "",
  },
  resource: {
    kind: "shell",
  },
  action: {
    operation: "ExecuteShellCommand",
    args: { command: "git push --dry-run" },
  },
  normalized: {
    verb: "execute",
    mutation: true,
    destructive: false,
    network: true,
    credential_access: false,
    risk_class: "high",
    command_family: "git",
    subcommand: "push",
  },
})

const activatePolicyBundle = async (
  sourceText: string,
  database: Awaited<ReturnType<typeof createTestDatabase>>,
): Promise<void> => {
  await database.query(
    `
      UPDATE policy_bundles
      SET source_text = $1,
          source_hash = 'policy-test-hash',
          active = true
      WHERE tenant_id = 't_demo'
        AND id = '33333333-3333-3333-3333-333333333333'
    `,
    [sourceText],
  )
}

test("parsePolicyTestCommand accepts request-file and candidate bundle options", () => {
  assert.deepEqual(
    parsePolicyTestCommand([
      "--request-file",
      "fixtures/request.json",
      "--policy-file",
      "fixtures/candidate.cedar",
      "--tenant-id",
      "tenant_a",
    ]),
    {
      requestFile: "fixtures/request.json",
      policyFile: "fixtures/candidate.cedar",
      tenantId: "tenant_a",
    },
  )
})

test("parsePolicyTestCommand rejects missing request-file", () => {
  assert.throws(
    () => parsePolicyTestCommand(["--policy-file", "fixtures/candidate.cedar"]),
    /--request-file is required/u,
  )
})

test("runPolicyTestCommand reports allow, deny, and approval_required from the active bundle", async () => {
  const database = await createTestDatabase()
  const tempDirectory = await mkdtemp(path.join(tmpdir(), "policy-test-"))

  try {
    await activatePolicyBundle(defaultPolicySource, database)

    const allowRequestPath = await writeRequestFixture(
      tempDirectory,
      "allow.json",
      safeReadRequest("req_policy_test_allow_0001"),
    )
    const denyRequestPath = await writeRequestFixture(
      tempDirectory,
      "deny.json",
      {
        ...safeReadRequest("req_policy_test_deny_0001"),
        normalized: {
          ...safeReadRequest("req_policy_test_deny_0001").normalized,
          credential_access: true,
          risk_class: "critical",
        },
        resource: {
          id: "/workspace/.env",
          kind: "file",
          path: "/workspace/.env",
        },
        action: {
          operation: "ReadFile",
          args: { path: "/workspace/.env" },
        },
      },
    )
    const approvalRequestPath = await writeRequestFixture(
      tempDirectory,
      "approval.json",
      gitPushRequest("req_policy_test_approval_0001"),
    )

    const allowResult = await runPolicyTestCommand(
      { requestFile: allowRequestPath, tenantId: "t_demo" },
      { database },
    )
    const denyResult = await runPolicyTestCommand(
      { requestFile: denyRequestPath, tenantId: "t_demo" },
      { database },
    )
    const approvalResult = await runPolicyTestCommand(
      { requestFile: approvalRequestPath, tenantId: "t_demo" },
      { database },
    )

    assert.equal(allowResult.response.decision, "allow")
    assert.equal(allowResult.response.reason_code, "allowed")
    assert.equal(allowResult.policySource.kind, "active_bundle")

    assert.equal(denyResult.response.decision, "deny")
    assert.equal(denyResult.response.reason_code, "policy_forbid.credential_path")
    assert.equal(denyResult.policySource.kind, "active_bundle")

    assert.equal(approvalResult.response.decision, "approval_required")
    assert.equal(approvalResult.response.reason_code, "approval_required")
    assert.equal(approvalResult.policySource.kind, "active_bundle")
  } finally {
    await rm(tempDirectory, { recursive: true, force: true })
    await database.close()
  }
})

test("runPolicyTestCommand evaluates a candidate policy file instead of the active bundle", async () => {
  const database = await createTestDatabase()
  const tempDirectory = await mkdtemp(path.join(tmpdir(), "policy-test-"))

  try {
    const requestPath = await writeRequestFixture(
      tempDirectory,
      "candidate-request.json",
      {
        ...safeReadRequest("req_policy_test_candidate_0001"),
        normalized: {
          ...safeReadRequest("req_policy_test_candidate_0001").normalized,
          credential_access: true,
          risk_class: "critical",
        },
        resource: {
          id: "/workspace/.env",
          kind: "file",
          path: "/workspace/.env",
        },
        action: {
          operation: "ReadFile",
          args: { path: "/workspace/.env" },
        },
      },
    )
    const policyPath = path.join(tempDirectory, "deny-all.cedar")
    await writeFile(
      policyPath,
      `forbid (
  principal,
  action,
  resource
);`,
      "utf8",
    )

    const result = await runPolicyTestCommand(
      {
        requestFile: requestPath,
        policyFile: policyPath,
        tenantId: "t_demo",
      },
      { database },
    )

    assert.equal(result.response.decision, "deny")
    assert.equal(result.response.reason_code, "policy_forbid.credential_path")
    assert.equal(result.policySource.kind, "policy_file")
    assert.equal(result.policySource.path, policyPath)
  } finally {
    await rm(tempDirectory, { recursive: true, force: true })
    await database.close()
  }
})
