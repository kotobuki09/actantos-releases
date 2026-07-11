import assert from "node:assert/strict"
import test from "node:test"

import {
  createCredentialBroker,
  createMemoryAwsCredentialProvider,
  scanForSecretResidue,
} from "./credential-broker.ts"

test("credential broker issues hashed leases and cleans secrets from residue surfaces", async () => {
  const provider = createMemoryAwsCredentialProvider()
  const broker = createCredentialBroker(provider)
  const { lease, material } = await broker.issue({
    tenantId: "t_alpha",
    agentId: "a1",
    sessionId: "s1",
    toolName: "aws_cli",
    roleArn: "arn:aws:iam::123456789012:role/actantos-runner",
    audience: "aws",
    scope: "s3:GetObject",
    maxTtlSeconds: 900,
  })

  assert.equal(lease.revoked, false)
  assert.equal(lease.accessKeyIdHash.length, 64)
  assert.notEqual(lease.accessKeyIdHash, material.accessKeyId)

  const residue = scanForSecretResidue(
    {
      api_log: JSON.stringify(lease),
      db_row: JSON.stringify(lease),
      process_args: "aws s3 ls",
      workspace: "README",
    },
    material,
  )
  assert.deepEqual(residue, [])

  await broker.revoke(lease.leaseId)
  assert.equal(provider.revoked.includes(lease.reference), true)
  assert.equal(broker.listOpenLeases().length, 0)
})

test("credential broker rejects invalid role/ttl/scope", async () => {
  const broker = createCredentialBroker(createMemoryAwsCredentialProvider())
  await assert.rejects(
    () =>
      broker.issue({
        tenantId: "t_alpha",
        agentId: "a1",
        sessionId: "s1",
        toolName: "aws_cli",
        roleArn: "not-an-arn",
        audience: "aws",
        scope: "s3:GetObject",
        maxTtlSeconds: 900,
      }),
    /invalid role arn/u,
  )
  await assert.rejects(
    () =>
      broker.issue({
        tenantId: "t_alpha",
        agentId: "a1",
        sessionId: "s1",
        toolName: "aws_cli",
        roleArn: "arn:aws:iam::123456789012:role/actantos-runner",
        audience: "aws",
        scope: "",
        maxTtlSeconds: 900,
      }),
    /scope required/u,
  )
})
