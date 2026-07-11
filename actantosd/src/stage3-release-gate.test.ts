import assert from "node:assert/strict"
import test from "node:test"

import {
  appendAuditAndOutbox,
  createTransactionalStore,
  leaseOutboxItem,
  completeOutboxDelivery,
  verifyAuditChain,
} from "./audit-outbox.ts"
import {
  createCredentialBroker,
  createMemoryAwsCredentialProvider,
  scanForSecretResidue,
} from "./credential-broker.ts"
import {
  archiveEvidenceArtifact,
  buildEvidenceArtifact,
  createEvidenceArchiveStore,
  verifyArchivedArtifact,
} from "./evidence-archive.ts"
import { createGvisorIsolationProvider } from "./gvisor-provider.ts"
import {
  clearUsedExecutionTokens,
  signExecutionSpec,
  verifyAndConsumeExecutionToken,
  type ExecutionSpec,
} from "./isolation-provider.ts"
import { createSiemDispatcher } from "./siem-connectors.ts"
import { resolveRequestTenantId, TenantMismatchError } from "./tenant-request.ts"

/**
 * Combined Stage 3 gate: tenant → decision → STS → gVisor → audit → Object Lock → SIEM
 * using deterministic in-process fakes (hardened lanes skip when external deps missing).
 */
test("stage3 combined release gate happy path and adversarial matrix", async () => {
  // Tenant isolation
  assert.equal(resolveRequestTenantId({ explicitTenantId: "t_alpha", principalTenantId: "t_alpha" }), "t_alpha")
  assert.throws(
    () => resolveRequestTenantId({ explicitTenantId: "t_alpha", principalTenantId: "t_beta" }),
    TenantMismatchError,
  )

  // STS credentials
  const broker = createCredentialBroker(createMemoryAwsCredentialProvider())
  const { lease, material } = await broker.issue({
    tenantId: "t_alpha",
    agentId: "agent",
    sessionId: "sess",
    toolName: "shell",
    roleArn: "arn:aws:iam::123456789012:role/runner",
    audience: "aws",
    scope: "s3:GetObject",
    maxTtlSeconds: 600,
  })

  // Signed gVisor execution
  clearUsedExecutionTokens()
  const gvisor = createGvisorIsolationProvider({
    runtime: "runsc",
    imageDigest: "sha256:feedface",
    requireProxy: true,
    proxyEndpoint: "http://proxy:3128",
    runtimeAvailable: true,
    seccompProfilePresent: true,
    apparmorProfilePresent: true,
  })
  const spec: ExecutionSpec = {
    tenantId: "t_alpha",
    agentId: "agent",
    sessionId: "sess",
    toolCallId: "tc1",
    requestId: "req1",
    provider: "gvisor",
    imageDigest: "sha256:feedface",
    workspacePath: "/workspace",
    argv: ["echo", "governed"],
    networkMode: "none",
    networkAllowlist: [],
    timeoutMs: 5_000,
    maxOutputBytes: 8_000,
    readOnlyRoot: true,
    credentialGrants: [{ reference: lease.reference, audience: "aws", maxTtlSeconds: 600 }],
    exp: Math.floor(Date.now() / 1000) + 60,
  }
  const token = signExecutionSpec(spec, "gate-secret")
  const verified = verifyAndConsumeExecutionToken(token, "gate-secret")
  const execution = await gvisor.execute(verified)
  assert.equal(execution.status, "executed")
  assert.equal(execution.provider, "gvisor")

  // Audit + outbox
  const store = createTransactionalStore()
  const { event, outboxIds } = appendAuditAndOutbox(
    store,
    {
      tenantId: "t_alpha",
      eventType: "execution.completed",
      actorType: "system",
      actorId: "daemon",
      payload: { requestId: "req1", status: execution.status },
    },
    ["siem:webhook", "archive:s3"],
  )
  assert.deepEqual(verifyAuditChain(store, "t_alpha"), { valid: true, length: 1 })

  // Object Lock archive
  const archives = createEvidenceArchiveStore()
  const artifact = buildEvidenceArtifact({
    tenantId: "t_alpha",
    chainHead: event.eventHash,
    fromSeq: 1,
    toSeq: 1,
    eventCount: 1,
    signerKeyId: "gate-key",
    signingSecret: "evidence-secret",
  })
  const archived = archiveEvidenceArtifact(archives, artifact, {
    chainValid: true,
    bucketVersioning: true,
    objectLockEnabled: true,
  })
  assert.equal(archived.status, "complete")
  assert.equal(verifyArchivedArtifact(archives, archived.objectKey!, "evidence-secret").valid, true)

  // SIEM delivery from outbox
  const dispatcher = createSiemDispatcher(async () => ({ status: 200, body: "ok" }))
  const item = leaseOutboxItem(store, "siem-worker")
  assert.ok(item)
  assert.equal(item.id, outboxIds[0])
  const delivery = await dispatcher.deliver(
    {
      id: "webhook-1",
      tenantId: "t_alpha",
      kind: "webhook",
      endpoint: "https://siem.example.com/ingest",
      secretRef: "ref",
      secretValue: "siem-secret",
      enabled: true,
      paused: false,
    },
    { eventId: event.eventId, tenantId: "t_alpha", body: item.payload },
  )
  assert.equal(delivery.status, "delivered")
  completeOutboxDelivery(store, item.id, "delivered")

  // Secret residue scan
  assert.deepEqual(
    scanForSecretResidue(
      {
        lease_record: JSON.stringify(lease),
        audit_event: JSON.stringify(event),
        execution_log: JSON.stringify(execution),
      },
      material,
    ),
    [],
  )

  await broker.revoke(lease.leaseId)

  // Adversarial: cross-tenant SIEM rejected
  const cross = await dispatcher.deliver(
    {
      id: "webhook-1",
      tenantId: "t_alpha",
      kind: "webhook",
      endpoint: "https://siem.example.com/ingest",
      secretRef: "ref",
      secretValue: "siem-secret",
      enabled: true,
      paused: false,
    },
    { eventId: "x", tenantId: "t_beta", body: {} },
  )
  assert.equal(cross.status, "rejected")

  // Adversarial: missing gVisor runtime fails closed
  const broken = createGvisorIsolationProvider({
    ...{
      runtime: "runsc" as const,
      imageDigest: "sha256:feedface",
      requireProxy: true,
      proxyEndpoint: "http://proxy:3128",
      runtimeAvailable: false,
      seccompProfilePresent: true,
      apparmorProfilePresent: true,
    },
  })
  assert.equal((await broken.readiness()).ready, false)
})
