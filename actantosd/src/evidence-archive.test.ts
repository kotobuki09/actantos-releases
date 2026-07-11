import assert from "node:assert/strict"
import test from "node:test"

import {
  archiveEvidenceArtifact,
  buildEvidenceArtifact,
  createEvidenceArchiveStore,
  tryDeleteArchivedObject,
  verifyArchivedArtifact,
} from "./evidence-archive.ts"

test("evidence archive completes only with valid chain and Object Lock controls", () => {
  const store = createEvidenceArchiveStore()
  const secret = "evidence-secret"
  const artifact = buildEvidenceArtifact({
    tenantId: "t_alpha",
    chainHead: "hash_head",
    fromSeq: 1,
    toSeq: 10,
    eventCount: 10,
    signerKeyId: "key-1",
    signingSecret: secret,
  })

  assert.equal(
    archiveEvidenceArtifact(store, artifact, { chainValid: false }).status,
    "rejected",
  )
  assert.equal(
    archiveEvidenceArtifact(store, artifact, { objectLockEnabled: false }).status,
    "rejected",
  )

  const archived = archiveEvidenceArtifact(store, artifact, {
    chainValid: true,
    bucketVersioning: true,
    objectLockEnabled: true,
    retentionDays: 365,
  })
  assert.equal(archived.status, "complete")
  assert.equal(verifyArchivedArtifact(store, archived.objectKey!, secret).valid, true)

  assert.equal(
    archiveEvidenceArtifact(store, artifact, {
      chainValid: true,
      bucketVersioning: true,
      objectLockEnabled: true,
    }).status,
    "rejected",
  )

  const locked = tryDeleteArchivedObject(store, archived.objectKey!)
  assert.deepEqual(locked, { deleted: false, reason: "object_lock_compliance" })
})
