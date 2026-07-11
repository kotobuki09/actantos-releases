import { createHmac, randomUUID } from "node:crypto"

import { canonicalHash } from "./hash.ts"

export type EvidenceArtifact = {
  readonly version: "stage3-evidence-v1"
  readonly tenantId: string
  readonly artifactId: string
  readonly createdAt: string
  readonly chainHead: string
  readonly eventCount: number
  readonly bounds: { readonly fromSeq: number; readonly toSeq: number }
  readonly digest: string
  readonly signerKeyId: string
  readonly signature: string
}

export type ObjectLockObject = {
  readonly key: string
  readonly versionId: string
  readonly body: string
  readonly retentionMode: "COMPLIANCE"
  readonly retainUntil: string
  readonly sseKms: true
  deleted: boolean
}

export type EvidenceArchiveStore = {
  artifacts: EvidenceArtifact[]
  objects: Map<string, ObjectLockObject>
}

export const createEvidenceArchiveStore = (): EvidenceArchiveStore => ({
  artifacts: [],
  objects: new Map(),
})

export const buildEvidenceArtifact = (input: {
  readonly tenantId: string
  readonly chainHead: string
  readonly fromSeq: number
  readonly toSeq: number
  readonly eventCount: number
  readonly signerKeyId: string
  readonly signingSecret: string
}): EvidenceArtifact => {
  const artifactId = randomUUID()
  const createdAt = new Date().toISOString()
  const unsigned = {
    version: "stage3-evidence-v1" as const,
    tenantId: input.tenantId,
    artifactId,
    createdAt,
    chainHead: input.chainHead,
    eventCount: input.eventCount,
    bounds: { fromSeq: input.fromSeq, toSeq: input.toSeq },
    signerKeyId: input.signerKeyId,
  }
  const digest = canonicalHash(unsigned)
  const signature = createHmac("sha256", input.signingSecret).update(digest).digest("hex")
  return { ...unsigned, digest, signature }
}

export const archiveEvidenceArtifact = (
  store: EvidenceArchiveStore,
  artifact: EvidenceArtifact,
  options: {
    readonly retentionDays?: number
    readonly bucketVersioning?: boolean
    readonly objectLockEnabled?: boolean
    readonly chainValid?: boolean
  } = {},
): { readonly status: "complete" | "rejected"; readonly reason?: string; readonly objectKey?: string } => {
  const retentionDays = options.retentionDays ?? 365
  if (retentionDays < 30 || retentionDays > 365 * 7) {
    return { status: "rejected", reason: "retention_out_of_range" }
  }
  if (options.chainValid === false) {
    return { status: "rejected", reason: "chain_invalid" }
  }
  if (options.bucketVersioning === false || options.objectLockEnabled === false) {
    return { status: "rejected", reason: "bucket_not_worm" }
  }

  const key = `tenants/${artifact.tenantId}/evidence/${artifact.artifactId}.json`
  const existing = store.objects.get(key)
  if (existing !== undefined && !existing.deleted) {
    return { status: "rejected", reason: "overwrite_forbidden" }
  }

  const retainUntil = new Date(Date.now() + retentionDays * 86_400_000).toISOString()
  const object: ObjectLockObject = {
    key,
    versionId: randomUUID(),
    body: JSON.stringify(artifact),
    retentionMode: "COMPLIANCE",
    retainUntil,
    sseKms: true,
    deleted: false,
  }
  store.objects.set(key, object)
  store.artifacts.push(artifact)
  return { status: "complete", objectKey: key }
}

export const tryDeleteArchivedObject = (
  store: EvidenceArchiveStore,
  key: string,
  now: Date = new Date(),
): { readonly deleted: boolean; readonly reason?: string } => {
  const object = store.objects.get(key)
  if (object === undefined) {
    return { deleted: false, reason: "not_found" }
  }
  if (new Date(object.retainUntil).getTime() > now.getTime()) {
    return { deleted: false, reason: "object_lock_compliance" }
  }
  object.deleted = true
  return { deleted: true }
}

export const verifyArchivedArtifact = (
  store: EvidenceArchiveStore,
  key: string,
  signingSecret: string,
): { readonly valid: boolean; readonly reason?: string } => {
  const object = store.objects.get(key)
  if (object === undefined || object.deleted) {
    return { valid: false, reason: "missing" }
  }
  const artifact = JSON.parse(object.body) as EvidenceArtifact
  const unsigned = {
    version: artifact.version,
    tenantId: artifact.tenantId,
    artifactId: artifact.artifactId,
    createdAt: artifact.createdAt,
    chainHead: artifact.chainHead,
    eventCount: artifact.eventCount,
    bounds: artifact.bounds,
    signerKeyId: artifact.signerKeyId,
  }
  const digest = canonicalHash(unsigned)
  const expected = createHmac("sha256", signingSecret).update(digest).digest("hex")
  if (digest !== artifact.digest || expected !== artifact.signature) {
    return { valid: false, reason: "signature_mismatch" }
  }
  if (!object.sseKms || object.retentionMode !== "COMPLIANCE") {
    return { valid: false, reason: "storage_controls_missing" }
  }
  return { valid: true }
}
