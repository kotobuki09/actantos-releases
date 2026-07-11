import { createHash, randomUUID } from "node:crypto"

export type CredentialLeaseRequest = {
  readonly tenantId: string
  readonly agentId: string
  readonly sessionId: string
  readonly toolName: string
  readonly roleArn: string
  readonly audience: string
  readonly scope: string
  readonly maxTtlSeconds: number
}

export type CredentialLease = {
  readonly leaseId: string
  readonly reference: string
  readonly tenantId: string
  readonly expiresAt: string
  readonly accessKeyIdHash: string
  readonly secretAccessKeyHash: string
  readonly sessionTokenHash: string
  revoked: boolean
  cleanupPending: boolean
}

export type IssuedSecretMaterial = {
  readonly accessKeyId: string
  readonly secretAccessKey: string
  readonly sessionToken: string
  readonly tmpfsPath: string
}

export interface CredentialProvider {
  assumeRole(request: CredentialLeaseRequest): Promise<IssuedSecretMaterial & { readonly expiresAt: string }>
  revoke(reference: string): Promise<void>
}

export type CredentialBroker = {
  issue(request: CredentialLeaseRequest): Promise<{
    readonly lease: CredentialLease
    readonly material: IssuedSecretMaterial
  }>
  revoke(leaseId: string): Promise<void>
  listOpenLeases(): readonly CredentialLease[]
}

const hashSecret = (value: string): string => createHash("sha256").update(value).digest("hex")

export const createMemoryAwsCredentialProvider = (): CredentialProvider & {
  readonly revoked: string[]
} => {
  const revoked: string[] = []
  return {
    revoked,
    async assumeRole(request) {
      if (!request.roleArn.startsWith("arn:aws:iam::")) {
        throw new Error("invalid role arn")
      }
      if (request.maxTtlSeconds <= 0 || request.maxTtlSeconds > 3600) {
        throw new Error("ttl out of range")
      }
      return {
        accessKeyId: `AKIA${randomUUID().replaceAll("-", "").slice(0, 16)}`,
        secretAccessKey: randomUUID() + randomUUID(),
        sessionToken: randomUUID(),
        tmpfsPath: `/run/actantos/creds/${request.tenantId}/${request.sessionId}`,
        expiresAt: new Date(Date.now() + request.maxTtlSeconds * 1000).toISOString(),
      }
    },
    async revoke(reference) {
      revoked.push(reference)
    },
  }
}

export const createCredentialBroker = (provider: CredentialProvider): CredentialBroker => {
  const leases = new Map<string, CredentialLease>()

  return {
    async issue(request) {
      if (request.scope.length === 0) {
        throw new Error("scope required")
      }
      const material = await provider.assumeRole(request)
      const leaseId = randomUUID()
      const reference = `cred:${leaseId}`
      const lease: CredentialLease = {
        leaseId,
        reference,
        tenantId: request.tenantId,
        expiresAt: material.expiresAt,
        accessKeyIdHash: hashSecret(material.accessKeyId),
        secretAccessKeyHash: hashSecret(material.secretAccessKey),
        sessionTokenHash: hashSecret(material.sessionToken),
        revoked: false,
        cleanupPending: false,
      }
      leases.set(leaseId, lease)
      // Secrets are returned only for tmpfs injection; never persisted on the lease record.
      return { lease, material }
    },
    async revoke(leaseId) {
      const lease = leases.get(leaseId)
      if (lease === undefined) {
        return
      }
      try {
        await provider.revoke(lease.reference)
        lease.revoked = true
        lease.cleanupPending = false
      } catch {
        lease.cleanupPending = true
      }
    },
    listOpenLeases() {
      return [...leases.values()].filter((lease) => !lease.revoked || lease.cleanupPending)
    },
  }
}

export const scanForSecretResidue = (
  surfaces: Readonly<Record<string, string>>,
  material: IssuedSecretMaterial,
): readonly string[] => {
  const needles = [material.accessKeyId, material.secretAccessKey, material.sessionToken]
  const hits: string[] = []
  for (const [surface, content] of Object.entries(surfaces)) {
    for (const needle of needles) {
      if (content.includes(needle)) {
        hits.push(surface)
      }
    }
  }
  return hits
}
