import { createHash } from "node:crypto"

import type { CapabilityGrant } from "./delegation.ts"
import {
  CapabilityBroker,
  type CapabilityExecuteArgs,
  type CapabilityProvider,
  type CredentialProvider,
  type CredentialRequestContext,
  type DownstreamCredential,
} from "./capability-broker.ts"

/**
 * Capability provider adapters.
 *
 * Each provider delegates to an injected client so the fabric stays vendor-neutral and the
 * tests never need live credentials or network access. A provider receives a short-lived
 * credential, uses it, and must return data only — the broker enforces that boundary
 * independently via `assertNoCredentialsInResult` and `assertCredentialNotEchoed`.
 *
 * No provider here returns a credential to the agent, and no provider hard-codes a vendor
 * SDK. The production HTTP implementations that satisfy these client interfaces live in
 * `production-providers.ts`.
 */

/**
 * An AWS `RoleSessionName` that names the agent that asked for it.
 *
 * STS constrains the name to 2-64 characters of `[\w+=,.@-]`, and a SPIFFE ID contains
 * `://`, so the identity is sanitised rather than pasted. Two details are load-bearing:
 * underscore is inside `\w` and must stay, because without it `t_demo` and `t-demo` — two
 * different tenants — would collapse onto one session name; and truncation keeps a digest
 * of the original, so two long identities cannot collide either.
 */
export const sessionNameForAgent = (context: CredentialRequestContext): string => {
  const identity = `${context.tenantId}/${context.agentSpiffeId}`
  const sanitised = identity.replace(/[^A-Za-z0-9_+=,.@-]/gu, "-").replace(/^-+|-+$/gu, "")
  const prefix = "actant-"

  if (`${prefix}${sanitised}`.length <= 64) {
    return `${prefix}${sanitised}`
  }

  const digest = createHash("sha256").update(identity).digest("hex").slice(0, 12)
  const room = 64 - prefix.length - digest.length - 1
  return `${prefix}${sanitised.slice(0, room)}-${digest}`
}

// --- AWS STS ------------------------------------------------------------------------

export interface StsClient {
  assumeRole(args: {
    readonly roleArn: string
    readonly sessionName: string
    readonly durationSeconds: number
  }): Promise<{ readonly accessKeyId: string; readonly secretAccessKey: string; readonly sessionToken: string; readonly expiration: Date }>
}

/** Exchanges a grant for short-lived AWS session credentials. */
export const createStsCredentialProvider = (client: StsClient): CredentialProvider => ({
  id: "aws-sts",

  async obtain(
    grant: CapabilityGrant,
    context: CredentialRequestContext,
  ): Promise<DownstreamCredential> {
    if (grant.provider !== "aws") {
      throw new Error("unsupported provider for STS credential provider")
    }

    const roleArn = grant.segments.join("/")
    const assumed = await client.assumeRole({
      roleArn,
      // Named for the verified caller, so a CloudTrail entry records which agent produced
      // the effect instead of recording that "actant" did.
      sessionName: sessionNameForAgent(context),
      durationSeconds: 900,
    })

    // Assembled server-side. The agent never observes this object.
    return {
      value: JSON.stringify({
        accessKeyId: assumed.accessKeyId,
        secretAccessKey: assumed.secretAccessKey,
        sessionToken: assumed.sessionToken,
      }),
      expiresAt: assumed.expiration,
      // STS offers no call to delete a session early, so the session name is the only
      // release handle that exists. Carrying it also means the audit trail records the name
      // the session was minted under, which is what makes the effect attributable.
      handle: `sts:${assumed.accessKeyId}`,
    }
  },

  async destroy(): Promise<void> {
    // STS session credentials cannot be revoked before expiry; the session name and short
    // duration bound the window. Nothing to release in-process.
  },
})

// --- GitHub -------------------------------------------------------------------------

export interface GitHubClient {
  listIssues(args: { readonly repo: string; readonly credential: string }): Promise<unknown>
  mergePullRequest(args: {
    readonly repo: string
    readonly number: number
    readonly method: string
    readonly credential: string
  }): Promise<unknown>
}

const githubProvider = (
  client: GitHubClient,
  requiresCredential: boolean,
): CapabilityProvider => ({
  provider: "github",
  requiresCredential,

  supports(grant: CapabilityGrant): boolean {
    return grant.provider === "github"
  },

  async execute(args: CapabilityExecuteArgs): Promise<unknown> {
    const [owner, repo, resource, ...rest] = args.grant.segments

    if (owner === undefined || repo === undefined || resource === undefined) {
      throw new Error("malformed github grant")
    }

    const credential = args.credential?.value ?? ""

    if (resource === "issues" && rest[0] === "read") {
      return client.listIssues({ repo: `${owner}/${repo}`, credential })
    }

    if (resource === "pull-request" && rest[0] === "merge") {
      const number = args.args["number"]
      const method = args.args["method"]

      if (typeof number !== "number" || typeof method !== "string") {
        throw new Error("malformed merge arguments")
      }

      return client.mergePullRequest({
        repo: `${owner}/${repo}`,
        number,
        method,
        credential,
      })
    }

    throw new Error(`unsupported github grant: ${args.grantUri}`)
  },
})

/** Broker-executed GitHub actions. Credentials never leave the broker. */
export const createGitHubCapabilityProvider = (client: GitHubClient): CapabilityProvider =>
  githubProvider(client, true)

/** Read-only GitHub calls that need no downstream credential. */
export const createPublicGitHubCapabilityProvider = (
  client: GitHubClient,
): CapabilityProvider => githubProvider(client, false)

// --- Generic OAuth / token exchange ------------------------------------------------

export interface TokenExchangeClient {
  exchange(args: {
    readonly audience: string
    readonly scope: string
    readonly credential: string
  }): Promise<{ readonly accessToken: string; readonly expiresInSeconds: number }>
}

/**
 * Exchanges an upstream credential for a narrower downstream token. This is the shape used
 * for OAuth token exchange and for STS-style role assumption on non-AWS providers.
 */
export const createOAuthCredentialProvider = (
  client: TokenExchangeClient,
): CredentialProvider => ({
  id: "oauth-exchange",

  async obtain(
    grant: CapabilityGrant,
    context: CredentialRequestContext,
  ): Promise<DownstreamCredential> {
    const [provider, ...rest] = grant.segments

    if (provider === undefined) {
      throw new Error("malformed oauth grant")
    }

    const exchanged = await client.exchange({
      audience: provider,
      scope: rest.join("/"),
      credential: "",
    })

    return {
      value: exchanged.accessToken,
      expiresAt: new Date(context.at.getTime() + exchanged.expiresInSeconds * 1000),
      handle: `oauth:${sessionNameForAgent(context)}`,
    }
  },

  async destroy(): Promise<void> {},
})

// --- Database temporary credentials -------------------------------------------------

export interface DatabaseCredentialClient {
  mintTemporaryUser(args: {
    readonly database: string
    readonly role: string
    readonly ttlSeconds: number
  }): Promise<{ readonly username: string; readonly password: string; readonly expiresAt: Date }>
}

export const createDatabaseCredentialProvider = (
  client: DatabaseCredentialClient,
): CredentialProvider => ({
  id: "database-temporary",

  async obtain(
    grant: CapabilityGrant,
    context: CredentialRequestContext,
  ): Promise<DownstreamCredential> {
    const [database, scope] = grant.segments

    if (database === undefined) {
      throw new Error("malformed database grant")
    }

    const minted = await client.mintTemporaryUser({
      database,
      role: scope ?? "readonly",
      ttlSeconds: 300,
    })

    return {
      value: JSON.stringify({
        username: minted.username,
        password: minted.password,
      }),
      expiresAt: minted.expiresAt,
      handle: `db:${minted.username}#${sessionNameForAgent(context)}`,
    }
  },

  async destroy(): Promise<void> {},
})

// --- Vault / dynamic secret ---------------------------------------------------------

export interface VaultClient {
  readDynamicSecret(args: {
    readonly path: string
    readonly ttlSeconds: number
  }): Promise<{ readonly value: string; readonly leaseId: string; readonly expiresAt: Date }>
  revokeLease(args: { readonly leaseId: string }): Promise<void>
}

export const createVaultCredentialProvider = (client: VaultClient): CredentialProvider => {
  /**
   * Lease ids are held per credential, not in a single slot.
   *
   * One slot cannot answer "which lease belongs to the credential I am destroying". Two
   * concurrent grants overwrite it, so destroying the first revokes the second's
   * still-in-use lease while the first's lease survives unrevoked for its full TTL. That
   * was measured, not hypothesised — see `providers-production.test.ts`.
   *
   * Keyed by the credential handle so `destroy` resolves the exact lease it was given.
   */
  const leaseIdByHandle = new Map<string, string>()

  return {
    id: "vault-dynamic",

    async obtain(
      grant: CapabilityGrant,
      context: CredentialRequestContext,
    ): Promise<DownstreamCredential> {
      const secret = await client.readDynamicSecret({
        path: `secret/${grant.segments.join("/")}`,
        ttlSeconds: 300,
      })

      // The handle must be unique per lease, or two grants could still collide on it.
      const handle = `${sessionNameForAgent(context)}#${secret.leaseId}`

      leaseIdByHandle.set(handle, secret.leaseId)

      return {
        value: secret.value,
        expiresAt: secret.expiresAt,
        handle,
      }
    },

    async destroy(credential: DownstreamCredential): Promise<void> {
      const leaseId =
        credential.handle === undefined
          ? undefined
          : leaseIdByHandle.get(credential.handle)

      // Remove before awaiting: if `revokeLease` throws, the entry is already gone, so a
      // retry cannot revoke a lease that has since been reassigned to another grant.
      if (credential.handle !== undefined) {
        leaseIdByHandle.delete(credential.handle)
      }

      if (leaseId !== undefined) {
        await client.revokeLease({ leaseId })
      }
    },
  }
}

export { CapabilityBroker }
export type { CapabilityProvider, CredentialProvider, DownstreamCredential }