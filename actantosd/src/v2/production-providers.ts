import {
  amzDate,
  SIGV4_SERVICE,
  sha256Hex,
  sigv4FormBody,
  signSigv4,
  signRs256Jwt,
} from "./provider-signing.ts"
import type { StsClient, VaultClient } from "./providers.ts"

/**
 * Production HTTP implementations of the capability clients.
 *
 * Everything here is real: real sockets, real HTTP, real request signing with
 * `node:crypto`. What is *not* real is the far end — these talk to a local test server in
 * the suite, never to github.com, AWS or Vault. That distinction is the whole reason this
 * file is listed as INTEGRATION rather than REAL_SUBSTRATE in the substrate registry:
 * the wire format and the signature are proven, and the vendor's willingness to accept
 * them is not. See `security-fabric-state.mjs` and docs/SECURITY_TEST_MATRIX.md.
 *
 * Every one of these keeps a long-lived deployment secret — a GitHub App private key, an
 * AWS access key, a Vault secret id — and none of them can return one: `readDynamicSecret`
 * returns the leased secret, and the broker is what decides whether that reaches an agent.
 */

type Fetch = (input: string, init?: RequestInit) => Promise<Response>

const defaultNow = (): Date => new Date()

const resolveFetch = (candidate: Fetch | undefined): Fetch => candidate ?? fetch

/** Read a JSON object response, refusing rather than guessing when the shape is wrong. */
const readJsonObject = async (response: Response, what: string): Promise<Record<string, unknown>> => {
  const parsed = await readJson(response, what)

  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(`${what} returned a JSON value that is not an object`)
  }

  return parsed as Record<string, unknown>
}

/**
 * Read a JSON response of any shape.
 *
 * Not every endpoint answers with an object — GitHub's issue listing is a top-level array —
 * so parsing refuses only malformed JSON, and each caller still checks the shape it needs.
 * An earlier version required an object here, which made the list endpoint throw.
 */
const readJson = async (response: Response, what: string): Promise<unknown> => {
  const text = await response.text()

  if (!response.ok) {
    // The status and the endpoint are logged; the body is not, because a vendor error
    // body can echo the request, and the request carried the credential.
    throw new Error(`${what} failed with HTTP ${response.status}`)
  }

  try {
    return JSON.parse(text)
  } catch {
    throw new Error(`${what} returned a body that is not JSON`)
  }
}

const requireString = (
  source: Record<string, unknown>,
  key: string,
  what: string,
): string => {
  const value = source[key]
  if (typeof value !== "string" || value === "") {
    throw new Error(`${what} returned no usable ${key}`)
  }
  return value
}

// --- GitHub App authentication -----------------------------------------------------------

export interface GitHubAppConfig {
  /** The App's numeric id. Goes in the JWT `iss`; GitHub rejects anything else. */
  readonly appId: string
  readonly installationId: string
  /** PKCS#8 or PKCS#1 RSA private key. Stays in this process. */
  readonly privateKeyPem: string
  readonly apiBase?: string | undefined
  readonly fetchImpl?: Fetch | undefined
  readonly now?: (() => Date) | undefined
}

/**
 * Mints GitHub installation access tokens.
 *
 * The alternative to this is a personal access token in the environment, which is a
 * long-lived secret with the owner's whole account attached and no expiry. A GitHub App
 * installation token is scoped to one installation, lives an hour, and is minted on demand
 * — which is the property S1 needs: the credential exists for the length of one call and
 * is not present in the model's context before or after it.
 */
export const createGitHubAppClient = (
  config: GitHubAppConfig,
): { readonly obtainInstallationToken: () => Promise<{ readonly token: string; readonly expiresAt: Date }> } => {
  const apiBase = config.apiBase ?? "https://api.github.com"
  const fetchImpl = resolveFetch(config.fetchImpl)
  const now = config.now ?? defaultNow

  let cached: { readonly token: string; readonly expiresAt: Date } | undefined

  const mint = async (): Promise<{ readonly token: string; readonly expiresAt: Date }> => {
    const at = now()
    const issuedAt = Math.floor(at.getTime() / 1000) - 60
    // GitHub refuses a JWT whose lifetime exceeds 10 minutes. The backdated `iat` absorbs
    // clock skew between this host and GitHub, which otherwise fails as an opaque 401.
    const expiresAtSeconds = issuedAt + 540

    const jwt = signRs256Jwt(
      { iat: issuedAt, exp: expiresAtSeconds, iss: config.appId },
      config.privateKeyPem,
    )

    const response = await fetchImpl(
      `${apiBase}/app/installations/${encodeURIComponent(config.installationId)}/access_tokens`,
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${jwt}`,
          accept: "application/vnd.github+json",
          "x-github-api-version": "2022-11-28",
        },
      },
    )

    const body = await readJsonObject(response, "GitHub installation token request")
    const expiresAtRaw = body["expires_at"]

    if (typeof expiresAtRaw !== "string") {
      throw new Error("GitHub installation token response carried no expires_at")
    }

    return {
      token: requireString(body, "token", "GitHub installation token response"),
      expiresAt: new Date(expiresAtRaw),
    }
  }

  return {
    async obtainInstallationToken() {
      const at = now()

      // Re-mint a minute before expiry so a token cannot lapse mid-call.
      if (cached !== undefined && at.getTime() < cached.expiresAt.getTime() - 60_000) {
        return cached
      }

      cached = await mint()
      return cached
    },
  }
}

// --- The GitHub REST calls themselves -----------------------------------------------------

export interface HttpGitHubClientConfig {
  /** Mints a short-lived installation token per call. */
  readonly obtainToken: () => Promise<string>
  readonly apiBase?: string | undefined
  readonly fetchImpl?: Fetch | undefined
}

/**
 * The GitHub REST calls the capability provider needs, over real HTTP.
 *
 * The token is fetched inside each call and never stored on this object, so there is no
 * field for it to leak from: `execute()` returns whatever GitHub returned, and the broker
 * checks that against the credential it is holding. A response that contained the token
 * would be refused by the boundary rather than by this file's good behaviour.
 */
export const createHttpGitHubClient = (
  config: HttpGitHubClientConfig,
): {
  listIssues(args: { readonly repo: string; readonly credential: string }): Promise<unknown>
  mergePullRequest(args: {
    readonly repo: string
    readonly number: number
    readonly method: string
    readonly credential: string
  }): Promise<unknown>
} => {
  const apiBase = config.apiBase ?? "https://api.github.com"
  const fetchImpl = resolveFetch(config.fetchImpl)

  const call = async (path: string, init: RequestInit = {}): Promise<unknown> => {
    const token = await config.obtainToken()
    const response = await fetchImpl(`${apiBase}${path}`, {
      ...init,
      headers: {
        accept: "application/vnd.github+json",
        "x-github-api-version": "2022-11-28",
        ...(init.headers as Record<string, string> | undefined),
        authorization: `Bearer ${token}`,
      },
    })

    const body = await readJson(response, `GitHub ${init.method ?? "GET"} ${path}`)

    // GitHub answers 204 with an empty body on a successful merge, which is not JSON.
    if (response.status === 204) {
      return { merged: true }
    }

    return body
  }

  return {
    listIssues: ({ repo }) =>
      call(`/repos/${repo}/issues?state=open&per_page=30`),

    mergePullRequest: ({ repo, number, method }) =>
      call(`/repos/${repo}/pulls/${number}/merge`, {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ merge_method: method }),
      }),
  }
}

// --- AWS STS ---------------------------------------------------------------------------

export interface AwsStsConfig {
  readonly region: string
  /** Long-lived deployment credentials. Signing keys, not a session. */
  readonly accessKeyId: string
  readonly secretAccessKey: string
  /**
   * Defaults to the regional STS endpoint. Overridable so the tests can point at a local
   * server — and so a deployment inside a VPC can use a regional endpoint rather than the
   * global one, which keeps the call inside the audited network path.
   */
  readonly endpoint?: string | undefined
  readonly fetchImpl?: Fetch | undefined
  readonly now?: (() => Date) | undefined
  readonly sessionTtlSeconds?: number | undefined
}

/**
 * Extract one field from an STS `Query` response.
 *
 * STS answers XML and no XML parser is vendored here. Rather than take on a dependency or
 * write a general parser, this handles the one flat document `AssumeRole` produces and
 * fails closed on anything else: a missing field throws, so an unexpected shape can never
 * become a credential assembled from `undefined`. That limit is recorded rather than
 * hidden — a response carrying a nested structure would be refused, not misread.
 */
const xmlField = (body: string, name: string): string => {
  const match = new RegExp(`<${name}>([^<]*)</${name}>`, "u").exec(body)
  const value = match?.[1]
  if (value === undefined || value === "") {
    throw new Error(`STS response carried no ${name}`)
  }
  return value
}

export const createAwsStsClient = (config: AwsStsConfig): StsClient => {
  const endpoint = new URL(config.endpoint ?? `https://sts.${config.region}.amazonaws.com`)
  const fetchImpl = resolveFetch(config.fetchImpl)
  const now = config.now ?? defaultNow
  const durationSeconds = config.sessionTtlSeconds ?? 900

  return {
    async assumeRole({ roleArn, sessionName, durationSeconds: requested }) {
      const at = now()
      const seconds = requested ?? durationSeconds

      // Body and signature are built from the same parameters, so they cannot disagree.
      const payload = sigv4FormBody({
        Action: "AssumeRole",
        Version: "2011-06-15",
        RoleArn: roleArn,
        RoleSessionName: sessionName,
        DurationSeconds: String(seconds),
      })

      const headers = signSigv4({
        request: {
          method: "POST",
          canonicalUri: "/",
          canonicalQuery: "",
          headers: new Map([
            ["host", endpoint.host],
            ["x-amz-date", amzDate(at).full],
            ["content-type", "application/x-www-form-urlencoded; charset=utf-8"],
          ]),
          payload,
          at,
        },
        accessKeyId: config.accessKeyId,
        secretAccessKey: config.secretAccessKey,
        region: config.region,
        service: SIGV4_SERVICE,
      })

      const response = await fetchImpl(endpoint.toString(), {
        method: "POST",
        headers: Object.fromEntries(headers),
        body: payload,
      })

      const body = await response.text()

      if (!response.ok) {
        throw new Error(`STS AssumeRole failed with HTTP ${response.status}`)
      }

      return {
        accessKeyId: xmlField(body, "AccessKeyId"),
        secretAccessKey: xmlField(body, "SecretAccessKey"),
        sessionToken: xmlField(body, "SessionToken"),
        expiration: new Date(xmlField(body, "Expiration")),
      }
    },
  }
}

// --- HashiCorp Vault -------------------------------------------------------------------

export interface VaultAppRoleConfig {
  readonly address: string
  /** AppRole role id and secret id. The secret id is rotated; see docs on Phase O. */
  readonly roleId: string
  readonly secretId: string
  /** Path the grant names, e.g. `database/creds/app`. */
  readonly pathPrefix?: string | undefined
  readonly fetchImpl?: Fetch | undefined
  readonly now?: (() => Date) | undefined
}

/**
 * Vault over its HTTP API using AppRole login.
 *
 * AppRole is chosen over a static token because a static Vault token in the environment is
 * exactly the kind of long-lived secret the fabric is meant to keep out of reach: it does
 * not expire on its own, and it is readable by anything that can read the environment. A
 * secret id can be rotated independently, and a lease is revoked explicitly, so a grant
 * that finished can be ended rather than waiting out its TTL.
 */
export const createVaultAppRoleClient = (config: VaultAppRoleConfig): VaultClient => {
  const base = config.address.endsWith("/") ? config.address.slice(0, -1) : config.address
  const fetchImpl = resolveFetch(config.fetchImpl)
  const now = config.now ?? defaultNow
  const pathPrefix = config.pathPrefix ?? ""

  let clientToken: { readonly value: string; readonly expiresAt: Date } | undefined

  const login = async (): Promise<string> => {
    const response = await fetchImpl(`${base}/v1/auth/approle/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ role_id: config.roleId, secret_id: config.secretId }),
    })

    const body = await readJsonObject(response, "Vault AppRole login")
    const auth = body["auth"]

    if (auth === null || typeof auth !== "object" || Array.isArray(auth)) {
      throw new Error("Vault AppRole login returned no auth block")
    }

    const record = auth as Record<string, unknown>
    const value = record["client_token"]
    if (typeof value !== "string" || value === "") {
      throw new Error("Vault AppRole login returned no client_token")
    }

    // Vault reports TTL in seconds. Renew on a fraction of it so a call never starts with
    // a token that expires before the secret is even read.
    const ttlSeconds = typeof record["lease_duration"] === "number" ? record["lease_duration"] : 60

    clientToken = {
      value,
      expiresAt: new Date(now().getTime() + Math.floor(ttlSeconds / 2) * 1000),
    }

    return value
  }

  const authenticatedFetch = async (
    path: string,
    init: RequestInit,
  ): Promise<Response> => {
    const at = now()
    const token =
      clientToken !== undefined && at.getTime() < clientToken.expiresAt.getTime()
        ? clientToken.value
        : await login()

    const response = await fetchImpl(`${base}${path}`, {
      ...init,
      headers: { ...(init.headers as Record<string, string> | undefined), "x-vault-token": token },
    })

    // A revoked or expired token gets exactly one re-login and one retry. An unlimited
    // retry would turn a hard authorization failure into a loop.
    if (response.status === 403 && clientToken !== undefined) {
      clientToken = undefined
      const fresh = await login()
      return fetchImpl(`${base}${path}`, {
        ...init,
        headers: { ...(init.headers as Record<string, string> | undefined), "x-vault-token": fresh },
      })
    }

    return response
  }

  return {
    async readDynamicSecret({ path, ttlSeconds }) {
      const response = await authenticatedFetch(`/v1/${pathPrefix}${path}`, {
        method: "GET",
        headers: { accept: "application/json" },
      })

      const body = await readJsonObject(response, "Vault dynamic secret read")
      const data = body["data"]

      if (data === null || typeof data !== "object" || Array.isArray(data)) {
        throw new Error("Vault dynamic secret read returned no data block")
      }

      const fields = data as Record<string, unknown>
      const leaseId = requireString(body, "lease_id", "Vault dynamic secret read")

      // Vault reports the TTL it actually granted, which can be shorter than the one
      // requested. Trusting the request instead would hand out a credential that expires
      // earlier than the broker believes, and the broker would use it past its life.
      const granted =
        typeof body["lease_duration"] === "number" ? body["lease_duration"] : ttlSeconds

      return {
        value: JSON.stringify(fields),
        leaseId,
        expiresAt: new Date(now().getTime() + granted * 1000),
      }
    },

    async revokeLease({ leaseId }) {
      const response = await authenticatedFetch("/v1/sys/leases/revoke", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ lease_id: leaseId }),
      })

      if (!response.ok) {
        throw new Error(`Vault lease revoke failed with HTTP ${response.status}`)
      }
    },
  }
}

export { sha256Hex }