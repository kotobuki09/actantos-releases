import {
  AuthoritativeEvaluatorUnavailableError,
  createConfiguredCedarProvider,
  resolveEvaluatorMode,
} from "./cedar-provider.ts"
import { createDatabase } from "./database.ts"
import { buildServer } from "./server.ts"
import { PostgresToolCallRepository } from "./tool-call-repository.ts"
import {
  isRunscAvailable,
  isSandboxRuntimeRequired,
  isStrictSandboxMode,
} from "./sandbox-runtime.ts"
import {
  EGRESS_CELL_NETWORK,
  resolveEgressCellMode,
} from "./v2/egress-cell.ts"
import {
  createFabricGate,
  resolveFabricMode,
  SidecarFabricDecider,
  type FabricDecider,
} from "./v2/fabric.ts"
import { defaultSocketPath } from "./v2/sidecar-server.ts"
import { ed25519 } from "./v2/signature.ts"
import { PostgreSQLReplayStore } from "./v2/replay-store.ts"
import { signDecisionTokenEd25519 } from "./decision-token-signature.ts"
import { ReplayStoreDecisionNonceStore } from "./decision-nonce-store.ts"
import {
  createDecisionExecutionService,
  loadStoredAuthorization,
} from "./decision-execution.ts"
import {
  createSpireIdentityProvider,
  resolveIdentitySource,
} from "./v2/workload-identity-provider.ts"
import {
  mintWorkloadIdentity,
  signWorkloadIdentity,
} from "./v2/workload-identity.ts"

const port = Number.parseInt(process.env["PORT"] ?? "3100", 10)
const host = process.env["HOST"] ?? "0.0.0.0"
const databaseUrl = process.env["DATABASE_URL"]
const rawApiKey = process.env["ACTANTOS_API_KEY"]?.trim()
const apiKey = rawApiKey !== undefined && rawApiKey.length > 0 ? rawApiKey : undefined
const hmacSecret = process.env["HMAC_SECRET"] ?? process.env["ACTANTOS_HMAC_SECRET"]

/**
 * Decision execution is off unless it is asked for by name.
 *
 * Registering an execution route by default would change the public surface of every deployment,
 * including the ones that never intended to let the control plane run containers. "1" exactly, not
 * a truthy parse, so `ACTANTOS_DECISION_EXECUTION=true` does not silently enable it.
 */
const decisionExecutionEnabled = process.env["ACTANTOS_DECISION_EXECUTION"] === "1"

/**
 * The Ed25519 public key the executor verifies with.
 *
 * Read as a PEM with literal `\n` sequences unescaped, because the same key is almost always
 * supplied as an environment variable where a real newline cannot be written. It is a *public* key
 * by design: the executor holds no signing material, so it can verify an authorization it is not
 * able to manufacture (S7).
 */
const readTokenPublicKey = (): string | undefined => {
  const raw = process.env["ACTANTOS_TOKEN_VERIFICATION_KEY"]
  if (raw === undefined || raw.trim().length === 0) {
    return undefined
  }
  return raw.replace(/\\n/gu, "\n").trim()
}

/** The Ed25519 *private* key the control plane signs with. Read exactly as the public key is. */
const readTokenSigningKey = (): string | undefined => {
  const raw = process.env["ACTANTOS_TOKEN_SIGNING_KEY"]
  if (raw === undefined || raw.trim().length === 0) {
    return undefined
  }
  return raw.replace(/\\n/gu, "\n").trim()
}
const oidcIssuer = process.env["OIDC_ISSUER"]
const oidcClientId = process.env["OIDC_CLIENT_ID"]
const oidcClientSecret = process.env["OIDC_CLIENT_SECRET"]
const oidcRedirectUri = process.env["OIDC_REDIRECT_URI"]

const rawServiceRole = process.env["ACTANTOS_SERVICE_ROLE"]
const serviceRole = (rawServiceRole === "control_plane" || rawServiceRole === "data_plane") ? rawServiceRole : "standalone"

/**
 * Build the identity function the fabric decider presents to the sidecar.
 *
 * ## `local_key` — the weaker mode, kept as the default
 *
 * The daemon signs the workload identity itself, using the Ed25519 key the sidecar trusts. That
 * key is configured, not generated: generating one here would mint a fresh identity issuer on
 * every restart, and a sidecar that restarted separately would be verifying against a different
 * key and denying everything.
 *
 * What it does not give you is distinctness. The process asserting an identity is the process
 * holding the key that asserts it, so the signature proves only that the caller had this key —
 * which is also what an attacker who read `ACTANTOS_FABRIC_IDENTITY_KEY` has. It cannot tell one
 * agent from another, or an agent from the control plane.
 *
 * ## `spire` — the mode that makes S4 distinctness a property
 *
 * A SPIRE agent attests the calling workload to the SPIRE server, and the server issues a JWT-SVID
 * signed by the trust domain. The workload never holds a signing key and cannot obtain an
 * identity for a different workload. That is the property the local key cannot have.
 *
 * The SVID is verified against the trust domain's published JWKS before it is used, so a spoofed
 * Workload API does not get to name whichever agent it likes.
 *
 * Both modes present the same shape to the decider — a function returning an identity token — so
 * nothing downstream of here knows which one is in use.
 */
const buildIdentityIssuer = (
  source: string,
): ((tenantId: string, agentId: string, at: Date) => unknown) => {
  if (source === "spire") {
    // Read each required value through a function that throws, rather than collecting the missing
    // names in a loop. The loop reports a better error message but leaves the values typed as
    // `string | undefined`, and the only honest way to narrow that is a check the compiler sees.
    const required = (name: string): string => {
      const value = process.env[name]

      if (value === undefined || value.trim() === "") {
        throw new Error(
          `ACTANTOS_FABRIC_IDENTITY_SOURCE=spire, but ${name} is not set. Refusing to start: ` +
            "without it this process cannot ask for or verify an SVID, and a mode that quietly " +
            "fell back to a local key would run without node attestation while looking configured.",
        )
      }

      return value.trim()
    }

    // The audience is optional. A trust domain with no expected audience accepts whatever the SVID
    // names, which is correct only when the trust domain is single-purpose; it is not recorded as
    // a control here because an operator who wants one has to configure it deliberately.
    const audience = process.env["ACTANTOS_SPIRE_AUDIENCE"]?.trim()

    const provider = createSpireIdentityProvider({
      spiffeId: required("ACTANTOS_SPIRE_SPIFFE_ID"),
      trustDomain: required("ACTANTOS_SPIRE_TRUST_DOMAIN"),
      jwksUri: required("ACTANTOS_SPIRE_JWKS_URI"),
      ...(process.env["ACTANTOS_SPIRE_WORKLOAD_SOCKET"] === undefined
        ? {}
        : { workloadSocket: process.env["ACTANTOS_SPIRE_WORKLOAD_SOCKET"].trim() }),
      // Kept as an escape hatch for a stub or a proxy. No SPIRE version serves the Workload API
      // over HTTP, so this is not a fallback the agent offers; the socket above is the real path.
      ...(process.env["ACTANTOS_SPIRE_WORKLOAD_API"] === undefined
        ? {}
        : { workloadApi: process.env["ACTANTOS_SPIRE_WORKLOAD_API"].trim() }),
      ...(audience === undefined || audience === "" ? {} : { expectedAudience: audience }),
    })

    // One SVID per request. It is deliberately not cached: an SVID is short-lived, and a cached
    // one would outlive its own expiry without anything noticing. Only the verified token is sent;
    // the sidecar re-derives the identity from these exact bytes.
    return async (tenantId, agentId) => (await provider.issue(tenantId, agentId)).token
  }

  const issuerId = process.env["ACTANTOS_FABRIC_IDENTITY_ISSUER"] ?? "actantos-control-plane"
  const privateKeyPem = process.env["ACTANTOS_FABRIC_IDENTITY_KEY"]

  if (privateKeyPem === undefined || privateKeyPem.trim() === "") {
    throw new Error(
      `ACTANTOS_FABRIC_IDENTITY_SOURCE is "${source}", which signs a workload identity locally, ` +
        "but ACTANTOS_FABRIC_IDENTITY_KEY is not set. Refusing to start: a fabric that cannot " +
        "identify its own requests would deny every one of them, and quietly generating a key " +
        "here would do the same on every restart.",
    )
  }

  // PEMs are passed through the environment, where a literal newline cannot survive a shell.
  const key = privateKeyPem.replace(/\\n/gu, "\n")

  return (tenantId, agentId, at) =>
    signWorkloadIdentity(
      mintWorkloadIdentity({ tenantId, agentId, issuedAt: at }),
      { algorithm: "ed25519", issuer_id: issuerId, value: "" },
      { privateKeyPem: key },
    )
}

/**
 * Build the fabric decider for a v2 mode, or fail startup.
 *
 * The mode that decides where the identity comes from is `ACTANTOS_FABRIC_IDENTITY_SOURCE`, and
 * both modes fail closed at startup when they are misconfigured rather than at the first request.
 */
const buildFabricDecider = (mode: string): FabricDecider => {
  const socketPath = process.env["ACTANTOS_FABRIC_SOCKET"] ?? defaultSocketPath()
  const identitySource = resolveIdentitySource(process.env["ACTANTOS_FABRIC_IDENTITY_SOURCE"])

  return new SidecarFabricDecider({
    socketPath,
    issueIdentity: buildIdentityIssuer(identitySource),
  })
}

const bootstrap = async (): Promise<void> => {
  // Resolved before anything else is built. An unrecognised mode throws here, so a
  // misconfigured deployment never reaches the point of serving a decision.
  const fabricMode = resolveFabricMode(process.env["ACTANTOS_FABRIC_MODE"])

  // Resolved alongside the fabric mode, for the same reason and with the same failure: the default
  // is `none`, so a typo that fell back to it would run no cell while looking configured.
  const egressCellMode = resolveEgressCellMode(process.env["ACTANTOS_EGRESS_CELL"])

  // Resolved here even though only the v2 modes use it, so a typo is a startup failure rather than
  // something discovered when the fabric first needs an identity.
  const identitySource = resolveIdentitySource(process.env["ACTANTOS_FABRIC_IDENTITY_SOURCE"])

  // Fail closed at process start when production requires Cedar and it is missing.
  // buildServer also constructs the provider; constructing once here surfaces mode clearly in logs.
  const evaluatorMode = resolveEvaluatorMode()
  let cedarProvider
  try {
    cedarProvider = createConfiguredCedarProvider()
  } catch (error) {
    if (error instanceof AuthoritativeEvaluatorUnavailableError) {
      console.error(
        `FATAL: ${error.message}. Set ACTANTOS_EVALUATOR_MODE=development only for local non-production use, or install Cedar and set CEDAR_CLI_PATH.`,
      )
      process.exitCode = 1
      return
    }
    throw error
  }

  // A-04: emit a prominent banner whenever the authoritative Cedar evaluator is NOT active.
  // Operators must see this before the server begins serving decisions.
  if (evaluatorMode !== "production") {
    console.warn(
      `[ACTANTOS] WARNING: evaluator_mode=${evaluatorMode}. ` +
        `FakeCedarProvider is active — Cedar policy is NOT enforced. ` +
        `Do NOT use this configuration in production. ` +
        `Set NODE_ENV=production or ACTANTOS_EVALUATOR_MODE=production and install the Cedar CLI.`,
    )
  }

  // P2: Enforce HMAC secret in production — reject startup if using the insecure default.
  // Fires when NODE_ENV=production OR evaluatorMode=production to ensure the gate cannot
  // be bypassed by setting only one of the two environment variables.
  const DEV_HMAC_SECRET = "actantos-dev-secret"
  const resolvedHmacSecret = hmacSecret ?? DEV_HMAC_SECRET
  const isProductionEnv =
    process.env["NODE_ENV"] === "production" || evaluatorMode === "production"
  if (isProductionEnv && resolvedHmacSecret === DEV_HMAC_SECRET) {
    console.error(
      `FATAL: ACTANTOS_HMAC_SECRET is not set (or equals the insecure default "actantos-dev-secret"). ` +
        `Evidence package signatures can be forged. ` +
        `Set a strong secret via the ACTANTOS_HMAC_SECRET environment variable before starting in production.`,
    )
    process.exit(1)
  }
  if (resolvedHmacSecret === DEV_HMAC_SECRET) {
    console.warn(
      `[ACTANTOS] WARNING: ACTANTOS_HMAC_SECRET is not set — using insecure dev default. ` +
        `Evidence signatures are not trustworthy. Set ACTANTOS_HMAC_SECRET before production use.`,
    )
  }

  // P3 / S12: a requested-but-missing gVisor runtime is a policy violation, not a
  // performance note. The executor refuses such a request at run time; in strict mode the
  // server refuses to start at all, so it never accepts traffic it cannot enforce.
  if (isSandboxRuntimeRequired() && !isRunscAvailable()) {
    const message =
      `ACTANTOS_USE_GVISOR=true but 'runsc' was not found on PATH. Sandbox executions will be ` +
      `refused rather than silently downgraded to the default Docker runtime. ` +
      `Install gVisor (https://gvisor.dev/docs/user_guide/install/) or unset ` +
      `ACTANTOS_USE_GVISOR to accept the weaker runtime deliberately.`

    if (isStrictSandboxMode()) {
      console.error(`[ACTANTOS] FATAL: ${message}`)
      process.exit(1)
    }

    console.warn(`[ACTANTOS] WARNING: ${message}`)
  }

  const fabricGate = createFabricGate({
    mode: fabricMode,
    ...(fabricMode === "v1_compat"
      ? {}
      : { decider: buildFabricDecider(fabricMode) }),
  })

  if (egressCellMode === "egress_proxy") {
    console.warn(
      `[ACTANTOS] egress_cell=${egressCellMode}. Workloads run on the internal Docker network ` +
        `${EGRESS_CELL_NETWORK}, whose only reachable peer is the egress proxy. Every destination ` +
        "is authenticated and checked at connect time. This only holds if the proxy is running and " +
        "is attached to both that network and one with a route out.",
    )
  } else if (egressCellMode === "broker_only") {
    console.warn(
      `[ACTANTOS] egress_cell=${egressCellMode}. Workloads have no network, and any call that ` +
        "needs one is denied with egress_broker_required rather than silently failing to connect. " +
        "Those calls have to be routed through the capability broker.",
    )
  }

  if (fabricMode === "v2_enforce") {
    console.warn(
      `[ACTANTOS] fabric_mode=${fabricMode}. The v2 security fabric is now authoritative for ` +
        "every tool call. A fabric denial, and an unreachable fabric, both deny. " +
        "Set ACTANTOS_FABRIC_MODE=v2_observe to record fabric verdicts without changing outcomes.",
    )
    if (identitySource === "spire") {
      console.warn(
        `[ACTANTOS] fabric_identity_source=${identitySource}. Workload identities are JWT-SVIDs ` +
          "from the SPIFFE Workload API, verified against the trust domain's JWKS. The process " +
          "holds no signing key, so an agent and the control plane cannot impersonate each other. " +
          "The JWKS URI is a trust anchor: pin it. An unpinned URI means this process trusts " +
          "whatever that URL serves.",
      )
    } else {
      console.warn(
        `[ACTANTOS] fabric_identity_source=${identitySource}. The control plane signs its own ` +
          "workload identity with a local key. That key authenticates the *process*, not the " +
          "agent: anything that can read ACTANTOS_FABRIC_IDENTITY_KEY can present any agent's " +
          "identity. Set ACTANTOS_FABRIC_IDENTITY_SOURCE=spire with SPIRE deployed to get node " +
          "attestation and per-agent distinctness (S4).",
      )
    }
  } else if (fabricMode === "v2_observe") {
    console.warn(
      `[ACTANTOS] fabric_mode=${fabricMode}. Fabric verdicts are recorded but cannot change any ` +
        "outcome. A fabric denial here does NOT block the request.",
    )
  }

  if (decisionExecutionEnabled && databaseUrl === undefined) {
    // Fail closed at startup. A decision executor whose nonce store is process memory cannot tell a
    // first use from a replay across a restart, which would silently downgrade S9 rather than
    // refuse it, so there is no in-memory fallback here.
    console.error(
      "FATAL: ACTANTOS_DECISION_EXECUTION=1 requires DATABASE_URL. The executor consumes its " +
        "nonce in the database so that a replay survives a restart; refusing to start is the only " +
        "way to avoid claiming a protection this process cannot deliver.",
    )
    process.exit(1)
  }

  if (decisionExecutionEnabled && readTokenPublicKey() === undefined) {
    console.error(
      "FATAL: ACTANTOS_DECISION_EXECUTION=1 requires ACTANTOS_TOKEN_VERIFICATION_KEY (an Ed25519 " +
        "public key in PEM form). Without it the only scheme available is HMAC, and an executor " +
        "verifying with HMAC holds the signing key and can therefore mint its own authorizations.",
    )
    process.exit(1)
  }

  const tokenSigningKey = readTokenSigningKey()

  if (decisionExecutionEnabled && tokenSigningKey === undefined) {
    // The executor refuses HMAC tokens, so a control plane that only mints HMAC could never
    // execute anything. Saying so at startup is better than accepting traffic that always 409s.
    console.error(
      "FATAL: ACTANTOS_DECISION_EXECUTION=1 requires ACTANTOS_TOKEN_SIGNING_KEY (an Ed25519 " +
        "private key in PEM form). The executor refuses HMAC tokens, so without an Ed25519 signer " +
        "every decision it was asked to execute would be unexecutable.",
    )
    process.exit(1)
  }

  const decisionTokenSigner =
    tokenSigningKey === undefined
      ? undefined
      : (payload: string) => signDecisionTokenEd25519(payload, tokenSigningKey)

  if (databaseUrl !== undefined) {
    const database = createDatabase(databaseUrl)

    const tokenPublicKey = decisionExecutionEnabled ? readTokenPublicKey() : undefined
    const executionService =
      decisionExecutionEnabled && tokenPublicKey !== undefined
        ? createDecisionExecutionService({
            lookup: loadStoredAuthorization(database),
            // The durable store, not the in-memory one: this is the whole reason the executor can
            // claim single use across restarts and replicas.
            nonceStore: new ReplayStoreDecisionNonceStore(
              new PostgreSQLReplayStore({ client: database }),
            ),
            tokenVerification: { kind: "ed25519", publicKeyPem: tokenPublicKey },
          })
        : undefined

    const server = buildServer({
      ...(apiKey === undefined ? {} : { apiKey }),
      ...(hmacSecret === undefined ? {} : { hmacSecret }),
      repository: new PostgresToolCallRepository(database),
      database,
      cedarProvider,
      ...(executionService === undefined ? {} : { executionService }),
      ...(decisionTokenSigner === undefined ? {} : { decisionTokenSigner }),
      ...(oidcIssuer && oidcClientId && oidcClientSecret && oidcRedirectUri
        ? {
            oidcConfig: {
              issuer: oidcIssuer,
              clientId: oidcClientId,
              clientSecret: oidcClientSecret,
              redirectUri: oidcRedirectUri,
            },
          }
        : {}),
      serviceRole,
      fabricGate,
    })

    await server.listen({ port, host })
    server.log.info({ host, port, evaluatorMode, fabricMode }, "actantosd listening")
    return
  }

  const server = buildServer({
    ...(apiKey === undefined ? {} : { apiKey }),
    ...(hmacSecret === undefined ? {} : { hmacSecret }),
    cedarProvider,
    ...(oidcIssuer && oidcClientId && oidcClientSecret && oidcRedirectUri
      ? {
          oidcConfig: {
            issuer: oidcIssuer,
            clientId: oidcClientId,
            clientSecret: oidcClientSecret,
            redirectUri: oidcRedirectUri,
          },
        }
      : {}),
    serviceRole,
    fabricGate,
  })
  await server.listen({ port, host })
  server.log.info({ host, port, evaluatorMode, fabricMode }, "actantosd listening")
}

bootstrap()
  .catch((error: unknown) => {
    console.error(error)
    process.exitCode = 1
  })
