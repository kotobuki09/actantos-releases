import { PROTOCOL_VERSION } from "./sidecar-protocol.ts"
import { connectSidecar, type SidecarClient } from "./sidecar-server.ts"

/**
 * Runtime wiring for the v2 fabric (phase F).
 *
 * Phases A–E built the fabric and proved it works. None of it was reachable from a running
 * daemon: `server.ts`, `intercept-service.ts` and `mcp-gateway.ts` imported nothing from
 * `src/v2/`. This module is the seam that makes it participate in a real decision, under an
 * operator-controlled mode rather than a request-controlled one.
 *
 * ## Why the mode is not the request's `dry_run`
 *
 * `intercept-service.ts` already has an observe/enforce switch, and it is the wrong one to
 * build on: `dry_run` is chosen by the *caller*, which is the agent. An agent that could set
 * `dry_run: true` on its own request would be choosing whether it is enforced. The mode here is
 * read from the environment at startup, so it is chosen by the operator and cannot be set from
 * the request path.
 *
 * ## The three modes, and what each one guarantees
 *
 *   v1_compat   (default) The fabric is not consulted. Behaviour is byte-for-byte what it was
 *               before this module existed. This is what keeps the current public and production
 *               behaviour from regressing.
 *
 *   v2_observe  The fabric is consulted and every verdict is recorded, but **no verdict can
 *               change an outcome** — not an allow, not a denial, not an unreachable sidecar.
 *               This is how divergence between the v1 pipeline and the v2 fabric is measured
 *               before anyone depends on it.
 *
 *   v2_enforce  The fabric's denial is a denial, and an *unreachable* fabric is a denial too.
 *               The unavailable case is the one that matters: a fabric that cannot be reached
 *               and answers "allow" is worse than no fabric, because it converts an outage into
 *               a bypass.
 *
 * ## Two fail-closed rules that are enforced here rather than at the call site
 *
 * An unrecognised mode **throws at startup**. It does not fall back to `v1_compat`, because a
 * typo in `ACTANTOS_FABRIC_MODE=v2_enforc` that silently disabled enforcement would be the
 * single most damaging thing this module could do. A process that will not start is recoverable;
 * a process that quietly stopped enforcing is not.
 *
 * `v2_observe` and `v2_enforce` **require a decider**. Enforcing with no decider configured
 * would otherwise read as "the fabric had nothing to say", which is an allow.
 *
 * The third rule — that `v2_observe` never governs — is enforced by `fabricDenial` below, which
 * is the only function the caller uses to turn an assessment into a denial.
 */

export const FABRIC_MODES = ["v1_compat", "v2_observe", "v2_enforce"] as const

export type FabricMode = (typeof FABRIC_MODES)[number]

/**
 * `v1_compat` is the default because it is the only mode that is guaranteed not to change any
 * existing outcome. A deployment that upgrades the binary and sets nothing keeps today's
 * behaviour exactly.
 */
export const DEFAULT_FABRIC_MODE: FabricMode = "v1_compat"

export const isFabricMode = (value: string): value is FabricMode =>
  (FABRIC_MODES as readonly string[]).includes(value)

/**
 * Read the mode from configuration. Unset means the default; unrecognised is a startup failure.
 */
export const resolveFabricMode = (raw: string | undefined): FabricMode => {
  if (raw === undefined || raw.trim() === "") {
    return DEFAULT_FABRIC_MODE
  }

  const normalised = raw.trim().toLowerCase()

  if (isFabricMode(normalised)) {
    return normalised
  }

  throw new Error(
    `ACTANTOS_FABRIC_MODE is "${raw}", which is not one of ${FABRIC_MODES.join(", ")}. ` +
      "Refusing to start: falling back to a default here would decide, silently, whether this " +
      "deployment enforces the security fabric.",
  )
}

/** The action a fabric decider is asked about, reduced to what the sidecar protocol carries. */
export type FabricActionRequest = {
  readonly tenantId: string
  readonly agentId: string
  readonly requestId: string
  readonly tool: string
  /** Always non-empty: the sidecar protocol requires a resource, and an absent one would be a way to skip the destination check. */
  readonly resource: string
  readonly args: Readonly<Record<string, unknown>>
}

export type FabricDecision = {
  readonly allowed: boolean
  /**
   * A stable, machine-readable code — the sidecar's deny reason. Kept free of variable text so
   * it can be used as a `reason_code`, counted, and alerted on.
   */
  readonly reason: string
  /** Human-readable context. Never part of the code. */
  readonly detail?: string | undefined
}

export type FabricDecider = {
  check(request: FabricActionRequest): Promise<FabricDecision>
}

/**
 * What the fabric said, kept separate from what the caller should do about it.
 *
 * `unavailable` is a distinct outcome rather than a denial because "the sidecar is down" and
 * "the policy forbids this" are different events, and an operator reading a log has to be able
 * to tell them apart.
 */
export type FabricAssessment =
  | { readonly outcome: "not_evaluated"; readonly mode: FabricMode }
  | { readonly outcome: "allowed"; readonly mode: FabricMode; readonly reason: string }
  | {
      readonly outcome: "denied"
      readonly mode: FabricMode
      readonly reason: string
      readonly reasonCode: string
    }
  | { readonly outcome: "unavailable"; readonly mode: FabricMode; readonly reason: string }

export type FabricGate = {
  readonly mode: FabricMode
  /** False in `v1_compat`, so a caller can skip the work entirely rather than pay for a call whose result cannot matter. */
  readonly evaluates: boolean
  evaluate(request: FabricActionRequest): Promise<FabricAssessment>
}

export type CreateFabricGateOptions = {
  readonly mode: FabricMode
  readonly decider?: FabricDecider | undefined
  /** Called for every assessment, in every mode. Where observe-mode telemetry goes. */
  readonly onAssessment?: ((assessment: FabricAssessment) => void) | undefined
}

export const createFabricGate = (options: CreateFabricGateOptions): FabricGate => {
  const { mode } = options

  if (mode === "v1_compat") {
    return {
      mode,
      evaluates: false,
      evaluate: async () => ({ outcome: "not_evaluated", mode }),
    }
  }

  const decider = options.decider

  if (decider === undefined) {
    throw new Error(
      `ACTANTOS_FABRIC_MODE is "${mode}" but no fabric decider is configured. Refusing to start: ` +
        "a fabric with nothing to consult would answer every request by saying nothing, which " +
        "is an allow.",
    )
  }

  return {
    mode,
    evaluates: true,
    evaluate: async (request) => {
      let decision: FabricDecision

      try {
        decision = await decider.check(request)
      } catch (error) {
        const detail = error instanceof Error ? error.message : String(error)
        const assessment: FabricAssessment = {
          outcome: "unavailable",
          mode,
          reason: `security fabric could not be consulted: ${detail}`,
        }
        options.onAssessment?.(assessment)
        return assessment
      }

      const assessment: FabricAssessment = decision.allowed
        ? { outcome: "allowed", mode, reason: decision.reason }
        : {
            outcome: "denied",
            mode,
            // The detail goes in the prose an operator reads; the code stays a code, so
            // "how many fabric denials named this host" is a query rather than a log scrape.
            reason:
              decision.detail === undefined
                ? decision.reason
                : `${decision.reason}: ${decision.detail}`,
            // Namespaced so a fabric denial is never confused with a v1 `policy_forbid` in the
            // audit trail. The two pipelines are independent and their denials mean different
            // things; an operator reading a decision row has to be able to tell them apart.
            reasonCode: `fabric.${decision.reason}`,
          }

      options.onAssessment?.(assessment)
      return assessment
    },
  }
}

export type FabricDenial = {
  readonly reason: string
  readonly reasonCode: string
}

/**
 * The only place a fabric verdict becomes a denial.
 *
 * All three of the rules live here rather than at the call site so that a caller cannot
 * accidentally implement observe-mode as "record and then deny anyway":
 *
 *   - `v1_compat` and `v2_observe` never produce a denial, whatever the fabric said.
 *   - `v2_enforce` denies on an explicit refusal.
 *   - `v2_enforce` also denies when the fabric could not be reached. This is the fail-closed
 *     case, and it is why `unavailable` is not folded into `allowed`.
 */
export const fabricDenial = (
  assessment: FabricAssessment,
): FabricDenial | null => {
  if (assessment.mode !== "v2_enforce") {
    return null
  }

  if (assessment.outcome === "denied") {
    return { reason: assessment.reason, reasonCode: assessment.reasonCode }
  }

  if (assessment.outcome === "unavailable") {
    return {
      reason: assessment.reason,
      reasonCode: "fabric.unavailable",
    }
  }

  return null
}

export type SidecarDeciderOptions = {
  readonly socketPath: string
  /**
   * Returns a signed workload identity token for this agent.
   *
   * May return a promise, because a SPIFFE/SPIRE-backed authority has to ask the Workload API for
   * a JWT-SVID before it has anything to send. It is awaited here rather than cached: an SVID is
   * short-lived, and a cached one would outlive its own expiry.
   */
  readonly issueIdentity: (tenantId: string, agentId: string, at: Date) => unknown | Promise<unknown>
  readonly timeoutMs?: number
}

/**
 * Ask a real sidecar over a real socket.
 *
 * The connection is held open between requests and re-established on failure, because a
 * long-lived agent should pay the socket setup once rather than on every call. A failed
 * connection is cleared rather than cached, so the next request retries instead of inheriting
 * a dead socket forever.
 *
 * Timeouts are short by default. In `v2_enforce` this call is on the request path of a
 * single-threaded server, so a generous timeout is an availability hole: an unresponsive
 * sidecar would hold every request rather than just its own.
 */
export class SidecarFabricDecider implements FabricDecider {
  readonly #options: SidecarDeciderOptions
  readonly #timeoutMs: number
  #client: SidecarClient | undefined
  #connecting: Promise<SidecarClient> | undefined

  constructor(options: SidecarDeciderOptions) {
    this.#options = options
    this.#timeoutMs = options.timeoutMs ?? 2000
  }

  async #connect(): Promise<SidecarClient> {
    if (this.#client !== undefined) {
      return this.#client
    }

    // Concurrent requests must share one connect attempt, or each opens its own socket and the
    // losers leak theirs.
    this.#connecting ??= connectSidecar({
      socketPath: this.#options.socketPath,
      timeoutMs: this.#timeoutMs,
    })
      .then((client) => {
        this.#client = client
        return client
      })
      .finally(() => {
        this.#connecting = undefined
      })

    return await this.#connecting
  }

  async check(request: FabricActionRequest): Promise<FabricDecision> {
    const client = await this.#connect()

    let decision
    try {
      decision = await client.send({
        protocol_version: PROTOCOL_VERSION,
        request_id: request.requestId,
        request_type: "CheckAction",
        identity_token: await this.#options.issueIdentity(
          request.tenantId,
          request.agentId,
          new Date(),
        ),
        tool: request.tool,
        resource: request.resource,
        args: request.args,
      })
    } catch (error) {
      // A socket that failed mid-request is not reusable. Dropping it here is what makes the
      // next call reconnect rather than retry against a connection the peer has already closed.
      this.#client = undefined
      void client.close().catch(() => undefined)
      throw error
    }

    return {
      allowed: decision.allowed,
      reason: decision.reason,
      // `detail` exists only on the denial branch of `SidecarDecision`, so it is read through
      // the same narrowing rather than assumed.
      ...(decision.allowed || decision.detail === undefined
        ? {}
        : { detail: decision.detail }),
    }
  }

  /** Release the held connection. Callers should invoke this on shutdown. */
  async close(): Promise<void> {
    const client = this.#client
    this.#client = undefined
    if (client !== undefined) {
      await client.close()
    }
  }
}

/**
 * Reduce a v1 interception request to the action the fabric is asked about.
 *
 * The resource string is built rather than passed through, because the sidecar requires a
 * non-empty one and the v1 contract allows every field of `resource` to be absent. The URL is
 * preferred and kept intact on purpose: `checkNetworkTargets` reads its targets out of this
 * string, so normalising or dropping the URL here would remove the destination from the S3 check
 * rather than merely shortening it.
 */
export const toFabricActionRequest = (request: {
  readonly request_id: string
  readonly tenant_id: string
  readonly agent: { readonly id: string }
  readonly tool: { readonly name: string }
  readonly resource: {
    readonly id?: string | undefined
    readonly kind?: string | undefined
    readonly path?: string | undefined
    readonly url?: string | undefined
    readonly database?: string | undefined
    readonly table?: string | undefined
  }
  readonly action: Readonly<Record<string, unknown>>
}): FabricActionRequest => ({
  tenantId: request.tenant_id,
  agentId: request.agent.id,
  requestId: request.request_id,
  tool: request.tool.name,
  resource:
    request.resource.url ??
    request.resource.path ??
    request.resource.database ??
    request.resource.id ??
    request.resource.kind ??
    request.tool.name,
  args: request.action,
})
