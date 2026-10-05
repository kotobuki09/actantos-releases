import {
  executeDockerCommand,
  type DockerExecutionResult,
} from "./docker-executor.ts"
import type { DecisionNonceStore } from "./decision-nonce-store.ts"
import type { Database } from "./database.ts"
import type {
  DecisionTokenVerification,
} from "./decision-token-signature.ts"

/**
 * The production caller for the decision-token executor.
 *
 * ## Why this module exists
 *
 * `executeDockerCommand` had no non-test caller anywhere in the repository. The control plane minted
 * a signed decision token, returned it in the interception response, stored it, and re-verified it
 * on the `/v1/tool-result` callback — but nothing in the daemon ever handed it to an executor. The
 * whole signed-authorization chain therefore terminated in a column, and a reviewer looking at the
 * tests could reasonably conclude the executor was exercised while the product had no way to reach
 * it.
 *
 * This module closes that gap. It is deliberately thin: it looks up the authorization the control
 * plane already stored, refuses anything that is not a live `allow`, and hands the stored token to
 * the executor together with the caller's proposed command. Everything that makes the execution safe
 * — signature verification, nonce consumption, sandbox selection, egress cell — happens inside
 * `executeDockerCommand`. This file decides only *which* stored authorization is being spent.
 *
 * ## Why identity comes from the record and not from the caller
 *
 * `executeDockerCommand` calls `assertClaimsMatch`, which compares the token's claims against the
 * request fields: tenant, agent, session, scope hash, expiry, and the hashes binding the command and
 * the constraints. If this service copied those fields out of the token it had just read, that check
 * would compare the token against itself and could never fail.
 *
 * So tenant, agent, session and scope hash are read back from PostgreSQL, from the same row the
 * control plane wrote at decision time. The caller supplies only `argv` and `workspacePath` — the
 * things an agent legitimately re-states when it goes to run the command it was cleared for. That is
 * exactly the S8 surface: swap in a different binary, add an argument, or point at a different
 * directory and `command_hash` no longer matches, so the token is refused.
 *
 * ## Why this is not registered by default
 *
 * Enabling an execution path by default would change the public behaviour of a deployment that never
 * asked for one. `ACTANTOS_DECISION_EXECUTION=1` is required, and the route is absent from the server
 * otherwise, so the default build is byte-for-byte the behaviour it was before this module existed.
 */

export type DecisionAuthorization = {
  readonly decisionId: string
  readonly tenantId: string
  readonly agentId: string
  readonly sessionId: string
  readonly scopeHash: string
  readonly toolName: string
  readonly decisionToken: string
  readonly constraints: {
    readonly network_mode?: "none" | "egress_proxy" | undefined
    readonly timeout_ms?: number | undefined
    readonly max_output_bytes?: number | undefined
  }
}

export type DecisionAuthorizationLookup = (query: {
  readonly tenantId: string
  readonly requestId: string
}) => Promise<DecisionAuthorization | null>

export type ExecuteDecisionInput = {
  readonly tenantId: string
  readonly requestId: string
  /** The command the agent wants to run. Checked against the token's `command_hash`. */
  readonly argv: readonly string[]
  /** The directory it wants to run it in. Also covered by `command_hash`. */
  readonly workspacePath: string
}

export type DecisionExecutionService = {
  execute(input: ExecuteDecisionInput): Promise<DockerExecutionResult>
}

export type CreateDecisionExecutionServiceOptions = {
  readonly lookup: DecisionAuthorizationLookup
  /**
   * Required. An executor with no replay store cannot tell a first use from a second one, and the
   * only value that may be injected here is the durable, database-backed one.
   */
  readonly nonceStore: DecisionNonceStore
  /**
   * Required. The service takes no HMAC secret, so an HMAC token cannot be executed here at all:
   * verifying it would require the signing key, and a verifier that holds the signing key can also
   * mint (S7). Tokens minted before Ed25519 was configured are therefore unexecutable, which is a
   * fail-closed outcome rather than a silent fallback to the weaker scheme.
   */
  readonly tokenVerification: DecisionTokenVerification
  readonly spawnCommand?: Parameters<typeof executeDockerCommand>[1]["spawnCommand"]
  readonly checkRunsc?: () => boolean
}

/**
 * Raised for every refusal, carrying the exact reason.
 *
 * The route maps `reason` to a response code. Distinct reasons are not decoration: an operator
 * debugging "the agent says it was allowed but nothing ran" needs to tell a stale authorization from
 * a mismatched command from a spent nonce, and a single 403 for all of them cannot.
 */
export class DecisionExecutionRefusal extends Error {
  readonly reason: DecisionExecutionRefusalReason

  constructor(reason: DecisionExecutionRefusalReason, message: string) {
    super(message)
    this.name = "DecisionExecutionRefusal"
    this.reason = reason
  }
}

export type DecisionExecutionRefusalReason =
  | "no_such_authorization"
  | "not_allowed"
  | "no_decision_token"
  | "token_not_ed25519"

export const createDecisionExecutionService = (
  options: CreateDecisionExecutionServiceOptions,
): DecisionExecutionService => {
  if (options.tokenVerification.kind !== "ed25519") {
    // Fail at construction, not at first use. A service that could accept HMAC tokens would be a
    // verifier holding the signing key, which is the exact property S7 forbids.
    throw new Error(
      "decision execution requires an ed25519 token verifier; an hmac verifier can also mint",
    )
  }

  return {
    async execute(input: ExecuteDecisionInput): Promise<DockerExecutionResult> {
      const authorization = await options.lookup({
        tenantId: input.tenantId,
        requestId: input.requestId,
      })

      if (authorization === null) {
        throw new DecisionExecutionRefusal(
          "no_such_authorization",
          "no stored decision for this tenant and request",
        )
      }

      if (authorization.decisionToken.length === 0) {
        throw new DecisionExecutionRefusal(
          "no_decision_token",
          "the stored decision carries no decision token",
        )
      }

      if (authorization.decisionToken.split(".")[0] !== "ed25519") {
        // Named separately from `not_allowed` so an operator can tell "this decision was never
        // executable" from "this decision said no". Both are refusals; only one is a policy verdict.
        throw new DecisionExecutionRefusal(
          "token_not_ed25519",
          "the stored decision token was not signed with ed25519",
        )
      }

      return executeDockerCommand(
        {
          decisionToken: authorization.decisionToken,
          // Required by the request type and never read once `tokenVerification` is Ed25519. It is
          // deliberately an empty string rather than the real secret: if a future change ever made
          // this path fall back to HMAC, it would fail closed instead of quietly succeeding.
          hmacSecret: "",
          requestId: input.requestId,
          tenantId: authorization.tenantId,
          agentId: authorization.agentId,
          sessionId: authorization.sessionId,
          toolName: authorization.toolName,
          scopeHash: authorization.scopeHash,
          workspacePath: input.workspacePath,
          argv: input.argv,
          // Constraints are read from the stored decision, never from the caller. A caller that
          // asked for `network_mode: "egress_proxy"` against an authorization that said `"none"`
          // would be asking to widen what policy granted.
          networkMode: authorization.constraints.network_mode ?? "none",
          timeoutMs: authorization.constraints.timeout_ms ?? 30_000,
          maxOutputBytes: authorization.constraints.max_output_bytes ?? 200_000,
        },
        {
          nonceStore: options.nonceStore,
          tokenVerification: options.tokenVerification,
          ...(options.spawnCommand === undefined ? {} : { spawnCommand: options.spawnCommand }),
          ...(options.checkRunsc === undefined ? {} : { checkRunsc: options.checkRunsc }),
        },
      )
    },
  }
}

type StoredAuthorizationRow = {
  readonly decision_id: string
  readonly final_decision: string
  readonly tool_name: string
  readonly scope_hash: string
  readonly decision_token: string | null
  readonly constraints_json: unknown
  readonly agent_external_id: string
  readonly session_external_id: string
}

/**
 * Read an authorization back out of the tables the control plane wrote.
 *
 * `agents` and `sessions` are joined for their `external_id` rather than their UUID because the UUID
 * is what the token is *not* signed over: `createDecisionToken` binds `request.agent.id` and
 * `request.session.id`, which are the external identifiers the caller sent. Comparing a UUID here
 * would reject every token, and comparing the external id is what makes `assertClaimsMatch` mean
 * something.
 */
export const loadStoredAuthorization = (
  database: Database,
): DecisionAuthorizationLookup => {
  return async ({ tenantId, requestId }) => {
    const rows = await database.query<StoredAuthorizationRow>(
      `
        SELECT
          pd.id AS decision_id,
          pd.final_decision,
          pd.request_id,
          tc.tool_name,
          tc.scope_hash,
          tc.mcp_json->>'decision_token' AS decision_token,
          pd.constraints_json,
          a.external_id AS agent_external_id,
          s.external_id AS session_external_id
        FROM policy_decisions pd
        INNER JOIN tool_calls tc ON tc.id = pd.tool_call_id
        INNER JOIN agents a ON a.id = tc.agent_id
        INNER JOIN sessions s ON s.id = tc.session_id
        WHERE pd.tenant_id = $1
          AND pd.request_id = $2
        ORDER BY pd.created_at ASC
        LIMIT 1
      `,
      [tenantId, requestId],
    )

    const row = rows[0]

    if (row === undefined) {
      return null
    }

    if (row.final_decision !== "allow") {
      // Returned as a refusal rather than a null: "this decision said no" and "no such decision"
      // are different operator problems and must not collapse into one 404.
      throw new DecisionExecutionRefusal(
        "not_allowed",
        `the stored decision is "${row.final_decision}", not "allow"`,
      )
    }

    return {
      decisionId: row.decision_id,
      tenantId,
      agentId: row.agent_external_id,
      sessionId: row.session_external_id,
      scopeHash: row.scope_hash,
      toolName: row.tool_name,
      decisionToken: row.decision_token ?? "",
      constraints: readConstraints(row.constraints_json),
    }
  }
}

const readConstraints = (
  value: unknown,
): DecisionAuthorization["constraints"] => {
  if (typeof value !== "object" || value === null) {
    return {}
  }

  const raw = value as Record<string, unknown>
  const networkMode = raw["network_mode"]

  return {
    network_mode:
      networkMode === "none" || networkMode === "egress_proxy"
        ? networkMode
        : undefined,
    timeout_ms: typeof raw["timeout_ms"] === "number" ? raw["timeout_ms"] : undefined,
    max_output_bytes:
      typeof raw["max_output_bytes"] === "number" ? raw["max_output_bytes"] : undefined,
  }
}