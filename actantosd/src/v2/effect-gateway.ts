import {
  issueEffectPermit,
  verifyEffectPermit,
  NonceStore,
  type CanonicalAction,
  type EffectPermit,
  type PermitRejectionReason,
} from "./effect-permit.ts"
import { EvidenceChain } from "./evidence.ts"
import { evaluateIfc, type DeclassificationRule, type SinkType } from "./ifc.ts"
import { canonicalHash } from "../hash.ts"
import type { DataLabel } from "./signed-policy-bundle.ts"
import { InMemoryReplayStore, type ReplayStore } from "./replay-store.ts"
import type { EffectJournal } from "./effect-commit.ts"
import type { EvidenceStore, EvidenceAppendOutcome } from "./evidence-store.ts"
import type { EvidenceRecord, EvidenceType } from "./evidence.ts"

/**
 * Effect gateway: the single place an external effect actually happens.
 *
 * The protected agent never marks a permit used and never declares an effect valid. It asks
 * the gateway to perform an action; the gateway independently re-verifies the permit,
 * re-checks information flow, performs the effect, and emits evidence. If the gateway is
 * unreachable the effect does not happen (invariant S12).
 */

export type EffectExecutionResult = {
  readonly ok: true
  readonly result: unknown
}

export type EffectExecutor = (
  action: CanonicalAction,
) => Promise<EffectExecutionResult | { readonly ok: false; readonly error: string }>

export type EffectGatewayOutcome =
  | {
      readonly performed: true
      readonly permitId: string
      /** Digest of the result, for commitment into evidence without storing the payload. */
      readonly resultDigest: string
    }
  | {
      readonly performed: false
      readonly reason:
        | PermitRejectionReason
        | "ifc_denied"
        | "no_executor"
        | "evidence_unavailable"
        | "replay_store_unavailable"
        | "journal_unavailable"
        | "journal_refused"
      readonly detail?: string
    }

export type EffectGatewayOptions = {
  readonly tenantId: string
  readonly trustedIssuerKeys: ReadonlyMap<string, string>
  /**
   * In-process evidence chain. Optional only when `evidenceStore` is supplied; supplying neither
   * is a configuration error and is rejected in the constructor rather than silently producing
   * an enforcement path that records nothing.
   */
  readonly evidenceChain?: EvidenceChain | undefined
  /**
   * Durable evidence (S13). When present it is the only place evidence is written, for the same
   * reason the replay store is the only first-use authority: two writers of the same fact cannot
   * both be right about where it lives.
   */
  readonly evidenceStore?: EvidenceStore | undefined
  readonly executors: Readonly<Record<string, EffectExecutor>>
  readonly nonces?: NonceStore
  /**
   * Durable first-use authority (S9).
   *
   * When absent the gateway falls back to the process-memory `nonces`, which protects only
   * against replay within one running process. That is adequate for tests and single-process
   * development; a deployment that restarts or replicates the gateway needs the PostgreSQL store.
   */
  readonly replayStore?: ReplayStore
  readonly revokedPermitIds?: ReadonlySet<string>
  /**
   * Effect commit protocol (S13). When present, every effect opens a journal entry before the
   * executor is called and closes it afterwards, so a process that dies mid-effect leaves a row
   * that says so rather than a silent gap.
   *
   * Optional because the in-process suites construct gateways directly and would otherwise all
   * need a journal. A deployment that omits it loses crash accountability, not authorization: the
   * permit is still consumed before the effect and still single-use.
   */
  readonly journal?: EffectJournal | undefined
  readonly declassificationRules?: readonly DeclassificationRule[]
  readonly now?: () => Date
}

export class EffectGateway {
  readonly #options: EffectGatewayOptions
  readonly #nonces: NonceStore
  readonly #replayStore: ReplayStore | undefined
  readonly #evidenceStore: EvidenceStore | undefined
  readonly #journal: EffectJournal | undefined
  readonly #evidenceChain: EvidenceChain

  constructor(options: EffectGatewayOptions) {
    if (options.evidenceChain === undefined && options.evidenceStore === undefined) {
      // Fail closed at construction rather than at the first append. A gateway that silently
      // records nothing is the one configuration S13 exists to prevent.
      throw new Error("EffectGateway requires evidenceChain or evidenceStore")
    }

    this.#options = options
    this.#nonces = options.nonces ?? new NonceStore()
    this.#replayStore = options.replayStore
    this.#evidenceStore = options.evidenceStore
    this.#journal = options.journal
    this.#evidenceChain = options.evidenceChain ?? new EvidenceChain({
      tenantId: options.tenantId,
      issuerId: "unused-when-a-store-is-configured",
      keyPair: { privateKeyPem: "" },
    })
  }

  get nonces(): NonceStore {
    return this.#nonces
  }

  /**
   * Record one piece of evidence.
   *
   * Throws when the record could not be made durable. Every caller either treats that as
   * `evidence_unavailable` or is on a path where the exception is fatal, which is the intent:
   * an effect with no record of its authorization is worse than a refused effect.
   */
  async #record(
    evidenceType: EvidenceType,
    payload: Record<string, unknown>,
    now: Date,
  ): Promise<EvidenceRecord | EvidenceAppendOutcome> {
    if (this.#evidenceStore !== undefined) {
      const outcome = await this.#evidenceStore.append({
        tenantId: this.#options.tenantId,
        evidenceType,
        payload,
        occurredAt: now,
      })

      if (outcome.outcome === "unavailable") {
        throw new Error(`evidence not recorded: store unavailable (${outcome.error})`)
      }

      if (outcome.outcome === "fork_detected") {
        throw new Error(`evidence not recorded: chain forked at seq ${outcome.seq}`)
      }

      return outcome
    }

    return this.#evidenceChain.append(evidenceType, payload, { occurredAt: now })
  }

  /**
   * Perform an authorized effect.
   *
   * `action` is supplied by the caller but compared against the permit digest, so a caller
   * cannot pass a different action than the one that was authorized.
   */
  async perform(args: {
    readonly permit: unknown
    readonly action: CanonicalAction
    readonly executionId: string
    readonly principalSpiffeId: string
    readonly sinkType: SinkType
    readonly dataLabels?: readonly DataLabel[]
    readonly expectedPolicyBundleDigest?: string
  }): Promise<EffectGatewayOutcome> {
    const now = this.#options.now?.() ?? new Date()

    // When a durable replay store is configured it is the *only* first-use authority. The
    // process-memory set is not consulted, because a check that can disagree with the
    // authority is a second source of truth about whether an effect has already happened.
    const verification = verifyEffectPermit(args.permit, {
      trustedIssuerKeys: this.#options.trustedIssuerKeys,
      expectedTenantId: this.#options.tenantId,
      expectedPrincipalSpiffeId: args.principalSpiffeId,
      expectedExecutionId: args.executionId,
      action: args.action,
      expectedPolicyBundleDigest: args.expectedPolicyBundleDigest,
      nonces: this.#replayStore === undefined ? this.#nonces : undefined,
      revokedPermitIds: this.#options.revokedPermitIds,
      now,
      // Consume before executing so two concurrent uses cannot both succeed. With a durable
      // store the consume happens below, once the permit itself is known to be genuine.
      consumeNonce: this.#replayStore === undefined,
    })

    if (!verification.accepted) {
      await this.#record("security_violation", {
        reason: verification.reason,
        tool: args.action.tool,
        resource: args.action.resource,
        occurred_at: now.toISOString(),
      }, now)

      return { performed: false, reason: verification.reason }
    }

    const permit: EffectPermit = verification.permit

    // S9 durable first-use. This runs after signature and binding verification, so an unsigned
    // or misbound permit cannot burn a legitimate nonce, and before any external call, so a
    // replayed permit never reaches the executor.
    if (this.#replayStore !== undefined) {
      const claim = await this.#replayStore.consume({
        tenantId: permit.tenant_id,
        permitId: permit.permit_id,
        nonce: permit.nonce,
        expiresAt: new Date(permit.expires_at),
      })

      if (claim.outcome === "replayed") {
        await this.#record("security_violation", {
          reason: "already_used",
          detail: claim.reason,
          permit_id: permit.permit_id,
          tool: args.action.tool,
          resource: args.action.resource,
          occurred_at: now.toISOString(),
        }, now)

        return { performed: false, reason: "already_used", detail: claim.reason }
      }

      if (claim.outcome === "unavailable") {
        // Fail closed. An unreachable replay store means we cannot prove this permit is unused,
        // and "cannot prove" is not "proved unused".
        await this.#record("security_violation", {
          reason: "replay_store_unavailable",
          permit_id: permit.permit_id,
          occurred_at: now.toISOString(),
        }, now)

        return {
          performed: false,
          reason: "replay_store_unavailable",
          detail: claim.error,
        }
      }
    }

    const ifc = evaluateIfc(
      args.dataLabels ?? permit.data_labels,
      args.sinkType,
      { declassificationRules: this.#options.declassificationRules },
    )

    if (!ifc.allowed) {
      await this.#record("security_violation", {
        reason: "ifc_denied",
        data_label: ifc.dataLabel,
        sink_type: ifc.sinkType,
        occurred_at: now.toISOString(),
      }, now)

      return {
        performed: false,
        reason: "ifc_denied",
        detail: `${ifc.dataLabel} may not flow into ${ifc.sinkType} (clearance ${ifc.sinkClearance})`,
      }
    }

    const executor = this.#options.executors[args.action.tool]

    if (executor === undefined) {
      return { performed: false, reason: "no_executor" }
    }

    // S13 requires every important effect to leave verifiable evidence. The authorization is
    // therefore recorded *before* the effect, and a failure to record it stops the effect.
    // Writing afterwards would allow an effect to happen with no evidence of it, which is the
    // one outcome this whole layer exists to prevent.
    try {
      await this.#record("effect_permit", {
        permit_id: permit.permit_id,
        principal_spiffe_id: permit.principal_spiffe_id,
        tenant_id: permit.tenant_id,
        execution_id: permit.execution_id,
        action_digest: permit.action_digest,
        policy_bundle_digest: permit.policy_bundle_digest,
        tool: args.action.tool,
        resource: args.action.resource,
        occurred_at: now.toISOString(),
      }, now)
    } catch {
      return {
        performed: false,
        reason: "evidence_unavailable",
        detail: "effect not performed: evidence could not be recorded",
      }
    }

    // The intent becomes durable before the executor is called. After this point the effect may
    // exist in the real world with nobody left to observe it, so the row has to exist first.
    if (this.#journal !== undefined) {
      const opened = await this.#journal.prepare({
        tenantId: permit.tenant_id,
        permitId: permit.permit_id,
        actionDigest: permit.action_digest,
        tool: args.action.tool,
        resource: args.action.resource,
      })

      if (opened.outcome === "unavailable") {
        // Fail closed. The effect cannot be performed and accounted for, so it is not performed.
        return {
          performed: false,
          reason: "journal_unavailable",
          detail: opened.error,
        }
      }

      if (opened.outcome === "rejected") {
        // The permit id is already journaled. The replay store should have caught this first;
        // reaching here means two authorities disagree, and the safe reading is to refuse.
        return {
          performed: false,
          reason: "journal_refused",
          detail: `permit already journaled as ${opened.state}`,
        }
      }

      const started = await this.#journal.transition({
        tenantId: permit.tenant_id,
        permitId: permit.permit_id,
        to: "executing",
        attempt: true,
      })

      if (started.outcome !== "recorded") {
        return {
          performed: false,
          reason: started.outcome === "unavailable" ? "journal_unavailable" : "journal_refused",
          detail: started.outcome === "rejected" ? started.reason : started.error,
        }
      }
    }

    const outcome = await executor(args.action)

    if (outcome.ok === false) {
      await this.#record("effect_execution", {
        permit_id: permit.permit_id,
        tool: args.action.tool,
        resource: args.action.resource,
        ok: false,
        error: outcome.error,
        occurred_at: now.toISOString(),
      }, now)

      await this.#journal?.transition({
        tenantId: permit.tenant_id,
        permitId: permit.permit_id,
        to: "failed",
        error: outcome.error,
      })

      return {
        performed: false,
        reason: "no_executor",
        detail: outcome.error,
      }
    }

    const resultDigest = canonicalHash(outcome.result)

    await this.#record("effect_execution", {
      permit_id: permit.permit_id,
      principal_spiffe_id: permit.principal_spiffe_id,
      tenant_id: permit.tenant_id,
      execution_id: permit.execution_id,
      delegation_digest: permit.delegation_digest,
      policy_bundle_digest: permit.policy_bundle_digest,
      action_digest: permit.action_digest,
      tool: args.action.tool,
      resource: args.action.resource,
      ok: true,
      occurred_at: now.toISOString(),
    }, now)

    // Closed only after the execution evidence is durable. A crash in between leaves the row at
    // `executing`, which recovery resolves to `uncertain` rather than to a guessed outcome.
    await this.#journal?.transition({
      tenantId: permit.tenant_id,
      permitId: permit.permit_id,
      to: "committed",
      resultDigest,
    })

    await this.#record("tool_result_commitment", {
      permit_id: permit.permit_id,
      result_digest: resultDigest,
      occurred_at: now.toISOString(),
    }, now)

    return { performed: true, permitId: permit.permit_id, resultDigest }
  }
}

export type PermitIssuerOptions = {
  readonly issuerId: string
  readonly keyPair: { privateKeyPem: string }
}

export const issuePermitFor = (
  args: Parameters<typeof issueEffectPermit>[0] & PermitIssuerOptions,
): EffectPermit => issueEffectPermit(args)