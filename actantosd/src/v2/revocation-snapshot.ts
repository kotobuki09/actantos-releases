import { z } from "zod"

import { canonicalStringify, toJsonValue } from "../hash.ts"
import { resolveIssuerKeys, type TrustedKeySource } from "./keyring.ts"
import {
  getSignatureAlgorithm,
  type SignatureAlgorithmName,
  type SigningKeyPair,
} from "./signature.ts"

/**
 * Signed revocation snapshots (invariants S9, S12, phase I).
 *
 * ## What revocation is protecting against, and why a set was not enough
 *
 * Revocation already existed, as `ReadonlySet<string>` handed to each verifier by its caller. That
 * shape has a defect that only shows up in a real deployment: a set is a snapshot with no identity.
 * Whoever fills it decides what it contains, and a compromised caller can pass an empty set and get
 * "nothing is revoked" — an allow. There is no way for the enforcement point to tell a real empty
 * set from a lie.
 *
 * Every revocation decision here is therefore made against a *signed, versioned, expiring*
 * document. The sidecar verifies the signature before it reads a single entry, so an attacker who
 * can write into the process still cannot remove a revocation.
 *
 * ## Why revocation rides the same local-enforcement path as policy
 *
 * S11 says enforcement continues without a control-plane round-trip. Revocation that required one
 * would undo that: the control plane goes down, revocation stops applying, and every revoked agent
 * resumes working. So the snapshot is a lease with an expiry, and an expired snapshot means the
 * entries in it are still enforced but no *new* revocation can arrive — which is a stated
 * availability trade, not a silent one.
 *
 * ## What is deliberately absent
 *
 * No "un-revocation". Entries are only ever added, within a snapshot, and the whole snapshot is
 * replaced by a higher version. An attacker who can present version 3 cannot present version 2 again
 * to drop an entry, because the version is monotonic and checked. Reinstating a revoked identity
 * means publishing a higher version that does not list it — which is a decision the control plane
 * signs and an operator can audit, rather than something an attacker can arrange.
 *
 * ## Compaction, and why there is no TTL
 *
 * The obvious fix for a growing list is to prune entries older than some age. That is not
 * implemented, and the reason is the same un-revocation rule above: `revoked_at` is informational
 * and is never read, so nothing here knows when a revoked nonce's identity window has passed.
 * Pruning by age would drop entries that are still the only record of a revocation, and the
 * agent would become active again. An entry stops applying only when a **higher signed version
 * omits it**, which is an auditable control-plane decision rather than a timer.
 *
 * What is bounded instead is the size. `MAX_REVOCATION_ENTRIES` refuses an oversized snapshot as
 * `too_many_entries`, so an operator learns that the list has grown past what this control plane
 * will ship — rather than discovering it as a frame-decoder `overflowed` at the transport, which
 * names a symptom and not a cause.
 */

export const REVOCATION_REASONS = [
  "agent_disabled",
  "credential_compromised",
  "policy_violation",
  "session_terminated",
  "operator_request",
] as const

export type RevocationReason = (typeof REVOCATION_REASONS)[number]

/**
 * Maximum entries in one snapshot.
 *
 * Chosen to sit well under the 256 KiB sidecar frame limit, because an oversized snapshot that
 * is only discovered at the transport arrives as `overflowed` — a symptom with no indication of
 * which document was at fault. Refusing it here names the actual problem.
 *
 * A list larger than this needs a control plane that omits stale entries in a higher version.
 * That is the supported remedy, and it is the same mechanism un-revocation already uses.
 */
export const MAX_REVOCATION_ENTRIES = 5_000

const revokedEntrySchema = z.object({
  /** What was revoked. Exactly one of these is set. */
  agent_id: z.string().min(1).optional(),
  /** A single workload identity nonce. Narrower than revoking the whole agent. */
  nonce: z.string().min(1).optional(),
  permit_id: z.string().min(1).optional(),
  reason: z.enum(REVOCATION_REASONS),
  /** When the control plane decided this. Informational; enforcement uses the snapshot's own window. */
  revoked_at: z.string().min(1),
})

/**
 * The signed body. Excludes the signature envelope, exactly as the policy bundle does.
 */
export const revocationSnapshotBodySchema = z
  .object({
    snapshot_id: z.string().min(1),
    tenant_id: z.string().min(1),
    /**
     * Monotonic, strictly increasing per tenant. The same anti-rollback property the policy bundle
     * has: a genuinely signed older snapshot must not be replayable to un-revoke.
     */
    version: z.number().int().positive(),
    issued_at: z.string().min(1),
    expires_at: z.string().min(1),
    entries: z.array(revokedEntrySchema),
  })
  .refine(
    (body) =>
      body.entries.every(
        (entry) =>
          entry.agent_id !== undefined ||
          entry.nonce !== undefined ||
          entry.permit_id !== undefined,
      ),
    // An entry that names nothing would verify, occupy a version, and revoke nothing — or, worse,
    // be mistaken for a "this agent is clear" marker by a future reader. Refuse it at the schema.
    { message: "every revocation entry must name something to revoke" },
  )

export type RevocationSnapshotBody = z.infer<typeof revocationSnapshotBodySchema>

export const revocationSignatureSchema = z.object({
  algorithm: z.string().min(1),
  issuer_id: z.string().min(1),
  value: z.string().min(1),
})

export type RevocationSignature = z.infer<typeof revocationSignatureSchema>

export const signedRevocationSnapshotSchema = z.object({
  body: revocationSnapshotBodySchema,
  signature: revocationSignatureSchema,
})

export type SignedRevocationSnapshot = z.infer<typeof signedRevocationSnapshotSchema>

/** Canonical bytes that get signed. Key order is fixed, so equal bodies produce equal bytes. */
export const canonicalRevocationBytes = (body: RevocationSnapshotBody): Uint8Array =>
  Buffer.from(canonicalStringify(toJsonValue(body)), "utf8")

export const signRevocationSnapshot = (
  body: RevocationSnapshotBody,
  signature: RevocationSignature,
  keyPair: SigningKeyPair,
): SignedRevocationSnapshot => {
  const algorithm = getSignatureAlgorithm(signature.algorithm as SignatureAlgorithmName)

  if (algorithm === undefined) {
    throw new Error(
      `Cannot sign revocation snapshot: unsupported algorithm "${signature.algorithm}"`,
    )
  }

  const value = Buffer.from(
    algorithm.sign(canonicalRevocationBytes(body), keyPair.privateKeyPem),
  ).toString("base64")

  return { body, signature: { ...signature, value } }
}

export type SnapshotRejectionReason =
  | "malformed_snapshot"
  | "too_many_entries"
  | "unsupported_algorithm"
  | "untrusted_issuer"
  | "invalid_signature"
  | "tenant_mismatch"
  | "expired"
  | "not_yet_valid"
  | "invalid_expiry_window"
  | "version_rollback"

export type SnapshotVerification =
  | { readonly accepted: true; readonly body: RevocationSnapshotBody }
  | { readonly accepted: false; readonly reason: SnapshotRejectionReason }

export type VerifyRevocationSnapshotOptions = {
  readonly expectedTenantId: string
  /**
   * One PEM per issuer, or a keyring of several with validity windows. See `keyring.ts`; the
   * plain map is unchanged.
   */
  readonly trustedIssuerKeys: TrustedKeySource
  readonly now?: Date
  /** Highest version already applied. A snapshot at or below it is refused. */
  readonly minimumVersion?: number
}

/**
 * Verify a revocation snapshot for local enforcement.
 *
 * Same order as the policy bundle: parse, then algorithm, then issuer, then signature, then
 * tenant, then time, then anti-rollback. The signature is checked before any entry is read, which
 * is the entire point — an entry from an unsigned document must never be able to revoke anything,
 * and equally must never be able to un-revoke.
 */
export const verifyRevocationSnapshot = (
  candidate: unknown,
  options: VerifyRevocationSnapshotOptions,
): SnapshotVerification => {
  const now = options.now ?? new Date()

  const parsed = signedRevocationSnapshotSchema.safeParse(candidate)

  if (!parsed.success) {
    return { accepted: false, reason: "malformed_snapshot" }
  }

  // Checked before the signature, which inverts this module's usual order, and the reasoning is
  // worth stating. Every other check here refuses because of what the document *says*; this one
  // refuses because of how much of it there is, and reading an entry's contents is not needed to
  // count the array. It fails closed, so it cannot un-revoke anything, and it stops a large
  // document from being canonicalized and signature-checked at all.
  if (parsed.data.body.entries.length > MAX_REVOCATION_ENTRIES) {
    return { accepted: false, reason: "too_many_entries" }
  }

  const { body, signature } = parsed.data

  const algorithm = getSignatureAlgorithm(signature.algorithm as SignatureAlgorithmName)

  if (algorithm === undefined) {
    return { accepted: false, reason: "unsupported_algorithm" }
  }

  const issuerKeys = resolveIssuerKeys(options.trustedIssuerKeys, signature.issuer_id, now)

  if (issuerKeys.length === 0) {
    return { accepted: false, reason: "untrusted_issuer" }
  }

  const signatureBytes = Buffer.from(signature.value, "base64")

  // Every key valid for this issuer at `now` is tried, so a rotation overlap does not create a
  // window in which a legitimately signed snapshot is refused.
  const signatureValid = issuerKeys.some((key) =>
    algorithm.verify(canonicalRevocationBytes(body), signatureBytes, key.publicKeyPem),
  )

  if (!signatureValid) {
    return { accepted: false, reason: "invalid_signature" }
  }

  if (body.tenant_id !== options.expectedTenantId) {
    return { accepted: false, reason: "tenant_mismatch" }
  }

  const issuedAt = Date.parse(body.issued_at)
  const expiresAt = Date.parse(body.expires_at)

  if (Number.isNaN(issuedAt) || Number.isNaN(expiresAt) || expiresAt <= issuedAt) {
    return { accepted: false, reason: "invalid_expiry_window" }
  }

  if (now.getTime() < issuedAt) {
    return { accepted: false, reason: "not_yet_valid" }
  }

  if (now.getTime() >= expiresAt) {
    return { accepted: false, reason: "expired" }
  }

  if (options.minimumVersion !== undefined && body.version <= options.minimumVersion) {
    return { accepted: false, reason: "version_rollback" }
  }

  return { accepted: true, body }
}

export type SnapshotState =
  | { readonly kind: "active"; readonly body: RevocationSnapshotBody }
  /**
   * A snapshot was accepted and has since expired.
   *
   * This is a distinct state rather than "empty" because the difference decides an outcome. Empty
   * means nothing is known, so nothing may be enforced. Expired means what is known is still
   * enforced — and that is the correct behaviour for a revocation list: an entry that was signed
   * should not stop applying because the control plane went away. Dropping it would turn an outage
   * into an un-revocation.
   */
  | { readonly kind: "expired"; readonly body: RevocationSnapshotBody }
  | { readonly kind: "empty" }

/**
 * Lookup tables derived from an accepted snapshot.
 *
 * Built once when a snapshot is accepted rather than on every question. The reason is that these
 * are per-request: a sidecar makes up to three revocation lookups for every action it decides,
 * and each one used to scan the whole entry array. With `MAX_REVOCATION_ENTRIES` at 5,000 that is
 * 15,000 string comparisons per request, paid by the enforcement path on every call.
 *
 * An index built by a compromised control plane cannot widen the decision — it is derived from the
 * same signed body and only ever answers "is this exact id revoked, and why". The signature has
 * already been verified before the index exists.
 */
type RevocationIndex = {
  readonly byAgentId: ReadonlyMap<string, RevocationReason>
  readonly byNonce: ReadonlyMap<string, RevocationReason>
  readonly byPermitId: ReadonlyMap<string, RevocationReason>
  readonly agentIds: ReadonlySet<string>
  readonly nonces: ReadonlySet<string>
  readonly permitIds: ReadonlySet<string>
}

const emptyRevocationIndex = (): RevocationIndex => ({
  byAgentId: new Map(),
  byNonce: new Map(),
  byPermitId: new Map(),
  agentIds: new Set(),
  nonces: new Set(),
  permitIds: new Set(),
})

/**
 * `first wins` matches what `Array.prototype.find` did, so an id appearing twice keeps the reason
 * from the earliest entry rather than silently changing when the list is re-ordered.
 */
const buildRevocationIndex = (body: RevocationSnapshotBody): RevocationIndex => {
  const byAgentId = new Map<string, RevocationReason>()
  const byNonce = new Map<string, RevocationReason>()
  const byPermitId = new Map<string, RevocationReason>()

  for (const entry of body.entries) {
    if (entry.agent_id !== undefined && !byAgentId.has(entry.agent_id)) {
      byAgentId.set(entry.agent_id, entry.reason)
    }
    if (entry.nonce !== undefined && !byNonce.has(entry.nonce)) {
      byNonce.set(entry.nonce, entry.reason)
    }
    if (entry.permit_id !== undefined && !byPermitId.has(entry.permit_id)) {
      byPermitId.set(entry.permit_id, entry.reason)
    }
  }

  return {
    byAgentId,
    byNonce,
    byPermitId,
    agentIds: new Set(byAgentId.keys()),
    nonces: new Set(byNonce.keys()),
    permitIds: new Set(byPermitId.keys()),
  }
}

/**
 * The local revocation store.
 *
 * Mirrors `PolicyLease` deliberately. The two are read on the same path and must fail in the same
 * direction, and a reader who knows one should not have to learn the other's rules.
 */
export class RevocationStore {
  readonly #tenantId: string
  #trustedIssuerKeys: TrustedKeySource
  #body: RevocationSnapshotBody | undefined
  #index: RevocationIndex = emptyRevocationIndex()
  #highestAppliedVersion = 0

  constructor(options: {
    readonly tenantId: string
    readonly trustedIssuerKeys: TrustedKeySource
  }) {
    this.#tenantId = options.tenantId
    this.#trustedIssuerKeys = options.trustedIssuerKeys
  }

  /**
   * Replace the trusted keys, so an issuer rotation takes effect on a running sidecar.
   *
   * Mirrors `PolicyLease.setTrustedKeys`, including the property that matters: an applied
   * snapshot keeps applying after its issuer's keys are withdrawn. A revocation list that went
   * empty on a key update would turn a rotation into a mass un-revocation, which is the worst
   * outcome available here.
   */
  setTrustedKeys(trustedIssuerKeys: TrustedKeySource): void {
    this.#trustedIssuerKeys = trustedIssuerKeys
  }

  /**
   * Offer a snapshot.
   *
   * A refused snapshot leaves the previous one in place. A refusal never clears a still-enforceable
   * list, because clearing on error is exactly how a corrupted push becomes an un-revocation.
   */
  offer(
    candidate: unknown,
    now: Date = new Date(),
  ): { readonly accepted: boolean; readonly reason?: string } {
    const result = verifyRevocationSnapshot(candidate, {
      expectedTenantId: this.#tenantId,
      trustedIssuerKeys: this.#trustedIssuerKeys,
      minimumVersion: this.#highestAppliedVersion,
      now,
    })

    if (!result.accepted) {
      return { accepted: false, reason: result.reason }
    }

    this.#body = result.body
    this.#index = buildRevocationIndex(result.body)
    this.#highestAppliedVersion = Math.max(this.#highestAppliedVersion, result.body.version)

    return { accepted: true }
  }

  state(now: Date = new Date()): SnapshotState {
    if (this.#body === undefined) {
      return { kind: "empty" }
    }

    if (now.getTime() >= Date.parse(this.#body.expires_at)) {
      return { kind: "expired", body: this.#body }
    }

    return { kind: "active", body: this.#body }
  }

  get appliedVersion(): number {
    return this.#highestAppliedVersion
  }

  /**
   * Whether an agent is revoked, by what, and since when.
   *
   * An empty store answers `false` rather than "unknown", because that is the only answer that
   * does not deny every request on a freshly started sidecar. The store's own emptiness is
   * reported by `state()`, so a caller that needs to distinguish the two can — see
   * `propagationAgeMs` below for why a caller should care.
   */
  isAgentRevoked(agentId: string, now: Date = new Date()): { readonly revoked: boolean; readonly reason?: RevocationReason } {
    return this.#lookup(now, agentId, this.#index.byAgentId)
  }

  isNonceRevoked(nonce: string, now: Date = new Date()): { readonly revoked: boolean; readonly reason?: RevocationReason } {
    return this.#lookup(now, nonce, this.#index.byNonce)
  }

  isPermitRevoked(permitId: string, now: Date = new Date()): { readonly revoked: boolean; readonly reason?: RevocationReason } {
    return this.#lookup(now, permitId, this.#index.byPermitId)
  }

  /**
   * Sets for the existing `ReadonlySet` verifier options.
   *
   * These come from the index rather than being rebuilt per request. The earlier comment here
   * warned that a cache would have to be invalidated on every snapshot and that a stale cache is
   * an un-revocation — that reasoning was right, and it is why the index is derived inside
   * `offer()` rather than memoised lazily: a snapshot and its index are replaced together, in one
   * statement, so there is no window in which they disagree.
   */
  agentIdSet(now: Date = new Date()): ReadonlySet<string> {
    return this.#all(now, this.#index.agentIds)
  }

  nonceSet(now: Date = new Date()): ReadonlySet<string> {
    return this.#all(now, this.#index.nonces)
  }

  permitIdSet(now: Date = new Date()): ReadonlySet<string> {
    return this.#all(now, this.#index.permitIds)
  }

  /**
   * How long the enforcement point has been without a fresh snapshot, or `undefined` when it has
   * never had one.
   *
   * This is the SLO instrument. A snapshot that is still being enforced but is minutes past its
   * refresh interval is not a security failure — the entries in it are still denied — but it does
   * mean new revocations cannot land, and that is something an operator has to be able to see. It
   * is exposed rather than logged-and-forgotten because the whole point of an SLO is that
   * exceeding it is visible.
   */
  propagationAgeMs(now: Date = new Date()): number | undefined {
    const state = this.state(now)

    if (state.kind === "empty") {
      return undefined
    }

    return now.getTime() - Date.parse(state.body.issued_at)
  }

  /**
   * Look up one id in the index.
   *
   * The empty check lives here rather than at each call site, because that is what keeps "empty"
   * and "expired" from converging: an empty store answers nothing, an expired snapshot still
   * answers from the index. An expired store that answered "nothing" would be an un-revocation.
   */
  #lookup(
    now: Date,
    id: string,
    table: ReadonlyMap<string, RevocationReason>,
  ): { readonly revoked: boolean; readonly reason?: RevocationReason } {
    if (this.state(now).kind === "empty") {
      return { revoked: false }
    }

    // An expired snapshot is still enforced. See `SnapshotState` for why. The index was built
    // from the signed body and outlives the window exactly as the body does.
    const reason = table.get(id)

    return reason === undefined ? { revoked: false } : { revoked: true, reason }
  }

  /**
   * The whole set, for the `ReadonlySet` verifier options.
   *
   * Copied rather than handed over. `ReadonlySet` is a compile-time contract, not a runtime one:
   * a caller holding the internal set could `add()` to it, and every later revocation check would
   * see an entry that the signed body never contained. Returning the same object the index uses
   * would trade the scan this index exists to remove for a much quieter failure.
   *
   * Copying is not on the per-request path — the `#lookup` methods are — so this stays off the
   * enforcement hot path that motivated the index.
   */
  #all(now: Date, set: ReadonlySet<string>): ReadonlySet<string> {
    if (this.state(now).kind === "empty") {
      return new Set()
    }

    return new Set(set)
  }
}
