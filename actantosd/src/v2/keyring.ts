/**
 * Trusted signing keys, and how they change over time.
 *
 * ## What was wrong before this file existed
 *
 * Every verifier took `trustedIssuerKeys: ReadonlyMap<string, string>` — one issuer id to one
 * PEM, no key id, no validity window, no way to hold two keys at once. The consequences were not
 * hypothetical:
 *
 * - **Rotation was impossible.** An issuer that generated a new key either kept the old PEM and
 *   had every new document refused as `invalid_signature`, or swapped the map and had every
 *   document signed by the previous key stop verifying. There was no overlap, so there was no
 *   way to roll a key without a window in which one side was broken.
 *
 * - **Rotation was indistinguishable from forgery.** Both surfaced as `invalid_signature` under
 *   the same issuer id. An operator could not tell "the control plane rotated" from "someone
 *   forged this", and neither could a log.
 *
 * - **Nothing noticed key substitution.** The issuer id is configuration, not derived from key
 *   material. Swapping the PEM under an unchanged issuer id was invisible until verification
 *   started failing.
 *
 * The JWKS path in `workload-identity-provider.ts` already tolerated several keys published under
 * one `kid`, so the idea was not new to this codebase — it just did not reach the issuer path,
 * which is the path that signs policy.
 *
 * ## What this is not
 *
 * This is a key *set* with time bounds. It is not a hierarchy: there is no root, no
 * cross-signature, and no chain to walk. A key here is trusted because an operator put it in the
 * map, exactly as before. Adding a chain would mean a second trust model, and nothing in the
 * product requires one.
 */

import { createHash } from "node:crypto"

/** One trusted key, with the window in which it may be used to verify. */
export type TrustedKey = {
  /**
   * Distinguishes keys within one issuer. Purely diagnostic: it appears in `keyFingerprint` and
   * in rejection details, and nothing verifies against it.
   */
  readonly keyId: string
  /** SPKI PEM. The same material the plain map form carries. */
  readonly publicKeyPem: string
  /** Verification with this key is refused before this instant. Absent means "no lower bound". */
  readonly notBefore?: Date | undefined
  /**
   * Verification with this key is refused at or after this instant. Absent means "no upper bound".
   *
   * This is the field that makes rotation expressible: the old key gets a `notAfter`, the new key
   * arrives with no `notBefore`, both are present during the overlap, and the old key is removed
   * or expires afterwards.
   */
  readonly notAfter?: Date | undefined
}

/**
 * Issuer id to the keys currently trusted for it.
 *
 * This is a superset of the historical `ReadonlyMap<string, string>`, not a replacement for it —
 * see `toKeyring`. A plain map is still accepted everywhere a keyring is, so nothing that exists
 * today needs to change to keep working.
 */
export type TrustedKeyring = ReadonlyMap<string, readonly TrustedKey[]>

/** One key that is trusted for an issuer right now, paired with the id it was declared under. */
export type ResolvedIssuerKey = {
  readonly keyId: string
  readonly publicKeyPem: string
}

/** Either shape a verifier accepts. A bare string map means "one key, no time bounds". */
export type TrustedKeySource = ReadonlyMap<string, string> | TrustedKeyring

/**
 * A stable, non-secret identifier for key material.
 *
 * Exists because the issuer id is configuration and therefore says nothing about *which* key is
 * loaded. An operator comparing two deployments needs a value that changes when the key changes
 * and does not change when only a timestamp or a comment changes, so this is the SHA-256 of the
 * DER SPKI, not of the PEM text — PEM rewrapping would otherwise look like a rotation.
 *
 * This is a fingerprint, not a secret. It is safe to log.
 */
export const keyFingerprint = (publicKeyPem: string): string => {
  const der = Buffer.from(
    publicKeyPem
      .replace(/-----(BEGIN|END) PUBLIC KEY-----/gu, "")
      .replace(/\s+/gu, ""),
    "base64",
  )

  return createHash("sha256").update(der).digest("hex").slice(0, 16)
}

/** Wrap the historical single-key map so it can be used where a keyring is expected. */
export const toKeyring = (keys: ReadonlyMap<string, string>): TrustedKeyring =>
  new Map(
    [...keys].map(([issuerId, pem]) => [
      issuerId,
      [{ keyId: keyFingerprint(pem), publicKeyPem: pem }],
    ]),
  )

const isKeyring = (source: TrustedKeySource): source is TrustedKeyring =>
  [...source.values()].every((value) => Array.isArray(value))

/** True when `instant` falls inside the key's window. An absent bound does not constrain. */
const withinWindow = (key: TrustedKey, now: Date): boolean => {
  const at = now.getTime()

  if (Number.isNaN(at)) {
    // An unusable clock cannot be evidence that a key is current. Refuse rather than assume.
    return false
  }

  if (key.notBefore !== undefined) {
    const from = key.notBefore.getTime()
    if (Number.isNaN(from) || at < from) return false
  }

  if (key.notAfter !== undefined) {
    const until = key.notAfter.getTime()
    // Inclusive end: a key is usable up to but not including its expiry, matching how the
    // document expiry checks in the other verifiers are written.
    if (Number.isNaN(until) || at >= until) return false
  }

  return true
}

/** The key material to try for `issuerId` at `now`, in declaration order, with its key id. */
export const resolveIssuerKeys = (
  source: TrustedKeySource,
  issuerId: string,
  now: Date,
): readonly ResolvedIssuerKey[] => {
  const entry = source.get(issuerId)

  if (entry === undefined) return []

  if (!isKeyring(source)) {
    // The historical shape: one key, no window. Behaviour is exactly what it always was.
    return typeof entry === "string"
      ? [{ keyId: keyFingerprint(entry), publicKeyPem: entry }]
      : []
  }

  return (entry as readonly TrustedKey[])
    .filter((key) => withinWindow(key, now))
    .map((key) => ({ keyId: key.keyId, publicKeyPem: key.publicKeyPem }))
}

/**
 * The key ids usable for `issuerId` at `now`. Diagnostic only; never used to make a decision.
 */
export const activeKeyIds = (
  source: TrustedKeySource,
  issuerId: string,
  now: Date,
): readonly string[] => resolveIssuerKeys(source, issuerId, now).map((key) => key.keyId)

/**
 * Verify a signature against every key currently trusted for an issuer.
 *
 * Returns which key verified, so a caller can log the rotation rather than guess at it. The
 * multiple-candidate loop is the same shape `verifyJwtSvid` already uses for `kid`, deliberately:
 * one mechanism, not two.
 */
export const verifyAgainstIssuerKeys = (args: {
  readonly trustedKeys: TrustedKeySource
  readonly issuerId: string
  readonly signature: Uint8Array
  readonly signedBytes: Uint8Array
  readonly algorithm: {
    verify(message: Uint8Array, signature: Uint8Array, publicKeyPem: string): boolean
  }
  readonly now: Date
}): { readonly verified: true; readonly keyId: string } | { readonly verified: false } => {
  for (const candidate of resolveIssuerKeys(args.trustedKeys, args.issuerId, args.now)) {
    // ed25519.verify already swallows malformed-key errors and returns false, so a key that
    // cannot check this signature is simply not the right key for it.
    if (args.algorithm.verify(args.signedBytes, args.signature, candidate.publicKeyPem)) {
      return { verified: true, keyId: candidate.keyId }
    }
  }

  return { verified: false }
}
