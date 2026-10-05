import { verifyDecisionToken } from "./hash.ts"
import { ed25519 } from "./v2/signature.ts"

/**
 * Asymmetric signatures for decision tokens.
 *
 * ## Why this exists
 *
 * `signDecisionToken` in `hash.ts` is an HMAC, so it is symmetric: whoever can *verify* a token can
 * also *mint* one. The executors live on the agent side of the boundary, which means the component
 * that decides whether a shell command may run is the same component that would need to be trusted
 * to issue that permission. Every other signer in the fabric is Ed25519 for exactly this reason.
 *
 * ## What is reused, and why
 *
 * `ed25519` from `./v2/signature.ts`, which wraps `node:crypto`. This module does not implement a
 * signature scheme, does not define a curve, and does not touch key material beyond handing a PEM
 * to that wrapper. Adding a second Ed25519 code path would be the drift risk the single wrapper
 * exists to prevent.
 *
 * ## Token format
 *
 * `ed25519.<base64url(payload)>.<base64url(signature)>`
 *
 * The algorithm is bound into the token rather than chosen by the verifier. A verifier that picked
 * the algorithm from the token would let an attacker pick it too; naming it in the envelope means a
 * verifier decides which algorithm it will accept and the token can only disagree by being refused.
 *
 * ## Trust boundary
 *
 * This proves the holder of the *public* key cannot forge a token. It does not prove the private key
 * is kept off the adapter's host, which is a deployment property and not something a signature
 * format can demonstrate.
 */

/** Fixed width of the algorithm component, so a token is unambiguous. */
export const ASYMMETRIC_TOKEN_ALGORITHM = "ed25519"

export type DecisionTokenVerification =
  /** The current scheme. Symmetric: the verifier can also mint. */
  | { readonly kind: "hmac"; readonly secret: string }
  /** Ed25519. The verifier holds a public key and cannot mint. */
  | { readonly kind: "ed25519"; readonly publicKeyPem: string }

export type TokenVerificationResult =
  | { readonly valid: true; readonly payload: string }
  | { readonly valid: false }

const splitToken = (token: string): readonly string[] => token.split(".")

/** True when the token claims to be asymmetric. Used by tests and by refusal messages. */
export const isAsymmetricDecisionToken = (token: string): boolean =>
  splitToken(token)[0] === ASYMMETRIC_TOKEN_ALGORITHM

export const signDecisionTokenEd25519 = (payload: string, privateKeyPem: string): string => {
  const signature = ed25519.sign(Buffer.from(payload, "utf8"), privateKeyPem)

  return [
    ASYMMETRIC_TOKEN_ALGORITHM,
    Buffer.from(payload, "utf8").toString("base64url"),
    Buffer.from(signature).toString("base64url"),
  ].join(".")
}

/**
 * Verify an asymmetric token against a public key.
 *
 * Returns `{ valid: false }` for every failure mode — wrong key, tampered payload, malformed
 * envelope, HMAC token presented here — rather than throwing or naming a cause. A caller must not
 * be able to turn an exception into a success, and `ed25519.verify` already treats a malformed key
 * as a verification failure rather than an error.
 */
export const verifyDecisionTokenEd25519 = (
  token: string,
  publicKeyPem: string,
): TokenVerificationResult => {
  const parts = splitToken(token)

  if (parts.length !== 3) {
    return { valid: false }
  }

  const [algorithm, encodedPayload, encodedSignature] = parts
  if (
    algorithm !== ASYMMETRIC_TOKEN_ALGORITHM ||
    encodedPayload === undefined ||
    encodedSignature === undefined
  ) {
    return { valid: false }
  }

  let payload: string
  let signature: Uint8Array
  try {
    payload = Buffer.from(encodedPayload, "base64url").toString("utf8")
    signature = Buffer.from(encodedSignature, "base64url")
  } catch {
    return { valid: false }
  }

  // The signature covers the raw payload bytes, the same rule signDecisionToken follows for HMAC.
  // Signing the base64url text instead would be a second, incompatible definition of the same
  // thing, and the two would disagree silently.
  if (!ed25519.verify(Buffer.from(payload, "utf8"), signature, publicKeyPem)) {
    return { valid: false }
  }

  return { valid: true, payload }
}

/**
 * Verify under whichever scheme `verification` names.
 *
 * The verifier chooses the algorithm from `verification`, never from the token, so an attacker
 * cannot downgrade a token to a scheme they can satisfy. The one asymmetry: an HMAC verifier will
 * accept an HMAC token, and an Ed25519 verifier will not, so a caller that wants Ed25519-only
 * enforcement gets it by passing `{ kind: "ed25519" }`.
 */
export const verifyDecisionTokenWith = (
  token: string,
  verification: DecisionTokenVerification,
): TokenVerificationResult => {
  if (verification.kind === "ed25519") {
    return verifyDecisionTokenEd25519(token, verification.publicKeyPem)
  }

  // An HMAC token has exactly two components. An asymmetric one has three, so this rejects it
  // here: a caller who passes `{ kind: "hmac" }` has not asked for Ed25519 enforcement, and an
  // attacker cannot use an ed25519 token to get a signature check that was never requested.
  if (splitToken(token).length !== 2) {
    return { valid: false }
  }

  return verifyDecisionToken(token, verification.secret)
}