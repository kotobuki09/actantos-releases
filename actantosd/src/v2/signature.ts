import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as nodeSign,
  verify as nodeVerify,
  type KeyObject,
} from "node:crypto"

/**
 * Asymmetric signature abstraction for the v2 security fabric.
 *
 * Bundle consumers depend on this interface, not on Ed25519 directly, so a future
 * algorithm (ML-DSA, or a PQ scheme) can be registered without changing call sites.
 *
 * This module invents no cryptographic primitive. Every implementation delegates to
 * `node:crypto`.
 */

export type SignatureAlgorithmName = "ed25519"

export interface SigningKeyPair {
  readonly algorithm: SignatureAlgorithmName
  /** SPKI PEM. This is the value distributed in `trusted_issuers`. */
  readonly publicKeyPem: string
  /** PKCS#8 PEM. Never leaves the control plane. */
  readonly privateKeyPem: string
}

export interface SignatureAlgorithm {
  readonly name: SignatureAlgorithmName
  generateKeyPair(): SigningKeyPair
  sign(data: Uint8Array, privateKeyPem: string): Uint8Array
  verify(
    data: Uint8Array,
    signature: Uint8Array,
    publicKeyPem: string,
  ): boolean
}

// `KeyObject.export` is overloaded on a discriminated union; these two call sites use the
// PEM string forms, so the overload is fixed here rather than at each call.
const toPublicPem = (key: KeyObject): string =>
  key.export({ type: "spki", format: "pem" }) as string

const toPrivatePem = (key: KeyObject): string =>
  key.export({ type: "pkcs8", format: "pem" }) as string

/**
 * Ed25519 via `node:crypto`. Ed25519 signs the message directly, so the algorithm
 * argument to `sign`/`verify` must be `null`.
 */
export const ed25519: SignatureAlgorithm = {
  name: "ed25519",

  generateKeyPair(): SigningKeyPair {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519")

    return {
      algorithm: "ed25519",
      publicKeyPem: toPublicPem(publicKey),
      privateKeyPem: toPrivatePem(privateKey),
    }
  },

  sign(data: Uint8Array, privateKeyPem: string): Uint8Array {
    return nodeSign(null, data, createPrivateKey(privateKeyPem))
  },

  verify(
    data: Uint8Array,
    signature: Uint8Array,
    publicKeyPem: string,
  ): boolean {
    try {
      return nodeVerify(null, data, createPublicKey(publicKeyPem), signature)
    } catch {
      // A malformed key or signature is a verification failure, not a thrown error.
      // Callers must not be able to distinguish "bad signature" from "bad key" by
      // catching an exception, and must never treat either as success.
      return false
    }
  },
}

const registry: Map<SignatureAlgorithmName, SignatureAlgorithm> = new Map([
  [ed25519.name, ed25519],
])

export const registerSignatureAlgorithm = (
  algorithm: SignatureAlgorithm,
): void => {
  registry.set(algorithm.name, algorithm)
}

export const getSignatureAlgorithm = (
  name: SignatureAlgorithmName,
): SignatureAlgorithm | undefined => registry.get(name)

/** Names this build will accept in a bundle. An unknown name is never a fallback. */
export const supportedSignatureAlgorithms = (): SignatureAlgorithmName[] => [
  ...registry.keys(),
]