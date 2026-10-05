import assert from "node:assert/strict"
import { generateKeyPairSync } from "node:crypto"
import test from "node:test"

import {
  ASYMMETRIC_TOKEN_ALGORITHM,
  isAsymmetricDecisionToken,
  signDecisionTokenEd25519,
  verifyDecisionTokenEd25519,
  verifyDecisionTokenWith,
} from "./decision-token-signature.ts"
import { signDecisionToken } from "./hash.ts"
import { ed25519 } from "./v2/signature.ts"

const PAYLOAD = JSON.stringify({ decision: "allow", command_hash: "abc" })

const newKeys = () => ed25519.generateKeyPair()

test("an Ed25519 token verifies against the matching public key", () => {
  const keys = newKeys()
  const token = signDecisionTokenEd25519(PAYLOAD, keys.privateKeyPem)

  const result = verifyDecisionTokenEd25519(token, keys.publicKeyPem)

  assert.equal(result.valid, true)
  assert.equal(result.valid ? result.payload : undefined, PAYLOAD)
})

test("S7: the holder of the public key cannot mint a token", () => {
  // The claim that justifies asymmetric signatures, stated as the property it actually is: a
  // verifier that holds a public key has nothing to sign with.
  const keys = newKeys()
  const token = signDecisionTokenEd25519(PAYLOAD, keys.privateKeyPem)

  // Everything an attacker gets from a legitimate token, minus the private key.
  const stolen = {
    token,
    publicKeyPem: keys.publicKeyPem,
  }

  // Recomputing the signature is impossible without the private key, so the honest attempt is to
  // re-sign the payload they already have.
  const attackerPayload = PAYLOAD
  assert.equal(
    verifyDecisionTokenEd25519(
      `${ASYMMETRIC_TOKEN_ALGORITHM}.${Buffer.from(attackerPayload, "utf8").toString("base64url")}.${stolen.token.split(".")[2] ?? ""}`,
      stolen.publicKeyPem,
    ).valid,
    true,
    "re-using the real signature over the real payload is still valid, which is correct",
  )

  // What they cannot do is alter the payload while keeping the signature. This is the part the
  // signature actually buys.
  const tampered = PAYLOAD.replace("abc", "xyz")
  assert.equal(
    verifyDecisionTokenEd25519(
      `${ASYMMETRIC_TOKEN_ALGORITHM}.${Buffer.from(tampered, "utf8").toString("base64url")}.${stolen.token.split(".")[2] ?? ""}`,
      stolen.publicKeyPem,
    ).valid,
    false,
    "a verifier holding only the public key changed the payload and the token still verified",
  )
})

test("an HMAC verifier cannot mint, which is the reason this module exists", () => {
  // The contrast, made executable. With a symmetric scheme the verifier holds the signing key, so
  // it can produce a token that verifies. This is the limitation S7 does not permit.
  const secret = "shared-secret"
  const forged = signDecisionToken(PAYLOAD, secret)

  assert.equal(verifyDecisionTokenWith(forged, { kind: "hmac", secret }).valid, true)
})

test("a token signed by a different key does not verify", () => {
  const signer = newKeys()
  const other = newKeys()
  const token = signDecisionTokenEd25519(PAYLOAD, signer.privateKeyPem)

  assert.equal(verifyDecisionTokenEd25519(token, other.publicKeyPem).valid, false)
})

test("an HMAC token is refused by the Ed25519 verifier", () => {
  // Algorithm confusion, in the direction that matters: an attacker must not downgrade a token to a
  // scheme the verifier cannot check properly.
  const secret = "shared-secret"
  const hmacToken = signDecisionToken(PAYLOAD, secret)

  assert.equal(verifyDecisionTokenEd25519(hmacToken, newKeys().publicKeyPem).valid, false)
  assert.equal(isAsymmetricDecisionToken(hmacToken), false)
})

test("an Ed25519 token is refused by an HMAC verifier", () => {
  const keys = newKeys()
  const token = signDecisionTokenEd25519(PAYLOAD, keys.privateKeyPem)

  assert.equal(verifyDecisionTokenWith(token, { kind: "hmac", secret: "shared-secret" }).valid, false)
  assert.equal(isAsymmetricDecisionToken(token), true)
})

test("the verifier chooses the algorithm, so a token cannot select one", () => {
  // The token names its algorithm, but that name is checked against a fixed expectation rather
  // than used to dispatch. A token claiming a different algorithm is refused, not looked up.
  const keys = newKeys()
  const token = signDecisionTokenEd25519(PAYLOAD, keys.privateKeyPem)
  const [, payload, signature] = token.split(".")

  const renamed = `rsa.${payload ?? ""}.${signature ?? ""}`

  assert.equal(verifyDecisionTokenEd25519(renamed, keys.publicKeyPem).valid, false)
})

test("a malformed envelope is a verification failure, not a thrown error", () => {
  const keys = newKeys()

  for (const token of ["", ".", "ed25519.", "ed25519..", "ed25519.only-two", "a.b.c.d"]) {
    assert.equal(
      verifyDecisionTokenEd25519(token, keys.publicKeyPem).valid,
      false,
      `expected ${JSON.stringify(token)} to fail verification`,
    )
  }
})

test("a malformed public key is a verification failure, not a thrown error", () => {
  // If this threw, a caller that caught it and continued would turn a key fault into a pass.
  const keys = newKeys()
  const token = signDecisionTokenEd25519(PAYLOAD, keys.privateKeyPem)

  assert.equal(verifyDecisionTokenEd25519(token, "not-a-pem").valid, false)
})

test("the signature covers the raw payload, not its base64url text", () => {
  // A real interoperability hazard: signing the encoded text instead would be a second definition
  // of the same token, and the two halves of the fabric would disagree silently.
  const keys = newKeys()
  const token = signDecisionTokenEd25519(PAYLOAD, keys.privateKeyPem)
  const [algorithm, encodedPayload, signature] = token.split(".")

  const swapped = `${algorithm}.${signature}.${encodedPayload}`

  assert.equal(verifyDecisionTokenEd25519(swapped, keys.publicKeyPem).valid, false)
})

test("signature verification uses the shared node:crypto Ed25519 primitive", () => {
  // Guards against a reimplementation drifting from the wrapper the rest of the fabric uses: a
  // token produced by the actantosd wrapper must verify through node:crypto here, and vice versa.
  const keys = newKeys()
  const payload = Buffer.from(PAYLOAD, "utf8")
  const signature = ed25519.sign(payload, keys.privateKeyPem)
  const token = `ed25519.${payload.toString("base64url")}.${Buffer.from(signature).toString("base64url")}`

  assert.equal(verifyDecisionTokenEd25519(token, keys.publicKeyPem).valid, true)
})

test("a key pair from node:crypto works, so the PEM formats are interchangeable", () => {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519")
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString()
  const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString()

  const token = signDecisionTokenEd25519(PAYLOAD, privateKeyPem)

  assert.equal(verifyDecisionTokenEd25519(token, publicKeyPem).valid, true)
})