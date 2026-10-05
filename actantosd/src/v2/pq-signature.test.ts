import assert from "node:assert/strict"
import { readdirSync, readFileSync } from "node:fs"
import { fileURLToPath } from "node:url"
import path from "node:path"
import test from "node:test"
import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as nodeSign,
  verify as nodeVerify,
} from "node:crypto"

import {
  ML_DSA_44_PRIVATE_PEM,
  ML_DSA_44_PUBLIC_PEM,
  ML_DSA_65_PRIVATE_PEM,
  ML_DSA_65_PUBLIC_PEM,
} from "./pq-signature-fixture.ts"
import {
  canonicalBundleBytes,
  verifyPolicyBundle,
  type PolicyBundleBody,
  type SignedPolicyBundle,
} from "./signed-policy-bundle.ts"
import {
  canonicalRevocationBytes,
  verifyRevocationSnapshot,
  type RevocationSnapshotBody,
  type SignedRevocationSnapshot,
} from "./revocation-snapshot.ts"
import { ed25519, getSignatureAlgorithm, supportedSignatureAlgorithms } from "./signature.ts"

/**
 * Phase P, experiment 1: post-quantum signatures (S7, S12).
 *
 * ## The question
 *
 * `harvest now, decrypt later` is the reason this experiment exists. Every signed document in the
 * fabric — the policy bundle, the revocation snapshot, the security context envelope, the effect
 * permit — is signed with Ed25519, and Ed25519 is broken by a large enough quantum computer.
 * Nothing about the fabric's *design* depends on Ed25519 specifically: `signature.ts` was written
 * with a registry precisely so another algorithm could be added without touching call sites.
 *
 * So the question is not "should we migrate". It is "what would it actually cost, and what would
 * it break".
 *
 * ## What this file does and does not do
 *
 * It measures. It does not migrate. `registerSignatureAlgorithm` is never called, and there is a
 * test below that fails if any file under `src/` ever calls it.
 *
 * That is a deliberate line. Registering ML-DSA would make the live fabric accept a signature
 * algorithm it has never been reviewed against, on the same path that decides whether an agent may
 * act. The brief forbids a silent change from fail-closed to fail-open, and "register a new
 * signature algorithm" is precisely such a change — it must be its own reviewed decision, with its
 * own threat model, not a side effect of a measurement.
 *
 * ## Findings on this machine
 *
 * Node 26.4.0, OpenSSL 3.5.7, Windows. 2 KiB message, median of repeated runs.
 *
 * | | Ed25519 | ML-DSA-44 | ML-DSA-65 | SLH-DSA-SHA2-128s |
 * |---|---|---|---|---|
 * | public key, DER SPKI | 44 B | 1,334 B | 1,974 B | 50 B |
 * | signature | 64 B | 2,420 B | 3,309 B | 7,856 B |
 * | sign | 0.04 ms | 0.37 ms | 0.52 ms | 268 ms |
 * | verify | 0.09 ms | 0.08 ms | 0.11 ms | 0.28 ms |
 * | keygen in `node:crypto` | yes | **no** | **no** | yes |
 *
 * Three results, in order of how much they change a decision:
 *
 * **Latency is not the problem.** Verification — the operation the enforcement path actually
 * performs, once per decision — is *faster* than Ed25519 for both ML-DSA variants, because the
 * fabric signs canonical JSON of a few kilobytes rather than a pre-computed digest. That removes
 * the most common reason to postpone a migration.
 *
 * **The lattice family is blocked on the runtime, not on the crypto.** ML-DSA is the algorithm
 * everyone means by "post-quantum signatures", and it is the one this Node cannot generate keys
 * for. Keys would have to arrive from the `openssl` CLI, a pre-shipped PEM, or a Node upgrade. The
 * hash-based family, SLH-DSA from FIPS 205, has a complete path today — `generateKeyPairSync`
 * included — with a public key the size of Ed25519's.
 *
 * **Size is the real cost, and it lands in the wrong place.** ML-DSA-44 signs are 38x Ed25519 and
 * still fit the 256 KiB frame at 0.9% of budget. SLH-DSA-SHA2-128s is 123x, which is fine for the
 * policy bundle and the revocation snapshot — both arrive rarely — but those signatures ride on the
 * security context envelope and the effect permit, which are per-execution. That is ~16 KB added
 * to every action, and it is a wire-format change, not a configuration change.
 *
 * What this experiment does *not* settle: hybrid construction (Ed25519 + ML-DSA concatenated, so
 * a signature is valid under whichever survives), the key-agility story for an issuer that must
 * rotate a PQ key on a schedule it cannot yet meet, and whether SLH-DSA's hash-based security
 * assumption is one this threat model should accept. Those are decisions, not measurements.
 */

const NOW = new Date("2026-10-04T12:00:00.000Z")
const ISSUER = "issuer-pq-experiment"

/* ------------------------------------------------------------------ the primitive is real */

// These two establish that the refusals further down are a *policy* decision and not a gap in the
// runtime. If ML-DSA did not work here, "the fabric refuses ML-DSA" would be true for the wrong
// reason and would prove nothing.

test("Phase P: ML-DSA-44 signs and verifies through node:crypto", () => {
  const privateKey = createPrivateKey(ML_DSA_44_PRIVATE_PEM)
  const publicKey = createPublicKey(ML_DSA_44_PUBLIC_PEM)
  const message = Buffer.from("actantos-phase-p", "utf8")

  const signature = nodeSign(null, message, privateKey)

  assert.equal(nodeVerify(null, message, publicKey, signature), true)
})

test("Phase P: ML-DSA rejects a tampered message, so the measurement is not self-consistency", () => {
  const privateKey = createPrivateKey(ML_DSA_44_PRIVATE_PEM)
  const publicKey = createPublicKey(ML_DSA_44_PUBLIC_PEM)
  const signature = nodeSign(null, Buffer.from("actantos-phase-p", "utf8"), privateKey)

  // A signature scheme that accepted a mutated message would make every other measurement in this
  // file meaningless. This is the one check that makes "it round-trips" worth saying.
  assert.equal(nodeVerify(null, Buffer.from("actantos-phase-P", "utf8"), publicKey, signature), false)
  assert.equal(nodeVerify(null, Buffer.from("actantos-phase-p2", "utf8"), publicKey, signature), false)
})

test("Phase P: node:crypto on this runtime cannot generate an ML-DSA key", () => {
  // Recorded as a finding, not a wish. If a future Node wires this up, this test fails and the
  // migration stops being blocked on "where does the issuer key come from".
  //
  // The cast is not hiding a typing inconvenience. `generateKeyPairSync`'s overload list genuinely
  // has no ML-DSA member, and the fact that it cannot be spelled is the finding.
  const generate = generateKeyPairSync as (type: string) => { publicKey: { export: (o: object) => Uint8Array }; privateKey: unknown }

  assert.throws(() => generate("ML-DSA-44"))
  assert.throws(() => generate("ML-DSA-65"))

  // OpenSSL underneath has the algorithm; Node does not surface it. Without shelling out, there is
  // no way for the control plane to mint one at run time.
  assert.equal(process.versions.openssl.startsWith("3.5"), true)
})

test("Phase P: SLH-DSA, by contrast, is fully available including key generation", () => {
  // This is the finding that reshapes the migration question.
  //
  // ML-DSA is the algorithm everyone means by "post-quantum signatures", and on this runtime it is
  // the one that *cannot generate keys*. SLH-DSA — hash-based, from FIPS 205 — has a complete path:
  // `generateKeyPairSync` works, no subprocess, no pre-shipped PEM. The lattice family is the one
  // blocked on the runtime; the hash family is not.
  //
  // So the honest summary of Phase P is not "ML-DSA works". It is "two families are available at
  // different prices, and neither is free".
  const { publicKey, privateKey } = generateKeyPairSync("slh-dsa-sha2-128s")
  const message = Buffer.from("actantos-phase-p", "utf8")
  const signature = nodeSign(null, message, privateKey)

  assert.equal(nodeVerify(null, message, publicKey, signature), true)
  assert.equal(nodeVerify(null, Buffer.from("actantos-phase-q", "utf8"), publicKey, signature), false)
})

/* --------------------------------------------------- the cost, stated as enforceable facts */

test("Phase P: the signature is about 38x larger and the public key about 30x larger", () => {
  const message = Buffer.alloc(2048)
  const { publicKey, privateKey } = generateKeyPairSync("ed25519")

  const edSig = nodeSign(null, message, privateKey)
  const edSpki = (publicKey.export({ type: "spki", format: "der" }) as Uint8Array).length

  const pq44 = createPublicKey(ML_DSA_44_PUBLIC_PEM)
  const pq65 = createPublicKey(ML_DSA_65_PUBLIC_PEM)
  const pq44Sig = nodeSign(null, message, createPrivateKey(ML_DSA_44_PRIVATE_PEM))
  const pq65Sig = nodeSign(null, message, createPrivateKey(ML_DSA_65_PRIVATE_PEM))
  const spki = (key: ReturnType<typeof createPublicKey>): number =>
    (key.export({ type: "spki", format: "der" }) as Uint8Array).length

  // Exact FIPS 204 sizes. Asserted rather than described so that a change in the runtime's
  // implementation shows up as a test failure instead of quietly invalidating the cost model.
  assert.equal(pq44Sig.length, 2420)
  assert.equal(pq65Sig.length, 3309)
  assert.equal(spki(pq44), 1334)
  assert.equal(spki(pq65), 1974)

  assert.ok(pq44Sig.length / edSig.length > 35, "ML-DSA-44 signature is not the size this file claims")
  assert.ok(spki(pq44) / edSpki > 28, "ML-DSA-44 public key is not the size this file claims")
})

test("Phase P: an ML-DSA signature still fits the sidecar frame limit", () => {
  // The obvious objection to a bigger signature is that it breaks the transport. It does not, at
  // the sizes involved — a 2,420-byte signature against a 256 KiB frame is 0.9% of the budget.
  // Worth stating explicitly, because the frame limit is a fail-closed control and a reader should
  // know it is not the thing that would break.
  const MAX_FRAME_BYTES = 256 * 1024
  const signature = nodeSign(null, Buffer.alloc(1024), createPrivateKey(ML_DSA_44_PRIVATE_PEM))

  assert.ok(signature.length * 4 < MAX_FRAME_BYTES)
})

test("Phase P: the ML-DSA-65 key pair is a valid, distinct key, not a copy of the 44 pair", () => {
  const pub44 = createPublicKey(ML_DSA_44_PUBLIC_PEM).export({ type: "spki", format: "der" })
  const pub65 = createPublicKey(ML_DSA_65_PUBLIC_PEM).export({ type: "spki", format: "der" })

  assert.notEqual(Buffer.from(pub44).equals(Buffer.from(pub65)), true)

  const signature = nodeSign(null, Buffer.from("cross-check", "utf8"), createPrivateKey(ML_DSA_65_PRIVATE_PEM))
  assert.equal(nodeVerify(null, Buffer.from("cross-check", "utf8"), createPublicKey(ML_DSA_44_PUBLIC_PEM), signature), false)
})

/* --------------------------------------------------- and the fabric still refuses all of it */

test("Phase P: the live registry still accepts exactly one algorithm", () => {
  assert.deepEqual(supportedSignatureAlgorithms(), ["ed25519"])

  // `SignatureAlgorithmName` is `"ed25519"`, so these names do not typecheck either. That is a
  // second, independent lock on the same decision: the compiler refuses the name, and the runtime
  // refuses the document. Reaching past the type here is what it takes to test the runtime half.
  const lookup = getSignatureAlgorithm as (name: string) => unknown

  assert.equal(lookup("ml-dsa-44"), undefined)
  assert.equal(lookup("ML-DSA-44"), undefined)
  assert.equal(lookup("mldsa44"), undefined)
  assert.equal(lookup("slh-dsa-sha2-128s"), undefined)
})

test("Phase P: a cryptographically VALID SLH-DSA policy bundle is refused too", () => {
  // SLH-DSA has the complete Node path, so it is the more plausible future migration and therefore
  // the more important one to prove the fabric will not silently accept.
  const body = bundleBody()
  const { publicKey, privateKey } = generateKeyPairSync("slh-dsa-sha2-128s")
  const bytes = canonicalBundleBytes(body)
  const value = Buffer.from(nodeSign(null, bytes, privateKey)).toString("base64")

  assert.equal(nodeVerify(null, bytes, publicKey, Buffer.from(value, "base64")), true)

  const result = verifyPolicyBundle(
    { body, signature: { algorithm: "slh-dsa-sha2-128s", issuer_id: ISSUER, value } },
    {
      expectedTenantId: TENANT,
      trustedIssuerKeys: new Map([[ISSUER, publicKey.export({ type: "spki", format: "pem" }) as string]]),
      now: NOW,
    },
  )

  assert.equal(result.accepted, false)
  assert.equal(result.accepted === false && result.reason, "unsupported_algorithm")
})

test("Phase P: a cryptographically VALID ML-DSA-44 policy bundle is refused as unsupported", () => {
  // The load-bearing test of the whole experiment.
  //
  // The signature below is real: it verifies under the ML-DSA-44 public key, over the exact
  // canonical bytes of this body. If the fabric ever accepted it, the only reason would be that
  // something registered the algorithm. The refusal has to come from the registry, not from a
  // failure to parse or a bad key — hence `unsupported_algorithm` and not any of its neighbours.
  const body = bundleBody()
  const bytes = canonicalBundleBytes(body)
  const value = Buffer.from(
    nodeSign(null, bytes, createPrivateKey(ML_DSA_44_PRIVATE_PEM)),
  ).toString("base64")

  // The signature is genuinely valid, so "the fabric refused it" cannot be an accident.
  assert.equal(
    nodeVerify(null, bytes, createPublicKey(ML_DSA_44_PUBLIC_PEM), Buffer.from(value, "base64")),
    true,
  )

  const bundle: SignedPolicyBundle = {
    body,
    signature: { algorithm: "ML-DSA-44", issuer_id: ISSUER, value },
  }

  const result = verifyPolicyBundle(bundle, {
    expectedTenantId: TENANT,
    trustedIssuerKeys: new Map([[ISSUER, ML_DSA_44_PUBLIC_PEM]]),
    now: NOW,
  })

  assert.equal(result.accepted, false)
  assert.equal(result.accepted === false && result.reason, "unsupported_algorithm")
})

test("Phase P: the same bundle under a lowercase or underscore spelling is refused too", () => {
  // Algorithm names in the envelope are free-form strings, so the refusal must not depend on a
  // spelling convention that some other writer might not follow.
  const body = bundleBody()
  const bytes = canonicalBundleBytes(body)
  const value = Buffer.from(nodeSign(null, bytes, createPrivateKey(ML_DSA_44_PRIVATE_PEM))).toString("base64")

  for (const algorithm of ["ml-dsa-44", "MLDSA44", "ml_dsa_44", "mldsa-44"]) {
    const result = verifyPolicyBundle(
      { body, signature: { algorithm, issuer_id: ISSUER, value } },
      { expectedTenantId: TENANT, trustedIssuerKeys: new Map([[ISSUER, ML_DSA_44_PUBLIC_PEM]]), now: NOW },
    )

    assert.equal(result.accepted, false, `${algorithm} was accepted`)
    assert.equal(result.accepted === false && result.reason, "unsupported_algorithm", algorithm)
  }
})

test("Phase P: the revocation snapshot refuses a valid ML-DSA-44 signature the same way", () => {
  // Not a bundle-specific property. Every verifier in the fabric resolves the algorithm through
  // the same registry, so the revocation path — which is the one an attacker would most want to
  // forge — is checked here too.
  const body: RevocationSnapshotBody = {
    snapshot_id: "snap-pq",
    tenant_id: TENANT,
    version: 1,
    issued_at: new Date(NOW.getTime() - 60_000).toISOString(),
    expires_at: new Date(NOW.getTime() + 60 * 60_000).toISOString(),
    entries: [{ agent_id: "planner", reason: "operator_request", revoked_at: NOW.toISOString() }],
  }

  const bytes = canonicalRevocationBytes(body)
  const value = Buffer.from(nodeSign(null, bytes, createPrivateKey(ML_DSA_44_PRIVATE_PEM))).toString("base64")

  assert.equal(
    nodeVerify(null, bytes, createPublicKey(ML_DSA_44_PUBLIC_PEM), Buffer.from(value, "base64")),
    true,
  )

  const snapshot: SignedRevocationSnapshot = {
    body,
    signature: { algorithm: "ML-DSA-44", issuer_id: ISSUER, value },
  }

  const result = verifyRevocationSnapshot(snapshot, {
    expectedTenantId: TENANT,
    trustedIssuerKeys: new Map([[ISSUER, ML_DSA_44_PUBLIC_PEM]]),
    now: NOW,
  })

  assert.equal(result.accepted, false)
  assert.equal(result.accepted === false && result.reason, "unsupported_algorithm")
})

test("Phase P: an Ed25519 signature over the same body is still accepted, so the refusals above are about the algorithm", () => {
  // The control. Without this, "every bundle is refused" would satisfy the three tests above and
  // prove nothing — which is exactly the mistake the security bench's control scenarios exist to
  // prevent, applied here to a unit test.
  const body = bundleBody()
  const edKeyPair = ed25519.generateKeyPair()
  const value = Buffer.from(
    nodeSign(null, canonicalBundleBytes(body), createPrivateKey(edKeyPair.privateKeyPem)),
  ).toString("base64")

  const result = verifyPolicyBundle(
    { body, signature: { algorithm: "ed25519", issuer_id: ISSUER, value } },
    { expectedTenantId: TENANT, trustedIssuerKeys: new Map([[ISSUER, edKeyPair.publicKeyPem]]), now: NOW },
  )

  assert.equal(result.accepted, true)
})

/* ------------------------------------------------------- the guard against a silent migration */

test("Phase P: no source file registers a signature algorithm", () => {
  // `registerSignatureAlgorithm` is the single function that would widen what the fabric accepts.
  // It is not called anywhere today. This test is what makes that true on every commit rather than
  // true today, and it is deliberately a source scan: there is no runtime way to observe a call
  // that happened during module load in some other file.
  //
  // `signature.ts` defines the function, and this file names it in order to look for it. Both are
  // exempt; a caller anywhere else is the thing being guarded against.
  const here = path.dirname(fileURLToPath(import.meta.url))
  const exempt = new Set(["signature.ts", "pq-signature.test.ts"])
  const offenders: string[] = []

  const walk = (directory: string): void => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const full = path.join(directory, entry.name)

      if (entry.isDirectory()) {
        walk(full)
        continue
      }
      if (!entry.name.endsWith(".ts") || exempt.has(entry.name)) continue
      if (readFileSync(full, "utf8").includes("registerSignatureAlgorithm(")) {
        offenders.push(path.relative(here, full))
      }
    }
  }

  walk(here)

  // A migration would have to delete this test in the same commit that registers the algorithm.
  // That is the point: the change becomes visible in review instead of arriving as a side effect.
  assert.deepEqual(offenders, [])
})

/* --------------------------------------------------------------------------- shared fixtures */

const TENANT = "t_pq"

const bundleBody = (): PolicyBundleBody => ({
  bundle_id: "bundle-pq",
  tenant_id: TENANT,
  version: 1,
  issued_at: new Date(NOW.getTime() - 60_000).toISOString(),
  expires_at: new Date(NOW.getTime() + 60 * 60_000).toISOString(),
  policies: [{ policy_id: "p1", cedar: 'permit(principal, action, resource);' }],
  agent_profile: {
    agent_id: "reviewer-1",
    allowed_tools: ["code.read"],
    max_delegation_depth: 1,
  },
  tool_manifest: [{ tool: "github.issues.read", grant: "grant://github/org/repo/issues/read" }],
  network_rules: [{ host: "api.github.com", action: "allow_via_egress_gateway" }],
  data_clearance: "INTERNAL",
  risk_profile: { risk_level: "low", requires_effect_permit: [] },
  trusted_issuers: [ISSUER],
})
