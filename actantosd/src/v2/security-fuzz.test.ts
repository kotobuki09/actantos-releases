import assert from "node:assert/strict"
import test from "node:test"

import fc from "fast-check"

import { canonicalStringify, toJsonValue } from "../hash.ts"
import { scopeIsNarrowerThan } from "./delegation.ts"
import { signRevocationSnapshot, signedRevocationSnapshotSchema, verifyRevocationSnapshot } from "./revocation-snapshot.ts"
import {
  securityContextEnvelopeSchema,
  signSecurityContextEnvelope,
  verifySecurityContextEnvelope,
  type SecurityContextEnvelopeBody,
} from "./security-context-envelope.ts"
import { ed25519 } from "./signature.ts"
import {
  policyBundleBodySchema,
  signPolicyBundle,
  signedPolicyBundleSchema,
  verifyPolicyBundle,
  type PolicyBundleBody,
} from "./signed-policy-bundle.ts"
import { verifyWorkloadIdentity } from "./workload-identity.ts"

/**
 * Property-based fuzzing of every verifier that stands between the network and an allow.
 *
 * The unit tests check the cases their author thought of. These check the ones they did not.
 *
 * Three properties, in order of how much they matter:
 *
 *   1. **Acceptance is a pure function of the canonical bytes.** A genuine document is signed,
 *      then one random part of it is changed. The signature covers canonical bytes, so a
 *      mutation that changes those bytes must be refused, and a mutation that leaves them
 *      unchanged must be accepted. Asserting only the first half is not enough, because a
 *      verifier that simply refused everything would pass it; the control assertion covers that.
 *      Any mutation that changed the bytes and was still accepted would be a forgery primitive,
 *      and this is the test that would find it.
 *
 *      The distinction matters because the verifiers parse with a Zod schema *before* hashing.
 *      Zod strips unknown keys, so inserting a field the schema does not declare produces a
 *      parsed body that is byte-identical to the authentic one. Refusing that would be a bug,
 *      not a defence: the attacker has changed nothing the verifier reads.
 *
 *   2. **Garbage is never accepted.** Arbitrary JSON, arbitrary strings, arbitrary token
 *      shapes. Verifiers parse untrusted input; a parser that throws is a crash, and a
 *      verifier that somehow returns `accepted` on noise is worse.
 *
 *   3. **Scope algebra never widens.** `scopeIsNarrowerThan` is the check behind S6. It must
 *      return false rather than throw on unparseable input, because a throw here would be a
 *      caller-side crash and a `true` would be an authority grant from nothing.
 *
 * Every property runs with a fixed seed. A fuzzer that finds something on one machine and not
 * the next is a fuzzer whose failures get ignored, which is worse than no fuzzer.
 */

const SEED = 20261004
const RUNS = 300

const ISSUER_ID = "issuer-primary"
const keyPair = ed25519.generateKeyPair()
const trustedIssuerKeys = new Map([[ISSUER_ID, keyPair.publicKeyPem]])
const otherKeys = ed25519.generateKeyPair()

const NOW = new Date("2026-10-04T12:00:00.000Z")
const TENANT = "t_demo"
const at = (offsetMs: number): string => new Date(NOW.getTime() + offsetMs).toISOString()

// --- A generic JSON mutator ----------------------------------------------------------------

type Mutation =
  | { readonly kind: "replace"; readonly path: readonly (string | number)[]; readonly value: unknown }
  | { readonly kind: "delete"; readonly path: readonly (string | number)[] }
  | { readonly kind: "insert"; readonly path: readonly (string | number)[]; readonly key: string; readonly value: unknown }

/**
 * Pick a random location in a JSON value and change it in one of three ways.
 *
 * Changing a *value* and *removing a field* both matter: removing `signature` entirely must
 * be refused as malformed rather than as a missing-signature crash, and replacing a field
 * with a plausible-but-wrong value is what a targeted attacker would actually send.
 *
 * `insert` is restricted to paths whose container is an object. Inserting into a string or a
 * number is not a thing that can be observed, so allowing it would spend the run budget on
 * mutations that provably cannot change the document.
 */
const mutationArb = (root: unknown): fc.Arbitrary<Mutation> => {
  const paths: (string | number)[][] = []
  const objectPaths: (string | number)[][] = []
  const collect = (value: unknown, path: (string | number)[], insertable: boolean): void => {
    paths.push(path)
    if (insertable) objectPaths.push(path)
    if (Array.isArray(value)) {
      value.forEach((item, index) => collect(item, [...path, index], false))
      return
    }
    if (value !== null && typeof value === "object") {
      for (const [key, nested] of Object.entries(value)) {
        collect(nested, [...path, key], false)
      }
    }
  }
  collect(root, [], true)

  const junk = fc.oneof(
    fc.string({ maxLength: 40 }),
    fc.integer(),
    fc.boolean(),
    fc.constant(null),
    fc.constantFrom("", "0", "-1", "{}", "[]", "null", "NaN", "Infinity", "\u202e", "\u0000"),
  )

  return fc.oneof(
    fc.tuple(fc.constantFrom(...paths), junk).map(([path, value]) => ({ kind: "replace", path, value }) as const),
    fc.constantFrom(...paths).map((path) => ({ kind: "delete", path }) as const),
    fc.tuple(
      fc.constantFrom(...objectPaths),
      fc.string({ maxLength: 12 }),
      junk,
    ).map(([path, key, value]) => ({ kind: "insert", path, key, value }) as const),
  )
}

const applyMutation = (root: unknown, mutation: Mutation): unknown => {
  const clone = structuredClone(root) as unknown

  const containerAt = (path: readonly (string | number)[]): unknown => {
    let node: unknown = clone
    for (const step of path) {
      node = node === null || node === undefined
        ? undefined
        : (node as Record<string | number, unknown>)[step]
    }
    return node
  }

  if (mutation.kind === "insert") {
    const parent = containerAt(mutation.path)
    if (parent !== null && typeof parent === "object" && !Array.isArray(parent)) {
      ;(parent as Record<string, unknown>)[mutation.key] = mutation.value
    }
    return clone
  }

  const parent = containerAt(mutation.path.slice(0, -1))
  if (parent === null || parent === undefined) return clone

  const last = mutation.path[mutation.path.length - 1]
  if (Array.isArray(parent) && typeof last === "number") {
    if (mutation.kind === "delete") parent.splice(last, 1)
    else parent[last] = mutation.value
  } else if (typeof parent === "object") {
    if (mutation.kind === "delete") delete (parent as Record<string, unknown>)[String(last)]
    else (parent as Record<string, unknown>)[String(last)] = mutation.value
  }

  return clone
}

// --- Fixtures: genuinely signed documents ----------------------------------------------------

const bundleBody = (): PolicyBundleBody =>
  policyBundleBodySchema.parse({
    bundle_id: "bundle-1",
    tenant_id: TENANT,
    version: 7,
    issued_at: at(-60_000),
    expires_at: at(3_600_000),
    policies: [{ policy_id: "p1", cedar: "permit(principal, action, resource);" }],
    agent_profile: { agent_id: "reviewer-1", allowed_tools: ["github.issues.read"], max_delegation_depth: 1 },
    tool_manifest: [{ tool: "github.issues.read", grant: "grant://github/org/repo/issues/read" }],
    network_rules: [{ host: "api.github.com", action: "allow_via_egress_gateway" }],
    data_clearance: "CONFIDENTIAL",
    risk_profile: { risk_level: "medium", requires_effect_permit: ["github.pull-request.merge"] },
    trusted_issuers: [ISSUER_ID],
  })

const signedBundle = () =>
  signPolicyBundle(bundleBody(), { algorithm: "ed25519", issuer_id: ISSUER_ID, value: "" }, keyPair)

const envelopeBody = (): SecurityContextEnvelopeBody => ({
  envelope_id: "env-1",
  tenant_id: TENANT,
  spiffe_id: `spiffe://${TENANT}/reviewer-1`,
  nonce: "nonce-abc",
  version: 3,
  issued_at: at(-60_000),
  expires_at: at(300_000),
  context: {
    data_clearance: "CONFIDENTIAL",
    grants: ["grant://github/org/repo/issues/read"],
    tools: ["github.issues.read"],
    network_hosts: ["api.github.com"],
    max_delegation_depth: 1,
  },
})

const signedEnvelope = () =>
  signSecurityContextEnvelope(
    envelopeBody(),
    { algorithm: "ed25519", issuer_id: ISSUER_ID },
    keyPair,
  )

const signedRevocation = () =>
  signRevocationSnapshot(
    {
      snapshot_id: "snap-1",
      tenant_id: TENANT,
      version: 4,
      issued_at: at(-60_000),
      expires_at: at(300_000),
      entries: [
        {
          agent_id: "reviewer-1",
          reason: "credential_compromised",
          revoked_at: at(-30_000),
        },
      ],
    },
    { algorithm: "ed25519", issuer_id: ISSUER_ID, value: "" },
    keyPair,
  )

// --- Property 1: no mutation of a signed document is accepted --------------------------------

const verifierFor = (document: "bundle" | "envelope" | "revocation") => {
  if (document === "bundle") {
    return (candidate: unknown) =>
      verifyPolicyBundle(candidate, { expectedTenantId: TENANT, trustedIssuerKeys, now: NOW })
  }
  if (document === "envelope") {
    return (candidate: unknown) =>
      verifySecurityContextEnvelope(candidate, {
        expectedTenantId: TENANT,
        trustedIssuerKeys,
        now: NOW,
      })
  }
  return (candidate: unknown) =>
    verifyRevocationSnapshot(candidate, {
      expectedTenantId: TENANT,
      trustedIssuerKeys,
      now: NOW,
    })
}

/**
 * The canonical bytes a verifier would actually sign-check, or `undefined` if the candidate
 * does not even parse. This is deliberately the *schema's* view of the document, not the
 * raw JSON: the verifiers parse first, then hash the parsed result.
 */
const canonicalBytesFor = (document: "bundle" | "envelope" | "revocation") =>
  (candidate: unknown): string | undefined => {
    const schema =
      document === "bundle"
        ? signedPolicyBundleSchema
        : document === "envelope"
          ? securityContextEnvelopeSchema
          : signedRevocationSnapshotSchema

    const parsed = schema.safeParse(candidate)
    if (!parsed.success) return undefined

    return canonicalStringify(toJsonValue(parsed.data))
  }

for (const document of ["bundle", "envelope", "revocation"] as const) {
  test(`S12 fuzz: acceptance of a signed ${document} depends only on its canonical bytes`, () => {
    const authentic =
      document === "bundle" ? signedBundle() : document === "envelope" ? signedEnvelope() : signedRevocation()

    // The control: unmodified, the document verifies. Without this the property would be
    // satisfied by a verifier that refuses everything, including the real thing.
    assert.equal(verifierFor(document)(authentic).accepted, true)

    const authenticBytes = canonicalBytesFor(document)(authentic)
    assert.notEqual(authenticBytes, undefined, `the ${document} fixture must parse`)

    fc.assert(
      fc.property(mutationArb(authentic), (mutation) => {
        const mutated = applyMutation(authentic, mutation)
        const result = verifierFor(document)(mutated)
        const mutatedBytes = canonicalBytesFor(document)(mutated)

        const describe = JSON.stringify(mutation).slice(0, 200)

        if (mutatedBytes === undefined) {
          // Does not parse at all. Refusing is the only correct answer, and it also proves
          // the schema did not accept a partially-understood document.
          assert.equal(result.accepted, false, `an unparseable ${document} was accepted: ${describe}`)
          return
        }

        if (mutatedBytes === authenticBytes) {
          // The mutation was invisible to the verifier — an unknown key that Zod stripped,
          // or a no-op. Nothing the verifier reads has changed, so accepting is correct.
          // Asserting it keeps this from degenerating into "refuse everything".
          assert.equal(result.accepted, true, `an unchanged ${document} was refused: ${describe}`)
          return
        }

        // The security property. These bytes are what the signature covers, and they differ,
        // so the signature cannot verify and the document must be refused.
        assert.notEqual(
          result.accepted,
          true,
          `a byte-changing mutation of a signed ${document} was accepted: ${describe}`,
        )
      }),
      { seed: SEED, numRuns: RUNS, endOnFailure: true },
    )
  })
}

// --- Property 2: garbage is never accepted, and never throws ---------------------------------

for (const document of ["bundle", "envelope", "revocation"] as const) {
  test(`S12 fuzz: arbitrary JSON is refused without throwing for a ${document}`, () => {
    fc.assert(
      fc.property(fc.jsonValue({ maxDepth: 5 }), (junk) => {
        let result
        try {
          result = verifierFor(document)(junk)
        } catch (error) {
          assert.fail(`verifier threw on arbitrary input: ${String(error)}`)
        }

        assert.notEqual(result.accepted, true)
      }),
      { seed: SEED, numRuns: RUNS, endOnFailure: true },
    )
  })
}

test("S12 fuzz: arbitrary strings are refused as workload identities without throwing", () => {
  fc.assert(
    fc.property(fc.string({ maxLength: 200 }), (candidate) => {
      let result
      try {
        result = verifyWorkloadIdentity(candidate, {
          trustedIssuerKeys,
          expectedTenantId: TENANT,
          now: NOW,
        })
      } catch (error) {
        assert.fail(`verifyWorkloadIdentity threw on a string: ${String(error)}`)
      }

      assert.notEqual(result.accepted, true)
    }),
    { seed: SEED, numRuns: RUNS, endOnFailure: true },
  )
})

test("S12 fuzz: an arbitrary object is never accepted as a workload identity", () => {
  fc.assert(
    fc.property(fc.jsonValue({ maxDepth: 5 }), (candidate) => {
      const result = verifyWorkloadIdentity(candidate, {
        trustedIssuerKeys,
        expectedTenantId: TENANT,
        now: NOW,
      })

      assert.notEqual(result.accepted, true)
    }),
    { seed: SEED, numRuns: RUNS, endOnFailure: true },
  )
})

test("S12 fuzz: an envelope re-signed with an untrusted key is refused", () => {
  // Property 1 mutates bytes; this changes the *signer*. A verifier that checked the shape
  // but not who signed would accept it, and byte mutation cannot express that.
  const forged = signSecurityContextEnvelope(
    envelopeBody(),
    { algorithm: "ed25519", issuer_id: ISSUER_ID },
    otherKeys,
  )

  fc.assert(
    fc.property(mutationArb(forged), (mutation) => {
      const result = verifySecurityContextEnvelope(applyMutation(forged, mutation), {
        expectedTenantId: TENANT,
        trustedIssuerKeys,
        now: NOW,
      })

      assert.notEqual(result.accepted, true)
    }),
    { seed: SEED, numRuns: RUNS, endOnFailure: true },
  )
})

// --- Property 3: the scope algebra never widens ------------------------------------------------

test("S6 fuzz: scopeIsNarrowerThan never returns true for unparseable input", () => {
  fc.assert(
    fc.property(
      fc.array(fc.string({ maxLength: 30 }), { maxLength: 6 }),
      fc.array(fc.string({ maxLength: 30 }), { maxLength: 6 }),
      (child, parent) => {
        const result = scopeIsNarrowerThan(child, parent)
        assert.equal(typeof result, "boolean")

        // An empty child set is vacuously inside any parent. That is correct and harmless —
        // it grants nothing — so it is excluded rather than asserted either way.
        if (child.length > 0 && child.some((uri) => !uri.startsWith("grant://"))) {
          assert.equal(result, false, `a non-grant uri was treated as in scope: ${child.join(", ")}`)
        }
      },
    ),
    { seed: SEED, numRuns: RUNS, endOnFailure: true },
  )
})

test("S6 fuzz: a grant is never narrower than an unrelated grant", () => {
  fc.assert(
    fc.property(
      fc.stringMatching(/^[a-z][a-z0-9-]{0,12}$/u),
      fc.stringMatching(/^[a-z][a-z0-9-]{0,12}$/u),
      fc.stringMatching(/^[a-z][a-z0-9-]{0,12}$/u),
      (provider, owner, repo) => {
        const a = `grant://${provider}/${owner}/${repo}/issues/read`
        const b = `grant://${provider}/${owner}/${repo}/pull-request/merge`

        // Equal depth, different resource: neither may contain the other.
        assert.equal(scopeIsNarrowerThan([a], [b]), false)
        assert.equal(scopeIsNarrowerThan([b], [a]), false)
      },
    ),
    { seed: SEED, numRuns: RUNS, endOnFailure: true },
  )
})

test("S6 fuzz: a wider parent always covers a narrower child", () => {
  fc.assert(
    fc.property(
      fc.stringMatching(/^[a-z][a-z0-9-]{0,12}$/u),
      fc.stringMatching(/^[a-z][a-z0-9-]{0,12}$/u),
      fc.stringMatching(/^[a-z][a-z0-9-]{0,12}$/u),
      (provider, owner, repo) => {
        const child = `grant://${provider}/${owner}/${repo}/issues/read`
        const parent = `grant://${provider}/${owner}/${repo}/**`

        assert.equal(scopeIsNarrowerThan([child], [parent]), true, `** must absorb: ${child}`)
      },
    ),
    { seed: SEED, numRuns: RUNS, endOnFailure: true },
  )
})

// --- Canonicalization must be total -------------------------------------------------------------

test("S12 fuzz: canonicalStringify never throws and is stable for any JSON value", () => {
  fc.assert(
    fc.property(fc.jsonValue({ maxDepth: 6 }), (value) => {
      let first: string
      let second: string

      try {
        first = canonicalStringify(toJsonValue(value))
        second = canonicalStringify(toJsonValue(value))
      } catch (error) {
        assert.fail(`canonicalStringify threw: ${String(error)}`)
      }

      assert.equal(first, second)
      // Key order in the input must not change the output.
      assert.equal(first, canonicalStringify(toJsonValue(JSON.parse(JSON.stringify(value)))))
    }),
    { seed: SEED, numRuns: RUNS, endOnFailure: true },
  )
})