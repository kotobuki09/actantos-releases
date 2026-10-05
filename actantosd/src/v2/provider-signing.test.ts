import assert from "node:assert/strict"
import { createHash, createHmac, createPublicKey, generateKeyPairSync, verify } from "node:crypto"
import test from "node:test"

import {
  amzDate,
  base64url,
  sha256Hex,
  sigv4Encode,
  sigv4FormBody,
  sigv4SigningKey,
  signRs256Jwt,
  signSigv4,
} from "./provider-signing.ts"

/**
 * Signature conformance for the production credential providers.
 *
 * The load-bearing test is the known-answer vector. A signer that is merely self-consistent
 * proves nothing: the same bug in the signer and its test would agree forever. So the
 * expected signature here is AWS's published `get-vanilla` value, and the key-derivation
 * intermediates are checked against AWS's published derivation. Those two together pin the
 * implementation to the specification rather than to itself.
 *
 * This caught a real defect while it was being written. `toISOString()` already ends in `Z`
 * and the signer appended a second one, so every request carried `...Z Z`. The signature was
 * well-formed, the timestamp was not, and only the external vector distinguished them.
 */

const ACCESS_KEY = "AKIDEXAMPLE"
const SECRET_KEY = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
const AT = new Date("2015-08-30T12:36:00.000Z")

const VANILLA_SIGNATURE =
  "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"

// --- Known-answer vectors ----------------------------------------------------------------

test("SigV4 reproduces AWS's published get-vanilla signature", () => {
  const signed = signSigv4({
    request: {
      method: "GET",
      canonicalUri: "/",
      canonicalQuery: "",
      headers: new Map([
        ["host", "example.amazonaws.com"],
        ["x-amz-date", "20150830T123600Z"],
      ]),
      payload: "",
      at: AT,
    },
    accessKeyId: ACCESS_KEY,
    secretAccessKey: SECRET_KEY,
    region: "us-east-1",
    service: "service",
  })

  assert.equal(
    signed.get("authorization"),
    `AWS4-HMAC-SHA256 Credential=${ACCESS_KEY}/20150830/us-east-1/service/aws4_request, ` +
      `SignedHeaders=host;x-amz-date, Signature=${VANILLA_SIGNATURE}`,
  )
})

test("SigV4 reproduces AWS's published signing-key derivation", () => {
  // AWS documents each step of the derivation. Checking all four means a bug that happens
  // to produce a plausible final key is still caught, and it localises *where* it went wrong.
  assert.equal(
    sigv4SigningKey({
      secretAccessKey: SECRET_KEY,
      dateStamp: "20150830",
      region: "us-east-1",
      service: "service",
    }).toString("hex"),
    "938127b5336810ddb6a5d6af445fcac9e371f9ed418ed386b022aed82901be75",
  )
})

test("SigV4 derives the documented date, region and service keys", () => {
  const hmac = (key: Buffer | string, data: string): Buffer =>
    createHmac("sha256", key).update(data, "utf8").digest()

  const kDate = hmac(`AWS4${SECRET_KEY}`, "20150830")

  assert.equal(kDate.toString("hex"), "0138c7a6cbd60aa727b2f653a522567439dfb9f3e72b21f9b25941a42f04a7cd")
  assert.equal(
    hmac(kDate, "us-east-1").toString("hex"),
    "f33d5808504bf34812e5fade63308b424b244c59189be2a591dd2282c7cb563f",
  )
  assert.equal(
    hmac(hmac(kDate, "us-east-1"), "service").toString("hex"),
    "f7fd819348e53789a8474fb1aebea778f5af85c40612e0f064eecd5642c81bc1",
  )
})

test("the empty-payload hash is the documented SHA-256 of the empty string", () => {
  assert.equal(
    sha256Hex(""),
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  )
})

// --- The timestamp defect this file exists for ---------------------------------------------

test("amzDate emits exactly one Z", () => {
  // The regression: toISOString() ends in Z, so appending another produced "20150830T123600ZZ".
  assert.equal(amzDate(AT).full, "20150830T123600Z")
  assert.equal(amzDate(AT).short, "20150830")
  assert.equal(/Z{2,}/u.test(amzDate(AT).full), false)
})

test("amzDate is what makes the vector pass, so the vector guards it", () => {
  // If amzDate regressed, the get-vanilla signature above would change too. This test
  // documents that the two are coupled rather than independent.
  const signed = signSigv4({
    request: {
      method: "GET",
      canonicalUri: "/",
      canonicalQuery: "",
      headers: new Map([
        ["host", "example.amazonaws.com"],
        ["x-amz-date", amzDate(AT).full],
      ]),
      payload: "",
      at: AT,
    },
    accessKeyId: ACCESS_KEY,
    secretAccessKey: SECRET_KEY,
    region: "us-east-1",
    service: "service",
  })

  assert.match(signed.get("authorization") ?? "", new RegExp(VANILLA_SIGNATURE, "u"))
})

// --- Encoding rules -----------------------------------------------------------------------

test("sigv4Encode leaves only the RFC 3986 unreserved characters literal", () => {
  // encodeURIComponent is wrong here: it percent-encodes !'()* which SigV4 requires literal.
  assert.equal(sigv4Encode("a-b._~"), "a-b._~")
  assert.equal(sigv4Encode("!'()*"), "%21%27%28%29%2A")
  assert.equal(sigv4Encode("a b"), "a%20b")
  assert.equal(sigv4Encode("a/b"), "a%2Fb")
  assert.equal(sigv4Encode("é"), "%C3%A9")
  // The characters that make encodeURIComponent unusable here are the unreserved ones it
  // still escapes. Space is not one of them: both produce %20.
  assert.notEqual(sigv4Encode("!'()*"), encodeURIComponent("!'()*"))
})

test("sigv4FormBody sorts parameters so the body and the signature cannot disagree", () => {
  const body = sigv4FormBody({ RoleSessionName: "actant-t/a", Action: "AssumeRole", Version: "2011-06-15" })

  assert.equal(body, "Action=AssumeRole&RoleSessionName=actant-t%2Fa&Version=2011-06-15")
  // Sorted, so a caller cannot produce two bodies from one object.
  assert.equal(body, sigv4FormBody({ Version: "2011-06-15", RoleSessionName: "actant-t/a", Action: "AssumeRole" }))
})

test("base64url is URL-safe and unpadded", () => {
  const encoded = base64url(Buffer.from([251, 255, 190, 255]))

  assert.equal(encoded, "-_--_w")
  assert.equal(/[+/=]/u.test(encoded), false)
})

// --- A body-bearing request is verified by an independent recomputation --------------------

test("a signed POST with a body is accepted by an independently written recomputation", () => {
  // The external vector above covers GET with no body. This covers the shape STS actually
  // uses. Independence comes from deriving it here step by step from the specification
  // rather than calling into the module under test.
  const payload = sigv4FormBody({
    Action: "AssumeRole",
    Version: "2011-06-15",
    RoleArn: "arn:aws:iam::123456789012:role/demo",
    RoleSessionName: "actant-t_demo-reviewer-1",
    DurationSeconds: "900",
  })

  const headers = new Map([
    ["host", "sts.us-east-1.amazonaws.com"],
    ["x-amz-date", "20261004T120000Z"],
    ["content-type", "application/x-www-form-urlencoded; charset=utf-8"],
  ])

  const signed = signSigv4({
    request: { method: "POST", canonicalUri: "/", canonicalQuery: "", headers, payload, at: new Date("2026-10-04T12:00:00.000Z") },
    accessKeyId: "ASIAEXAMPLE",
    secretAccessKey: SECRET_KEY,
    region: "us-east-1",
    service: "sts",
  })

  // --- independent recomputation, written from the SigV4 specification ---
  const sha = (s: string): string => createHash("sha256").update(s, "utf8").digest("hex")
  const mac = (k: Buffer | string, d: string): Buffer => createHmac("sha256", k).update(d, "utf8").digest()

  const canonicalRequest = [
    "POST",
    "/",
    "",
    ...[...headers.entries()]
      .map(([k, v]) => [k.toLowerCase(), v] as const)
      .sort(([a], [b]) => (a < b ? -1 : 1))
      .flatMap(([k, v]) => [`${k}:${v}`]),
    "",
    "content-type;host;x-amz-date",
    sha(payload),
  ].join("\n")

  const scope = "20261004/us-east-1/sts/aws4_request"
  const stringToSign = ["AWS4-HMAC-SHA256", "20261004T120000Z", scope, sha(canonicalRequest)].join("\n")
  const signingKey = mac(mac(mac(mac(`AWS4${SECRET_KEY}`, "20261004"), "us-east-1"), "sts"), "aws4_request")
  const expected = createHmac("sha256", signingKey).update(stringToSign, "utf8").digest("hex")

  assert.equal(
    signed.get("authorization"),
    `AWS4-HMAC-SHA256 Credential=ASIAEXAMPLE/${scope}, ` +
      `SignedHeaders=content-type;host;x-amz-date, Signature=${expected}`,
  )
})

test("changing the body after signing invalidates the signature", () => {
  // The property that makes SigV4 a defence rather than a decoration: the payload hash is
  // inside the signed canonical request, so a tampered body cannot keep the signature.
  const sign = (payload: string): string =>
    signSigv4({
      request: {
        method: "POST",
        canonicalUri: "/",
        canonicalQuery: "",
        headers: new Map([
          ["host", "sts.us-east-1.amazonaws.com"],
          ["x-amz-date", "20261004T120000Z"],
        ]),
        payload,
        at: new Date("2026-10-04T12:00:00.000Z"),
      },
      accessKeyId: "ASIAEXAMPLE",
      secretAccessKey: SECRET_KEY,
      region: "us-east-1",
      service: "sts",
    }).get("authorization") ?? ""

  const original = sigv4FormBody({ Action: "AssumeRole", RoleArn: "arn:aws:iam::1:role/a" })
  const tampered = sigv4FormBody({ Action: "AssumeRole", RoleArn: "arn:aws:iam::1:role/admin" })

  assert.notEqual(sign(original), sign(tampered))
})

// --- RS256 ---------------------------------------------------------------------------------

test("signRs256Jwt produces a token GitHub can verify with the matching public key", () => {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 })
  const privatePem = privateKey.export({ type: "pkcs8", format: "pem" }) as string
  const publicPem = publicKey.export({ type: "spki", format: "pem" }) as string

  const token = signRs256Jwt({ iat: 1, exp: 541, iss: "12345" }, privatePem)
  const [header, payload, signature] = token.split(".")

  assert.equal(token.split(".").length, 3)
  assert.deepEqual(JSON.parse(Buffer.from(header ?? "", "base64url").toString("utf8")), {
    alg: "RS256",
    typ: "JWT",
  })
  assert.deepEqual(JSON.parse(Buffer.from(payload ?? "", "base64url").toString("utf8")), {
    iat: 1,
    exp: 541,
    iss: "12345",
  })

  const valid = verify(
    "sha256",
    Buffer.from(`${header}.${payload}`, "utf8"),
    createPublicKey(publicPem),
    Buffer.from(signature ?? "", "base64url"),
  )
  assert.equal(valid, true)
})

test("signRs256Jwt refuses a key that is not RSA rather than signing with it", () => {
  const { privateKey } = generateKeyPairSync("ed25519")
  const pem = privateKey.export({ type: "pkcs8", format: "pem" }) as string

  // GitHub App keys are RSA. Signing with an Ed25519 key must fail loudly at mint time,
  // not produce a token the provider will treat as valid.
  assert.throws(() => signRs256Jwt({ iss: "1" }, pem))
})