#!/usr/bin/env node
// Mutation harness for Phase J.
//
// A test that passes proves nothing about which behaviour it pins. Each mutation below
// breaks one enforcement point in the product code and re-runs the suite; a mutation that
// still passes is a hole in the tests, and the name is reported so it can be fixed or
// recorded as behaviourally equivalent.
//
// Product files only. Mutating a test proves nothing, which was the mistake M23b corrected.

import { execFileSync } from "node:child_process"
import { readFileSync, writeFileSync } from "node:fs"
import { dirname, join } from "node:path"
import { fileURLToPath } from "node:url"

const V2 = join(dirname(fileURLToPath(import.meta.url)), "..", "src", "v2")
const SUITES = [
  join(V2, "providers-production.test.ts"),
  join(V2, "provider-signing.test.ts"),
  join(V2, "capability-broker.test.ts"),
]

const original = new Map()
const read = (file) => {
  if (!original.has(file)) original.set(file, readFileSync(file, "utf8"))
  return original.get(file)
}
const write = (file, source) => writeFileSync(file, source, "utf8")

const run = () => {
  try {
    const output = execFileSync(
      process.execPath,
      ["--experimental-strip-types", "--test", ...SUITES],
      { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
    )
    return { failed: /# fail 0|# fail \d+/u.test(output) && !/# fail 0/u.test(output), output }
  } catch (error) {
    return { failed: true, output: String(error.stdout ?? "") + String(error.stderr ?? "") }
  }
}

/** Apply `find` -> `replacement`. Refuses to run if the anchor is absent. */
const mutate = (file, find, replacement) => {
  const source = read(file)
  if (!source.includes(find)) {
    throw new Error(`mutation anchor not found in ${file}:\n${find.slice(0, 160)}`)
  }
  write(file, source.replace(find, replacement))
}

const MUTATIONS = [
  {
    id: "M25",
    what: "the Vault lease handle, restored to a single mutable slot (Defect A)",
    apply: () =>
      mutate(
        join(V2, "providers.ts"),
        "const leaseId =\n        credential.handle === undefined\n          ? undefined\n          : leaseIdByHandle.get(credential.handle)",
        "const leaseId = leaseIdByHandle.get(\"single-slot\")",
      ),
  },
  {
    id: "M26",
    what: "the Vault handle unique per lease, made constant",
    apply: () =>
      mutate(
        join(V2, "providers.ts"),
        'const handle = `${sessionNameForAgent(context)}#${secret.leaseId}`',
        'const handle = "constant"',
      ),
  },
  {
    id: "M27",
    what: "the AWS session name, restored to a constant",
    apply: () =>
      mutate(
        join(V2, "providers.ts"),
        "sessionName: sessionNameForAgent(context),",
        'sessionName: "actant-broker",',
      ),
  },
  {
    id: "M28",
    what: "the session-name charset, dropping underscore so t_demo collapses onto t-demo",
    apply: () =>
      mutate(
        join(V2, "providers.ts"),
        "/[^A-Za-z0-9_+=,.@-]/gu",
        "/[^A-Za-z0-9+=,.@-]/gu",
      ),
  },
  {
    id: "M29",
    what: "the credential-echo check, disabled",
    apply: () =>
      mutate(
        join(V2, "capability-broker.ts"),
        "        assertCredentialNotEchoed(result, markers)",
        "        void markers",
      ),
  },
  {
    id: "M30",
    what: "the echo check, applied only to top-level string values",
    apply: () =>
      mutate(
        join(V2, "capability-broker.ts"),
        "      assertCredentialNotEchoed(key, markers, `${path}.${key}` as string)\n",
        "",
      ),
  },
  {
    id: "M31",
    what: "the JSON component markers, so only the whole blob is matched",
    apply: () =>
      mutate(
        join(V2, "capability-broker.ts"),
        "      for (const nested of Object.values(parsed as Record<string, unknown>)) {\n        add(nested)\n      }",
        "      void parsed",
      ),
  },
  {
    id: "M32",
    what: "the marker length floor, removed so short fragments refuse everything",
    apply: () =>
      mutate(
        join(V2, "capability-broker.ts"),
        "candidate.trim().length >= MARKER_FLOOR",
        "true",
      ),
  },
  {
    id: "M33",
    what: "the expired-credential check, removed",
    apply: () =>
      mutate(
        join(V2, "capability-broker.ts"),
        "        now.getTime() >= credential.expiresAt.getTime()",
        "        false",
      ),
  },
  {
    id: "M34",
    what: "the unusable-expiry check, so an Invalid Date passes as unlimited",
    apply: () =>
      mutate(
        join(V2, "capability-broker.ts"),
        "        !Number.isFinite(credential.expiresAt.getTime()) ||\n",
        "",
      ),
  },
  {
    id: "M35",
    what: "the SigV4 timestamp, back to emitting a doubled Z",
    apply: () =>
      mutate(
        join(V2, "provider-signing.ts"),
        "const stamp = at.toISOString().replace(/[:-]|\\.\\d{3}/gu, \"\")",
        "const stamp = `${at.toISOString().replace(/[:-]|\\.\\d{3}/gu, \"\")}Z`",
      ),
  },
  {
    id: "M36",
    what: "the SigV4 form body, no longer sorted",
    apply: () =>
      mutate(
        join(V2, "provider-signing.ts"),
        "  Object.keys(parameters)\n    .sort()\n    .map",
        "  Object.keys(parameters)\n    .map",
      ),
  },
  {
    id: "M37",
    what: "the STS response field extraction, tolerating a missing field",
    apply: () =>
      mutate(
        join(V2, "production-providers.ts"),
        "  if (value === undefined || value === \"\") {\n    throw new Error(`STS response carried no ${name}`)\n  }",
        "  if (value === undefined) {\n    return \"\"\n  }",
      ),
  },
  {
    id: "M38",
    what: "the GitHub App JWT lifetime, raised past GitHub's 10-minute ceiling",
    apply: () =>
      mutate(
        join(V2, "production-providers.ts"),
        "const expiresAtSeconds = issuedAt + 540",
        "const expiresAtSeconds = issuedAt + 60_000",
      ),
  },
  {
    id: "M39",
    what: "the Vault granted-lease-duration, replaced with the requested one",
    apply: () =>
      mutate(
        join(V2, "production-providers.ts"),
        'typeof body["lease_duration"] === "number" ? body["lease_duration"] : ttlSeconds',
        "ttlSeconds",
      ),
  },
  {
    id: "M40",
    what: "the error-body suppression, so a vendor error echoes the credential",
    apply: () =>
      mutate(
        join(V2, "production-providers.ts"),
        "throw new Error(`${what} failed with HTTP ${response.status}`)",
        "throw new Error(`${what} failed with HTTP ${response.status}: ${text}`)",
      ),
  },
]

let survivors = 0

for (const mutation of MUTATIONS) {
  let outcome
  try {
    mutation.apply()
    outcome = run()
  } catch (error) {
    outcome = { failed: false, output: `ANCHOR MISSING: ${error.message}` }
    process.stdout.write(`${mutation.id}: ANCHOR MISSING — ${error.message.split("\n")[0]}\n`)
    for (const [file, source] of original) write(file, source)
    continue
  }

  for (const [file, source] of original) write(file, source)

  if (outcome.failed) {
    process.stdout.write(`${mutation.id}: caught   — ${mutation.what}\n`)
  } else {
    survivors += 1
    process.stdout.write(`${mutation.id}: SURVIVED — ${mutation.what}\n`)
  }
}

process.stdout.write(`\n${MUTATIONS.length} mutations, ${survivors} survived\n`)