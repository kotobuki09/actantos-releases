#!/usr/bin/env node
// Mutation harness for Phase K (security context envelope).
//
// The same standard as phase J: break one enforcement point, re-run, and report. The
// widening mutations matter most, because they test the check that exists specifically
// because a valid signature is not sufficient.

import { execFileSync } from "node:child_process"
import { readFileSync, writeFileSync } from "node:fs"
import { dirname, join } from "node:path"
import { fileURLToPath } from "node:url"

const V2 = join(dirname(fileURLToPath(import.meta.url)), "..", "src", "v2")
const SUITES = [join(V2, "security-context-envelope.test.ts")]

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
    return { failed: !/# fail 0/u.test(output), output }
  } catch (error) {
    return { failed: true, output: String(error.stdout ?? "") }
  }
}

const mutate = (file, find, replacement) => {
  const source = read(file)
  if (!source.includes(find)) {
    throw new Error(`anchor not found:\n${find.slice(0, 140)}`)
  }
  write(file, source.replace(find, replacement))
}

const SRC = join(V2, "security-context-envelope.ts")

const MUTATIONS = [
  { id: "M41", what: "the grant narrowing check, removed", apply: () =>
      mutate(SRC, '  if (!scopeIsNarrowerThan(context.grants, ceiling.grants)) {\n    return { accepted: false, reason: "grant_widened" }\n  }\n\n', "") },
  { id: "M42", what: "the tool narrowing check, removed", apply: () =>
      mutate(SRC, '  if (!context.tools.every((tool) => ceiling.tools.includes(tool))) {\n    return { accepted: false, reason: "tool_widened" }\n  }\n\n', "") },
  { id: "M43", what: "the host narrowing check, removed", apply: () =>
      mutate(SRC, '  if (!context.network_hosts.every((host) => ceiling.networkHosts.includes(host))) {\n    return { accepted: false, reason: "host_widened" }\n  }\n\n', "") },
  { id: "M44", what: "the clearance comparison, inverted", apply: () =>
      mutate(SRC, "clearanceRank(context.data_clearance) > clearanceRank(ceiling.dataClearance)", "clearanceRank(context.data_clearance) < clearanceRank(ceiling.dataClearance)") },
  { id: "M45", what: "the delegation depth check, removed", apply: () =>
      mutate(SRC, '  if (context.max_delegation_depth > ceiling.maxDelegationDepth) {\n    return { accepted: false, reason: "depth_widened" }\n  }\n\n', "") },
  { id: "M46", what: "the nonce binding, removed", apply: () =>
      mutate(SRC, "  if (\n    options.expectedNonce !== undefined &&\n    body.nonce !== options.expectedNonce\n  ) {\n    return { accepted: false, reason: \"nonce_mismatch\" }\n  }\n\n", "") },
  { id: "M47", what: "the subject binding, removed", apply: () =>
      mutate(SRC, "  if (\n    options.expectedSpiffeId !== undefined &&\n    body.spiffe_id !== options.expectedSpiffeId\n  ) {\n    return { accepted: false, reason: \"identity_mismatch\" }\n  }\n\n", "") },
  { id: "M48", what: "the signature verification, removed", apply: () =>
      mutate(SRC, "  if (\n    !algorithm.verify(\n      canonicalEnvelopeBytes(body),\n      Buffer.from(signature.value, \"base64\"),\n      issuerKey,\n    )\n  ) {\n    return { accepted: false, reason: \"invalid_signature\" }\n  }\n\n", "") },
  { id: "M49", what: "the tenant binding, removed", apply: () =>
      mutate(SRC, '  if (body.tenant_id !== options.expectedTenantId) {\n    return { accepted: false, reason: "tenant_mismatch" }\n  }\n\n', "") },
  { id: "M50", what: "expiry enforcement, removed", apply: () =>
      mutate(SRC, "  if (now.getTime() >= expiresAt) {\n    return { accepted: false, reason: \"expired\" }\n  }\n\n", "") },
  { id: "M51", what: "the rollback check, removed", apply: () =>
      mutate(SRC, "  if (options.minimumVersion !== undefined && body.version <= options.minimumVersion) {\n    return { accepted: false, reason: \"version_rollback\" }\n  }\n\n", "") },
  { id: "M52", what: "the per-agent tools guard, so any bundle serves any agent", apply: () =>
      mutate(SRC, "      profile.agent_id === agentId\n        ? profile.allowed_tools\n        : // A bundle for one agent grants nothing to another. Reading another agent's\n          // allowed_tools here would hand out authority the bundle never gave this agent.\n          [],", "      profile.allowed_tools,") },
  { id: "M53", what: "the envelope version tracker, accepting equal versions", apply: () =>
      mutate(SRC, "    if (current !== undefined && version <= current) {", "    if (current !== undefined && version < current) {") },
  { id: "M54", what: "canonical bytes, made order-dependent", apply: () =>
      mutate(SRC, '  Buffer.from(canonicalStringify(toJsonValue(body)), "utf8")', '  Buffer.from(JSON.stringify(body), "utf8")') },
]

let survivors = 0

for (const mutation of MUTATIONS) {
  let outcome
  try {
    mutation.apply()
    outcome = run()
  } catch (error) {
    outcome = { failed: false }
    process.stdout.write(`${mutation.id}: ANCHOR MISSING — ${error.message.split("\n")[1] ?? error.message}\n`)
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