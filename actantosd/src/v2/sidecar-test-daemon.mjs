#!/usr/bin/env node
// A sidecar in its own process, for the transport tests.
//
// This exists so `sidecar-server.test.ts` can prove that the boundary survives process
// separation. An in-process call proves nothing about bypass, because code in the same process
// simply does not have to ask.
//
// Everything it needs arrives as arguments. There is no configuration file and no environment
// variable, because a daemon that reads ambient configuration is a daemon whose behaviour can be
// changed by whoever set the environment — which, in the threat model this repository works
// from, is the party being constrained.

import { PolicyLease } from "./policy-lease.ts"
import { ed25519 } from "./signature.ts"
import { ActantSidecar } from "./sidecar.ts"
import { startSidecarServer } from "./sidecar-server.ts"
import { signPolicyBundle } from "./signed-policy-bundle.ts"

const [socketPath, tenantId, agentId, nowIso, publicKeyPem, privateKeyPem, bundleJson] =
  process.argv.slice(2)

if (socketPath === undefined || tenantId === undefined || agentId === undefined) {
  process.stderr.write(
    "usage: sidecar-test-daemon.mjs <socket> <tenant> <agent> <now> <pubkey> <privkey> <bundle>\n",
  )
  process.exit(2)
}

const now = new Date(nowIso ?? new Date().toISOString())
const trustedIssuerKeys = new Map([["issuer-transport", (publicKeyPem ?? "").replace(/\\n/gu, "\n")]])

// The signing key arrives as an argument rather than being generated here, because the daemon has
// to trust exactly the issuer the client signs for. A daemon that minted its own key would trust
// nobody the client could be, and the test would be measuring nothing. This is a fixture key
// generated in the test process and thrown away with it.
const keyPair = { privateKeyPem: (privateKeyPem ?? "").replace(/\\n/gu, "\n") }

const lease = new PolicyLease({ tenantId, trustedIssuerKeys })
lease.offer(
  signPolicyBundle(
    JSON.parse(bundleJson ?? "{}"),
    { algorithm: "ed25519", issuer_id: "issuer-transport", value: "" },
    keyPair,
  ),
  now,
)

const sidecar = new ActantSidecar({
  tenantId,
  trustedIssuerKeys,
  lease,
  authorityFor: () => ["grant://github/org/repo/issues/read"],
  now: () => now,
})

const server = await startSidecarServer({ socketPath, sidecar })

process.stdout.write("ready\n")

const shutdown = async () => {
  await server.close()
  process.exit(0)
}

process.on("SIGINT", () => void shutdown())
process.on("SIGTERM", () => void shutdown())
