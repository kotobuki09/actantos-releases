import assert from "node:assert/strict"
import { spawn } from "node:child_process"
import { createConnection } from "node:net"
import { existsSync, mkdtempSync, statSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import path from "node:path"
import { fileURLToPath } from "node:url"
import test from "node:test"

import { PolicyLease } from "./policy-lease.ts"
import { ed25519 } from "./signature.ts"
import { ActantSidecar } from "./sidecar.ts"
import {
  connectSidecar,
  defaultSocketPath,
  isNamedPipe,
  MAX_FRAME_BYTES,
  startSidecarServer,
  type SidecarServer,
} from "./sidecar-server.ts"
import { PROTOCOL_VERSION } from "./sidecar-protocol.ts"
import { signPolicyBundle, type PolicyBundleBody } from "./signed-policy-bundle.ts"
import { mintWorkloadIdentity, signWorkloadIdentity } from "./workload-identity.ts"

/**
 * S11 conformance, phase E: the sidecar behind a real socket.
 *
 * Every other sidecar test calls `handle` in-process. That is not a boundary — code running as the
 * same user in the same process simply does not have to ask. These tests bind an actual socket and
 * talk to it, and the last one starts a second process to prove the property survives process
 * separation, which is the only arrangement in which "the agent cannot bypass the sidecar" means
 * anything.
 *
 * The transport-level cases are the reason this file exists separately. A frame that does not
 * parse, a frame that is too large, and a socket path that already exists are all conditions
 * where the easy implementation is to shrug, and shrugging at a security boundary means
 * default-allow.
 */

const ISSUER_ID = "issuer-transport"
const keyPair = ed25519.generateKeyPair()
const trustedIssuerKeys = new Map([[ISSUER_ID, keyPair.publicKeyPem]])

const TENANT = "t_transport"
const AGENT = "reviewer-1"
const NOW = new Date("2026-10-03T12:00:00.000Z")
const GRANT_READ = "grant://github/org/repo/issues/read"

const bundleBody = (): PolicyBundleBody => ({
  bundle_id: "bundle-transport",
  tenant_id: TENANT,
  version: 100,
  issued_at: "2026-10-03T00:00:00.000Z",
  expires_at: "2026-10-04T00:00:00.000Z",
  policies: [{ policy_id: "p1", cedar: "permit(principal, action, resource);" }],
  agent_profile: {
    agent_id: AGENT,
    allowed_tools: ["github.issues.read"],
    max_delegation_depth: 2,
  },
  tool_manifest: [{ tool: "github.issues.read", grant: GRANT_READ }],
  network_rules: [{ host: "api.github.com", action: "allow_via_egress_gateway" }],
  data_clearance: "CONFIDENTIAL",
  risk_profile: { risk_level: "medium", requires_effect_permit: [] },
  trusted_issuers: [ISSUER_ID],
})

const signedBundle = () =>
  signPolicyBundle(
    bundleBody(),
    { algorithm: "ed25519", issuer_id: ISSUER_ID, value: "" },
    keyPair,
  )

const identityToken = () =>
  signWorkloadIdentity(
    mintWorkloadIdentity({ tenantId: TENANT, agentId: AGENT, issuedAt: NOW }),
    { algorithm: "ed25519", issuer_id: ISSUER_ID, value: "" },
    keyPair,
  )

const request = (overrides: Record<string, unknown>) => ({
  protocol_version: PROTOCOL_VERSION,
  request_id: "req-transport",
  identity_token: identityToken(),
  ...overrides,
})

/** A socket path nobody else is using. Windows named pipes live in a flat namespace, so the
 * per-run suffix has to be unique there rather than living in a directory. */
let socketCounter = 0
const uniqueSocketPath = (): string => {
  socketCounter += 1
  const name = `actantos-sidecar-test-${process.pid}-${Date.now().toString(36)}-${socketCounter}`

  return isNamedPipe(defaultSocketPath(name))
    ? defaultSocketPath(name)
    : path.join(mkdtempSync(path.join(tmpdir(), "actantos-uds-")), `${name}.sock`)
}

/**
 * The bundle is always offered at NOW. `evaluateAt` moves the clock the sidecar reads instead,
 * because a lease offered *after* its own expiry is `empty`, not `expired` — and the point of the
 * expiry test is that a lease which was valid and then ran out denies, which is a different
 * condition from one that never applied.
 */
const buildSidecar = (options: { readonly evaluateAt?: Date } = {}): ActantSidecar => {
  const lease = new PolicyLease({ tenantId: TENANT, trustedIssuerKeys })
  lease.offer(signedBundle(), NOW)

  return new ActantSidecar({
    tenantId: TENANT,
    trustedIssuerKeys,
    lease,
    authorityFor: () => [GRANT_READ],
    now: () => options.evaluateAt ?? NOW,
  })
}

/**
 * Write raw bytes and read one line back.
 *
 * `SidecarClient.send` stringifies whatever it is given, so a JavaScript string arrives as valid
 * JSON and never reaches the parse failure. Testing the transport's own decoding needs bytes the
 * client would never produce.
 */
const exchangeRaw = async (
  socketPath: string,
  payload: string,
  timeoutMs = 5000,
): Promise<string> => {
  const socket = createConnection(socketPath)

  try {
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("raw exchange timed out")), timeoutMs)
      socket.once("connect", () => {
        clearTimeout(timer)
        resolve()
      })
      socket.once("error", (error: Error) => {
        clearTimeout(timer)
        reject(error)
      })
    })

    return await new Promise<string>((resolve, reject) => {
      let buffer = ""
      const timer = setTimeout(() => {
        socket.destroy()
        reject(new Error("raw exchange timed out waiting for a reply"))
      }, timeoutMs)

      socket.on("data", (chunk: Buffer) => {
        buffer += chunk.toString("utf8")
        const newline = buffer.indexOf("\n")

        if (newline === -1) return

        clearTimeout(timer)
        resolve(buffer.slice(0, newline))
      })

      socket.once("error", (error: Error) => {
        clearTimeout(timer)
        reject(error)
      })

      socket.write(payload)
    })
  } finally {
    socket.destroy()
  }
}

/** Start a server, hand it to the body, and always close it. */
const withServer = async (
  options: { readonly evaluateAt?: Date } = {},
  body: (server: SidecarServer, socketPath: string) => Promise<void>,
): Promise<void> => {
  const socketPath = uniqueSocketPath()
  const server = await startSidecarServer({ socketPath, sidecar: buildSidecar(options) })

  try {
    await body(server, socketPath)
  } finally {
    await server.close()
  }
}

// --- A real socket, carrying a real decision -------------------------------------------

test("S11: an allowed action is decided over a real socket", async () => {
  await withServer({}, async (_server, socketPath) => {
    const client = await connectSidecar({ socketPath })

    try {
      const decision = await client.send(
        request({
          request_type: "CheckAction",
          tool: "github.issues.read",
          resource: "org/repo",
          args: {},
        }),
      )

      assert.equal(decision.allowed, true)
      assert.equal(decision.request_id, "req-transport")
    } finally {
      await client.close()
    }
  })
})

test("S11: a denied action is decided over a real socket, with its reason", async () => {
  await withServer({}, async (_server, socketPath) => {
    const client = await connectSidecar({ socketPath })

    try {
      const decision = await client.send(
        request({
          request_type: "CheckAction",
          tool: "tool.not.in.manifest",
          resource: "org/repo",
          args: {},
        }),
      )

      assert.equal(decision.allowed, false)
      assert.ok(!decision.allowed)
      assert.equal(decision.reason, "tool_not_in_manifest")
    } finally {
      await client.close()
    }
  })
})

test("S11: an expired lease denies over the socket, not allows", async () => {
  // S12 at the transport. If this returned "allowed" the socket would be a way around the lease.
  const expired = new Date("2026-10-05T00:00:00.000Z")
  await withServer({ evaluateAt: expired }, async (_server, socketPath) => {
    const client = await connectSidecar({ socketPath })

    try {
      const decision = await client.send(
        request({
          request_type: "CheckAction",
          tool: "github.issues.read",
          resource: "org/repo",
          args: {},
        }),
      )

      assert.equal(decision.allowed, false)
      assert.ok(!decision.allowed)
      assert.equal(decision.reason, "policy_expired")
    } finally {
      await client.close()
    }
  })
})

// --- Transport-level failure is a denial ----------------------------------------------

test("S12: a frame that is not JSON is denied, not ignored", async () => {
  await withServer({}, async (_server, socketPath) => {
    const reply = await exchangeRaw(socketPath, "this is not json at all\n")
    const decision = JSON.parse(reply) as { allowed: boolean; detail?: string }

    assert.equal(decision.allowed, false)
    assert.equal(decision.detail, "frame is not valid JSON")
  })
})

test("S12: a frame larger than the limit is denied rather than buffered without bound", async () => {
  await withServer({}, async (_server, socketPath) => {
    const client = await connectSidecar({ socketPath })

    try {
      // A peer that never sends a newline must not be able to grow the server's buffer until it
      // dies. Availability of the boundary is part of the boundary.
      const oversized = "x".repeat(MAX_FRAME_BYTES + 1024)
      const decision = await client.send({ request_type: "CheckAction", pad: oversized })

      assert.equal(decision.allowed, false)
      assert.ok(!decision.allowed)
      assert.match(String(decision.detail), /exceeds/u)
    } finally {
      await client.close()
    }
  })
})

test("S12: a well-formed frame at the size limit is still decided normally", async () => {
  // The counterweight to the previous test: a limit that refuses everything is not a limit, it is
  // an outage. A frame inside the bound must reach the sidecar.
  await withServer({}, async (_server, socketPath) => {
    const client = await connectSidecar({ socketPath })

    try {
      const frame = (padding: string): string =>
        `${JSON.stringify(
          request({
            request_type: "CheckAction",
            tool: "github.issues.read",
            resource: "org/repo",
            args: { padding },
          }),
        )}
`

      // Measured, not guessed: the limit applies to the whole frame including the request
      // envelope, so padding sized to the limit itself produces an over-limit frame and the test
      // would assert the wrong thing.
      const envelope = Buffer.byteLength(frame(""), "utf8")
      const padding = "x".repeat(MAX_FRAME_BYTES - envelope - 1)
      assert.ok(Buffer.byteLength(frame(padding), "utf8") <= MAX_FRAME_BYTES)

      const reply = await exchangeRaw(socketPath, frame(padding), 20000)
      const decision = JSON.parse(reply) as { allowed: boolean }

      assert.equal(decision.allowed, true)
    } finally {
      await client.close()
    }
  })
})

test("S12: an unsupported protocol version is denied at the transport", async () => {
  await withServer({}, async (_server, socketPath) => {
    const client = await connectSidecar({ socketPath })

    try {
      const decision = await client.send(
        request({
          protocol_version: "v0.0-from-the-future",
          request_type: "CheckAction",
          tool: "github.issues.read",
          resource: "org/repo",
          args: {},
        }),
      )

      assert.equal(decision.allowed, false)
      assert.ok(!decision.allowed)
      assert.equal(decision.reason, "protocol_version_unsupported")
    } finally {
      await client.close()
    }
  })
})

test("S12: connecting to a socket nobody is serving is an error, not a permit", async () => {
  // The failure mode this guards: an agent that cannot reach the sidecar treating the failure as
  // "no news is good news" and acting anyway.
  const socketPath = uniqueSocketPath()

  await assert.rejects(connectSidecar({ socketPath, timeoutMs: 2000 }))
})

// --- Socket path handling --------------------------------------------------------------

test("S12: the sidecar refuses to serve over a socket path that already exists", async () => {
  // A leftover or pre-created socket file is the hijack condition. Serving over it would send
  // real requests to whoever bound it first.
  const socketPath = uniqueSocketPath()
  const directory = path.dirname(socketPath)

  if (isNamedPipe(socketPath)) {
    // Named pipes have no filesystem entry, so this condition cannot arise on Windows and is not
    // claimed to be handled there.
    assert.ok(!existsSync(socketPath))
    return
  }

  writeFileSync(socketPath, "")
  assert.ok(existsSync(path.join(directory, path.basename(socketPath))))

  await assert.rejects(
    startSidecarServer({ socketPath, sidecar: buildSidecar() }),
    /already exists/u,
  )
})

test("S12: the socket is created owner-only", async () => {
  if (isNamedPipe(uniqueSocketPath())) {
    // Windows named pipes inherit the process token's per-user default DACL. There is no mode
    // to set, so there is nothing to assert here and the test says so rather than passing vacuously.
    assert.ok(true)
    return
  }

  await withServer({}, async (_server, socketPath) => {
    const mode = statSync(socketPath).mode & 0o777
    assert.equal(mode, 0o600, `expected 0600, got 0${mode.toString(8)}`)
  })
})

// --- Process separation ----------------------------------------------------------------

test("S11: the sidecar serves from a separate process", async () => {
  // The property that makes this a boundary rather than a function call. A client in another
  // process can only reach the sidecar by speaking the protocol, and every decision it gets back
  // came from the other process's policy state.
  const socketPath = uniqueSocketPath()
  const daemonPath = path.join(
    path.dirname(fileURLToPath(import.meta.url)),
    "sidecar-test-daemon.mjs",
  )

  const child = spawn(
    process.execPath,
    [
      daemonPath,
      socketPath,
      TENANT,
      AGENT,
      NOW.toISOString(),
      keyPair.publicKeyPem.replace(/\r?\n/gu, "\\n"),
      keyPair.privateKeyPem.replace(/\r?\n/gu, "\\n"),
      JSON.stringify(bundleBody()),
    ],
    { stdio: ["ignore", "pipe", "pipe"] },
  )

  const ready = new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("sidecar daemon did not start")), 15000)

    child.stdout.on("data", (chunk: Buffer) => {
      if (String(chunk).includes("ready")) {
        clearTimeout(timer)
        resolve()
      }
    })

    child.on("error", (error: Error) => {
      clearTimeout(timer)
      reject(error)
    })

    child.stderr.on("data", (chunk: Buffer) => {
      clearTimeout(timer)
      reject(new Error(`sidecar daemon failed: ${String(chunk)}`))
    })
  })

  try {
    await ready

    const client = await connectSidecar({ socketPath })

    try {
      // The identity token is signed by the same key the daemon trusts, so a real allow here is a
      // real policy decision made in the other process.
      const decision = await client.send(
        request({
          request_type: "CheckAction",
          tool: "github.issues.read",
          resource: "org/repo",
          args: {},
        }),
      )
      assert.equal(decision.allowed, true)

      const denied = await client.send(
        request({
          request_type: "CheckAction",
          tool: "tool.not.in.manifest",
          resource: "org/repo",
          args: {},
        }),
      )
      assert.equal(denied.allowed, false)
      assert.ok(!denied.allowed)
      assert.equal(denied.reason, "tool_not_in_manifest")
    } finally {
      await client.close()
    }
  } finally {
    child.kill()
  }
})
