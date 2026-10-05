import assert from "node:assert/strict"
import { createServer, connect, type Server, type Socket } from "node:net"
import { test } from "node:test"

import { DEFAULT_ALLOWED_PORTS, type Destination } from "./egress-cell.ts"
import { startEgressProxy, type EgressProxyOptions, type EgressTicket } from "./egress-proxy.ts"
import { InMemoryReplayStore, type ReplayConsumeOutcome, type ReplayStore } from "./replay-store.ts"

/**
 * The proxy is exercised over real TCP sockets against a real upstream, because most of what it
 * does is framing and connection handling — things an in-process fake would let pass by never
 * happening. Every attack below is a request the proxy must refuse, sent as bytes over a socket.
 */

const ALLOWED_HOST = "api.github.com"
const DENIED_HOST = "evil.example.com"
const PUBLIC_ADDRESS = "93.184.216.34"

const NOW = new Date("2026-10-03T12:00:00.000Z")

const ticketFor = (
  destinations: readonly Destination[],
  overrides: Partial<EgressTicket> = {},
): EgressTicket => ({
  tenantId: "t_egress",
  agentId: "pi_demo",
  nonce: "nonce-1",
  permitId: "permit-1",
  expiresAt: new Date(NOW.getTime() + 60_000),
  destinations,
  ...overrides,
})

/** A real HTTP server that echoes what it receives, standing in for an allowed upstream. */
const startUpstream = async (): Promise<{ port: number; received: string[]; close: () => Promise<void> }> => {
  const received: string[] = []

  const server: Server = createServer((socket: Socket) => {
    socket.on("data", (chunk: Buffer) => {
      received.push(chunk.toString("utf8"))
      socket.write("upstream-ok")
    })
  })

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve))

  const address = server.address()

  assert.ok(address !== null && typeof address === "object")

  return {
    port: address.port,
    received,
    close: (): Promise<void> => new Promise((resolve) => server.close(() => resolve())),
  }
}

type Harness = {
  readonly proxy: Awaited<ReturnType<typeof startEgressProxy>>
  readonly send: (request: string) => Promise<{ status: number; body: string; raw: string }>
  readonly close: () => Promise<void>
}

/**
 * The harness resolves every name to a *public* address and dials 127.0.0.1.
 *
 * That split is deliberate and not a shortcut around the policy. The upstream in these tests is a
 * real socket on the loopback interface, and `127.0.0.0/8` is on the deny list because that is
 * exactly right — a cell that permitted loopback would let a workload reach its own neighbours. So
 * the injected `resolve` reports the public address the name would have, and the injected `dial`
 * stands in for the proxy's own route to it. The proxy still validates, still pins, and still
 * refuses a name that resolves anywhere else; only the last hop is local.
 */
const startHarness = async (
  overrides: Partial<EgressProxyOptions> = {},
  ticket: EgressTicket = ticketFor([{ host: ALLOWED_HOST, port: 443 }]),
  allowedPorts: readonly number[] = [...DEFAULT_ALLOWED_PORTS],
): Promise<Harness> => {
  const proxy = await startEgressProxy({
    host: "127.0.0.1",
    port: 0,
    allowHosts: [ALLOWED_HOST],
    allowedPorts: [...allowedPorts],
    resolve: (): Promise<readonly string[]> => Promise.resolve([PUBLIC_ADDRESS]),
    verifyTicket: (): Promise<{ ok: true; ticket: EgressTicket }> => Promise.resolve({ ok: true, ticket }),
    now: (): Date => NOW,
    dial: (address, port): Promise<Socket> =>
      new Promise((resolve, reject) => {
        const socket = connect({ host: "127.0.0.1", port })
        socket.once("connect", () => resolve(socket))
        socket.once("error", reject)
      }),
    ...overrides,
  })

  return {
    proxy,
    send: (request: string) =>
      new Promise((resolve, reject) => {
        const chunks: Buffer[] = []
        const socket = connect({ host: proxy.address, port: proxy.port })

        socket.on("data", (chunk: Buffer) => chunks.push(chunk))
        socket.on("error", reject)
        socket.on("close", () => {
          const raw = Buffer.concat(chunks).toString("utf8")
          const match = /^HTTP\/1\.1 (\d{3})/.exec(raw)

          resolve({ status: match === null ? 0 : Number(match[1]), body: raw, raw })
        })

        socket.write(request)
        // A tunnelled socket stays open by design, so the test closes its own side after a moment
        // and observes the response either way.
        setTimeout(() => socket.end(), 250)
      }),
    close: (): Promise<void> => proxy.close(),
  }
}

const connectRequest = (target: string, authorization = "Bearer ticket-1"): string =>
  `CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\nProxy-Authorization: ${authorization}\r\n\r\n`

/* ------------------------------------------------------------------ the permitted path */

test("an authenticated, allowlisted, resolvable destination is tunnelled to the real upstream", async (t) => {
  const upstream = await startUpstream()
  t.after(upstream.close)

  const ticket = ticketFor([{ host: ALLOWED_HOST, port: upstream.port }])
  const harness = await startHarness({}, ticket, [upstream.port])
  t.after(harness.close)

  const socket = connect({ host: harness.proxy.address, port: harness.proxy.port })
  await new Promise<void>((resolve, reject) => {
    socket.once("connect", resolve)
    socket.once("error", reject)
  })

  const chunks: Buffer[] = []
  socket.on("data", (chunk: Buffer) => chunks.push(chunk))

  socket.write(connectRequest(`${ALLOWED_HOST}:${upstream.port}`))

  await new Promise((resolve) => setTimeout(resolve, 200))

  assert.match(Buffer.concat(chunks).toString("utf8"), /200 Connection Established/)

  socket.write("GET / HTTP/1.1\r\n\r\n")
  await new Promise((resolve) => setTimeout(resolve, 200))

  assert.ok(
    upstream.received.some((chunk) => chunk.includes("GET / HTTP/1.1")),
    `upstream received ${JSON.stringify(upstream.received)}`,
  )
  assert.ok(
    Buffer.concat(chunks).toString("utf8").includes("upstream-ok"),
    "response bytes should travel back through the tunnel",
  )

  socket.destroy()
})

/* ------------------------------------------------------------------ authentication */

test("a CONNECT with no Proxy-Authorization is refused", async (t) => {
  const harness = await startHarness()
  t.after(harness.close)

  const response = await harness.send(`CONNECT ${ALLOWED_HOST}:443 HTTP/1.1\r\nHost: ${ALLOWED_HOST}\r\n\r\n`)

  assert.equal(response.status, 407)
})

test("a header name in a different case cannot smuggle past the credential check", async (t) => {
  // A check that compared `Proxy-Authorization` exactly would miss a client that sends it lowercased,
  // and the miss would be an allow.
  const harness = await startHarness()
  t.after(harness.close)

  const response = await harness.send(
    `CONNECT ${ALLOWED_HOST}:443 HTTP/1.1\r\nHost: ${ALLOWED_HOST}\r\nproxy-authorization: Bearer ticket-1\r\n\r\n`,
  )

  // The credential itself is accepted by the verifier stub, so this is 200-path, not 407 — which is
  // what proves the lowercased header was found at all.
  assert.notEqual(response.status, 407)
})

test("a ticket the verifier rejects is refused", async (t) => {
  const harness = await startHarness({
    verifyTicket: (): Promise<{ ok: false; reason: "signature_invalid" }> =>
      Promise.resolve({ ok: false, reason: "signature_invalid" }),
  })
  t.after(harness.close)

  const response = await harness.send(connectRequest(`${ALLOWED_HOST}:443`))

  assert.equal(response.status, 403)
  assert.match(response.raw, /signature_invalid/)
})

test("an expired ticket is refused even though its signature is valid", async (t) => {
  const expired = ticketFor([{ host: ALLOWED_HOST, port: 443 }], {
    expiresAt: new Date(NOW.getTime() - 1_000),
  })
  const harness = await startHarness({}, expired)
  t.after(harness.close)

  const response = await harness.send(connectRequest(`${ALLOWED_HOST}:443`))

  assert.equal(response.status, 403)
  assert.match(response.raw, /expired/)
})

test("an expiry boundary of exactly now is expired, not valid", async (t) => {
  // `expiresAt <= now` rather than `<`. An off-by-one here grants an extra second on every ticket.
  const boundary = ticketFor([{ host: ALLOWED_HOST, port: 443 }], { expiresAt: NOW })
  const harness = await startHarness({}, boundary)
  t.after(harness.close)

  const response = await harness.send(connectRequest(`${ALLOWED_HOST}:443`))

  assert.equal(response.status, 403)
  assert.match(response.raw, /expired/)
})

/* ------------------------------------------------------------------ single use */

test("a ticket is single use: the second CONNECT with the same nonce is refused", async (t) => {
  const upstream = await startUpstream()
  t.after(upstream.close)

  const replayStore = new InMemoryReplayStore()
  const ticket = ticketFor([{ host: ALLOWED_HOST, port: upstream.port }])
  const harness = await startHarness({ replayStore }, ticket, [upstream.port])
  t.after(harness.close)

  // The first CONNECT reaches the upstream, so this is a genuine consumption rather than a request
  // that happened to be refused for some other reason.
  const first = await harness.send(connectRequest(`${ALLOWED_HOST}:${upstream.port}`))
  const second = await harness.send(connectRequest(`${ALLOWED_HOST}:${upstream.port}`))

  assert.equal(first.status, 200)
  assert.equal(second.status, 403)
  assert.match(second.raw, /replayed/)
})

test("an unreachable replay store denies rather than treating the ticket as unused", async (t) => {
  // "The database is down" and "this permit was never used" must not produce the same answer, or a
  // single-use permit becomes a reusable one the first time the store has an incident.
  const unavailableStore: ReplayStore = {
    consume: (): Promise<ReplayConsumeOutcome> => Promise.resolve({ outcome: "unavailable", error: "connection refused" }),
    isConsumed: (): Promise<boolean> => Promise.resolve(false),
    cleanupExpired: (): Promise<number> => Promise.resolve(0),
  }

  const harness = await startHarness({ replayStore: unavailableStore })
  t.after(harness.close)

  const response = await harness.send(connectRequest(`${ALLOWED_HOST}:443`))

  assert.equal(response.status, 503)
  assert.match(response.raw, /replay_store_unavailable/)
})

/* ------------------------------------------------------------------ destination binding */

test("a destination the ticket does not name is refused even when it is allowlisted", async (t) => {
  // The ticket is for one decision, and a decision is about one destination. Without this, a ticket
  // issued for api.github.com could be pointed at any other allowlisted host.
  const harness = await startHarness()
  t.after(harness.close)

  const response = await harness.send(connectRequest(`${DENIED_HOST}:443`))

  assert.equal(response.status, 403)
  assert.match(response.raw, /destination_not_in_ticket/)
})

test("an allowlisted host on a port the ticket does not name is refused", async (t) => {
  const harness = await startHarness()
  t.after(harness.close)

  const response = await harness.send(connectRequest(`${ALLOWED_HOST}:8443`))

  assert.equal(response.status, 403)
})

test("a port the cell does not permit is refused", async (t) => {
  const ticket = ticketFor([{ host: ALLOWED_HOST, port: 22 }])
  const harness = await startHarness({ allowedPorts: [443] }, ticket)
  t.after(harness.close)

  const response = await harness.send(connectRequest(`${ALLOWED_HOST}:22`))

  assert.equal(response.status, 403)
  assert.match(response.raw, /port_not_permitted/)
})

test("a wildcard allowlist entry admits subdomains but not the parent domain", async (t) => {
  const upstream = await startUpstream()
  t.after(upstream.close)

  const harness = await startHarness(
    { allowHosts: ["*.trusted.example"] },
    ticketFor([{ host: "api.trusted.example", port: upstream.port }]),
    [upstream.port],
  )
  t.after(harness.close)

  const allowed = await harness.send(connectRequest(`api.trusted.example:${upstream.port}`))
  const parent = await harness.send(connectRequest(`trusted.example:${upstream.port}`))

  assert.equal(allowed.status, 200)
  // The parent domain is refused before it reaches the allowlist matcher, because no ticket names
  // it — which is the destination binding doing its job. The matcher would refuse it too.
  assert.equal(parent.status, 403)
})

/* ------------------------------------------------------------------ address policy at the boundary */

test("an allowlisted host that resolves to the metadata endpoint is refused", async (t) => {
  // The allowlist is the operator's policy and this is not: no rule should be able to grant the
  // link-local range, because nothing on it is ever the intended destination.
  const harness = await startHarness({
    resolve: (): Promise<readonly string[]> => Promise.resolve(["169.254.169.254"]),
  })
  t.after(harness.close)

  const response = await harness.send(connectRequest(`${ALLOWED_HOST}:443`))

  assert.equal(response.status, 403)
  assert.match(response.raw, /address_not_routable_from_the_cell/)
})

test("a host that resolves to both a public and a denied address is refused outright", async (t) => {
  // Narrowing to the public address would be a policy the attacker chooses which half of. If any
  // answer is denied, the whole destination is denied.
  const harness = await startHarness({
    resolve: (): Promise<readonly string[]> => Promise.resolve(["93.184.216.34", "127.0.0.1"]),
  })
  t.after(harness.close)

  const response = await harness.send(connectRequest(`${ALLOWED_HOST}:443`))

  assert.equal(response.status, 403)
  assert.match(response.raw, /address_not_routable_from_the_cell/)
})

test("the proxy connects to the address it validated, not the name the client supplied", async (t) => {
  // This is the property that makes the whole design work: the client's encoding is irrelevant
  // because the proxy resolved the name itself and dials the result.
  const dialled: { address: string; port: number }[] = []

  const harness = await startHarness({
    resolve: (): Promise<readonly string[]> => Promise.resolve(["93.184.216.34"]),
    dial: (address, port) => {
      dialled.push({ address, port })
      // The upstream is not really there, so the proxy answers 502 — but only after recording what
      // it was about to dial, which is the thing under test.
      return Promise.reject(new Error("no route"))
    },
  })
  t.after(harness.close)

  await harness.send(connectRequest(`${ALLOWED_HOST}:443`))

  assert.deepEqual(dialled, [{ address: "93.184.216.34", port: 443 }])
})

test("a resolver failure denies rather than falling through to an unchecked connect", async (t) => {
  const harness = await startHarness({
    resolve: (): Promise<readonly string[]> => Promise.reject(new Error("SERVFAIL")),
  })
  t.after(harness.close)

  const response = await harness.send(connectRequest(`${ALLOWED_HOST}:443`))

  assert.equal(response.status, 502)
  assert.match(response.raw, /resolver_failed/)
})

test("a host that resolves to nothing denies", async (t) => {
  const harness = await startHarness({ resolve: (): Promise<readonly string[]> => Promise.resolve([]) })
  t.after(harness.close)

  const response = await harness.send(connectRequest(`${ALLOWED_HOST}:443`))

  assert.equal(response.status, 502)
})

test("an unreachable upstream is a 502, not a denial of policy", async (t) => {
  // The distinction matters to an operator: 403 means the cell refused, 502 means the destination
  // was allowed and could not be reached.
  const harness = await startHarness({
    dial: (): Promise<Socket> => Promise.reject(new Error("ECONNREFUSED")),
  })
  t.after(harness.close)

  const response = await harness.send(connectRequest(`${ALLOWED_HOST}:443`))

  assert.equal(response.status, 502)
  assert.match(response.raw, /upstream_unreachable/)
})

/* ------------------------------------------------------------------ framing and protocol */

test("a plain-HTTP absolute-URI request is refused rather than rewritten", async (t) => {
  // Rewriting it correctly is a second protocol implementation with its own smuggling surface.
  const harness = await startHarness()
  t.after(harness.close)

  const response = await harness.send(
    `GET http://${ALLOWED_HOST}/path HTTP/1.1\r\nHost: ${ALLOWED_HOST}\r\nProxy-Authorization: Bearer ticket-1\r\n\r\n`,
  )

  assert.equal(response.status, 405)
})

test("a malformed CONNECT target is refused with a parse reason", async (t) => {
  const harness = await startHarness()
  t.after(harness.close)

  // These are targets the parser cannot read at all, so they never reach the policy checks and are
  // answered 400. A target the parser *can* read is refused later, for a different reason — the
  // distinction is asserted separately below, because collapsing it would hide which check fired.
  for (const target of ["api.github.com", "api.github.com:0", "https://api.github.com:443", "api.github.com:99999"]) {
    const response = await harness.send(connectRequest(target))
    assert.equal(response.status, 400, target)
    assert.match(response.raw, /malformed|port_out_of_range/, target)
  }
})

test("a bracketed IPv6 literal is refused by the address policy, not by the parser", async (t) => {
  // `[::1]:443` is well-formed syntax. It has to be stopped by the loopback rule rather than by a
  // parse error, otherwise a test suite full of 400s would look like coverage while never exercising
  // the address check at all.
  const harness = await startHarness(
    { allowHosts: ["::1"], resolve: (): Promise<readonly string[]> => Promise.resolve(["::1"]) },
    ticketFor([{ host: "::1", port: 443 }]),
  )
  t.after(harness.close)

  const response = await harness.send(connectRequest("[::1]:443"))

  assert.equal(response.status, 403)
  assert.match(response.raw, /address_not_routable_from_the_cell/)
})

test("a request head that never terminates is refused instead of buffered forever", async (t) => {
  // The size bound is the only thing standing between a client that never sends CRLFCRLF and an
  // out-of-memory crash of the process enforcing the cell.
  const harness = await startHarness()
  t.after(harness.close)

  const response = await harness.send(
    `CONNECT ${ALLOWED_HOST}:443 HTTP/1.1\r\nProxy-Authorization: Bearer ticket-1\r\nX-Pad: ${"A".repeat(64 * 1024)}\r\n`,
  )

  assert.equal(response.status, 431)
  assert.match(response.raw, /head_too_large/)
})

test("every refusal is recorded as an event, so the cell has an audit trail", async (t) => {
  const harness = await startHarness()
  t.after(harness.close)

  await harness.send(connectRequest(`${DENIED_HOST}:443`))

  assert.equal(harness.proxy.events.length, 1)
  assert.equal(harness.proxy.events[0]!.outcome, "denied")
  assert.equal(harness.proxy.events[0]!.reason, "destination_not_in_ticket")
  // The denial names the destination, which is what makes the event useful after the fact.
  assert.equal(harness.proxy.events[0]!.destination?.host, DENIED_HOST)
  assert.equal(harness.proxy.events[0]!.tenantId, "t_egress")
})

test("an address denial records the resolved address that caused it", async (t) => {
  const harness = await startHarness({
    resolve: (): Promise<readonly string[]> => Promise.resolve(["169.254.169.254"]),
  })
  t.after(harness.close)

  await harness.send(connectRequest(`${ALLOWED_HOST}:443`))

  assert.equal(harness.proxy.events[0]!.reason, "address_not_routable_from_the_cell")
  assert.equal(harness.proxy.events[0]!.resolvedAddress, "169.254.169.254")
})