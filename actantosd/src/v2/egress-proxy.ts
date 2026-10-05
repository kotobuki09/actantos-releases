import { createServer, connect, type Server, type Socket } from "node:net"

import {
  checkDestinationAddress,
  checkDestinationHost,
  parseConnectTarget,
  type Destination,
} from "./egress-cell.ts"
import type { ReplayStore } from "./replay-store.ts"

/**
 * The egress proxy: connect-time enforcement for the `egress_proxy` cell mode (S2, phase G).
 *
 * ## Position
 *
 * The workload reaches the outside world only through this process, and this process is the only
 * thing on the internal network that has a route off it. The workload cannot skip it, because the
 * network it sits on has no other exit — that is a property of the Docker topology in
 * `egress-cell.ts`, verified against real Docker, not of this code. What this code decides is
 * *which* destinations are permitted once somebody is knocking.
 *
 * ## Four checks, in order, and all four deny
 *
 *   1. Ticket.     A signed, single-use, expiring grant naming this exact destination.
 *   2. Host.       The host is in the ticket's destination set AND in the cell allowlist.
 *   3. Address.    Every address the host resolves to is checked against the denied ranges, and
 *                  the connection is pinned to an address that passed.
 *   4. Port.       The port is one the cell permits.
 *
 * The ordering is deliberate. Ticket first, because without one there is nothing to authorise;
 * host before address, because an allowlisted host resolving to a denied address is a rebinding
 * attempt and saying so is more useful than reporting a bare CIDR miss; address before connect,
 * because connecting first and checking after is how a check becomes a log line.
 *
 * ## Why the proxy resolves rather than believing
 *
 * A proxy that forwarded to whatever the client asked for, having been told by the client, would
 * enforce nothing. The client is the compromised party. So the proxy resolves the name itself,
 * checks every answer, and opens its own socket to a pinned address. `http://2852039166/` is a
 * hostname to the client and an address to this process, and by the time the address exists the
 * choice of encoding has already been made for it.
 *
 * ## What is refused, and why each refusal is its own code
 *
 * An operator reading a log needs to distinguish "the agent tried the metadata endpoint" from "the
 * proxy is misconfigured" from "someone is replaying a ticket". They are different incidents with
 * different responses, so they are different codes rather than one `denied`.
 *
 * ## Known limits
 *
 * * A CONNECT tunnel is opaque. A redirect inside an established tunnel is bytes this process
 *   carries without reading. The cell constrains where a connection is *opened*.
 * * Plain-HTTP absolute-URI requests are refused outright (`405`) rather than rewritten. Rewriting
 *   them correctly is a second protocol implementation with its own smuggling surface; refusing
 *   means the workload must use CONNECT, which is what every HTTPS-capable client does anyway.
 * * This process must be the only member of the cell network besides the workloads. That is a
 *   deployment property, and `egress-proxy-topology.test.ts` asserts it rather than assuming it.
 */

/** Largest request head the proxy will buffer before giving up on the client. */
export const MAX_HEAD_BYTES = 16 * 1024

export const EGRESS_PROXY_PROTOCOL = "actantos-egress/1"

export type EgressTicket = {
  readonly tenantId: string
  readonly agentId: string
  /** Unique per issuance. Consumed once, by the replay store. */
  readonly nonce: string
  readonly permitId: string
  readonly expiresAt: Date
  /**
   * Destinations this ticket authorises, as host/port pairs.
   *
   * Bind them here rather than in the allowlist alone, so that a ticket for one call cannot be
   * pointed at a different host that happens to also be allowlisted. A ticket is for a decision,
   * and a decision is about one destination.
   */
  readonly destinations: readonly Destination[]
}

export type EgressTicketVerification =
  | { readonly ok: true; readonly ticket: EgressTicket }
  | { readonly ok: false; readonly reason: EgressTicketFailure }

export type EgressTicketFailure =
  | "missing"
  | "malformed"
  | "signature_invalid"
  | "expired"
  | "replayed"
  | "replay_store_unavailable"

export type EgressDenialReason =
  | EgressTicketFailure
  | "destination_not_in_ticket"
  | "host_not_allowlisted"
  | "address_not_routable_from_the_cell"
  | "port_not_permitted"
  | "resolver_failed"
  | "upstream_unreachable"
  | "malformed_request"
  | "unsupported_method"
  | "head_too_large"

export type EgressEvent = {
  readonly outcome: "allowed" | "denied"
  readonly reason?: EgressDenialReason
  readonly tenantId?: string
  readonly agentId?: string
  readonly destination?: Destination
  readonly resolvedAddress?: string
}

export type EgressProxyOptions = {
  readonly host: string
  readonly port: number
  /**
   * Verify the `Proxy-Authorization` value and return what it authorises.
   *
   * Injected rather than implemented here so the signing scheme stays the one the control plane
   * already uses. The proxy never parses a token; it only ever sees the result of a verification
   * it did not perform.
   */
  readonly verifyTicket: (authorization: string) => Promise<EgressTicketVerification>
  /**
   * The allowlist, shared with the decision layer.
   *
   * This is the same list the sidecar checks and the Tetragon profile projects. It arrives as a
   * plain host list precisely so that the proxy is not a second place to express policy.
   */
  readonly allowHosts: readonly string[]
  readonly allowedPorts: readonly number[]
  /** Single-use enforcement. Omit to run without replay protection, which the tests do deliberately. */
  readonly replayStore?: ReplayStore
  /**
   * Resolve a hostname to every address it has.
   *
   * Every answer is checked. A host that resolves to one public and one link-local address is
   * refused, not narrowed to the public one — a narrowing policy is a policy an attacker chooses
   * which half of.
   */
  readonly resolve: (host: string) => Promise<readonly string[]>
  /** Injected so tests can drive the upstream without a real outbound network. */
  readonly dial?: (address: string, port: number) => Promise<Socket>
  readonly now?: () => Date
  readonly onEvent?: (event: EgressEvent) => void
}

export type EgressProxyServer = {
  readonly address: string
  readonly port: number
  readonly events: readonly EgressEvent[]
  close(): Promise<void>
}

type Refusal = {
  readonly status: number
  readonly reason: EgressDenialReason
  readonly detail: string
  /**
   * True when `authorise` has already recorded this denial with full context.
   *
   * Without it the transport would record a second, context-free event over the top and the log
   * would lose the destination and the tenant — which are the only parts that make a denial
   * investigable after the fact.
   */
  readonly recorded?: boolean
}

const refuse = (status: number, reason: EgressDenialReason, detail: string): Refusal => ({
  status,
  reason,
  detail,
})

/**
 * Split a head into its request line and headers.
 *
 * Returns `null` while more bytes are needed, so a client that sends the request in pieces is not
 * treated as malformed. The size bound is enforced against the un-split buffer so a client that
 * never sends the blank line cannot grow it without limit.
 */
class HeadReader {
  #buffer = ""
  #overflowed = false

  push(chunk: Buffer): { readonly head: string | null; readonly overflowed: boolean } {
    if (this.#overflowed) return { head: null, overflowed: true }

    this.#buffer += chunk.toString("latin1")

    if (Buffer.byteLength(this.#buffer, "latin1") > MAX_HEAD_BYTES) {
      this.#overflowed = true
      return { head: null, overflowed: true }
    }

    const end = this.#buffer.indexOf("\r\n\r\n")

    if (end === -1) return { head: null, overflowed: false }

    return { head: this.#buffer.slice(0, end), overflowed: false }
  }
}

const parseHead = (
  head: string,
): { method: string; target: string; authorization: string | undefined } | { error: Refusal } => {
  const lines = head.split("\r\n")
  const requestLine = lines[0]

  if (requestLine === undefined) return { error: refuse(400, "malformed_request", "empty request line") }

  const parts = requestLine.split(" ")

  if (parts.length < 3) {
    return { error: refuse(400, "malformed_request", "request line has fewer than three fields") }
  }

  const method = parts[0]!
  const target = parts[1]!

  let authorization: string | undefined

  for (const line of lines.slice(1)) {
    const colon = line.indexOf(":")

    if (colon === -1) continue

    // Header names are case-insensitive, and a client that sends `proxy-authorization` and not
    // `Proxy-Authorization` must not be able to slip an unauthenticated request past the check.
    if (line.slice(0, colon).trim().toLowerCase() === "proxy-authorization") {
      authorization = line.slice(colon + 1).trim()
    }
  }

  return { method, target, authorization }
}

export const startEgressProxy = async (options: EgressProxyOptions): Promise<EgressProxyServer> => {
  const now = options.now ?? ((): Date => new Date())
  const dial =
    options.dial ??
    ((address: string, port: number): Promise<Socket> =>
      new Promise((resolve, reject) => {
        const socket = connect({ host: address, port })
        socket.once("connect", () => {
          socket.removeListener("error", reject)
          resolve(socket)
        })
        socket.once("error", reject)
      }))

  const events: EgressEvent[] = []

  const record = (event: EgressEvent): void => {
    events.push(event)
    options.onEvent?.(event)
  }

  /**
   * Every check a CONNECT request must pass, in order. Returns either a refusal or the pinned
   * upstream socket.
   *
   * Every refusal path here records its own event, because at this point the destination, the
   * tenant and the agent are all known and a denial logged without them cannot be acted on.
   */
  const authorise = async (
    authorization: string | undefined,
    destination: Destination,
  ): Promise<{ readonly socket: Socket; readonly resolved: string; readonly ticket: EgressTicket } | { readonly error: Refusal }> => {
    /** Record and return in one step, so no path can forget to log. */
    const deny = (
      status: number,
      reason: EgressDenialReason,
      detail: string,
      resolvedAddress?: string,
    ): { readonly error: Refusal } => {
      record({
        outcome: "denied",
        reason,
        destination,
        ...(resolvedAddress === undefined ? {} : { resolvedAddress }),
      })
      return { error: { status, reason, detail, recorded: true } }
    }

    // The ticket fields are only known once it verifies, so a denial before that point cannot name
    // them. The destination is still recorded, because it came from the client and is known.
    let tenantId: string | undefined
    let agentId: string | undefined

    if (authorization === undefined || authorization === "") {
      return deny(407, "missing", "Proxy-Authorization is required")
    }

    const verification = await options.verifyTicket(authorization)

    if (!verification.ok) {
      // 407 is reserved for "authenticate"; everything else is a decision, and reporting a
      // replayed or expired ticket as 407 would tell the client to retry with fresh credentials
      // when retrying is precisely what it must not do.
      return deny(403, verification.reason, `ticket ${verification.reason}`)
    }

    const ticket = verification.ticket

    tenantId = ticket.tenantId
    agentId = ticket.agentId

    const denyAs = (
      status: number,
      reason: EgressDenialReason,
      detail: string,
      resolvedAddress?: string,
    ): { readonly error: Refusal } => {
      record({
        outcome: "denied",
        reason,
        destination,
        tenantId,
        agentId,
        ...(resolvedAddress === undefined ? {} : { resolvedAddress }),
      })
      return { error: { status, reason, detail, recorded: true } }
    }

    if (ticket.expiresAt.getTime() <= now().getTime()) {
      return denyAs(403, "expired", "ticket expired")
    }

    const permitted = ticket.destinations.some(
      (candidate) => candidate.host === destination.host && candidate.port === destination.port,
    )

    if (!permitted) {
      return denyAs(403, "destination_not_in_ticket", `ticket does not authorise ${destination.host}:${destination.port}`)
    }

    const hostVerdict = checkDestinationHost(destination.host, options.allowHosts)

    if (!hostVerdict.allowed) {
      return denyAs(403, "host_not_allowlisted", `${destination.host} is not allowlisted`)
    }

    if (!options.allowedPorts.includes(destination.port)) {
      return denyAs(403, "port_not_permitted", `port ${destination.port} is not permitted`)
    }

    if (options.replayStore !== undefined) {
      const consumed = await options.replayStore.consume({
        tenantId: ticket.tenantId,
        permitId: ticket.permitId,
        nonce: ticket.nonce,
        expiresAt: ticket.expiresAt,
      })

      // An unreachable replay store is a denial, and a distinct one. Treating "the database is
      // down" as "not yet used" is how a single-use permit becomes a reusable one.
      if (consumed.outcome === "replayed") {
        return denyAs(403, "replayed", `ticket ${consumed.reason}`)
      }

      if (consumed.outcome === "unavailable") {
        return denyAs(503, "replay_store_unavailable", consumed.error)
      }
    }

    let addresses: readonly string[]

    try {
      addresses = await options.resolve(destination.host)
    } catch (error) {
      // Fail closed on resolver failure. A proxy that fell through to "connect anyway" here would
      // turn a DNS outage into an outage of the security control itself.
      return denyAs(502, "resolver_failed", error instanceof Error ? error.message : "resolver failed")
    }

    if (addresses.length === 0) {
      return denyAs(502, "resolver_failed", `${destination.host} did not resolve`)
    }

    let pinned: string | undefined

    for (const address of addresses) {
      const verdict = checkDestinationAddress(address)

      if (!verdict.allowed) {
        return denyAs(403, "address_not_routable_from_the_cell", `${address} is not routable from the cell`, address)
      }

      pinned ??= address
    }

    const resolved = pinned!

    let upstream: Socket

    try {
      upstream = await dial(resolved, destination.port)
    } catch (error) {
      return denyAs(502, "upstream_unreachable", error instanceof Error ? error.message : "connect failed")
    }

    return { socket: upstream, resolved, ticket }
  }

  const server: Server = createServer((client: Socket) => {
    const reader = new HeadReader()

    const reject = (refusal: Refusal): void => {
      // Only transport-level refusals record here. A decision denial has already been logged by
      // `authorise` with the destination and tenant attached.
      if (refusal.recorded !== true) record({ outcome: "denied", reason: refusal.reason })

      client.end(
        `HTTP/1.1 ${refusal.status} ${refusal.reason}\r\n` +
          `content-length: 0\r\n` +
          `connection: close\r\n\r\n`,
      )
    }

    client.on("error", () => {
      // A client that vanishes mid-request is ordinary. Any decision already made is recorded.
    })

    client.on("data", (chunk: Buffer) => {
      const { head, overflowed } = reader.push(chunk)

      if (overflowed) {
        reject(refuse(431, "head_too_large", `request head exceeds ${MAX_HEAD_BYTES} bytes`))
        return
      }

      if (head === null) return

      const parsed = parseHead(head)

      if ("error" in parsed) {
        reject(parsed.error)
        return
      }

      void (async (): Promise<void> => {
        // A client that sets an absolute URI instead of CONNECT would otherwise have its path
        // rewritten for it by some other proxy and silently bypass this one.
        if (parsed.method !== "CONNECT") {
          reject(
            refuse(405, "unsupported_method", "only CONNECT is supported; use an HTTPS proxy"),
          )
          return
        }

        const target = parseConnectTarget(parsed.target)

        if (!target.ok) {
          reject(refuse(400, "malformed_request", `connect target ${target.reason}`))
          return
        }

        const decision = await authorise(parsed.authorization, target.destination)

        if ("error" in decision) {
          reject(decision.error)
          return
        }

        record({
          outcome: "allowed",
          tenantId: decision.ticket.tenantId,
          agentId: decision.ticket.agentId,
          destination: target.destination,
          resolvedAddress: decision.resolved,
        })

        // Bytes already read past the head belong to the tunnelled stream, not to the request.
        const pipelined = client.read()

        if (pipelined !== null) decision.socket.write(pipelined)

        client.write("HTTP/1.1 200 Connection Established\r\nproxy-agent: actantos\r\n\r\n")

        client.pipe(decision.socket)
        decision.socket.pipe(client)

        const teardown = (): void => {
          client.destroy()
          decision.socket.destroy()
        }

        client.on("error", teardown)
        client.on("close", teardown)
        decision.socket.on("error", teardown)
        decision.socket.on("close", teardown)
      })()
    })
  })

  const listening = new Promise<void>((resolve, reject) => {
    server.once("error", reject)
    server.listen(options.port, options.host, () => {
      server.removeListener("error", reject)
      resolve()
    })
  })

  await listening

  const address = server.address()

  return {
    address: typeof address === "object" && address !== null ? address.address : options.host,
    port: typeof address === "object" && address !== null ? address.port : options.port,
    events,
    close: (): Promise<void> =>
      new Promise((resolve) => {
        server.close(() => resolve())
      }),
  }
}