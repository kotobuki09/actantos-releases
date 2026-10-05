import { BlockList, isIP } from "node:net"

import { hostMatchesRule } from "./network-target-guard.ts"

/**
 * The controlled egress network cell (invariant S2, phase G).
 *
 * ## What this replaces
 *
 * Until now `constraints.network_mode` had two values. `none` put the workload on Docker's
 * `--network none`, which is measured to block a raw socket at the kernel. `egress_proxy`
 * selected a plain user-defined bridge called `actantos_egress` — a network with no proxy on it,
 * no internal flag, no firewall, and no destination check. Anything on it could reach anything.
 *
 * So `egress_proxy` was not a weaker version of containment. It was the *absence* of containment,
 * under a name that claimed otherwise. `milestones/A-05-egress-claim-integrity.md` recorded this
 * as a narrowed claim; the narrow claim was accurate about the code and misleading about the
 * consequence.
 *
 * ## The three modes
 *
 * `none`          The workload has no network. Nothing to configure, nothing to get wrong.
 * `broker_only`   The workload has no network either, but a network-capable call is **denied at
 *                 decision time** with `egress_broker_required` rather than handed a network and
 *                 silently getting `ENETUNREACH` at connect time. The operator-visible difference
 *                 is the reason code: one is "you asked for something this cell cannot give you",
 *                 the other is "you ran something and it happened to fail".
 * `egress_proxy`  The workload is on an **internal** Docker network whose only reachable peer is
 *                 the egress proxy. The proxy authenticates the connection, resolves the
 *                 destination itself, refuses any address that is not public and allowlisted,
 *                 and pins the outbound socket to the address it just validated.
 *
 * ## Why the internal network is the load-bearing part
 *
 * Measured on this host, against real Docker: a container on an internal bridge gets
 * `EGRESS_BLOCKED` for both `wget https://example.com` and a raw `nc` to a public IP, so the
 * block is kernel-level rather than application-level. The same container reaches a peer on that
 * network by name and by IP, and Docker's embedded resolver returns `SERVFAIL` for any name it
 * does not know a peer for. That is the whole design in one sentence: **the workload's only door
 * is the proxy, and the workload cannot open a second one.**
 *
 * The resolver property matters more than it looks. An agent that wants to exfiltrate over DNS
 * needs to resolve a name it controls. On an internal network with no upstream, that name does
 * not resolve, and the failure is `SERVFAIL` rather than an empty answer the agent could encode
 * data in.
 *
 * ## Why the proxy resolves the name itself
 *
 * Because the proxy resolves, the address it validates is the address it connects to. That makes
 * the entire family of textual tricks irrelevant in one step: `http://2852039166/`,
 * `http://0177.0.0.1/`, `http://[::ffff:169.254.169.254]/` and a hostname that resolves to
 * `169.254.169.254` all arrive at the same function as the string `169.254.169.254`, and all four
 * are refused. A blocklist of encodings would be a list of the encodings somebody thought of.
 *
 * `64:ff9b::/96` is in the denied set for the same reason: a NAT64 prefix turns any IPv4 literal
 * into a valid IPv6 destination, and a check that only understood `::1` and `fe80::/10` would miss
 * it. So would `::ffff:0:0/96`, which is the other way to write an IPv4 address.
 *
 * ## What this does not do
 *
 * An established CONNECT tunnel is opaque. If the workload fetches `https://allowed.example/` and
 * that page 302s to `https://elsewhere.example/`, the proxy is carrying bytes and cannot see it.
 * Following a redirect would require TLS interception with a proxy-trusted CA inside the workload,
 * which is a much larger change with its own key-distribution problem. Until that exists the
 * honest statement is: **the cell constrains where a connection is opened, not where it ends.**
 * Policy that needs the stronger property belongs in the allowlist check at decision time.
 */

export const EGRESS_CELL_MODES = ["none", "broker_only", "egress_proxy"] as const

export type EgressCellMode = (typeof EGRESS_CELL_MODES)[number]

export const DEFAULT_EGRESS_CELL_MODE: EgressCellMode = "none"

const isEgressCellMode = (value: string): value is EgressCellMode =>
  (EGRESS_CELL_MODES as readonly string[]).includes(value)

/**
 * Read the cell mode from the operator's environment.
 *
 * Unrecognised values throw, exactly as `resolveFabricMode` does, and for the same reason: the
 * default is `none`, so a typo that fell back to the default would look like a working deployment
 * while quietly disabling the cell. Throwing at startup is the only version of this that cannot be
 * mistaken for a decision.
 */
export const resolveEgressCellMode = (raw: string | undefined): EgressCellMode => {
  if (raw === undefined || raw.trim() === "") return DEFAULT_EGRESS_CELL_MODE

  const normalised = raw.trim().toLowerCase()

  if (isEgressCellMode(normalised)) return normalised

  throw new Error(
    `ACTANTOS_EGRESS_CELL is "${raw}", which is not one of ${EGRESS_CELL_MODES.join(", ")}. ` +
      "Refusing to start: falling back to a default here would decide, silently, whether this " +
      "deployment has a controlled egress cell.",
  )
}

/**
 * The internal Docker network the workload shares with the proxy, and nothing else.
 *
 * Named to match the `actantos_` prefix of the rest of the deployment's Docker objects so an
 * operator listing networks can tell which one is security-relevant.
 */
export const EGRESS_CELL_NETWORK = "actantos_egress_cell"

/** The DNS name the workload uses to reach the proxy. Resolved by Docker, not by the workload. */
export const EGRESS_CELL_PROXY_HOSTNAME = "actantos-egress-proxy"

export type EgressCellTopology = {
  readonly mode: EgressCellMode
  /** Docker network name. `"none"` is Docker's own sentinel for "no network at all". */
  readonly networkName: string
  /** Whether this mode puts the workload on any network whatsoever. */
  readonly hasNetwork: boolean
  /** Whether `docker network create` must be given `--internal`. */
  readonly internal: boolean
  /**
   * Whether a network-capable call is denied at decision time instead of being attempted.
   *
   * Only `broker_only` does this. Under `none` the call is also impossible, but it fails at
   * connect time inside the workload with a kernel error the agent sees and the operator does not.
   */
  readonly brokerRequired: boolean
}

export const egressCellTopology = (mode: EgressCellMode): EgressCellTopology => ({
  mode,
  networkName: mode === "egress_proxy" ? EGRESS_CELL_NETWORK : "none",
  hasNetwork: mode === "egress_proxy",
  internal: mode === "egress_proxy",
  brokerRequired: mode === "broker_only",
})

/**
 * The reason a network-capable call is refused under `broker_only`.
 *
 * Distinct from every other decision reason code in the codebase so that a dashboard can answer
 * "how often does the agent need a network we are not giving it" without parsing prose.
 */
export const EGRESS_BROKER_REQUIRED = "egress_broker_required"

/* -------------------------------------------------------------------------------------------- */
/* Address policy                                                                                  */
/* -------------------------------------------------------------------------------------------- */

/**
 * Ranges that must never be reachable through the cell, whatever an allowlist says.
 *
 * An allowlist is the operator's policy. This list is not policy — it is the part of the address
 * space where reaching the destination is never what anybody meant, including the cases where the
 * destination is the control plane's own infrastructure: the cloud metadata service at
 * `169.254.169.254`, a database on the same VPC, and the container network Docker hands out.
 *
 * Built once at module load. `BlockList` is Node's own CIDR matcher, not a hand-rolled one.
 *
 * ## Why the two families are separate BlockLists
 *
 * `BlockList.addSubnet("::ffff:0:0", 96, "ipv6")` poisons every IPv4 check in the same list. On
 * Node v26.4.0, measured:
 *
 * ```
 * const b = new BlockList()
 * b.addSubnet("10.0.0.0", 8, "ipv4")
 * b.check("8.8.8.8", "ipv4")   // false
 * b.addSubnet("::ffff:0:0", 96, "ipv6")
 * b.check("8.8.8.8", "ipv4")   // true   <-- every public address now denied
 * ```
 *
 * Adding `64:ff9b::/96` or `fe80::/10` does not trigger it; the IPv4-mapped prefix specifically
 * does, because in Node's internal representation every IPv4 address already *is* an IPv4-mapped
 * IPv6 address.
 *
 * The failure direction is the one that would have gone unnoticed: a deny list that has quietly
 * become a deny-everything list denies the entire internet, including the destinations the
 * allowlist permits, and the symptom is a broken cell rather than an open one. Keeping the
 * families apart removes the interaction entirely.
 *
 * `BlockList.check` also does **not** throw on a family mismatch — it silently returns `false`.
 * That direction is safe here, since a `false` is a denial, but it is why the family is taken from
 * `isIP` rather than assumed.
 */
const buildDeniedIpv4 = (): BlockList => {
  const denied = new BlockList()

  const ranges = [
    // "This network on this host", which resolves to every local interface including the host's.
    ["0.0.0.0", 8],
    // RFC 1918 private.
    ["10.0.0.0", 8],
    ["172.16.0.0", 12],
    ["192.168.0.0", 16],
    // Loopback. On the Docker bridge this is the workload's own neighbours; on the host it is the host.
    ["127.0.0.0", 8],
    // Link-local. Contains 169.254.169.254, the cloud metadata endpoint, which is the single most
    // valuable address to reach from inside a compromised workload and the reason S1 needs a
    // network-layer answer as well as a credential one.
    ["169.254.0.0", 16],
    // Carrier-grade NAT. Commonly used to reach operator-internal services.
    ["100.64.0.0", 10],
    // IETF protocol assignments, documentation ranges, and the 6to4 anycast relay prefix.
    ["192.0.0.0", 24],
    ["192.0.2.0", 24],
    ["192.88.99.0", 24],
    ["198.18.0.0", 15],
    ["198.51.100.0", 24],
    ["203.0.113.0", 24],
    ["224.0.0.0", 4],
    ["240.0.0.0", 4],
  ] as const

  for (const [address, prefix] of ranges) denied.addSubnet(address, prefix, "ipv4")

  return denied
}

const buildDeniedIpv6 = (): BlockList => {
  const denied = new BlockList()

  const ranges = [
    ["::", 128], // Unspecified.
    ["::1", 128], // Loopback.
    ["100::", 64], // Discard-only.
    ["2001:db8::", 32], // Documentation.
    ["fc00::", 7], // Unique local.
    ["fe80::", 10], // Link-local.
    ["ff00::", 8], // Multicast.
    // Deliberately absent: ::ffff:0:0/96 and 64:ff9b::/96. Both are handled by unwrapping the
    // embedded IPv4 and applying the IPv4 rules, which is both correct for a public address
    // written that way and immune to the BlockList interaction described above.
  ] as const

  for (const [address, prefix] of ranges) denied.addSubnet(address, prefix, "ipv6")

  return denied
}

let deniedIpv4: BlockList | undefined
let deniedIpv6: BlockList | undefined

const deniedV4 = (): BlockList => {
  deniedIpv4 ??= buildDeniedIpv4()
  return deniedIpv4
}

const deniedV6 = (): BlockList => {
  deniedIpv6 ??= buildDeniedIpv6()
  return deniedIpv6
}

/**
 * IPv6 spellings that carry an IPv4 address in their low 32 bits.
 *
 * Each is a way to write an IPv4 destination that would otherwise miss an IPv4-only check.
 * Unwrapping rather than denying the whole prefix means `::ffff:93.184.216.34` is allowed as the
 * public address it is, while `::ffff:169.254.169.254` is denied as the metadata endpoint it is.
 *
 * Written as explicit alternatives rather than one table with a capture-group index, because a
 * NAT64 address may spell its payload either way and a shared index silently captured the prefix
 * instead of the payload when it was tried the other way round.
 */
const IPV4_MAPPED_DOTTED = /^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i
const IPV4_COMPATIBLE_DOTTED = /^::(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i
const NAT64_DOTTED = /^64:ff9b::(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i
const NAT64_HEX = /^64:ff9b::([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i

const toDottedFromHex = (high: string, low: string): string => {
  const value = ((Number.parseInt(high, 16) << 16) | Number.parseInt(low, 16)) >>> 0
  return [(value >>> 24) & 255, (value >>> 16) & 255, (value >>> 8) & 255, value & 255].join(".")
}

/**
 * Recover the IPv4 address an IPv6 literal carries, if it carries one.
 *
 * Returns `null` for an ordinary IPv6 address, and also for a wrapper whose payload is not a valid
 * IPv4 address — in which case the literal is checked as IPv6 and the nonsense payload simply
 * fails to match any range.
 */
export const embeddedIpv4 = (address: string): string | null => {
  const dotted =
    IPV4_MAPPED_DOTTED.exec(address) ??
    IPV4_COMPATIBLE_DOTTED.exec(address) ??
    NAT64_DOTTED.exec(address)

  if (dotted !== null) {
    const captured = dotted[1]!

    return isIP(captured) === 4 ? captured : null
  }

  const hex = NAT64_HEX.exec(address)

  if (hex !== null) return toDottedFromHex(hex[1]!, hex[2]!)

  return null
}

export type AddressVerdict =
  | { readonly allowed: true; readonly address: string }
  | { readonly allowed: false; readonly address: string; readonly reason: string }

/**
 * Decide whether the proxy may open a connection to an address it has just resolved.
 *
 * This is the chokepoint. It takes the address, not the text the workload supplied, which is what
 * makes the encoding tricks inexpressible rather than merely unlisted.
 *
 * A malformed string is a denial rather than a pass-through, because "I could not classify this" and
 * "this is fine" must not produce the same answer.
 */
export const checkDestinationAddress = (address: string): AddressVerdict => {
  const family = isIP(address)

  if (family === 0) {
    return { allowed: false, address, reason: "not_an_ip_address" }
  }

  if (family === 4) {
    if (deniedV4().check(address, "ipv4")) {
      return { allowed: false, address, reason: "address_not_routable_from_the_cell" }
    }

    return { allowed: true, address }
  }

  // An IPv4 address dressed as IPv6 is judged by the IPv4 rules it is actually wearing, so a
  // public address is allowed and a private one is denied whatever prefix it arrived behind.
  const unwrapped = embeddedIpv4(address)

  if (unwrapped !== null && deniedV4().check(unwrapped, "ipv4")) {
    return { allowed: false, address, reason: "address_not_routable_from_the_cell" }
  }

  if (deniedV6().check(address, "ipv6")) {
    return { allowed: false, address, reason: "address_not_routable_from_the_cell" }
  }

  return { allowed: true, address }
}

/* -------------------------------------------------------------------------------------------- */
/* Destination parsing                                                                             */
/* -------------------------------------------------------------------------------------------- */

export type Destination = {
  readonly host: string
  readonly port: number
}

export type ParsedDestination =
  | { readonly ok: true; readonly destination: Destination }
  | { readonly ok: false; readonly reason: string }

/** `host:port` as it appears in an HTTP `CONNECT` target. */
const CONNECT_TARGET = /^\[([0-9A-Fa-f:.]+)\]:(\d{1,5})$/
const BARE_TARGET = /^(.+):(\d{1,5})$/

export const DEFAULT_ALLOWED_PORTS: readonly number[] = [80, 443]

/**
 * Parse an HTTP `CONNECT` target.
 *
 * Rejects rather than guesses. A port of `0`, a port of `99999`, an empty host, or a host carrying
 * a scheme all fail here, before any of them reaches a resolver — because a parser that repairs a
 * malformed target has to decide what it meant, and that decision is not one to make on a
 * compromised workload's behalf.
 */
export const parseConnectTarget = (raw: string): ParsedDestination => {
  const bracketed = CONNECT_TARGET.exec(raw)

  if (bracketed !== null) {
    const port = Number(bracketed[2])

    if (port < 1 || port > 65535) return { ok: false, reason: "port_out_of_range" }

    return { ok: true, destination: { host: bracketed[1]!.toLowerCase(), port } }
  }

  const bare = BARE_TARGET.exec(raw)

  if (bare === null) return { ok: false, reason: "malformed_connect_target" }

  const port = Number(bare[2])
  const host = bare[1]!.toLowerCase()

  if (port < 1 || port > 65535) return { ok: false, reason: "port_out_of_range" }
  // A bare IPv6 literal without brackets is ambiguous with `host:port`. Refusing it under its own
  // reason, rather than letting the generic malformed case swallow it, keeps the distinction
  // visible: this is a client that got the syntax wrong, not one that sent nonsense.
  if (host.includes(":")) return { ok: false, reason: "unbracketed_ipv6_target" }
  // Anything carrying a scheme, userinfo or path is not a `host:port` pair, and treating it as one
  // would mean resolving `https://api.github.com` as a hostname.
  if (/[/@?#\s]/.test(host)) return { ok: false, reason: "malformed_connect_target" }
  if (host.length === 0) return { ok: false, reason: "empty_host" }

  return { ok: true, destination: { host, port } }
}

export type DestinationHostVerdict =
  | { readonly allowed: true }
  | { readonly allowed: false; readonly host: string; readonly reason: string }

/**
 * Is this host in the allowlist?
 *
 * The rule syntax is the one the signed policy bundle already uses for `network_rules` —
 * `hostMatchesRule` from `network-target-guard.ts`. Reusing it means the proxy enforces the same
 * allowlist the sidecar enforces and the Tetragon profile projects, and there is no second place
 * for the two to disagree. That is also why this module takes a plain host list rather than
 * defining a rule object of its own.
 */
export const checkDestinationHost = (
  host: string,
  allowHosts: readonly string[],
): DestinationHostVerdict => {
  const target = host.toLowerCase()

  for (const ruleHost of allowHosts) {
    if (hostMatchesRule(target, ruleHost)) return { allowed: true }
  }

  return { allowed: false, host, reason: "host_not_allowlisted" }
}

/**
 * Normalise an allowlist host that is itself an IP literal.
 *
 * A rule naming `169.254.169.254` is a rule the address check will refuse anyway, and failing at
 * parse time means the operator sees the refusal on the rule rather than on a live request.
 */
export const normalizeAllowlistHost = (host: string): string => host.toLowerCase()