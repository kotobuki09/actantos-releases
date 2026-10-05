import assert from "node:assert/strict"
import { BlockList } from "node:net"
import { test } from "node:test"

import {
  DEFAULT_ALLOWED_PORTS,
  EGRESS_BROKER_REQUIRED,
  EGRESS_CELL_MODES,
  EGRESS_CELL_NETWORK,
  EGRESS_CELL_PROXY_HOSTNAME,
  checkDestinationAddress,
  checkDestinationHost,
  egressCellTopology,
  parseConnectTarget,
  resolveEgressCellMode,
} from "./egress-cell.ts"

/* ------------------------------------------------------------------ mode resolution */

test("an unset cell mode is none, and none means the workload has no network", () => {
  assert.equal(resolveEgressCellMode(undefined), "none")
  assert.equal(resolveEgressCellMode("  "), "none")
  assert.equal(egressCellTopology("none").networkName, "none")
  assert.equal(egressCellTopology("none").hasNetwork, false)
})

test("an unrecognised cell mode throws rather than falling back", () => {
  // The default is `none`, so a tolerant parser here would look like a working deployment while
  // silently running no cell at all. This is the whole reason it throws.
  assert.throws(() => resolveEgressCellMode("egress_prox"), /ACTANTOS_EGRESS_CELL/)
  assert.throws(() => resolveEgressCellMode("allowed"), /ACTANTOS_EGRESS_CELL/)
  assert.throws(() => resolveEgressCellMode("true"), /ACTANTOS_EGRESS_CELL/)
})

test("every declared cell mode parses back to itself", () => {
  for (const mode of EGRESS_CELL_MODES) {
    assert.equal(resolveEgressCellMode(mode), mode)
    assert.equal(resolveEgressCellMode(mode.toUpperCase()), mode)
    assert.equal(resolveEgressCellMode(` ${mode} `), mode)
  }
})

/* ------------------------------------------------------------------ topology */

test("broker_only leaves the workload with no network and flags the call as unbrokerable", () => {
  const topology = egressCellTopology("broker_only")

  assert.equal(topology.networkName, "none")
  assert.equal(topology.hasNetwork, false)
  assert.equal(topology.brokerRequired, true)
  assert.equal(EGRESS_BROKER_REQUIRED, "egress_broker_required")
})

test("broker_only and none differ only in whether the refusal is visible to the operator", () => {
  // Both give the workload no network. Only broker_only says so at decision time, so an operator
  // can distinguish "you cannot have this here" from "your command failed". If this test ever
  // fails because the two modes converged, the operator-facing reason code is gone.
  assert.notEqual(egressCellTopology("broker_only").brokerRequired, egressCellTopology("none").brokerRequired)
  assert.equal(egressCellTopology("none").networkName, egressCellTopology("broker_only").networkName)
})

test("egress_proxy puts the workload on an internal network, not a bridge", () => {
  const topology = egressCellTopology("egress_proxy")

  assert.equal(topology.networkName, EGRESS_CELL_NETWORK)
  assert.equal(topology.internal, true)
  assert.equal(topology.hasNetwork, true)
  assert.equal(topology.brokerRequired, false)
  // The old name was `actantos_egress` and it was a plain bridge with no proxy on it.
  assert.notEqual(EGRESS_CELL_NETWORK, "actantos_egress")
  assert.equal(EGRESS_CELL_PROXY_HOSTNAME, "actantos-egress-proxy")
})

test("no mode other than egress_proxy grants a network", () => {
  for (const mode of EGRESS_CELL_MODES) {
    assert.equal(egressCellTopology(mode).hasNetwork, mode === "egress_proxy")
  }
})

/* ------------------------------------------------------------------ address policy */

test("public addresses are allowed through the cell", () => {
  for (const address of ["1.1.1.1", "8.8.8.8", "93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"]) {
    assert.equal(checkDestinationAddress(address).allowed, true, address)
  }
})

test("loopback, private, link-local and metadata addresses are refused", () => {
  const denied = [
    "127.0.0.1",
    "127.1.2.3",
    "10.0.0.5",
    "172.16.0.1",
    "172.31.255.254",
    "192.168.1.1",
    "169.254.169.254", // The cloud metadata endpoint.
    "100.64.0.1",
    "0.0.0.0",
    "224.0.0.1",
    "255.255.255.255",
  ]

  for (const address of denied) {
    const verdict = checkDestinationAddress(address)
    assert.equal(verdict.allowed, false, address)
    assert.equal(verdict.reason, "address_not_routable_from_the_cell")
  }
})

test("an IPv6 address that writes an IPv4 address is refused just like the IPv4 form", () => {
  // `::ffff:169.254.169.254` and `::ffff:127.0.0.1` reach the same endpoints as the bare forms.
  // An address check that only listed the IPv4 ranges would pass both of these.
  for (const address of ["::ffff:169.254.169.254", "::ffff:127.0.0.1", "::ffff:10.0.0.1"]) {
    const verdict = checkDestinationAddress(address)
    assert.equal(verdict.allowed, false, address)
    assert.equal(verdict.reason, "address_not_routable_from_the_cell")
  }
})

test("a NAT64 prefix cannot smuggle an IPv4 destination past the cell", () => {
  // 64:ff9b::/96 is the well-known translation prefix. Written as `64:ff9b::a9fe:a9fe` this is
  // 169.254.169.254, and a resolver on a NAT64 network will happily return it.
  const verdict = checkDestinationAddress("64:ff9b::a9fe:a9fe")

  assert.equal(verdict.allowed, false)
  assert.equal(verdict.reason, "address_not_routable_from_the_cell")
})

test("IPv6 loopback, unique-local, link-local and multicast are refused", () => {
  for (const address of ["::1", "::", "fc00::1", "fd12:3456::1", "fe80::1", "ff02::1"]) {
    assert.equal(checkDestinationAddress(address).allowed, false, address)
  }
})

test("a public IPv6 address immediately after a denied range boundary is still allowed", () => {
  // A prefix-length mistake here is the classic way a deny list silently stops denying, so both
  // sides of the boundary are asserted rather than only the denied one.
  assert.equal(checkDestinationAddress("172.15.255.255").allowed, true)
  assert.equal(checkDestinationAddress("172.16.0.0").allowed, false)
  assert.equal(checkDestinationAddress("172.31.255.255").allowed, false)
  assert.equal(checkDestinationAddress("172.32.0.0").allowed, true)
  // A /16 at 169.254 ends at 169.254.255.255. 169.255.0.0 is the next network and is allowed —
  // asserting the whole 169/8 is private would be a wider deny list than the policy declares.
  assert.equal(checkDestinationAddress("169.253.255.255").allowed, true)
  assert.equal(checkDestinationAddress("169.254.0.0").allowed, false)
  assert.equal(checkDestinationAddress("169.254.255.255").allowed, false)
  assert.equal(checkDestinationAddress("169.255.0.0").allowed, true)
  assert.equal(checkDestinationAddress("fdff::1").allowed, false)
  assert.equal(checkDestinationAddress("fe00::1").allowed, true)
})

test("something that is not an address at all is refused rather than passed through", () => {
  // "I could not classify this" and "this is fine" must not produce the same answer, or a parsing
  // bug anywhere upstream becomes an allow.
  for (const value of ["example.com", "", "1.2.3.4.5", "1.2.3", "999.1.1.1", "not-an-ip"]) {
    const verdict = checkDestinationAddress(value)
    assert.equal(verdict.allowed, false, value)
    assert.equal(verdict.reason, "not_an_ip_address")
  }
})

test("an IPv4-mapped or NAT64 wrapper carrying a public address is allowed on its merits", () => {
  // These are not blanket-denied prefixes. Each carries an IPv4 address, and the answer is whatever
  // that address deserves — so a legitimate dual-stack or NAT64 client still works.
  for (const address of ["::ffff:93.184.216.34", "::ffff:8.8.8.8", "64:ff9b::5db8:d822", "::93.184.216.34"]) {
    assert.equal(checkDestinationAddress(address).allowed, true, address)
  }
})

test("the two address families stay in separate BlockLists, because merging them is unsound", () => {
  // This is the reason `buildDeniedIpv4` and `buildDeniedIpv6` exist as two objects rather than one.
  // Adding the IPv4-mapped prefix to a shared list makes *every* IPv4 address match it, which would
  // turn the cell's deny list into a deny-everything list. Reproduced here so that a future
  // refactor to a single list fails this test instead of silently breaking every deployment.
  const shared = new BlockList()
  shared.addSubnet("10.0.0.0", 8, "ipv4")
  assert.equal(shared.check("8.8.8.8", "ipv4"), false)

  shared.addSubnet("::ffff:0:0", 96, "ipv6")

  // Node v26.4.0 behaviour this module works around: the public address is now denied.
  assert.equal(shared.check("8.8.8.8", "ipv4"), true)

  // The split design does not have that failure, which is the property under test.
  assert.equal(checkDestinationAddress("8.8.8.8").allowed, true)
})

/* ------------------------------------------------------------------ connect target parsing */

test("a well-formed CONNECT target parses to host and port", () => {
  assert.deepEqual(parseConnectTarget("api.github.com:443"), {
    ok: true,
    destination: { host: "api.github.com", port: 443 },
  })
  assert.deepEqual(parseConnectTarget("API.GitHub.com:443"), {
    ok: true,
    destination: { host: "api.github.com", port: 443 },
  })
})

test("a bracketed IPv6 CONNECT target parses without losing the address", () => {
  assert.deepEqual(parseConnectTarget("[2606:2800::1]:443"), {
    ok: true,
    destination: { host: "2606:2800::1", port: 443 },
  })
})

test("malformed CONNECT targets are refused instead of repaired", () => {
  // The proxy never guesses what a compromised workload meant.
  const refused = ["api.github.com", "api.github.com:", "api.github.com:0", "api.github.com:99999", ":443", "https://api.github.com:443"]

  for (const target of refused) {
    assert.equal(parseConnectTarget(target).ok, false, target)
  }
})

test("an unbracketed IPv6 CONNECT target is refused as ambiguous", () => {
  // `2606:2800::1:443` is a valid address *or* a host and a port, depending on who is asking.
  // Choosing an interpretation on the workload's behalf is how a bypass gets written.
  const result = parseConnectTarget("2606:2800::1:443")

  assert.equal(result.ok, false)
  assert.equal(result.ok === false && result.reason, "unbracketed_ipv6_target")
})

/* ------------------------------------------------------------------ host allowlist */

test("the host allowlist matches exactly and by suffix, and nothing else", () => {
  const allowlist = ["api.github.com", "*.trusted.example"]

  assert.equal(checkDestinationHost("api.github.com", allowlist).allowed, true)
  assert.equal(checkDestinationHost("API.GITHUB.COM", allowlist).allowed, true)
  assert.equal(checkDestinationHost("a.trusted.example", allowlist).allowed, true)
  assert.equal(checkDestinationHost("deep.nested.trusted.example", allowlist).allowed, true)

  assert.equal(checkDestinationHost("evil.example.com", allowlist).allowed, false)
  assert.equal(checkDestinationHost("api.github.com.evil.test", allowlist).allowed, false)
  // A suffix match must not be satisfied by a rule that is a *parent* of the suffix.
  assert.equal(checkDestinationHost("trusted.example", allowlist).allowed, false)
  assert.equal(checkDestinationHost("nottrusted.example", allowlist).allowed, false)
})

test("an empty allowlist allows nothing", () => {
  assert.equal(checkDestinationHost("api.github.com", []).allowed, false)
})

test("the default permitted ports are the two a client needs to do anything useful", () => {
  assert.deepEqual(DEFAULT_ALLOWED_PORTS, [80, 443])
})