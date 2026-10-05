import assert from "node:assert/strict"
import { test } from "node:test"

import {
  checkNetworkTargets,
  collectNetworkTargets,
  MAX_TARGET_WALK_NODES,
} from "./network-target-guard.ts"
import { MAX_FRAME_BYTES } from "./sidecar-server.ts"

/**
 * S3: a policy must not be bypassable through any transport. These tests cover the
 * decision-layer target guard that makes the destination, not the tool, the thing checked.
 */

const RULES = [
  { host: "api.github.com", action: "allow_via_egress_gateway" as const },
  { host: "*.trusted.example", action: "allow_via_egress_gateway" as const },
  { host: "blocked.example", action: "deny" as const },
]

test("S3: an ordinary non-network argument is not treated as a target", () => {
  assert.deepEqual(
    collectNetworkTargets({ number: 42, method: "squash", dryRun: false }),
    [],
  )
})

test("S3: an https URL to the allowed host is permitted", () => {
  const result = checkNetworkTargets(
    { url: "https://api.github.com/repos/org/repo/issues" },
    { rules: RULES },
  )

  assert.equal(result.allowed, true)
})

test("S3: an https URL to any other host is denied", () => {
  const result = checkNetworkTargets(
    { url: "https://evil.example.com/collect" },
    { rules: RULES },
  )

  assert.equal(result.allowed, false)
  assert.equal(result.allowed === false && result.host, "evil.example.com")
})

test("S3: a raw IPv4 literal is denied even with no URL scheme", () => {
  const result = checkNetworkTargets("93.184.216.34:443", { rules: RULES })

  assert.equal(result.allowed, false)
  assert.equal(result.allowed === false && result.host, "93.184.216.34")
})

test("S3: an IPv6 loopback literal is denied", () => {
  const result = checkNetworkTargets("http://[::1]:9200/_cluster/health", {
    rules: RULES,
  })

  assert.equal(result.allowed, false)
})

test("S3: an IPv6 global literal is denied", () => {
  const result = checkNetworkTargets("http://[2606:4700:4700::1111]/collect", {
    rules: RULES,
  })

  assert.equal(result.allowed, false)
})

test("S3: a bare unbracketed IPv6 literal is denied", () => {
  const result = checkNetworkTargets("fd00::1", { rules: RULES })

  assert.equal(result.allowed, false)
  assert.equal(result.allowed === false && result.host, "fd00::1")
})

test("S3: userinfo in the authority cannot smuggle a different host", () => {
  // The host is the part after '@'. Reading the whole authority would let
  // `https://api.github.com@evil.example.com` look allowed.
  const result = checkNetworkTargets("https://api.github.com@evil.example.com/x", {
    rules: RULES,
  })

  assert.equal(result.allowed, false)
  assert.equal(result.allowed === false && result.host, "evil.example.com")
})

test("S3: a port does not change which host is matched", () => {
  const result = checkNetworkTargets("https://api.github.com:8443/x", {
    rules: RULES,
  })

  assert.equal(result.allowed, true)
})

test("S3: host matching is case-insensitive", () => {
  const result = checkNetworkTargets("https://API.GitHub.com/x", { rules: RULES })

  assert.equal(result.allowed, true)
})

test("S3: a wildcard rule covers subdomains but not the bare domain", () => {
  assert.equal(
    checkNetworkTargets("https://a.trusted.example/x", { rules: RULES }).allowed,
    true,
  )
  assert.equal(
    checkNetworkTargets("https://trusted.example/x", { rules: RULES }).allowed,
    false,
  )
})

test("S3: a wildcard rule does not cover a domain that merely ends with the text", () => {
  const result = checkNetworkTargets("https://nottrusted.example/x", {
    rules: RULES,
  })

  assert.equal(result.allowed, false)
})

test("S3: an explicit deny rule never permits, even for an exact host", () => {
  const result = checkNetworkTargets("https://blocked.example/x", { rules: RULES })

  assert.equal(result.allowed, false)
})

test("S3: with no rules at all, every network target is denied", () => {
  assert.equal(
    checkNetworkTargets("https://api.github.com/x", { rules: [] }).allowed,
    false,
  )
})

test("S3: a target hidden in a nested argument is still found", () => {
  const result = checkNetworkTargets(
    { nested: { list: ["safe", { deep: "https://evil.example.com/collect" }] } },
    { rules: RULES },
  )

  assert.equal(result.allowed, false)
})

test("S3: one bad target denies the whole request", () => {
  const result = checkNetworkTargets(
    { first: "https://api.github.com/x", second: "https://evil.example.com/y" },
    { rules: RULES },
  )

  assert.equal(result.allowed, false)
})

test("S3: a protocol-relative URL is still a target", () => {
  const result = checkNetworkTargets("//evil.example.com/collect", { rules: RULES })

  assert.equal(result.allowed, false)
})

// --- Availability of the boundary itself ------------------------------------------------
//
// These are S3 tests in the sense that matters here: a guard that can be made to hang is a
// guard an attacker can use to stop every other agent from being decided, and the sidecar is
// single-threaded, so a slow decision is a denial of service for every tenant sharing it.
//
// The regression that motivated them was a `URL_TARGET` regex whose optional scheme group made
// the engine retry at every start position. Measured in isolation it cost 31 s on the 256 KB
// letter run these tests use, and the full `checkNetworkTargets` path runs the scan twice per
// request on top of that. All of it is inside `MAX_FRAME_BYTES`, so one request from one agent
// held the sidecar long enough to deny service to every other agent sharing it.
//
// The bounds asserted here are deliberately loose. The fixed scan takes well under a
// millisecond; a thousand-fold margin still fails loudly on a superlinear scan while leaving
// no room for a slow or loaded machine to produce a false failure.

const timeScan = (value: unknown): number => {
  const started = process.hrtime.bigint()
  checkNetworkTargets(value, { rules: RULES })
  return Number(process.hrtime.bigint() - started) / 1e6
}

test("S3: an argument the size of a whole frame is decided promptly", () => {
  // The worst case for the old pattern was a long run of letters with no "//" anywhere, because
  // that is the shape that forces the most backtracking. The "//" suffix is included because the
  // old pattern was slow in that shape too.
  for (const shape of [
    "a".repeat(MAX_FRAME_BYTES),
    `${"a".repeat(MAX_FRAME_BYTES)}//h`,
  ]) {
    const elapsed = timeScan({ padding: shape })
    assert.ok(
      elapsed < 2000,
      `scanning a ${MAX_FRAME_BYTES}-byte argument took ${elapsed.toFixed(1)}ms, which is superlinear`,
    )
  }
})

test("S3: scanning cost grows with the request, not faster than it", () => {
  // Doubling the input must not multiply the work by anything like four. A quadratic scan fails
  // this by a wide margin; a linear one passes with room for noise.
  const smallMs = timeScan({ padding: "a".repeat(MAX_FRAME_BYTES / 4) })
  const largeMs = timeScan({ padding: "a".repeat(MAX_FRAME_BYTES) })

  assert.ok(
    largeMs <= smallMs * 4 + 20,
    `4x the input cost ${(largeMs / Math.max(smallMs, 0.01)).toFixed(1)}x the time, which suggests a superlinear scan`,
  )
})

test("S3: a request naming many distinct targets is decided promptly", () => {
  // De-duplication was a linear scan of the targets collected so far, which is quadratic in how
  // many there are. A request naming tens of thousands of hosts is how to reach it.
  const many = Array.from(
    { length: 20_000 },
    (_unused, index) => `https://h${index}.example/x`,
  )

  const elapsed = timeScan({ args: many })

  assert.ok(
    elapsed < 2000,
    `scanning 20000 distinct targets took ${elapsed.toFixed(1)}ms, which is superlinear`,
  )
})

test("S3: a permitted URL in front of a denied one does not hide it", () => {
  // An allowlist that reads only the first URL in a string is satisfied by putting the allowed
  // one first. Every "//" in the argument has to be checked, not just the leading one.
  const result = checkNetworkTargets(
    "https://api.github.com/x then https://evil.example.com/collect",
    { rules: RULES },
  )

  assert.equal(result.allowed, false)
  assert.equal(result.allowed === false && result.host, "evil.example.com")
})
/**
 * Availability of the enforcement path itself.
 *
 * `request.args` is written by the agent, which is the component this system assumes may be
 * fully compromised. The traversal is therefore bounded: a structure too large to inspect is
 * denied, not crashed on and not partially decided.
 */

const nested = (depth: number, leaf: unknown): unknown => {
  let node = leaf
  for (let i = 0; i < depth; i += 1) node = { nested: node }
  return node
}

test("S3: deeply nested arguments do not overflow the stack in the enforcement path", () => {
  // The guard used to recurse without a bound, so this raised a RangeError out of
  // checkNetworkTargets. handle() does not catch, so the sidecar died rather than denying.
  // Each level of nesting costs one visited node, so `MAX_TARGET_WALK_NODES` is the exact
  // depth boundary. Either side of it the call must return rather than throw.
  for (const depth of [1_000, 5_000, 100_000, 1_000_000]) {
    const result = checkNetworkTargets(nested(depth, "https://api.github.com/repos"), { rules: RULES })
    const withinBudget = depth <= MAX_TARGET_WALK_NODES

    if (withinBudget) {
      assert.deepEqual(result, { allowed: true }, `depth ${depth} should be decided on its merits`)
    } else {
      assert.equal(result.allowed, false, `depth ${depth} should be refused as uninspectable`)
      assert.equal(result.allowed === false && result.exhausted, true)
    }
  }
})

test("S3: a value too large to inspect is denied rather than partially allowed", () => {
  // The important direction. A *permitted* host in the visited prefix must not buy an allow
  // when the unvisited tail is unknown: the attacker chooses where the tail is.
  const result = checkNetworkTargets(nested(MAX_TARGET_WALK_NODES + 50, "https://api.github.com/repos"), {
    rules: RULES,
  })

  assert.equal(result.allowed, false)
  assert.equal(result.allowed === false && result.exhausted, true)
})

test("S3: a denied host hidden past the walk budget is still refused", () => {
  const result = checkNetworkTargets(nested(MAX_TARGET_WALK_NODES + 50, "https://evil.example.net/x"), {
    rules: RULES,
  })

  assert.equal(result.allowed, false)
})

test("S3: a value that throws on property access is denied without propagating", () => {
  // Object.values on a Proxy can throw. That is untrusted input, not an internal error.
  const hostile = new Proxy(
    {},
    {
      ownKeys() {
        throw new Error("trap")
      },
    },
  )

  let result
  try {
    result = checkNetworkTargets(hostile, { rules: RULES })
  } catch (error) {
    assert.fail(`a throwing property accessor escaped the guard: ${String(error)}`)
  }

  assert.equal(result.allowed, false)
})

test("S3: ordinary nesting within budget is still inspected normally", () => {
  // The budget must not change ordinary decisions, or it would be a silent deny-all.
  assert.deepEqual(
    checkNetworkTargets(
      { resource: "repo", args: { query: "https://api.github.com/user", retries: 3 } },
      { rules: RULES },
    ),
    { allowed: true },
  )
})
