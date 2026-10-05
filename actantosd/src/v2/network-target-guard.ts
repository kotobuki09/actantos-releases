/**
 * Network target guard (invariant S3).
 *
 * S3 says a policy must not be bypassable "through curl, Python sockets, Node HTTP, shell
 * tools, child processes, raw MCP calls, IPv6, or alternate DNS". Every one of those is the
 * same attack with a different transport, so the check belongs on the *destination*, not on
 * the API used to reach it.
 *
 * The guard therefore does not try to recognise tools. It collects the network targets a
 * request names — URLs, IPv4 literals, IPv6 literals — wherever they appear, and requires
 * each one to be covered by a network rule from the signed policy bundle.
 *
 * Relationship to v1: `src/url-target-guard.ts` is an SSRF *blocklist* on the v1 interception
 * path, denying known-bad destinations such as link-local metadata endpoints. This one is an
 * *allowlist* on the v2 sidecar path, driven by the signed bundle rather than by a fixed list.
 * An allowlist is what S3 needs, because a blocklist has to guess every name an attacker can
 * reach. Both remain: the blocklist is defence in depth, not a replacement.
 *
 * Honest limits, stated rather than hidden:
 *
 * - It is a decision-layer guard. It constrains requests that pass through the sidecar; it
 *   does not by itself stop a workload that never speaks to the sidecar. That is what the
 *   network cell (Phase 3) is for.
 * - It recognises URL forms, IPv4 literals and bracketed IPv6 literals. A bare hostname in a
 *   free-form string is not treated as a target, because guessing would deny legitimate
 *   arguments; the network cell is the backstop for that case.
 * - The scan is linear in the size of the request. That is a security property rather than a
 *   tuning detail: this guard runs inside the sidecar, on the request path, once per decision,
 *   so a superlinear scan is a denial of service that one agent can trigger against all the
 *   others with a single well-formed request. See `URL_TARGET_AT` for the failure it replaced.
 */

export type NetworkRule = {
  readonly host: string
  readonly action: "deny" | "allow_via_egress_gateway"
}

/**
 * `//host` — the authority that follows a `//`, whether or not a scheme precedes it.
 *
 * This is the capture half of the original `URL_TARGET` pattern, with the `y` (sticky) flag and
 * the scheme group removed. The scheme is optional in the original, so every `//` in a string
 * is a target boundary regardless of what comes before it; keeping the scheme would only add a
 * way to fail to recognise one.
 *
 * The `y` flag is the whole point of this constant. Without it the engine searches: it retries
 * the match at every later start position, and because the scheme group was optional and greedy
 * it first consumed the entire remaining run looking for a `:` before backtracking one character
 * at a time. That is quadratic in the length of the string. Measured in isolation on this
 * pattern, a run of letters cost 1.8 s at 64 KB, 7.5 s at 128 KB and 31 s at 256 KB — and
 * through the full `checkNetworkTargets` path, which runs the scan twice per request, worse.
 * Every one of those frames is inside `MAX_FRAME_BYTES`, so a single well-formed request from a
 * single agent could occupy the sidecar for half a minute and stop every other agent from being
 * served.
 *
 * Sticky removes the search: `lastIndex` is set to a `//` already located by the native
 * `indexOf` scan, so there is exactly one position to try and the cost is one match attempt.
 * The capture class `[^/?#\s"']+` is unchanged, so the set of strings treated as URLs is
 * unchanged too.
 */
const URL_TARGET_AT = /\/\/([^/?#\s"']+)/y

const IPV4_LITERAL = /(?:^|[^0-9])((?:[0-9]{1,3}\.){3}[0-9]{1,3})(?:[^0-9]|$)/
const BRACKETED_IPV6 = /\[([0-9A-Fa-f:.]+)\]/
/** Unbracketed IPv6 contains at least two colons; no hostname does. */
const BARE_IPV6 = /^(?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Fa-f:.]*$/

/**
 * Reduce a URL authority to its host: drop userinfo, unwrap IPv6 brackets, drop the port.
 */
const hostFromAuthority = (authority: string): string => {
  const afterUserInfo = authority.slice(authority.lastIndexOf("@") + 1)
  const unbracketed = afterUserInfo.startsWith("[")
    ? (BRACKETED_IPV6.exec(afterUserInfo)?.[1] ?? afterUserInfo)
    : afterUserInfo
  const colon = unbracketed.indexOf(":")

  return (colon === -1 ? unbracketed : unbracketed.slice(0, colon)).toLowerCase()
}

/**
 * Upper bound on the number of values walked in one request.
 *
 * `request.args` is written by the agent, which is the component this whole system assumes may
 * be fully compromised. Recursing over it without a bound means a few thousand levels of
 * nesting raises a `RangeError` inside the enforcement path, and `handle()` does not catch — so
 * the sidecar dies rather than denying. A denial is the correct answer for a structure this far
 * outside anything a legitimate tool call produces, and it costs the attacker nothing to trigger.
 */
export const MAX_TARGET_WALK_NODES = 10_000

/**
 * True when the walk hit its budget, meaning the value was not fully inspected.
 *
 * Truncating silently would be fail-open: the unvisited tail could hold any host at all. The
 * caller must treat this as a denial.
 */
export type TargetWalkResult = {
  readonly targets: readonly string[]
  readonly exhausted: boolean
}

/**
 * Walk `value` with an explicit stack instead of recursion.
 *
 * An explicit stack plus a node budget removes both availability failure modes at once: stack
 * depth no longer grows with input nesting, and a hostile structure is bounded work rather than
 * a crash. Property access is guarded because `value` is untrusted and a `Proxy` trap may throw.
 */
const walkTargets = (root: unknown): TargetWalkResult => {
  const targets: string[] = []
  const seen = new Set<string>(targets)
  const stack: unknown[] = [root]
  let visited = 0

  while (stack.length > 0) {
    if (visited >= MAX_TARGET_WALK_NODES) {
      return { targets, exhausted: true }
    }
    visited += 1

    const value = stack.pop()

    if (typeof value === "string") {
      scanStringTargets(value, targets, seen)
      continue
    }

    if (Array.isArray(value)) {
      for (const item of value) stack.push(item)
      continue
    }

    if (value !== null && typeof value === "object") {
      let values: unknown[]
      try {
        values = Object.values(value)
      } catch {
        // A throwing Proxy trap is untrusted input that cannot be inspected. Treat the whole
        // value as uninspectable rather than as target-free.
        return { targets, exhausted: true }
      }
      for (const nested of values) stack.push(nested)
    }
  }

  return { targets, exhausted: false }
}

/**
 * Every network target named anywhere in a request value.
 *
 * Strings are the only place a target can hide; numbers, booleans and null are ignored. A
 * value that carries several targets contributes all of them, so hiding one in a compound
 * argument does not help.
 */
export const collectNetworkTargets = (
  value: unknown,
  targets: string[] = [],
): string[] => {
  const walked = walkTargets(value)
  for (const host of walked.targets) {
    if (!targets.includes(host)) targets.push(host)
  }
  return targets
}

/**
 * `seen` is carried alongside `targets` so de-duplication is a set lookup rather than a scan
 * of the array. A request naming tens of thousands of distinct hosts would otherwise be
 * quadratic in the number of targets, which is the same availability failure as the regex
 * search this replaced, one function down.
 */
const scanStringTargets = (
  value: string,
  targets: string[],
  seen: Set<string>,
): void => {
  const add = (host: string): void => {
    if (host.length > 0 && !seen.has(host)) {
      seen.add(host)
      targets.push(host)
    }
  }

  // `//` is rare in ordinary arguments, and `indexOf` is a native scan with no backtracking.
  // Every `//` in the string is considered, not just the first: an allowlist that inspected one
  // URL per string would be satisfied by a permitted URL placed in front of a denied one, which
  // is the substitution S3 exists to prevent.
  let from = 0

  for (;;) {
    const at = value.indexOf("//", from)

    if (at === -1) {
      break
    }

    from = at + 2
    URL_TARGET_AT.lastIndex = at

    const match = URL_TARGET_AT.exec(value)

    if (match?.[1] !== undefined) {
      add(hostFromAuthority(match[1]))
    }
  }

  // Each remaining pattern needs a character an argument almost never carries. `includes` is
  // a native linear scan, so testing for the character first is what keeps these unanchored
  // patterns from being retried across a large string that cannot possibly match.
  if (value.includes("[")) {
    const bracketed = BRACKETED_IPV6.exec(value)

    if (bracketed?.[1] !== undefined) {
      add(bracketed[1].toLowerCase())
    }
  }

  if (value.includes(".")) {
    const ipv4 = IPV4_LITERAL.exec(value)

    if (ipv4?.[1] !== undefined) {
      add(ipv4[1])
    }
  }

  // A bare IPv6 literal only exists as a whole value, because colons also appear inside URLs
  // and arguments. Requiring the entire string to be the address keeps this from matching
  // ordinary text.
  if (value.includes("::") && BARE_IPV6.test(value)) {
    add(value.toLowerCase())
  }
}

/**
 * A rule host may be exact, or `*.example.com` for any subdomain.
 *
 * Exported because the egress proxy enforces the same `network_rules` allowlist, against the
 * address it actually resolved. Two independent wildcard matchers would be two places for the
 * decision layer and the network layer to disagree about what `*.example.com` means.
 */
export const hostMatchesRule = (host: string, ruleHost: string): boolean => {
  const rule = ruleHost.toLowerCase()

  if (rule.startsWith("*.")) {
    const suffix = rule.slice(1)

    return host.endsWith(suffix)
  }

  return host === rule
}

export type TargetCheckResult =
  | { readonly allowed: true }
  | {
      readonly allowed: false
      readonly host: string
      /**
       * True when the request value was too large to inspect completely, so the denial is a
       * budget decision rather than a rule match. This is the fail-closed path: the unvisited
       * tail is unknown, and unknown is denied.
       */
      readonly exhausted?: boolean
    }

export type CheckNetworkTargetsOptions = {
  readonly rules: readonly NetworkRule[]
}

/**
 * Every target must be covered by an allowing rule.
 *
 * A target with no matching rule is denied. There is no implicit allow for a hostname that
 * happens to look benign, because that would reintroduce exactly the bypass S3 forbids.
 */
export const checkNetworkTargets = (
  value: unknown,
  options: CheckNetworkTargetsOptions,
): TargetCheckResult => {
  const walked = walkTargets(value)

  // The request value could not be walked to the end. Deny rather than decide on the prefix
  // that happened to be visited: an attacker controls where the unvisited tail is.
  if (walked.exhausted) {
    return { allowed: false, host: "<uninspectable>", exhausted: true }
  }

  for (const target of walked.targets) {
    const allowed = options.rules.some(
      (rule) =>
        rule.action === "allow_via_egress_gateway" &&
        hostMatchesRule(target, rule.host),
    )

    if (!allowed) {
      return { allowed: false, host: target }
    }
  }

  return { allowed: true }
}