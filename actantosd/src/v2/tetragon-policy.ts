/**
 * Tetragon tracing-policy generator (invariant S3, runtime backstop).
 *
 * ## What this is, and what it is not
 *
 * This module *compiles* the signed policy bundle into a Tetragon TracingPolicy. It is a
 * compiler, not a second policy language: every value it emits traces back to
 * `PolicyBundleBody`, except `deniedBinaries`, which is deployment configuration and is
 * marked as such below. Nothing here is authored independently of the signed bundle, so a
 * bundle rotation automatically rotates the runtime policy.
 *
 * It observes and evidences, it does not authorize. Enforcement of S3 happens in the
 * sidecar decision layer (`network-target-guard.ts`) and in the network cell. A Tetragon
 * action that kills a process is emitted only when the profile explicitly asks for
 * `enforce`, because the failure mode of an enforcement path is worse than the failure mode
 * of an observation path.
 *
 * ## Measured substrate behaviour (Tetragon v1.1.2, Docker Desktop linux/amd64 on WSL2)
 *
 * Every shape below was imported on a live Tetragon v1.1.2 container and reported
 * `enabled` with a loaded sensor (`gkp-sensor-N`). These findings are load-time facts:
 *
 * - A `labels:` field is rejected at kprobe level (YAML/CRD parse error) and at policy
 *   level (`spec.labels` gives `json: unknown field "labels"`). A policy with no `labels`
 *   field loads. This generator therefore emits no labels, and the runtime adapter
 *   attributes events using the bundle, not a Tetragon-side label.
 * - `sys_enter_execve` cannot be attached through `tetra tracingpolicy add`:
 *   `kprobe spec pre-validation failed: call "sys_enter_execve" type name sys_enter_execve:
 *   not found`. `security_bprm_check` and `tcp_connect` do resolve, and are used instead.
 * - A built-in base sensor fails to load on this kernel with
 *   `detect modify return syscall ... __x64_sys_getcpu() is not modifiable`, and startup
 *   warns `procfs does not appear to be host procfs`. Neither prevents the kprobe sensors
 *   in this file from loading.
 * - NOT VERIFIED: whether the kprobe events reach the exporter was, until the next paragraph,
 *   unknown. It is now measured. See "Measured on v1.7.1" below.
 */

/**
 * ## Measured on Tetragon v1.7.1 (kernel 6.18.33.2-microsoft-standard-WSL2)
 *
 * The v1.1.2 findings above still hold, but running the *emitted* policy against v1.7.1 found a
 * defect in this module, and running it correctly found that events do flow on this kernel after
 * all. Both facts are recorded because the earlier ones were wrong:
 *
 * 1. **`operator: Mask` is not loadable.** Every kprobe using it was refused outright:
 *    `MatchArgs type linux_binprm unsupported` for the bprm hook and `MatchArgs type file
 *    unsupported` for the file hook. So this module's output could not be installed on a current
 *    agent at all. The fix is `operator: Equal`, which is also the semantically correct operator
 *    here — `deniedBinaries` and `deniedWritePaths` are exact absolute paths, not masks. The
 *    tracepoints and LSM probes below were *never* the blocker; the emitter was.
 *
 * 2. **Events do fire on this kernel.** The earlier claim that "no event originating from a
 *    user-supplied TracingPolicy was observed" was a measurement error: the probe read the
 *    agent's *stdout*, but Tetragon exports events to a file (`/var/log/tetragon/tetragon.log` by
 *    default) and writes nothing event-shaped to stdout. Reading the exporter instead:
 *    `security_bprm_check` events were observed in the hundreds, and `security_file_permission`
 *    in the thousands.
 *
 * 3. **The selectors are exact.** Three `touch` invocations under
 *    `operator: Equal` on `/usr/bin/touch` produced exactly three events, against 130 for the
 *    same policy with no selector and 75 with a `Prefix` selector. `Equal` is not a fallback that
 *    loses the filter; it is a real filter.
 *
 * What is still unverified is the *exec* path specifically: the built-in base sensor fails to
 * load on this kernel with `__x64_sys_getcpu() is not modifiable`, so `process_exec` events come
 * from the base sensor and not from this module's policy. `security_bprm_check` and
 * `security_file_permission` are kprobes on real symbols and do fire, which is why this module's
 * two path-based probes are measured rather than assumed. Treat the base-sensor exec stream as
 * still unverified here, and do not make an invariant depend on it. See
 * `docs/ARCHITECTURE_V2.md`.
 */

import type { PolicyBundleBody } from "./signed-policy-bundle.ts"

/**
 * Tetragon `matchActions`. `Post` emits the event; the others ask the BPF enforcer to act.
 *
 * `SIGKILL`/`SIGTERM` send a signal to the offending task. They are only meaningful when
 * the enforcer is enabled, which is exactly what this substrate cannot currently confirm.
 */
export const TETRAGON_ACTIONS = ["Post", "SIGKILL", "SIGTERM", "Kill"] as const

export type TetragonAction = (typeof TETRAGON_ACTIONS)[number]

/**
 * Runtime profile: the projection of a signed bundle onto what a kernel sensor can see.
 *
 * `deniedBinaries` and `deniedWritePaths` are the only fields not present in the bundle.
 * A binary path cannot be derived from a logical tool name without inventing a mapping
 * table, and that mapping table would itself be a second policy language. So they are
 * supplied as deployment configuration, and the caller is expected to scope them to the
 * agent container rather than to the whole host.
 */
export type TetragonRuntimeProfile = {
  /** Must be a DNS-1123 subdomain; Tetragon uses it as the policy name. */
  readonly policyName: string
  /** Absolute paths whose execution is a signal of a policy bypass. */
  readonly deniedBinaries: readonly string[]
  /** Destination ports whose connection is a signal of a policy bypass. */
  readonly deniedPorts: readonly number[]
  /** Absolute paths whose write is a signal of an unauthorized effect. */
  readonly deniedWritePaths: readonly string[]
  /**
   * Hosts the runtime treats as permitted destinations, projected from the bundle's
   * `network_rules` entries whose action is `allow_via_egress_gateway`. Used by the event
   * adapter to tell an off-list destination from an ordinary one. Empty means "no allowlist
   * configured", which the adapter treats as "do not classify destinations at all" rather
   * than "classify everything as denied".
   */
  readonly networkAllowlistHosts: readonly string[]
  /**
   * `observe` emits events only. `enforce` additionally asks the BPF enforcer to kill the
   * offending task. Defaults to `observe`, because an unverified enforcement action is
   * worse than a missing one.
   */
  readonly mode?: "observe" | "enforce"
  /** Tenant the profile was derived from. Carried for adapter-side attribution only. */
  readonly tenantId: string
  /** Agent the profile was derived from. Carried for adapter-side attribution only. */
  readonly agentId: string
}

const DNS_1123 = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$/

const assertPolicyName = (name: string): void => {
  if (name.length === 0 || name.length > 63 || !DNS_1123.test(name)) {
    throw new Error(
      `Tetragon policy name must be a DNS-1123 subdomain of 1-63 characters: "${name}"`,
    )
  }
}

const assertAbsolutePaths = (values: readonly string[], field: string): void => {
  for (const value of values) {
    if (!value.startsWith("/")) {
      throw new Error(`${field} entries must be absolute paths: "${value}"`)
    }
  }
}

const assertPorts = (values: readonly number[]): void => {
  for (const value of values) {
    if (!Number.isInteger(value) || value <= 0 || value > 65535) {
      throw new Error(`deniedPorts entries must be TCP/UDP ports: ${value}`)
    }
  }
}

const actionFor = (mode: "observe" | "enforce"): TetragonAction =>
  mode === "enforce" ? "SIGKILL" : "Post"

type Kprobe = {
  readonly call: string
  readonly args: readonly { readonly index: number; readonly type: string }[]
  readonly selectors: readonly {
    readonly matchArgs: readonly {
      readonly index: number
      readonly operator: string
      readonly values: readonly string[]
    }[]
    readonly matchActions: readonly { readonly action: TetragonAction }[]
  }[]
}

export type TracingPolicy = {
  readonly apiVersion: "cilium.io/v1alpha1"
  readonly kind: "TracingPolicy"
  readonly metadata: { readonly name: string }
  readonly spec: { readonly kprobes: readonly Kprobe[] }
}

const bprmCheckKprobe = (
  binaries: readonly string[],
  action: TetragonAction,
): Kprobe | undefined =>
  binaries.length === 0
    ? undefined
    : {
        call: "security_bprm_check",
        args: [{ index: 0, type: "linux_binprm" }],
        selectors: [
          {
            // `Equal`, not `Mask`. Measured against Tetragon v1.7.1: a `linux_binprm` arg with
            // `operator: Mask` is refused outright at load with
            // `writeMatchValues error: MatchArgs type linux_binprm unsupported`, so the policy
            // this module emitted could never be installed on a current agent. `Equal` loads and
            // is exact: three `touch` invocations produced exactly three events, against 130 for
            // a policy with no selector. See the module doc comment.
            matchArgs: [{ index: 0, operator: "Equal", values: binaries }],
            matchActions: [{ action }],
          },
        ],
      }

const tcpConnectKprobe = (
  ports: readonly number[],
  action: TetragonAction,
): Kprobe | undefined =>
  ports.length === 0
    ? undefined
    : {
        call: "tcp_connect",
        args: [{ index: 0, type: "sock" }],
        selectors: [
          {
            matchArgs: [
              {
                index: 0,
                operator: "DPort",
                values: ports.map((port) => String(port)),
              },
            ],
            matchActions: [{ action }],
          },
        ],
      }

/**
 * `security_file_permission` takes (file, mode). Only write and write/truncate bits
 * (S_IWUSR = 2) are selected. A pure write is what an unauthorized effect looks like at
 * the syscall layer.
 */
const fileWriteKprobe = (
  paths: readonly string[],
  action: TetragonAction,
): Kprobe | undefined =>
  paths.length === 0
    ? undefined
    : {
        call: "security_file_permission",
        args: [
          { index: 0, type: "file" },
          { index: 1, type: "int" },
        ],
        selectors: [
          {
            matchArgs: [
              { index: 1, operator: "Equal", values: ["2"] },
              // `Equal`, not `Mask`, for the same measured reason as the bprm hook above: a `file`
              // arg with `operator: Mask` is refused at load by Tetragon v1.7.1 with
              // `MatchArgs type file unsupported`. `Equal` loads and matches the exact path.
              { index: 0, operator: "Equal", values: paths },
            ],
            matchActions: [{ action }],
          },
        ],
      }

/**
 * Build the TracingPolicy object. Omit a kprobe entirely when its selector list is empty,
 * because a kprobe with no selector attaches to every call of that symbol and adds cost
 * without adding a signal.
 */
export const buildTracingPolicy = (
  profile: TetragonRuntimeProfile,
): TracingPolicy => {
  assertPolicyName(profile.policyName)
  assertAbsolutePaths(profile.deniedBinaries, "deniedBinaries")
  assertAbsolutePaths(profile.deniedWritePaths, "deniedWritePaths")
  assertPorts(profile.deniedPorts)

  const action = actionFor(profile.mode ?? "observe")

  const kprobes = [
    bprmCheckKprobe(profile.deniedBinaries, action),
    tcpConnectKprobe(profile.deniedPorts, action),
    fileWriteKprobe(profile.deniedWritePaths, action),
  ].filter((kprobe): kprobe is Kprobe => kprobe !== undefined)

  if (kprobes.length === 0) {
    throw new Error(
      "Tetragon profile selects nothing: at least one of deniedBinaries, deniedPorts or deniedWritePaths must be non-empty",
    )
  }

  return {
    apiVersion: "cilium.io/v1alpha1",
    kind: "TracingPolicy",
    // No `labels`. Tetragon v1.1.2 rejects them; see the module doc comment.
    metadata: { name: profile.policyName },
    spec: { kprobes },
  }
}

const yamlScalar = (value: string | number): string =>
  typeof value === "number" ? String(value) : `"${value.replace(/"/g, '\\"')}"`

/**
 * Emit the exact YAML text. Written by hand rather than with a YAML library because the
 * schema is fixed and small, and adding a dependency for it would be a larger change than
 * the output is worth.
 *
 * The output is what was loaded by the live Tetragon v1.1.2 check in the module comment.
 */
export const toTracingPolicyYaml = (policy: TracingPolicy): string => {
  const lines: string[] = [
    `apiVersion: ${policy.apiVersion}`,
    `kind: ${policy.kind}`,
    "metadata:",
    `  name: ${policy.metadata.name}`,
    "spec:",
    "  kprobes:",
  ]

  for (const kprobe of policy.spec.kprobes) {
    lines.push(`    - call: ${yamlScalar(kprobe.call)}`)
    lines.push("      syscall: false")
    lines.push("      args:")
    for (const arg of kprobe.args) {
      lines.push(`        - index: ${arg.index}`)
      lines.push(`          type: ${yamlScalar(arg.type)}`)
    }
    lines.push("      selectors:")
    for (const selector of kprobe.selectors) {
      lines.push("        - matchArgs:")
      for (const match of selector.matchArgs) {
        lines.push(`            - index: ${match.index}`)
        lines.push(`              operator: ${yamlScalar(match.operator)}`)
        lines.push("              values:")
        for (const value of match.values) {
          lines.push(`                - ${yamlScalar(value)}`)
        }
      }
      lines.push("          matchActions:")
      for (const matchAction of selector.matchActions) {
        lines.push(`            - action: ${matchAction.action}`)
      }
    }
  }

  return `${lines.join("\n")}\n`
}

/**
 * Project a signed bundle onto the runtime profile.
 *
 * Ports come from `network_rules`: every rule that names a port contributes it, because the
 * runtime observes connections whether the rule allows or denies them, and lets the bundle
 * decide. Rules without a port are skipped — a hostname rule cannot be expressed as a
 * kprobe selector, and pretending otherwise would be a false signal.
 *
 * The bundle digest is returned so a caller can bind generated policy to the bundle it
 * came from, and so evidence records can cite the exact policy in force at runtime.
 */
export const runtimeProfileFromBundle = (
  body: PolicyBundleBody,
  deployment: {
    readonly policyName: string
    readonly deniedBinaries: readonly string[]
    readonly deniedWritePaths: readonly string[]
    readonly mode?: "observe" | "enforce" | undefined
  },
): TetragonRuntimeProfile => {
  const ports = [
    ...new Set(
      body.network_rules.flatMap((rule) =>
        rule.port === undefined ? [] : [rule.port],
      ),
    ),
  ].sort((left, right) => left - right)

  return {
    policyName: deployment.policyName,
    deniedBinaries: [...deployment.deniedBinaries],
    deniedPorts: ports,
    deniedWritePaths: [...deployment.deniedWritePaths],
    networkAllowlistHosts: [
      ...new Set(
        body.network_rules
          .filter((rule) => rule.action === "allow_via_egress_gateway")
          .map((rule) => rule.host),
      ),
    ],
    ...(deployment.mode === undefined ? {} : { mode: deployment.mode }),
    tenantId: body.tenant_id,
    agentId: body.agent_profile.agent_id,
  }
}