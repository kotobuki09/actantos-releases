/**
 * Tetragon runtime-event adapter.
 *
 * Turns a stream of exported Tetragon events into evidence records. The kprobes in
 * `tetragon-policy.ts` decide what the kernel watches; this module decides what a watch
 * means, and writes the result into the tamper-evident evidence chain so a bypass attempt
 * leaves the same kind of verifiable record as an authorized effect (S13).
 *
 * ## Scope, stated honestly
 *
 * Two event shapes are modelled, and both were measured against a live agent rather than
 * assumed:
 *
 * - `process_exec`, from Tetragon's built-in base sensor. On this kernel that sensor fails to
 *   load (`__x64_sys_getcpu() is not modifiable`), so this shape is **not** observed here.
 * - `process_kprobe`, and specifically `security_bprm_check`. This is the shape the policy in
 *   `tetragon-policy.ts` selects, and it is observed on this kernel.
 *
 * `tcp_connect` and `security_file_permission` events parse but produce no signal: deciding that
 * a socket or a path write violates policy would be inventing an interpretation that has not
 * been measured. `deniedWritePaths` consequently has no runtime signal path yet.
 *
 * This adapter is an evidence path, not an enforcement path. It cannot stop anything; it
 * records what happened so a later control — or an auditor — can act on it. Any invariant
 * that depends on it alone is not demonstrated.
 */

import { z } from "zod"

import { canonicalHash } from "../hash.ts"
import type { EvidenceChain, EvidenceRecord } from "./evidence.ts"
import { collectNetworkTargets } from "./network-target-guard.ts"
import type { TetragonRuntimeProfile } from "./tetragon-policy.ts"

/**
 * The observed `process_exec` shape. Only the fields this adapter reads are declared;
 * Tetragon emits more (flags, start_time, refcnt, auid, cwd) and zod drops the rest.
 *
 * Note the nesting: the fields live under `process_exec.process`, not directly under
 * `process_exec`. Tetragon v1.1.2 emits `{ process_exec: { process, parent }, node_name,
 * time }`. The flat form does not occur in a live stream — this was corrected against a
 * recorded capture after the flat assumption produced zero matches against real data.
 */
const processSchema = z.object({
  exec_id: z.string().optional(),
  pid: z.number(),
  uid: z.number(),
  binary: z.string(),
  arguments: z.string().optional(),
  /** Docker container id. Present for containerised workloads; absent for host processes. */
  docker: z.string().optional(),
})

const tetragonEventSchema = z.object({
  process_exec: z.object({ process: processSchema }),
})

/**
 * The observed `process_kprobe` shape, measured against Tetragon v1.7.1 on a live agent.
 *
 * This is the shape the policy in `tetragon-policy.ts` actually selects. Tetragon emits it as
 *
 *   { process_kprobe: { process, function_name, args, action, policy_name, ... },
 *     node_name, time }
 *
 * and `args` is a heterogeneous array: `{ linux_binprm_arg: { path, permission } }` for the bprm
 * hook, `{ file_arg: { path, permission } }` and `{ int_arg: n }` for the file hook, `{ sock_arg:
 * { ... } }` for the socket hook. Only the two the adapter acts on are modelled.
 *
 * Modelled because the deny-binary signal arrives this way. Before this the adapter parsed only
 * `process_exec`, which is emitted by the built-in base sensor rather than by this repository's
 * policy — so the evidence path could not consume the events its own policy selects, and every
 * `security_bprm_check` line was classified `unmodelled` and dropped.
 */
const kprobeProcessSchema = z.object({
  pid: z.number(),
  uid: z.number().optional(),
  binary: z.string().optional(),
  arguments: z.string().optional(),
  docker: z.string().optional(),
})

const kprobeArgSchema = z.union([
  z.object({ linux_binprm_arg: z.object({ path: z.string(), permission: z.string().optional() }) }),
  z.object({ file_arg: z.object({ path: z.string(), permission: z.string().optional() }) }),
])

const kprobeEventSchema = z.object({
  process_kprobe: z.object({
    process: kprobeProcessSchema,
    function_name: z.string(),
    args: z.array(z.unknown()),
  }),
})

export type TetragonProcessExec = z.infer<typeof processSchema>

export type TetragonProcessKprobe = {
  readonly process: z.infer<typeof kprobeProcessSchema>
  readonly functionName: string
  /** The `linux_binprm_arg.path` of this event, when the hook carries one. */
  readonly binprmPath: string | undefined
  /** The `file_arg.path` of this event, when the hook carries one. */
  readonly filePath: string | undefined
}

export type ParsedTetragonEvent =
  | { readonly kind: "process_exec"; readonly event: TetragonProcessExec }
  | { readonly kind: "process_kprobe"; readonly event: TetragonProcessKprobe }
  | { readonly kind: "unmodelled"; readonly eventType: string }

/** Top-level keys Tetragon emits alongside the event itself. */
const ENVELOPE_KEYS = new Set(["node_name", "time"])

/**
 * Parse one line of `tetra getevents -o json`.
 *
 * The stream is newline-delimited JSON but is not guaranteed to be well-formed: a truncated
 * line at shutdown is normal. An unparseable line returns `undefined` rather than throwing,
 * because losing one line of telemetry must not stop the pipeline.
 */
export const parseTetragonEvent = (
  line: string,
): ParsedTetragonEvent | undefined => {
  const trimmed = line.trim()

  if (trimmed.length === 0) {
    return undefined
  }

  let value: unknown

  try {
    value = JSON.parse(trimmed)
  } catch {
    return undefined
  }

  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return undefined
  }

  const parsed = tetragonEventSchema.safeParse(value)

  if (parsed.success) {
    return { kind: "process_exec", event: parsed.data.process_exec.process }
  }

  const kprobe = kprobeEventSchema.safeParse(value)

  if (kprobe.success) {
    const body = kprobe.data.process_kprobe
    let binprmPath: string | undefined
    let filePath: string | undefined

    for (const arg of body.args) {
      const entry = kprobeArgSchema.safeParse(arg)

      if (!entry.success) {
        continue
      }

      if ("linux_binprm_arg" in entry.data) {
        binprmPath ??= entry.data.linux_binprm_arg.path
      } else {
        filePath ??= entry.data.file_arg.path
      }
    }

    return {
      kind: "process_kprobe",
      event: {
        process: body.process,
        functionName: body.function_name,
        binprmPath,
        filePath,
      },
    }
  }

  const eventType = Object.keys(value).find((key) => !ENVELOPE_KEYS.has(key))

  return eventType === undefined
    ? undefined
    : { kind: "unmodelled", eventType }
}

export type RuntimeSignalReason =
  | "denied_binary_exec"
  | "denied_network_target"

export type RuntimeSignal = {
  readonly reason: RuntimeSignalReason
  readonly invariant: "S3"
  readonly binary: string
  /** Present only for `denied_network_target`. */
  readonly target?: string
  readonly arguments: string
  readonly pid: number
  readonly containerId?: string | undefined
}

const commandLine = (event: TetragonProcessExec): string =>
  event.arguments === undefined ? event.binary : `${event.binary} ${event.arguments}`

/**
 * Decide whether an observed exec is a signal.
 *
 * Two ways an exec violates S3:
 *
 * 1. The binary itself is on the profile's deny list — `curl`, `wget`, a raw `nc`. Running
 *    it at all is the attempt, whatever the arguments.
 * 2. The command line names a network target the sidecar allowlist would refuse. This
 *    catches the case where the binary is unremarkable but the destination is not: a
 *    `node -e` one-liner, an interpreter reading a script from stdin.
 *
 * `profile.deniedPorts` is deliberately not consulted here. A port alone does not identify
 * a destination the allowlist would refuse, so treating it as a violation here would
 * produce false positives against ordinary HTTPS.
 */
export const classifyRuntimeEvent = (
  parsed: ParsedTetragonEvent,
  profile: Pick<
    TetragonRuntimeProfile,
    "deniedBinaries" | "networkAllowlistHosts" | "agentId"
  >,
): RuntimeSignal | undefined => {
  if (parsed.kind === "process_kprobe") {
    return classifyKprobe(parsed.event, profile)
  }

  if (parsed.kind !== "process_exec") {
    return undefined
  }

  const { event } = parsed
  const denied = new Set(profile.deniedBinaries)
  const base = {
    binary: event.binary,
    arguments: commandLine(event),
    pid: event.pid,
    ...(event.docker === undefined ? {} : { containerId: event.docker }),
  }

  if (denied.has(event.binary)) {
    return { ...base, reason: "denied_binary_exec", invariant: "S3", ...offListTarget(event, profile) }
  }

  const target = offListTarget(event, profile)

  return target === undefined ? undefined : { ...base, reason: "denied_network_target", invariant: "S3", ...target }
}

/**
 * Classify a `process_kprobe` event — the shape this repository's own policy selects.
 *
 * `security_bprm_check` carries the path the kernel is about to execute in
 * `linux_binprm_arg.path`. That is the authoritative value: it comes from the kernel's own
 * `struct linux_binprm`, so it does not depend on the process cache being populated and cannot be
 * stale the way a cached `process.binary` can. It is preferred over `process.binary`.
 *
 * Nothing else is classified. `security_file_permission` and `tcp_connect` events parse but
 * yield no signal, because turning a path or a socket into a policy violation would be inventing
 * an interpretation this adapter has not measured. `deniedWritePaths` therefore has no runtime
 * signal path yet, which is recorded rather than papered over.
 */
const classifyKprobe = (
  event: TetragonProcessKprobe,
  profile: Pick<
    TetragonRuntimeProfile,
    "deniedBinaries" | "networkAllowlistHosts" | "agentId"
  >,
): RuntimeSignal | undefined => {
  if (event.functionName !== "security_bprm_check" || event.binprmPath === undefined) {
    return undefined
  }

  if (!new Set(profile.deniedBinaries).has(event.binprmPath)) {
    return undefined
  }

  const containerId = event.process.docker

  return {
    reason: "denied_binary_exec",
    invariant: "S3",
    binary: event.binprmPath,
    // The hook reports the executable, not its arguments. Empty rather than invented: an
    // evidence record that claims to know a command line it never saw is worse than one that
    // says it does not.
    arguments: event.process.arguments ?? "",
    pid: event.process.pid,
    ...(containerId === undefined ? {} : { containerId }),
  }
}

/**
 * The off-list destination in the command line, if there is one.
 *
 * Reported even when the binary is already denied: knowing that `curl` was aimed at
 * `evil.example` is the difference between an unexplained attempt and an attributed one.
 */
const offListTarget = (
  event: TetragonProcessExec,
  profile: Pick<TetragonRuntimeProfile, "networkAllowlistHosts">,
): { readonly target: string } | undefined => {
  if (profile.networkAllowlistHosts.length === 0) {
    return undefined
  }

  const offList = collectNetworkTargets(commandLine(event)).find(
    (target) => !hostMatchesAny(target, profile.networkAllowlistHosts),
  )

  return offList === undefined ? undefined : { target: offList }
}

const hostMatchesAny = (
  host: string,
  allowedHosts: readonly string[],
): boolean => {
  const lowered = host.toLowerCase()

  return allowedHosts.some((allowed) => {
    const candidate = allowed.toLowerCase()

    return candidate.startsWith("*.")
      ? lowered === candidate.slice(2) || lowered.endsWith(candidate.slice(1))
      : lowered === candidate
  })
}

export type IngestOptions = {
  readonly profile: Pick<
    TetragonRuntimeProfile,
    "deniedBinaries" | "networkAllowlistHosts" | "agentId"
  >
  readonly evidenceChain: EvidenceChain
  readonly issuerId: string
  readonly keyPair: { readonly privateKeyPem: string }
  readonly occurredAt?: Date | undefined
}

export type IngestResult = {
  readonly records: readonly EvidenceRecord[]
  readonly unmodelled: readonly string[]
  readonly unparsed: number
}

/**
 * Fold a Tetragon stream into the evidence chain.
 *
 * Every signal becomes a signed `security_violation` record, so it is covered by the same
 * hash chain and offline verifier as everything else. That is what makes it evidence rather
 * than a log line (S13), and it is why this function writes to the chain instead of to a
 * logger.
 */
export const ingestTetragonStream = (
  lines: Iterable<string>,
  options: IngestOptions,
): IngestResult => {
  const records: EvidenceRecord[] = []
  const unmodelled: string[] = []
  let unparsed = 0

  for (const line of lines) {
    const parsed = parseTetragonEvent(line)

    if (parsed === undefined) {
      unparsed += 1
      continue
    }

    if (parsed.kind === "unmodelled") {
      if (!unmodelled.includes(parsed.eventType)) {
        unmodelled.push(parsed.eventType)
      }
      continue
    }

    const signal = classifyRuntimeEvent(parsed, options.profile)

    if (signal === undefined) {
      continue
    }

    records.push(
      options.evidenceChain.append(
        "security_violation",
        {
          invariant: signal.invariant,
          reason: signal.reason,
          agent_id: options.profile.agentId,
          binary: signal.binary,
          // The command line is recorded as a digest, not as text. `redactSensitive` matches
          // property *names*, so a bearer token passed as `-H 'authorization: Bearer ...'`
          // would otherwise land in evidence verbatim. The digest still proves which command
          // line was observed and that it has not changed since.
          arguments_digest: canonicalHash(signal.arguments),
          ...(signal.target === undefined ? {} : { target: signal.target }),
          pid: signal.pid,
          ...(signal.containerId === undefined
            ? {}
            : { container_id: signal.containerId }),
        },
        options.occurredAt === undefined
          ? {}
          : { occurredAt: options.occurredAt },
      ),
    )
  }

  return { records, unmodelled, unparsed }
}