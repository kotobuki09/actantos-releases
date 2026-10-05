import assert from "node:assert/strict"
import { execFileSync } from "node:child_process"
import { mkdtempSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import test from "node:test"

import { classifyRuntimeEvent, parseTetragonEvent } from "./runtime-events.ts"
import { buildTracingPolicy, toTracingPolicyYaml } from "./tetragon-policy.ts"
import type { TetragonRuntimeProfile } from "./tetragon-policy.ts"

/**
 * The Tetragon path, against events a real eBPF program produced.
 *
 * `runtime-events.test.ts` exercises this path against hand-built JSON. That proves the parser's
 * shape but not that the shape still matches what Tetragon emits on a live kernel, and — more
 * importantly — not that the policy this repository *emits* can be installed at all. Both are
 * measured here.
 *
 * The policy loaded is `toTracingPolicyYaml(buildTracingPolicy(profile))`, written straight out of
 * the product. A hand-written policy would prove Tetragon works; it would prove nothing about the
 * code under test, and the defect this file exists to catch was in the emitter.
 *
 * Two things about the substrate, both measured rather than assumed:
 *
 *  - **Tetragon exports to a file, not to stdout.** The agent logs
 *    `Exporter configuration enabled=true fileName=/var/log/tetragon/tetragon.log`. An earlier
 *    revision of this file grepped the agent's own stdout and concluded the kernel emitted
 *    nothing. That was a measurement error, and it had been carried into the state file as a host
 *    limitation. Reading the exporter instead: `security_bprm_check` events arrive, and
 *    `security_file_permission` events arrive.
 *
 *  - **The built-in base sensor does not load on this kernel**, with
 *    `detect modify return syscall ... __x64_sys_getcpu() is not modifiable`. So the
 *    `process_exec` shape is *not* observed here. The two probes this repository's policy
 *    selects are kprobes on real symbols, and those do fire — which is what these tests assert.
 *    The exec-sensor stream stays unverified and no invariant is claimed from it.
 *
 * The gate is deliberately about *events from this repository's policy*, not about whether the
 * binary exists. A probe that only asked "is tetragon installed" would report a substrate that
 * emits nothing, which is the exact failure mode this file exists to prevent.
 */

const SUBSTRATE_PASS = process.env["ACTANTOS_SUBSTRATE_TESTS"] === "1"
const DISTRO = process.env["ACTANTOS_TETRAGON_DISTRO"] ?? "Ubuntu-24.04"
const EXPORT_PATH = "/var/log/tetragon/tetragon.log"
const POLICY_PATH = "/tmp/actantos-tetragon-policy.yaml"

const profile: TetragonRuntimeProfile = {
  policyName: "actantos-substrate",
  deniedBinaries: ["/usr/bin/touch"],
  deniedPorts: [22],
  deniedWritePaths: [],
  networkAllowlistHosts: ["registry.internal.example"],
  tenantId: "t_substrate",
  agentId: "pi_tetragon_substrate",
}

const policyProfile = {
  deniedBinaries: profile.deniedBinaries,
  networkAllowlistHosts: profile.networkAllowlistHosts,
  agentId: profile.agentId,
}

/**
 * Write the emitted policy to a file the agent can load.
 *
 * `mkdtempSync` under the Windows temp directory means the path is not a POSIX path, so it is
 * translated before the agent is told about it. The bytes handed over are exactly what
 * `toTracingPolicyYaml` returned; the script `cat`s the file rather than interpolating the YAML,
 * so nothing rewrites it on the way through.
 */
const writePolicy = (yaml: string): string => {
  const dir = mkdtempSync(join(tmpdir(), "actantos-tetragon-"))
  const path = join(dir, "policy.yaml")

  writeFileSync(path, yaml)

  return path.replace(/\\/gu, "/")
}

/**
 * A minimal policy known to load on a current agent, used only by the capability probe.
 *
 * It exists so "is there a substrate" and "does this repository's policy load" are two separate
 * questions. It is never used to assert anything about this repository.
 */
const KNOWN_GOOD_POLICY = `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: actantos-capability
spec:
  kprobes:
    - call: "security_bprm_check"
      syscall: false
      args:
        - index: 0
          type: "linux_binprm"
      selectors:
        - matchArgs:
            - index: 0
              operator: "Equal"
              values:
                - "/usr/bin/touch"
          matchActions:
            - action: Post
`

/**
 * Load a policy on a real agent, run the given commands, and return what came back.
 *
 * Multi-line shell does not survive `wsl.exe bash -lc`, so the script goes in on stdin and the
 * markers below delimit the two payloads. The load verdict is returned alongside the events
 * because "Tetragon refused the policy" and "Tetragon accepted it but nothing fired" are
 * different failures — conflating them is how the original `Mask` defect stayed hidden.
 */
const collectEvents = (
  commands: readonly string[],
  yaml: string = toTracingPolicyYaml(buildTracingPolicy(profile)),
): { readonly rejected: boolean; readonly agentLog: string; readonly lines: string[] } => {
  const policyPath = writePolicy(yaml)

  const script = `
set -u
pkill -f "^tetragon" 2>/dev/null || true
sleep 3
mkdir -p /sys/fs/bpf
mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true
cat > ${POLICY_PATH} < '${policyPath}'
rm -f ${EXPORT_PATH}
nohup tetragon --bpf-lib /usr/local/lib/tetragon/bpf/ \\
  --tracing-policy ${POLICY_PATH} \\
  --server-address unix:///var/run/tetragon/tetragon.sock \\
  > /tmp/actantos-tetragon-agent.log 2>&1 &
sleep 22
if grep -q "Failed to execute tetragon" /tmp/actantos-tetragon-agent.log; then
  echo ACTANTOS_POLICY_REJECTED
else
  ${commands.map((command) => `${command} >/dev/null 2>&1 || true`).join("\n")}
  sleep 12
  pkill -f "^tetragon" 2>/dev/null || true
fi
echo ACTANTOS_AGENT_LOG_BEGIN
cat /tmp/actantos-tetragon-agent.log
echo ACTANTOS_AGENT_LOG_END
echo ACTANTOS_EXPORT_BEGIN
cat ${EXPORT_PATH} 2>/dev/null
echo ACTANTOS_EXPORT_END
`

  const stdout = execFileSync("wsl.exe", ["-d", DISTRO, "-u", "root", "--", "bash", "-s"], {
    input: script,
    encoding: "utf8",
    timeout: 300_000,
    stdio: ["pipe", "pipe", "pipe"],
  })

  const between = (start: string, end: string): string => {
    const from = stdout.indexOf(start)
    const to = stdout.indexOf(end, from)

    return from === -1 || to === -1 ? "" : stdout.slice(from + start.length, to)
  }

  return {
    rejected: stdout.includes("ACTANTOS_POLICY_REJECTED"),
    agentLog: between("ACTANTOS_AGENT_LOG_BEGIN", "ACTANTOS_AGENT_LOG_END"),
    lines: between("ACTANTOS_EXPORT_BEGIN", "ACTANTOS_EXPORT_END")
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line.startsWith("{") && line.includes(":")),
  }
}

/**
 * Can this host run Tetragon at all?
 *
 * Probed with a minimal hand-written policy, deliberately **not** this repository's. The two
 * questions have to be separable: if the capability probe used the emitted policy, then a
 * regression that made the policy unloadable would turn every test here into a skip, and the
 * suite would go quiet rather than red. Mutation-verified — restoring the `Mask` operator that
 * the emitter used to emit produced `pass=0 fail=0 skipped=5`, which is exactly that failure.
 *
 * So the gate answers only "is there a substrate", and each test asserts the emitted policy is
 * accepted as a test failure.
 */
const capability = ((): string | undefined => {
  if (!SUBSTRATE_PASS) {
    return "needs ACTANTOS_SUBSTRATE_TESTS=1"
  }

  try {
    const probe = collectEvents(["/usr/bin/touch /tmp/actantos-capability"], KNOWN_GOOD_POLICY)

    if (probe.rejected) {
      return "the reference policy would not load either, so the substrate is not usable here"
    }

    return probe.lines.length > 0 ? undefined : "tetragon emitted no events on this kernel"
  } catch (error) {
    return `could not run tetragon here: ${error instanceof Error ? error.message : String(error)}`
  }
})()

// Named `skipReason` and passed with an explicit `skip:` property rather than object
// shorthand, because the state guard counts skip sites textually and the shorthand would make
// this file report zero gated tests while five of them exist.
const skipReason = capability

/**
 * The exported lines, having first asserted the agent accepted the policy.
 *
 * Without this, a policy that fails to load yields an empty export, and every downstream
 * assertion would report "no event found" — a skip-shaped failure that reads like a host
 * limitation. Mutation-verified: restoring the `Mask` operator made the whole file skip rather
 * than fail while this helper did not exist.
 */
const exportedLines = (commands: readonly string[]): readonly string[] => {
  const { rejected, agentLog, lines } = collectEvents(commands)

  assert.equal(
    rejected,
    false,
    `Tetragon refused the policy this repository emits:
${agentLog.slice(0, 800)}`,
  )

  return lines
}

test(
  "tetragon substrate: the policy this repository emits is accepted by a live agent",
  { skip: skipReason },
  () => {
    const { rejected, agentLog } = collectEvents(["/bin/ls /tmp"])

    assert.equal(
      rejected,
      false,
      `Tetragon refused the emitted policy:\n${agentLog.slice(0, 800)}`,
    )
    // The load path, not merely a zero exit: the agent reports the sensor it attached.
    assert.match(agentLog, /Loaded sensor successfully/)
    assert.match(agentLog, /generic_kprobe/)
  },
)

test(
  "tetragon substrate: real kprobe events reach the exporter",
  { skip: skipReason },
  () => {
    const lines = exportedLines(["/usr/bin/touch /tmp/actantos-probe-a"])

    assert.ok(lines.length > 0, "the exporter held no event-shaped lines at all")

    const parsed = lines.map((line) => parseTetragonEvent(line))
    assert.ok(
      parsed.some((entry) => entry !== undefined && entry.kind === "process_kprobe"),
      "no exported line parsed as a process_kprobe event",
    )
  },
)

test(
  "tetragon substrate: an exec of a denied binary is classified as an S3 signal",
  { skip: skipReason },
  () => {
    const lines = exportedLines(["/usr/bin/touch /tmp/actantos-probe-b"])

    const signals = lines
      .map((line) => parseTetragonEvent(line))
      .map((entry) => (entry === undefined ? undefined : classifyRuntimeEvent(entry, policyProfile)))
      .filter((signal) => signal !== undefined)

    const denied = signals.find((signal) => signal?.binary === "/usr/bin/touch")

    assert.notEqual(
      denied,
      undefined,
      "no real eBPF event for /usr/bin/touch was classified as a signal",
    )
    assert.equal(denied?.reason, "denied_binary_exec")
    assert.equal(denied?.invariant, "S3")
  },
)

test(
  "tetragon substrate: an ordinary binary is not turned into a signal",
  { skip: skipReason },
  () => {
    // The negative control. Without it a classifier that flagged every event would satisfy the
    // test above, and the suite would be asserting that the product is broken.
    const lines = exportedLines(["/bin/ls /tmp"])

    const signals = lines
      .map((line) => parseTetragonEvent(line))
      .map((entry) => (entry === undefined ? undefined : classifyRuntimeEvent(entry, policyProfile)))
      .filter((signal) => signal !== undefined)

    assert.equal(
      signals.find((signal) => signal?.binary === "/bin/ls"),
      undefined,
      "/bin/ls is not on the deny list and must not be classified as a signal",
    )
  },
)

test(
  "tetragon substrate: the kernel-side selector discriminates, not just the adapter",
  { skip: skipReason },
  () => {
    // The adapter only ever sees what the BPF selector lets through. Three `touch` runs and three
    // `ls` runs against a deny list naming only `touch`: if the selector were not discriminating,
    // all six would appear, and the assertion below would be a statement about the adapter alone.
    const lines = exportedLines([
      "/usr/bin/touch /tmp/actantos-c-1",
      "/bin/ls /tmp",
      "/usr/bin/touch /tmp/actantos-c-2",
      "/bin/ls /etc",
      "/usr/bin/touch /tmp/actantos-c-3",
      "/bin/ls /usr",
    ])

    const paths = lines
      .map((line) => parseTetragonEvent(line))
      .filter(
        (entry) =>
          entry !== undefined &&
          entry.kind === "process_kprobe" &&
          entry.event.functionName === "security_bprm_check",
      )
      .map((entry) => (entry?.kind === "process_kprobe" ? entry.event.binprmPath : undefined))

    const noise = paths.filter(
      (path) => path === "/bin/ls" || path === "/usr/bin/touch",
    ).length

    assert.equal(
      noise,
      3,
      `expected exactly 3 events for 3 touch runs and none for the 3 ls runs, saw ${JSON.stringify(paths)}`,
    )
  },
)