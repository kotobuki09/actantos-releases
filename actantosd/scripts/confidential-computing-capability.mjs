/**
 * Report whether this host can run a confidential guest, so W-001's premise is falsifiable.
 *
 * Usage:
 *   node scripts/confidential-computing-capability.mjs
 *
 * Exit 0 whenever the probe itself ran. It does NOT exit 1 on a capable host: finding TDX or
 * SEV-SNP is information for the owner, not a test failure. What it exits 1 on is being unable
 * to determine anything at all, because a probe that silently reports nothing is worse than one
 * that refuses.
 *
 * This is a portable pre-check, not the measurement W-001 rests on. Node cannot execute CPUID,
 * so the leaf 7 / leaf 0x8000001F bits behind TDX, TME and SEV-SNP cannot be read from JavaScript
 * at all. What is readable is the kernel's or hypervisor's own advertisement of those bits. Where
 * the two disagree, the kernel's advertisement wins for "can I start a guest", and this script
 * says so rather than picking a winner silently.
 *
 * W-001's table was measured with a compiled CPUID program, not with this file. Running this on
 * a TDX or SEV-SNP host does not close W-001; it falsifies the reason W-001 gives for being
 * unreachable from here, which is the part an owner needs to see before signing.
 */
import { execFileSync } from "node:child_process"
import { readFileSync } from "node:fs"
import os from "node:os"
import process from "node:process"

/**
 * Kernel/hypervisor feature flags, by the name each platform actually uses.
 *
 * `tdx_host_platform` is the Linux spelling of "the firmware offers TDX to guests", and it
 * appeared in 6.9; older kernels have no spelling for it, which is why an absent flag on Linux
 * is reported as unknown rather than as absent.
 */
const FLAGS = [
  { bit: "tdx_host_platform", capability: "Intel TDX", meaning: "firmware offers TDX to guests" },
  { bit: "sev", capability: "AMD SEV", meaning: "SEV available" },
  { bit: "sev_es", capability: "AMD SEV-ES", meaning: "encrypted state available" },
  { bit: "sev_snp", capability: "AMD SEV-SNP", meaning: "SNP available; the AMD confidential VM" },
]

const readLinuxFlags = () => {
  const cpuinfo = readFileSync("/proc/cpuinfo", "utf8")
  const flags = /^(?:flags|Features)\s*:\s*(.+)$/mu.exec(cpuinfo)?.[1] ?? ""
  if (flags === "") return undefined
  const present = new Set(flags.trim().split(/\s+/u))
  return new Map(FLAGS.map((entry) => [entry.bit, present.has(entry.bit)]))
}

const readWindowsProcessor = () => {
  const script =
    "Get-CimInstance Win32_Processor | " +
    "Select-Object -First 1 ProcessorName,VirtualizationFirmwareEnabled | ConvertTo-Json -Compress"
  const out = execFileSync(
    "powershell.exe",
    ["-NoProfile", "-NonInteractive", "-Command", script],
    { encoding: "utf8", timeout: 20_000, stdio: ["ignore", "pipe", "ignore"] },
  )
  return JSON.parse(out)
}

const rows = []
let probed = false

if (os.platform() === "linux") {
  const flags = readLinuxFlags()
  if (flags !== undefined) {
    probed = true
    for (const entry of FLAGS) {
      rows.push({
        capability: entry.capability,
        how: `/proc/cpuinfo flag ${entry.bit}`,
        value: flags.get(entry.bit) === true ? "present" : "absent",
        meaning: entry.meaning,
      })
    }
  }
} else if (os.platform() === "win32") {
  const processor = readWindowsProcessor()
  probed = true
  rows.push({
    capability: "Virtualization presented to the OS",
    how: "Win32_Processor.VirtualizationFirmwareEnabled",
    value: String(processor.VirtualizationFirmwareEnabled),
    meaning: "firmware presents virtualization; a precondition for any confidential guest",
  })
  for (const entry of FLAGS) {
    rows.push({
      capability: entry.capability,
      how: "not readable from Node",
      value: "unknown",
      meaning: `${entry.meaning}; CPUID is not reachable from JavaScript on this platform`,
    })
  }
}

const width = Math.max(...rows.map((row) => row.capability.length), 12)
console.log(`host: ${os.platform()} ${os.arch()} — ${os.cpus()[0]?.model ?? "unknown CPU"}`)
console.log(`node: ${process.version}\n`)
for (const row of rows) {
  console.log(`  ${row.capability.padEnd(width)}  ${row.value.padEnd(8)}  ${row.how}`)
}

const capabilities = rows.filter((row) => row.capability !== "Virtualization presented to the OS")
const present = capabilities.filter((row) => row.value === "present")
const unknown = capabilities.filter((row) => row.value === "unknown")
console.log()
if (!probed) {
  console.error(
    "this probe could not read any capability advertisement; treat the result as UNKNOWN, not absent",
  )
  process.exit(1)
}
if (present.length > 0) {
  console.log(
    `A confidential-VM capability is advertised: ${present.map((row) => row.capability).join(", ")}.\n` +
      "W-001's stated reason for being unreachable from this host does not hold here. Re-measure\n" +
      "with a compiled CPUID program before treating W-001 as still open.",
  )
} else if (unknown.length > 0) {
  // The honest report on a platform where the kernel advertises nothing this probe can read.
  // Saying "absent" here would be a claim this script did not measure.
  console.log(
    `Cannot determine: ${unknown.map((row) => row.capability).join(", ")} are not readable from Node\n` +
      "on this platform, so this probe neither confirms nor contradicts W-001. The CPUID program\n" +
      "W-001 cites is the measurement that settles it; this one only shows the absence of an\n" +
      "advertisement, which is weaker and must not be reported as an absent capability.",
  )
} else {
  console.log(
    "No confidential-VM capability is advertised. This is consistent with W-001, and it is not\n" +
      "the same as the CPUID measurement W-001 cites — run that program to confirm the bits.",
  )
}