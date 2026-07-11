import { spawn } from "node:child_process";

const requiredKeys = ["DATABASE_URL", "AWS_REGION", "STAGE3_AWS_ACCOUNT_ID", "STAGE3_S3_BUCKET", "STAGE3_SPLUNK_HEC_URL", "STAGE3_WEBHOOK_URL", "STAGE3_WEBHOOK_READY_MARKER"];

const parseRequiredConfig = (env) => {
  const missing = requiredKeys.filter((key) => !env[key]?.trim());
  if (missing.length > 0) return { ok: false, reason: `missing ${missing.join(", ")}` };
  if (!env.DATABASE_URL.startsWith("postgres://") && !env.DATABASE_URL.startsWith("postgresql://")) {
    return { ok: false, reason: "DATABASE_URL must use postgres:// or postgresql://" };
  }
  for (const key of ["STAGE3_SPLUNK_HEC_URL", "STAGE3_WEBHOOK_URL"]) {
    try {
      if (new URL(env[key]).protocol !== "https:") return { ok: false, reason: `${key} must use HTTPS` };
    } catch {
      return { ok: false, reason: `${key} must be a valid URL` };
    }
  }
  return { ok: true };
};

const probesFor = (env) => [
  { id: "postgres", command: "psql", args: [env.DATABASE_URL, "-Atc", "SELECT 'ACTANTOS_POSTGRES_READY'"], successMarker: "ACTANTOS_POSTGRES_READY" },
  { id: "runsc", command: "runsc", args: ["--version"], successMarker: "runsc version" },
  { id: "aws-sts", command: "aws", args: ["sts", "get-caller-identity", "--region", env.AWS_REGION, "--query", "Account", "--output", "text"], successMarker: env.STAGE3_AWS_ACCOUNT_ID.trim() },
  { id: "s3-object-lock", command: "aws", args: ["s3api", "get-object-lock-configuration", "--bucket", env.STAGE3_S3_BUCKET, "--region", env.AWS_REGION, "--query", "ObjectLockConfiguration.ObjectLockEnabled", "--output", "text"], successMarker: "Enabled" },
  { id: "splunk", command: "curl", args: ["--silent", "--show-error", "--fail", "--max-time", "5", `${env.STAGE3_SPLUNK_HEC_URL.replace(/\/$/, "")}/services/collector/health`], successMarker: "HEC is healthy" },
  { id: "webhook", command: "curl", args: ["--silent", "--show-error", "--output", "-", "--max-time", "5", "--request", "OPTIONS", env.STAGE3_WEBHOOK_URL], successMarker: env.STAGE3_WEBHOOK_READY_MARKER.trim() },
];

export const runCommand = (probe, timeoutMs = 7_000) => new Promise((resolve) => {
  const child = spawn(probe.command, probe.args, { env: process.env, windowsHide: true });
  let stdout = "";
  let stderr = "";
  let settled = false;
  const timer = setTimeout(() => {
    settled = true;
    child.kill("SIGKILL");
    resolve({ exitCode: null, stdout, stderr, timedOut: true });
  }, timeoutMs);
  child.stdout.on("data", (chunk) => { stdout += chunk.toString(); });
  child.stderr.on("data", (chunk) => { stderr += chunk.toString(); });
  child.on("error", (error) => {
    if (settled) return;
    settled = true;
    clearTimeout(timer);
    resolve({ exitCode: 127, stdout, stderr: error.message, timedOut: false });
  });
  child.on("close", (exitCode) => {
    if (settled) return;
    settled = true;
    clearTimeout(timer);
    resolve({ exitCode, stdout, stderr, timedOut: false });
  });
});

export const runPreflight = async ({ mode, env, runner = runCommand }) => {
  if (mode === "offline") return { exitCode: 0, output: "offline unit mode: READY (no external probes)" };
  if (mode !== "optional" && mode !== "required") return { exitCode: 2, output: `configuration: INVALID (unknown mode ${mode})` };
  const config = parseRequiredConfig(env);
  if (!config.ok) return { exitCode: mode === "required" ? 2 : 0, output: `configuration: INVALID (${config.reason})` };

  const lines = [];
  let ready = true;
  for (const probe of probesFor(env)) {
    const result = await runner(probe);
    if (result.timedOut) {
      ready = false;
      lines.push(`${probe.id}: UNAVAILABLE (probe timed out)`);
    } else if (result.exitCode !== 0) {
      ready = false;
      lines.push(`${probe.id}: UNAVAILABLE (${result.stderr.trim() || `exit ${result.exitCode}`})`);
    } else if (!probe.successMarker || result.stdout.trim() !== probe.successMarker) {
      ready = false;
      lines.push(`${probe.id}: MISCONFIGURED (success marker mismatch)`);
    } else {
      lines.push(`${probe.id}: READY`);
    }
  }
  if (ready) lines.push(`${mode} hardened lane: READY`);
  else lines.push(`${mode} hardened lane: BLOCKED`);
  return { exitCode: ready || mode === "optional" ? 0 : 1, output: lines.join("\n") };
};
