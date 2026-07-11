import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import test from "node:test";

import { runPreflight } from "./stage3-preflight-lib.mjs";

const readyRunner = async (probe) => ({
  exitCode: 0,
  stdout: probe.successMarker,
  stderr: "",
  timedOut: false,
});

test("Given offline mode When preflight runs Then it succeeds without probing", async () => {
  let calls = 0;
  const result = await runPreflight({ mode: "offline", env: {}, runner: async () => {
    calls += 1;
    return { exitCode: 1, stdout: "", stderr: "unexpected", timedOut: false };
  }});
  assert.equal(result.exitCode, 0);
  assert.equal(calls, 0);
  assert.match(result.output, /offline unit mode: READY/);
});

test("Given configured dependencies When every fresh probe is ready Then required lane succeeds", async () => {
  const env = {
    DATABASE_URL: "postgres://actantos:test@127.0.0.1:5432/actantos_test",
    AWS_REGION: "us-east-1",
    STAGE3_AWS_ACCOUNT_ID: "123456789012",
    STAGE3_S3_BUCKET: "locked-evidence",
    STAGE3_SPLUNK_HEC_URL: "https://splunk.example.test:8088",
    STAGE3_WEBHOOK_URL: "https://hooks.example.test/audit",
    STAGE3_WEBHOOK_READY_MARKER: "ACTANTOS_WEBHOOK_READY",
  };
  const result = await runPreflight({ mode: "required", env, runner: readyRunner });
  assert.equal(result.exitCode, 0);
  assert.match(result.output, /required hardened lane: READY/);
});

test("Given an unavailable dependency When required lane runs Then it exits nonzero with the reason", async () => {
  const env = {
    DATABASE_URL: "postgres://actantos:test@127.0.0.1:5432/actantos_test",
    AWS_REGION: "us-east-1",
    STAGE3_AWS_ACCOUNT_ID: "123456789012",
    STAGE3_S3_BUCKET: "locked-evidence",
    STAGE3_SPLUNK_HEC_URL: "https://splunk.example.test:8088",
    STAGE3_WEBHOOK_URL: "https://hooks.example.test/audit",
    STAGE3_WEBHOOK_READY_MARKER: "ACTANTOS_WEBHOOK_READY",
  };
  const result = await runPreflight({ mode: "required", env, runner: async (probe) => probe.id === "runsc"
    ? { exitCode: 127, stdout: "", stderr: "runsc not found", timedOut: false }
    : readyRunner(probe) });
  assert.equal(result.exitCode, 1);
  assert.match(result.output, /runsc: UNAVAILABLE \(runsc not found\)/);
});

test("Given misleading command output When marker is absent Then dependency is misconfigured", async () => {
  const result = await runPreflight({
    mode: "required",
    env: {
      DATABASE_URL: "postgres://actantos:test@127.0.0.1:5432/actantos_test",
      AWS_REGION: "us-east-1",
      STAGE3_AWS_ACCOUNT_ID: "123456789012",
      STAGE3_S3_BUCKET: "locked-evidence",
      STAGE3_SPLUNK_HEC_URL: "https://splunk.example.test:8088",
      STAGE3_WEBHOOK_URL: "https://hooks.example.test/audit",
      STAGE3_WEBHOOK_READY_MARKER: "ACTANTOS_WEBHOOK_READY",
    },
    runner: async (probe) => ({ exitCode: 0, stdout: probe.id === "postgres" ? "success" : probe.successMarker, stderr: "", timedOut: false }),
  });
  assert.equal(result.exitCode, 1);
  assert.match(result.output, /postgres: MISCONFIGURED \(success marker mismatch\)/);
});

for (const [position, output] of [
  ["prefix", "prefix ACTANTOS_POSTGRES_READY"],
  ["suffix", "ACTANTOS_POSTGRES_READY suffix"],
  ["embedded", "prefix ACTANTOS_POSTGRES_READY suffix"],
]) {
  test(`Given a ${position} marker When the probe exits zero Then dependency is misconfigured`, async () => {
    const result = await runPreflight({
      mode: "required",
      env: {
        DATABASE_URL: "postgres://actantos:test@127.0.0.1:5432/actantos_test",
        AWS_REGION: "us-east-1",
        STAGE3_AWS_ACCOUNT_ID: "123456789012",
        STAGE3_S3_BUCKET: "locked-evidence",
        STAGE3_SPLUNK_HEC_URL: "https://splunk.example.test:8088",
        STAGE3_WEBHOOK_URL: "https://hooks.example.test/audit",
        STAGE3_WEBHOOK_READY_MARKER: "ACTANTOS_WEBHOOK_READY",
      },
      runner: async (probe) => ({ exitCode: 0, stdout: probe.id === "postgres" ? output : probe.successMarker, stderr: "", timedOut: false }),
    });
    assert.equal(result.exitCode, 1);
    assert.match(result.output, /postgres: MISCONFIGURED \(success marker mismatch\)/);
  });
}

test("Given surrounding whitespace When output otherwise equals marker Then dependency is ready", async () => {
  const result = await runPreflight({
    mode: "required",
    env: {
      DATABASE_URL: "postgres://actantos:test@127.0.0.1:5432/actantos_test",
      AWS_REGION: "us-east-1",
      STAGE3_AWS_ACCOUNT_ID: "123456789012",
      STAGE3_S3_BUCKET: "locked-evidence",
      STAGE3_SPLUNK_HEC_URL: "https://splunk.example.test:8088",
      STAGE3_WEBHOOK_URL: "https://hooks.example.test/audit",
      STAGE3_WEBHOOK_READY_MARKER: "ACTANTOS_WEBHOOK_READY",
    },
    runner: async (probe) => ({ exitCode: 0, stdout: ` \r\n${probe.successMarker}\n `, stderr: "", timedOut: false }),
  });
  assert.equal(result.exitCode, 0);
});

test("Given a hung command When its timeout expires Then dependency is unavailable", async () => {
  const result = await runPreflight({
    mode: "required",
    env: {
      DATABASE_URL: "postgres://actantos:test@127.0.0.1:5432/actantos_test",
      AWS_REGION: "us-east-1",
      STAGE3_AWS_ACCOUNT_ID: "123456789012",
      STAGE3_S3_BUCKET: "locked-evidence",
      STAGE3_SPLUNK_HEC_URL: "https://splunk.example.test:8088",
      STAGE3_WEBHOOK_URL: "https://hooks.example.test/audit",
      STAGE3_WEBHOOK_READY_MARKER: "ACTANTOS_WEBHOOK_READY",
    },
    runner: async (probe) => probe.id === "splunk"
      ? { exitCode: null, stdout: "", stderr: "", timedOut: true }
      : readyRunner(probe),
  });
  assert.equal(result.exitCode, 1);
  assert.match(result.output, /splunk: UNAVAILABLE \(probe timed out\)/);
});

test("Given malformed configuration When required lane runs Then it fails before commands", async () => {
  let calls = 0;
  const result = await runPreflight({ mode: "required", env: { DATABASE_URL: "file:test.db" }, runner: async () => {
    calls += 1;
    return { exitCode: 0, stdout: "", stderr: "", timedOut: false };
  }});
  assert.equal(result.exitCode, 2);
  assert.equal(calls, 0);
  assert.match(result.output, /configuration: INVALID/);
});

test("Given CLI offline mode When invoked Then exact process exit is zero", () => {
  const result = spawnSync(process.execPath, ["scripts/stage3-preflight.mjs", "--mode=offline"], { cwd: process.cwd(), encoding: "utf8" });
  assert.equal(result.status, 0);
  assert.match(result.stdout, /offline unit mode: READY/);
});
