import { readFileSync } from "node:fs";

import { verifyEvidenceBundle } from "./v2/evidence.ts";

/**
 * `actant verify <evidence-bundle>` — offline evidence verification (Phase 8).
 *
 * Verifies a hash-chained, signed evidence bundle without contacting a running ActantOS
 * instance, so a third party can check a claim without trusting the system that produced it.
 *
 * Usage:
 *   tsx src/cli-verify-evidence.ts <bundle.json> --keys <trusted-keys.json> [--json]
 *
 * `trusted-keys.json` maps issuer id to PEM public key:
 *   { "issuer-primary": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n" }
 *
 * Exit codes: 0 verified, 1 verification failed, 2 usage or input error.
 */

type TrustedKeys = Record<string, string>;

const parseTrustedKeys = (text: string): TrustedKeys => {
  const parsed: unknown = JSON.parse(text);

  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("trusted keys file must be a JSON object of issuer id to PEM key");
  }

  const entries = Object.entries(parsed as Record<string, unknown>);

  for (const [issuerId, pem] of entries) {
    if (typeof pem !== "string" || !pem.includes("BEGIN PUBLIC KEY")) {
      throw new Error(`trusted key for issuer "${issuerId}" is not a PEM public key`);
    }
  }

  return Object.fromEntries(entries) as TrustedKeys;
};

const main = async () => {
  const args = process.argv.slice(2);
  const bundlePath = args[0];
  const keysIndex = args.indexOf("--keys");
  const keysPath = keysIndex === -1 ? undefined : args[keysIndex + 1];
  const asJson = args.includes("--json");

  if (bundlePath === undefined || keysPath === undefined) {
    console.error(
      "usage: actant verify <evidence-bundle.json> --keys <trusted-keys.json> [--json]",
    );
    process.exit(2);
    return;
  }

  let bundle: unknown;
  let keys: TrustedKeys;

  try {
    bundle = JSON.parse(readFileSync(bundlePath, "utf8"));
    keys = parseTrustedKeys(readFileSync(keysPath, "utf8"));
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exit(2);
    return;
  }

  const result = verifyEvidenceBundle(bundle, new Map(Object.entries(keys)));

  if (result.valid) {
    if (asJson) {
      console.log(JSON.stringify({ valid: true, recordCount: result.recordCount }));
    } else {
      console.log(`Verified ${result.recordCount} evidence records.`);
      console.log("Chain intact, signatures valid, no tampering detected.");
    }
    return;
  }

  if (asJson) {
    console.log(JSON.stringify({ valid: false, issues: result.issues }));
  } else {
    console.error("Evidence verification FAILED:");
    for (const issue of result.issues) {
      const where = issue.seq === -1 ? "bundle" : `record ${issue.seq}`;
      console.error(`  ${where}: ${issue.problem}`);
    }
  }

  process.exit(1);
};

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(2);
});