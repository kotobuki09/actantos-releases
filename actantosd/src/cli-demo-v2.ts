import { writeFileSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";

import { formatDemo, runDemo } from "./v2/demo.ts";

/**
 * `npm run demo:v2` — the §21 end-to-end reference demonstration.
 *
 * Exits non-zero if any attack in the demonstration was not blocked, or if the evidence chain
 * does not verify. It also writes the evidence bundle so `actant verify` can be run against
 * exactly the chain the demo produced.
 */

const main = async () => {
  const result = await runDemo();

  console.log(formatDemo(result));

  const outputPath = resolve(process.argv[2] ?? ".tmp/v2-demo-evidence.json");
  mkdirSync(dirname(outputPath), { recursive: true });
  writeFileSync(outputPath, JSON.stringify(result.evidence, null, 2));
  console.log("");
  console.log(`evidence bundle written to ${outputPath}`);

  if (result.orchestratorTokenSeenByAgent) {
    console.error("FAIL: a production credential reached the agent context");
    process.exit(1);
  }

  const attacks = result.steps.filter((step) => step.label.startsWith("ATTACK"));
  const failed = attacks.filter((step) => !step.blocked);

  if (failed.length > 0) {
    for (const step of failed) {
      console.error(`FAIL: ${step.label}`);
    }
    process.exit(1);
  }

  if (!result.evidenceValid) {
    console.error("FAIL: the evidence chain did not verify");
    process.exit(1);
  }
};

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.stack : String(error));
  process.exit(1);
});