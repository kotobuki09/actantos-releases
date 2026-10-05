import { verifyTenantAuditChain } from "./audit-chain-verifier.ts";
import { createDatabase } from "./database.ts";

async function main() {
  const args = process.argv.slice(2);
  const tenantId = (args.includes("--tenant") ? args[args.indexOf("--tenant") + 1] : undefined) ?? "t_demo";

  const databaseUrl = process.env["DATABASE_URL"];
  if (!databaseUrl) {
    throw new Error("DATABASE_URL is required");
  }

  const database = createDatabase(databaseUrl);
  try {
    const result = await verifyTenantAuditChain(database, tenantId);
    if (!result.valid) {
      console.error(`Verification failed for tenant ${result.tenantId}. Reason: ${result.error}`);
      process.exit(1);
    } else {
      console.log(`Verifying ${result.eventCount} audit events...`);
      console.log(`Chain intact. No tampering detected.`);
    }
  } finally {
    await database.close();
  }
}

main().catch(console.error);
