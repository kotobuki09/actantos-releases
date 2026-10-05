const fs = require('fs');
const path = require('path');

const srcDir = 'D:/Job/ActantOS/plan/actantosd/src';
const testFiles = [
  'audit-chain-verifier.test.ts',
  'budget-pipeline.test.ts',
  'fail-closed.test.ts',
  'intercept-service.test.ts',
  'mcp-gateway.test.ts',
  'postgres-repository.test.ts',
  'tool-result-service.test.ts',
  'policy-test.ts'
];

for (const file of testFiles) {
  const filePath = path.join(srcDir, file);
  if (!fs.existsSync(filePath)) continue;

  let content = fs.readFileSync(filePath, 'utf8');
  if (!content.includes('import { FakeCedarProvider } from "./fake-cedar-provider.ts"')) {
    content = 'import { FakeCedarProvider } from "./fake-cedar-provider.ts";\n' + content;
    fs.writeFileSync(filePath, content, 'utf8');
    console.log('Fixed', file);
  }
}
