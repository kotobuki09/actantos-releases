export const createQuickstartPlan = (port, { hasPackageLock, hasSource }) => {
  const baseUrl = `http://127.0.0.1:${port}`

  return {
    install: ["npm", [hasPackageLock ? "ci" : "install"]],
    build: hasSource ? ["npm", ["run", "build"]] : undefined,
    server: ["node", ["dist/index.js"]],
    readinessUrl: `${baseUrl}/health/ready`,
    agentTest: ["node", ["scripts/portable-agent-test.mjs", "--url", baseUrl]],
  }
}
