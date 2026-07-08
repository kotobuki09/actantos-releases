export const createFreshInstallCommandPlan = (demoUrl) => ([
  ["npm", ["ci"]],
  ["npm", ["run", "build"]],
  ["docker", ["compose", "down", "-v", "--remove-orphans"]],
  ["docker", ["compose", "up", "-d", "--build"]],
  ["npm", ["run", "demo", "--", "--url", demoUrl]],
])

export const runFreshInstallSmoke = async ({
  demoUrl,
  ensureEnvFile,
  runCommand,
  waitForReady,
}) => {
  ensureEnvFile()

  const commandPlan = createFreshInstallCommandPlan(demoUrl)
  runCommand(...commandPlan[0])
  runCommand(...commandPlan[1])
  runCommand(...commandPlan[2])
  runCommand(...commandPlan[3])

  try {
    await waitForReady()
    runCommand(...commandPlan[4])
  } finally {
    runCommand("docker", ["compose", "down", "-v", "--remove-orphans"])
  }
}
