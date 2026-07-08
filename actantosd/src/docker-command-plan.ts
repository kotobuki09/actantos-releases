export const DEFAULT_IMAGE = "alpine:3.20"
export const GIT_IMAGE = "alpine/git:latest"

export type DockerCommandPlan = {
  readonly image: string
  readonly containerArgv: readonly string[]
  readonly dockerFlags: readonly string[]
}

export const planDockerCommand = (argv: readonly string[]): DockerCommandPlan => {
  const commandFamily = argv[0]

  if (commandFamily === undefined) {
    throw new Error("docker command argv must not be empty")
  }

  if (commandFamily === "git") {
    return {
      image: GIT_IMAGE,
      containerArgv: [
        "-lc",
        "git config --global --add safe.directory \"*\" && exec git \"$@\"",
        "sh",
        ...argv.slice(1),
      ],
      dockerFlags: [
        "--entrypoint",
        "sh",
        "--env",
        "HOME=/tmp",
      ],
    }
  }

  return {
    image: DEFAULT_IMAGE,
    containerArgv: argv,
    dockerFlags: [],
  }
}
