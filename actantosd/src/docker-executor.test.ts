import assert from "node:assert/strict"
import { createHash } from "node:crypto"
import { EventEmitter } from "node:events"
import test from "node:test"

import { createDecisionConstraints } from "./decision-constraints.ts"
import { executeDockerCommand } from "./docker-executor.ts"
import { canonicalHash, signDecisionToken } from "./hash.ts"

type SpawnCall = {
  readonly command: string
  readonly args: readonly string[]
}

class FakeStream extends EventEmitter {
  setEncoding(): this {
    return this
  }
}

class FakeChildProcess extends EventEmitter {
  readonly stdout = new FakeStream()
  readonly stderr = new FakeStream()
  onKill?: () => void

  kill(_signal?: NodeJS.Signals): boolean {
    this.onKill?.()
    return true
  }
}

const secret = "docker-executor-test-secret"
const sha256Text = (value: string): string =>
  createHash("sha256").update(value, "utf8").digest("hex")

const defaultConstraints = createDecisionConstraints({
  networkMode: "none",
  timeoutMs: 1_000,
  maxOutputBytes: 32,
})

const createDecisionToken = (overrides: Partial<{
  decision_id: string
  tool_call_id: string
  request_id: string
  tenant_id: string
  agent_id: string
  session_id: string
  tool_name: string
  scope_hash: string
  constraints_hash: string
  decision: "allow"
  exp: number
  approved: boolean
}> = {}): string =>
  signDecisionToken(
    JSON.stringify({
      decision_id: "dec_shell_001",
      tool_call_id: "tc_shell_001",
      request_id: "req_shell_001",
      tenant_id: "t_demo",
      agent_id: "pi_demo",
      session_id: "s_demo",
      tool_name: "guarded_bash",
      scope_hash: "scope-demo",
      constraints_hash: canonicalHash(defaultConstraints),
      decision: "allow",
      exp: Math.floor(Date.now() / 1_000) + 600,
      ...overrides,
    }),
    secret,
  )

const createExecutionRequest = (overrides: Partial<Parameters<typeof executeDockerCommand>[0]> = {}) => ({
  decisionToken: createDecisionToken(),
  hmacSecret: secret,
  requestId: "req_shell_001",
  tenantId: "t_demo",
  agentId: "pi_demo",
  sessionId: "s_demo",
  toolName: "guarded_bash",
  scopeHash: "scope-demo",
  workspacePath: "/workspace",
  argv: ["printf", "hello"],
  networkMode: "none" as const,
  timeoutMs: 1_000,
  maxOutputBytes: 32,
  ...overrides,
})

test("executeDockerCommand rejects decision tokens whose agent_id does not match the request", async () => {
  await assert.rejects(
    () => executeDockerCommand(createExecutionRequest({
      decisionToken: createDecisionToken({ agent_id: "pi_other" }),
    })),
    /decision token claims mismatch/u,
  )
})

test("executeDockerCommand rejects expired decision tokens", async () => {
  await assert.rejects(
    () => executeDockerCommand(createExecutionRequest({
      decisionToken: createDecisionToken({ exp: Math.floor(Date.now() / 1_000) - 1 }),
    })),
    /decision token expired/u,
  )
})

test("executeDockerCommand rejects signed decision tokens with invalid JSON payloads", async () => {
  await assert.rejects(
    () => executeDockerCommand(createExecutionRequest({
      decisionToken: signDecisionToken("{", secret),
    })),
    /invalid decision token/u,
  )
})

test("executeDockerCommand rejects decision tokens whose constraints_hash does not match the request", async () => {
  await assert.rejects(
    () => executeDockerCommand(createExecutionRequest({
      decisionToken: createDecisionToken({ constraints_hash: "different-hash" }),
    })),
    /decision token constraints mismatch/u,
  )
})

test("executeDockerCommand runs with --network none, truncates output, and scrubs preview", async () => {
  const spawnCalls: SpawnCall[] = []
  const fullStdout = "stdout SECRET=hunter2 TOKEN=abc123 ghp_secret1234567890 "
  const fullStderr = "AWS_SECRET_ACCESS_KEY=abcd1234\nPRIVATE_KEY=multiline-secret"
  const spawnHandlers = [
    (child: FakeChildProcess) => {
      setImmediate(() => {
        child.emit("exit", 0)
      })
    },
    (child: FakeChildProcess) => {
      setImmediate(() => {
        child.stdout.emit("data", Buffer.from(fullStdout))
        child.stderr.emit("data", Buffer.from(fullStderr))
        child.emit("exit", 0)
      })
    },
  ]

  const result = await executeDockerCommand(
    createExecutionRequest(),
    {
      spawnCommand: (command, args) => {
        const child = new FakeChildProcess()
        spawnCalls.push({ command, args: [...args] })
        const handler = spawnHandlers.shift()

        if (handler === undefined) {
          throw new Error("unexpected spawn call")
        }

        handler(child)
        return child as never
      },
    },
  )

  assert.equal(spawnCalls.length, 2)
  assert.deepEqual(spawnCalls[0], {
    command: "docker",
    args: ["image", "inspect", "alpine:3.20"],
  })
  assert.equal(spawnCalls[1]?.args.includes("--user"), true)
  assert.equal(spawnCalls[1]?.args.includes("1001:1001"), true)
  assert.equal(spawnCalls[1]?.args.includes("--read-only"), true)
  assert.equal(spawnCalls[1]?.args.includes("--cap-drop"), true)
  assert.equal(spawnCalls[1]?.args.includes("ALL"), true)
  assert.equal(spawnCalls[1]?.args.includes("--security-opt"), true)
  assert.equal(spawnCalls[1]?.args.includes("no-new-privileges"), true)
  assert.equal(spawnCalls[1]?.args.includes("--memory"), true)
  assert.equal(spawnCalls[1]?.args.includes("512m"), true)
  assert.equal(spawnCalls[1]?.args.includes("--cpus"), true)
  assert.equal(spawnCalls[1]?.args.includes("0.5"), true)
  assert.equal(spawnCalls[1]?.args.includes("--pids-limit"), true)
  assert.equal(spawnCalls[1]?.args.includes("64"), true)
  assert.equal(spawnCalls[1]?.args.includes("--network"), true)
  const networkIndex = spawnCalls[1]!.args.indexOf("--network")
  assert.equal(spawnCalls[1]!.args[networkIndex + 1], "none")
  assert.equal(result.status, "executed")
  assert.equal(Buffer.byteLength(result.stdout, "utf8") <= 32, true)
  assert.equal(Buffer.byteLength(result.stderr, "utf8") <= 32, true)
  assert.equal(result.stdoutHash, sha256Text(fullStdout))
  assert.equal(result.stderrHash, sha256Text(fullStderr))
  assert.equal(result.redactedPreview.includes("hunter2"), false)
  assert.equal(result.redactedPreview.includes("abc123"), false)
  assert.equal(result.redactedPreview.includes("ghp_secret1234567890"), false)
  assert.equal(result.redactedPreview.includes("abcd1234"), false)
  assert.equal(result.redactedPreview.includes("multiline-secret"), false)
})

test("executeDockerCommand keeps hashes for full output while truncating failed execution output", async () => {
  const fullStdout = "abcdefghijklmnopqrstuvwxyz0123456789"
  const fullStderr = "stderr SECRET=hunter2 API_KEY=service-key ghp_secret1234567890"
  const spawnHandlers = [
    (child: FakeChildProcess) => {
      setImmediate(() => {
        child.emit("exit", 0)
      })
    },
    (child: FakeChildProcess) => {
      setImmediate(() => {
        child.stdout.emit("data", Buffer.from(fullStdout))
        child.stderr.emit("data", Buffer.from(fullStderr))
        child.emit("exit", 7)
      })
    },
  ]

  const result = await executeDockerCommand(
    createExecutionRequest(),
    {
      spawnCommand: (_command, _args) => {
        const child = new FakeChildProcess()
        const handler = spawnHandlers.shift()

        if (handler === undefined) {
          throw new Error("unexpected spawn call")
        }

        handler(child)
        return child as never
      },
    },
  )

  assert.equal(result.status, "failed")
  assert.equal(result.exitCode, 7)
  assert.equal(Buffer.byteLength(result.stdout, "utf8") <= 32, true)
  assert.equal(Buffer.byteLength(result.stderr, "utf8") <= 32, true)
  assert.equal(result.stdoutHash, sha256Text(fullStdout))
  assert.equal(result.stderrHash, sha256Text(fullStderr))
  assert.equal(result.redactedPreview.includes("hunter2"), false)
  assert.equal(result.redactedPreview.includes("service-key"), false)
  assert.equal(result.redactedPreview.includes("ghp_secret1234567890"), false)
})

test("executeDockerCommand scrubs multiline secrets in timeout previews", async () => {
  const fullStdout = "TOKEN=timeout-secret\nline-two"
  const fullStderr = "PASSWORD=hunter2\nAWS_SESSION_TOKEN=session-secret"
  const spawnHandlers = [
    (child: FakeChildProcess) => {
      setImmediate(() => {
        child.emit("exit", 0)
      })
    },
    (child: FakeChildProcess) => {
      child.onKill = () => {
        setImmediate(() => {
          child.emit("exit", null)
        })
      }
      setImmediate(() => {
        child.stdout.emit("data", Buffer.from(fullStdout))
        child.stderr.emit("data", Buffer.from(fullStderr))
      })
    },
  ]

  const result = await executeDockerCommand(
    createExecutionRequest({
      timeoutMs: 1,
      decisionToken: createDecisionToken({
        constraints_hash: canonicalHash(createDecisionConstraints({
          networkMode: "none",
          timeoutMs: 1,
          maxOutputBytes: 32,
        })),
      }),
    }),
    {
      spawnCommand: (_command, _args) => {
        const child = new FakeChildProcess()
        const handler = spawnHandlers.shift()

        if (handler === undefined) {
          throw new Error("unexpected spawn call")
        }

        handler(child)
        return child as never
      },
    },
  )

  assert.equal(result.status, "timeout")
  assert.equal(result.exitCode, -1)
  assert.equal(result.stdoutHash, sha256Text(fullStdout))
  assert.equal(result.stderrHash, sha256Text(fullStderr))
  assert.equal(result.redactedPreview.includes("timeout-secret"), false)
  assert.equal(result.redactedPreview.includes("hunter2"), false)
  assert.equal(result.redactedPreview.includes("session-secret"), false)
})

test("executeDockerCommand scrubs bearer headers, AWS access keys, and PEM private keys", async () => {
  const pemBlock = [
    "-----BEGIN PRIVATE KEY-----",
    "super-secret-private-key",
    "-----END PRIVATE KEY-----",
  ].join("\n")
  const fullStdout = [
    "Authorization: Bearer bearer-secret-token",
    "aws_access_key_id=AKIA1234567890ABCDEF",
  ].join("\n")
  const fullStderr = pemBlock
  const spawnHandlers = [
    (child: FakeChildProcess) => {
      setImmediate(() => {
        child.emit("exit", 0)
      })
    },
    (child: FakeChildProcess) => {
      setImmediate(() => {
        child.stdout.emit("data", Buffer.from(fullStdout))
        child.stderr.emit("data", Buffer.from(fullStderr))
        child.emit("exit", 0)
      })
    },
  ]

  const result = await executeDockerCommand(
    createExecutionRequest({
      maxOutputBytes: 512,
      decisionToken: createDecisionToken({
        constraints_hash: canonicalHash(createDecisionConstraints({
          networkMode: "none",
          timeoutMs: 1_000,
          maxOutputBytes: 512,
        })),
      }),
    }),
    {
      spawnCommand: (_command, _args) => {
        const child = new FakeChildProcess()
        const handler = spawnHandlers.shift()

        if (handler === undefined) {
          throw new Error("unexpected spawn call")
        }

        handler(child)
        return child as never
      },
    },
  )

  assert.equal(result.redactedPreview.includes("bearer-secret-token"), false)
  assert.equal(result.redactedPreview.includes("AKIA1234567890ABCDEF"), false)
  assert.equal(result.redactedPreview.includes("super-secret-private-key"), false)
  assert.equal(result.redactedPreview.includes("-----BEGIN PRIVATE KEY-----"), false)
  assert.equal(result.redactedPreview.includes("[REDACTED]"), true)
  assert.equal(result.redactedPreview.includes("[REDACTED_AWS_ACCESS_KEY_ID]"), true)
  assert.equal(result.redactedPreview.includes("[REDACTED_PRIVATE_KEY]"), true)
})

test("executeDockerCommand provisions actantos_egress for egress_proxy requests", async () => {
  const spawnCalls: SpawnCall[] = []
  const spawnHandlers = [
    (child: FakeChildProcess) => {
      setImmediate(() => {
        child.emit("exit", 1)
      })
    },
    (child: FakeChildProcess) => {
      setImmediate(() => {
        child.emit("exit", 0)
      })
    },
    (child: FakeChildProcess) => {
      setImmediate(() => {
        child.emit("exit", 0)
      })
    },
    (child: FakeChildProcess) => {
      setImmediate(() => {
        child.stdout.emit("data", Buffer.from("ok"))
        child.emit("exit", 0)
      })
    },
  ]

  const result = await executeDockerCommand(
    createExecutionRequest({
      networkMode: "egress_proxy",
      decisionToken: createDecisionToken({
        constraints_hash: canonicalHash(createDecisionConstraints({
          networkMode: "egress_proxy",
          timeoutMs: 1_000,
          maxOutputBytes: 32,
        })),
      }),
    }),
    {
      spawnCommand: (command, args) => {
        const child = new FakeChildProcess()
        spawnCalls.push({ command, args: [...args] })
        const handler = spawnHandlers.shift()

        if (handler === undefined) {
          throw new Error("unexpected spawn call")
        }

        handler(child)
        return child as never
      },
    },
  )

  assert.deepEqual(spawnCalls[0], {
    command: "docker",
    args: ["network", "inspect", "actantos_egress"],
  })
  assert.deepEqual(spawnCalls[1], {
    command: "docker",
    args: ["network", "create", "actantos_egress"],
  })
  assert.equal(result.status, "executed")
  const runArgs = spawnCalls[3]!.args
  const networkIndex = runArgs.indexOf("--network")
  assert.equal(runArgs[networkIndex + 1], "actantos_egress")
})
