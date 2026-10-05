import assert from "node:assert/strict"
import { createHash, randomUUID } from "node:crypto"
import { EventEmitter } from "node:events"
import test from "node:test"

import { createDecisionConstraints } from "./decision-constraints.ts"
import { canonicalCommandHash } from "./decision-command.ts"
import { executeDockerCommand } from "./docker-executor.ts"
import { InMemoryDecisionNonceStore } from "./decision-nonce-store.ts"
import { SandboxRuntimeUnavailableError } from "./sandbox-runtime.ts"
import { canonicalHash, signDecisionToken, verifyDecisionToken } from "./hash.ts"
import { signDecisionTokenEd25519 } from "./decision-token-signature.ts"
import { ed25519 } from "./v2/signature.ts"

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
  command_hash: string
  nonce: string
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
      command_hash: canonicalCommandHash(["printf", "hello"], "/workspace"),
      nonce: randomUUID(),
      decision: "allow",
      exp: Math.floor(Date.now() / 1_000) + 600,
      ...overrides,
    }),
    secret,
  )

/**
 * Records docker invocations and exits every one successfully.
 *
 * Used by the refusal tests below, which must prove that nothing was spawned at all rather
 * than only that the right error was raised.
 */
const createSpawnStub = (spawnCalls: SpawnCall[]) =>
  ((command: string, args: readonly string[]) => {
    const child = new FakeChildProcess()
    spawnCalls.push({ command, args: [...args] })
    queueMicrotask(() => {
      child.emit("exit", 0)
    })
    return child as never
  }) as never

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

/**
 * Calls the real executor with a fresh nonce store, so a test that is not about S9 does not have
 * to think about it. A test that is about S9 passes its own store to observe reuse directly.
 */
const runDockerCommand = (
  request: Parameters<typeof executeDockerCommand>[0],
  dependencies: Partial<Parameters<typeof executeDockerCommand>[1]> = {},
) => executeDockerCommand(request, { nonceStore: new InMemoryDecisionNonceStore(), ...dependencies })

test("executeDockerCommand rejects decision tokens whose agent_id does not match the request", async () => {
  await assert.rejects(
    () => runDockerCommand(createExecutionRequest({
      decisionToken: createDecisionToken({ agent_id: "pi_other" }),
    })),
    /decision token claims mismatch/u,
  )
})

test("executeDockerCommand rejects expired decision tokens", async () => {
  await assert.rejects(
    () => runDockerCommand(createExecutionRequest({
      decisionToken: createDecisionToken({ exp: Math.floor(Date.now() / 1_000) - 1 }),
    })),
    /decision token expired/u,
  )
})

test("executeDockerCommand rejects signed decision tokens with invalid JSON payloads", async () => {
  await assert.rejects(
    () => runDockerCommand(createExecutionRequest({
      decisionToken: signDecisionToken("{", secret),
    })),
    /invalid decision token/u,
  )
})

test("executeDockerCommand rejects decision tokens whose constraints_hash does not match the request", async () => {
  await assert.rejects(
    () => runDockerCommand(createExecutionRequest({
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

  const result = await runDockerCommand(
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

  const result = await runDockerCommand(
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

  const result = await runDockerCommand(
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

  const result = await runDockerCommand(
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

test("executeDockerCommand provisions the internal cell network for egress_proxy requests", async () => {
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

  const result = await runDockerCommand(
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
    args: ["network", "inspect", "actantos_egress_cell"],
  })
  // `--internal` is the whole security property of this network. Without it the cell has a gateway
  // and every workload on it can reach the internet directly.
  assert.deepEqual(spawnCalls[1], {
    command: "docker",
    args: ["network", "create", "--internal", "--driver", "bridge", "actantos_egress_cell"],
  })
  assert.equal(result.status, "executed")
  const runArgs = spawnCalls[3]!.args
  const networkIndex = runArgs.indexOf("--network")
  assert.equal(runArgs[networkIndex + 1], "actantos_egress_cell")
})

test("executeDockerCommand refuses to reuse a cell network that is not internal", async () => {
  // A network left behind by an earlier version, or created by hand, is a plain bridge with a
  // gateway. Reusing it would run an open cell under a name that says it is closed, so this fails
  // loudly instead.
  const spawnCalls: SpawnCall[] = []

  await assert.rejects(
    runDockerCommand(
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

          setImmediate(() => {
            child.stdout.emit("data", Buffer.from('[{"Name":"actantos_egress_cell","Internal":false}]'))
            child.emit("exit", 0)
          })

          return child as never
        },
      },
    ),
    /is not internal/,
  )

  // It must refuse rather than recreate, because the workload was already configured against it.
  assert.equal(spawnCalls.length, 1)
  assert.deepEqual(spawnCalls[0], {
    command: "docker",
    args: ["network", "inspect", "actantos_egress_cell"],
  })
})

test("executeDockerCommand reuses an existing internal cell network without recreating it", async () => {
  const spawnCalls: SpawnCall[] = []
  const spawnHandlers = [
    (child: FakeChildProcess) => {
      setImmediate(() => {
        child.stdout.emit("data", Buffer.from('[{"Name":"actantos_egress_cell","Internal":true}]'))
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

  const result = await runDockerCommand(
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

  // inspect, then the run. No `network create`, because the network is already correct.
  assert.equal(spawnCalls.length, 3)
  assert.deepEqual(spawnCalls[1]!.args.slice(0, 2), ["image", "inspect"])
  assert.equal(result.status, "executed")
})

test("executeDockerCommand includes --runtime runsc flags when ACTANTOS_USE_GVISOR=true", async () => {
  const previousUseGvisor = process.env["ACTANTOS_USE_GVISOR"]
  process.env["ACTANTOS_USE_GVISOR"] = "true"

  try {
    const spawnCalls: SpawnCall[] = []
    const spawnHandlers = [
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
    ]

    const result = await runDockerCommand(
      createExecutionRequest(),
      {
        // Stubs the availability check: this test is about the flag, not about whether
        // runsc happens to be installed on the machine running it.
        checkRunsc: () => true,
        checkRunscRegistry: () => true,
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
    assert.equal(spawnCalls[1]?.args.includes("--runtime"), true)
    const runtimeIndex = spawnCalls[1]!.args.indexOf("--runtime")
    assert.equal(spawnCalls[1]!.args[runtimeIndex + 1], "runsc")
    assert.equal(result.status, "executed")
  } finally {
    if (previousUseGvisor === undefined) {
      delete process.env["ACTANTOS_USE_GVISOR"]
    } else {
      process.env["ACTANTOS_USE_GVISOR"] = previousUseGvisor
    }
  }
})

test("executeDockerCommand does not include --runtime runsc flags when ACTANTOS_USE_GVISOR is not true", async () => {
  const previousUseGvisor = process.env["ACTANTOS_USE_GVISOR"]
  process.env["ACTANTOS_USE_GVISOR"] = "false"

  try {
    const spawnCalls: SpawnCall[] = []
    const spawnHandlers = [
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
    ]

    const result = await runDockerCommand(
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
    assert.equal(spawnCalls[1]?.args.includes("--runtime"), false)
    assert.equal(result.status, "executed")
  } finally {
    if (previousUseGvisor === undefined) {
      delete process.env["ACTANTOS_USE_GVISOR"]
    } else {
      process.env["ACTANTOS_USE_GVISOR"] = previousUseGvisor
    }
  }
})

// PQ-11 / 1.2: gVisor availability. S12: an unavailable sandbox runtime must fail closed.
test("executeDockerCommand refuses to run when gVisor is required but runsc is missing", async () => {
  const previousUseGvisor = process.env["ACTANTOS_USE_GVISOR"]
  process.env["ACTANTOS_USE_GVISOR"] = "true"

  const spawnCalls: string[][] = []

  try {
    await assert.rejects(
      () =>
        runDockerCommand(createExecutionRequest(), {
          checkRunsc: () => false,
          spawnCommand: (command, args) => {
            spawnCalls.push([command, ...args])
            throw new Error("docker must not be spawned at all")
          },
        }),
      (error: unknown) => {
        assert.ok(error instanceof SandboxRuntimeUnavailableError)
        assert.match((error as Error).message, /Refusing to execute/)
        return true
      },
    )

    // No image pull, no network creation: the refusal happens before any host mutation.
    assert.deepEqual(spawnCalls, [])
  } finally {
    if (previousUseGvisor === undefined) {
      delete process.env["ACTANTOS_USE_GVISOR"]
    } else {
      process.env["ACTANTOS_USE_GVISOR"] = previousUseGvisor
    }
  }
})

test("executeDockerCommand does not degrade silently: no warn-and-continue path exists", async () => {
  const previousUseGvisor = process.env["ACTANTOS_USE_GVISOR"]
  process.env["ACTANTOS_USE_GVISOR"] = "true"

  const warnings: string[] = []
  const originalWarn = console.warn
  console.warn = (...args: unknown[]) => {
    warnings.push(args.map(String).join(" "))
  }

  try {
    await assert.rejects(() =>
      runDockerCommand(createExecutionRequest(), {
        checkRunsc: () => false,
        spawnCommand: () => {
          throw new Error("docker must not be spawned at all")
        },
      }),
    )

    // A warning would imply a degraded-but-working run. There must be none.
    assert.deepEqual(warnings, [])
  } finally {
    console.warn = originalWarn
    if (previousUseGvisor === undefined) {
      delete process.env["ACTANTOS_USE_GVISOR"]
    } else {
      process.env["ACTANTOS_USE_GVISOR"] = previousUseGvisor
    }
  }
})

test("executeDockerCommand proceeds when gVisor is required and runsc is present", async () => {
  const previousUseGvisor = process.env["ACTANTOS_USE_GVISOR"]
  process.env["ACTANTOS_USE_GVISOR"] = "true"

  try {
    const spawnHandlers = [
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
    ]

    const result = await runDockerCommand(createExecutionRequest(), {
      checkRunsc: () => true,
      checkRunscRegistry: () => true,
      spawnCommand: () => {
        const child = new FakeChildProcess()
        const handler = spawnHandlers.shift()

        if (handler === undefined) {
          throw new Error("unexpected spawn call")
        }

        handler(child)
        return child as never
      },
    })

    assert.equal(result.status, "executed")
  } finally {
    if (previousUseGvisor === undefined) {
      delete process.env["ACTANTOS_USE_GVISOR"]
    } else {
      process.env["ACTANTOS_USE_GVISOR"] = previousUseGvisor
    }
  }
})

test("executeDockerCommand does NOT emit a console.warn when ACTANTOS_USE_GVISOR=true and runsc IS found", async () => {
  const previousUseGvisor = process.env["ACTANTOS_USE_GVISOR"]
  process.env["ACTANTOS_USE_GVISOR"] = "true"

  const warnings: string[] = []
  const originalWarn = console.warn
  console.warn = (...args: unknown[]) => {
    warnings.push(args.map(String).join(" "))
  }

  try {
    const spawnHandlers = [
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
    ]

    await runDockerCommand(
      createExecutionRequest(),
      {
        // Simulate runsc found
        checkRunsc: () => true,
        checkRunscRegistry: () => true,
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

    assert.equal(
      warnings.some((w) => w.includes("runsc") && w.includes("ACTANTOS_USE_GVISOR")),
      false,
      "should NOT emit a gVisor warning when runsc is available",
    )
  } finally {
    console.warn = originalWarn
    if (previousUseGvisor === undefined) {
      delete process.env["ACTANTOS_USE_GVISOR"]
    } else {
      process.env["ACTANTOS_USE_GVISOR"] = previousUseGvisor
    }
  }
})


/* -------------------------------------------------------------------------------------------- */
/* S8: the token must describe the command that runs                                                  */
/*                                                                                                  */
/* These were added after this path was found to accept a token minted for one command and run   */
/* another. The argv reached `docker run` unchecked, so authorization bound the caller and the   */
/* execution envelope but never the command itself.                                                */
/* -------------------------------------------------------------------------------------------- */

test("executeDockerCommand rejects a token whose command was substituted after authorization", async () => {
  const spawnCalls: SpawnCall[] = []

  await assert.rejects(
    () =>
      runDockerCommand(
        createExecutionRequest({
          argv: ["rm", "-rf", "/workspace/important"],
        }),
        { spawnCommand: createSpawnStub(spawnCalls), checkRunsc: () => false },
      ),
    /decision token command mismatch/u,
  )

  // The substituted command must never have reached a spawn.
  assert.deepEqual(spawnCalls, [])
})

test("executeDockerCommand rejects a token when only a trailing argument changes", async () => {
  await assert.rejects(
    () =>
      runDockerCommand(createExecutionRequest({ argv: ["printf", "goodbye"] }), {
        spawnCommand: createSpawnStub([]),
        checkRunsc: () => false,
      }),
    /decision token command mismatch/u,
  )
})

test("executeDockerCommand rejects a token when the mounted workspace changes", async () => {
  await assert.rejects(
    () =>
      runDockerCommand(createExecutionRequest({ workspacePath: "/etc" }), {
        spawnCommand: createSpawnStub([]),
        checkRunsc: () => false,
      }),
    /decision token command mismatch/u,
  )
})

test("executeDockerCommand rejects a token minted without a command digest", async () => {
  await assert.rejects(
    () =>
      runDockerCommand(
        createExecutionRequest({
          decisionToken: createDecisionToken({ command_hash: "" }),
        }),
        { spawnCommand: createSpawnStub([]), checkRunsc: () => false },
      ),
    /decision token command mismatch/u,
  )
})

test("executeDockerCommand rejects an expired token before running the command", async () => {
  const spawnCalls: SpawnCall[] = []
  await assert.rejects(
    () =>
      runDockerCommand(
        createExecutionRequest({
          decisionToken: createDecisionToken({ exp: Math.floor(Date.now() / 1_000) - 1 }),
        }),
        { spawnCommand: createSpawnStub(spawnCalls), checkRunsc: () => false },
      ),
    /decision token expired/u,
  )
  assert.deepEqual(spawnCalls, [])
})

test("end-to-end: the token the server mints is accepted for that command and refused for another", async () => {
  const { createDecisionToken } = await import("./intercept-response.ts")

  const secretE2E = "e2e-secret"
  const argv = ["printf", "hello"]
  const workspacePath = "/workspace"

  // The request the policy engine evaluated, carrying the command it authorized.
  const request = {
    request_id: "req_e2e_000001",
    tenant_id: "t_demo",
    agent: {
      id: "pi_demo",
      runtime_type: "pi",
      environment: "dev",
      risk_tier: "low",
    },
    subject: { user_id: "u_demo" },
    session: { id: "s_demo" },
    tool: { kind: "shell", name: "guarded_bash", operation: "ExecuteShellCommand" },
    action: {
      operation: "ExecuteShellCommand",
      args: { command: "printf hello", argv, host_workspace_path: workspacePath },
    },
    resource: { id: "/workspace", kind: "workspace", path: "/workspace" },
    normalized: {
      verb: "execute",
      mutation: false,
      destructive: false,
      network: false,
      credential_access: false,
      risk_class: "low",
      command_family: "printf",
      target_type: "argv_command",
    },
  }

  const token = createDecisionToken({
    decisionId: "dec_e2e_000001",
    toolCallId: "tc_e2e_000001",
    request: request as never,
    scopeHash: "scope-e2e",
    constraints: defaultConstraints,
    expiresAtEpochSeconds: Math.floor(Date.now() / 1_000) + 600,
    hmacSecret: secretE2E,
  })

  const base = {
    decisionToken: token,
    hmacSecret: secretE2E,
    requestId: "req_e2e_000001",
    tenantId: "t_demo",
    agentId: "pi_demo",
    sessionId: "s_demo",
    toolName: "guarded_bash",
    scopeHash: "scope-e2e",
    workspacePath,
    argv,
    networkMode: "none",
    timeoutMs: 1_000,
    maxOutputBytes: 32,
  }

  // The authorized command runs: the mint and the verifier agree.
  const acceptedCalls: SpawnCall[] = []
  const handlers: ((child: FakeChildProcess) => void)[] = [
    (child) => setImmediate(() => child.emit("exit", 0)),
    (child) => setImmediate(() => child.emit("exit", 0)),
  ]
  const accepted = await runDockerCommand(base as never, {
    spawnCommand: ((command: string, args: readonly string[]) => {
      const child = new FakeChildProcess()
      acceptedCalls.push({ command, args: [...args] })
      const handler = handlers.shift()
      if (handler === undefined) {
        throw new Error("unexpected spawn call")
      }
      handler(child)
      return child as never
    }) as never,
    checkRunsc: () => false,
  })

  assert.equal(accepted.status, "executed")
  const runCall = acceptedCalls.find((call) => call.args[0] === "run")
  assert.ok(runCall)
  assert.ok(runCall.args.includes("printf"), "expected the authorized command in the container argv")

  // Substituting the command after authorization is refused, before any spawn.
  const refusedCalls: SpawnCall[] = []
  await assert.rejects(
    () =>
      runDockerCommand({ ...base, argv: ["rm", "-rf", "/workspace"] } as never, {
        spawnCommand: createSpawnStub(refusedCalls),
        checkRunsc: () => false,
      }),
    /decision token command mismatch/u,
  )
  assert.deepEqual(refusedCalls, [])
})

// --- S9: single-use decision tokens ---------------------------------------

test("S9: a decision token authorises one execution, and a replay spawns nothing", async () => {
  const nonceStore = new InMemoryDecisionNonceStore()
  const spawnCalls: SpawnCall[] = []
  const request = createExecutionRequest()

  const first = await runDockerCommand(request, {
    spawnCommand: createSpawnStub(spawnCalls),
    nonceStore,
  })
  assert.equal(first.status, "executed")
  const spawnsAfterFirst = spawnCalls.length
  assert.ok(spawnsAfterFirst > 0)

  await assert.rejects(
    () =>
      executeDockerCommand(request, {
        spawnCommand: createSpawnStub(spawnCalls),
        nonceStore,
      }),
    /decision token already used/u,
  )

  // No additional spawn of any kind: not `docker run`, not even an `image inspect`.
  assert.equal(spawnCalls.length, spawnsAfterFirst)
})

test("S9: a token with no nonce claim is refused rather than treated as exempt", async () => {
  const spawnCalls: SpawnCall[] = []
  // Re-sign a normal token with its nonce removed. Dropping the claim from a freshly minted token
  // keeps every other field valid, so the only reason for refusal can be the missing nonce.
  const minted = verifyDecisionToken(createDecisionToken(), secret)
  assert.equal(minted.valid, true)
  const claims = JSON.parse(
    minted.valid ? minted.payload : "{}",
  ) as Record<string, unknown>
  delete claims["nonce"]

  await assert.rejects(
    () =>
      runDockerCommand(
        createExecutionRequest({
          decisionToken: signDecisionToken(JSON.stringify(claims), secret),
        }),
        { spawnCommand: createSpawnStub(spawnCalls) },
      ),
    /invalid decision token claims/u,
  )

  assert.deepEqual(spawnCalls, [])
})

test("S9: two independently issued tokens for the same command both execute", async () => {
  // The control. Single-use must not degenerate into "this command may run once, ever".
  const nonceStore = new InMemoryDecisionNonceStore()

  for (const _ of [1, 2]) {
    const result = await runDockerCommand(createExecutionRequest(), {
      spawnCommand: createSpawnStub([]),
      nonceStore,
    })
    assert.equal(result.status, "executed")
  }
})

test("S9: the replay refusal names the nonce, not the command or the expiry", async () => {
  // Asserting the exact reason matters. "already used", "command mismatch" and "expired" are
  // different failures; a test accepting any of them would keep passing if S8 or S9 broke.
  const nonceStore = new InMemoryDecisionNonceStore()
  const request = createExecutionRequest()

  await runDockerCommand(request, { spawnCommand: createSpawnStub([]), nonceStore })

  await assert.rejects(
    () => executeDockerCommand(request, { spawnCommand: createSpawnStub([]), nonceStore }),
    (error: unknown) => {
      assert.ok(error instanceof Error)
      assert.equal(error.message, "decision token already used")
      return true
    },
  )
})

// --- S7: the verifier must not also be the issuer ---------------------------

test("S7: an Ed25519-configured executor accepts an asymmetric token and refuses an HMAC one", async () => {
  const keys = ed25519.generateKeyPair()
  const spawnCalls: SpawnCall[] = []
  const overrides = { command_hash: canonicalCommandHash(["printf", "hello"], "/workspace") }

  const edToken = signDecisionTokenEd25519(
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
      ...overrides,
      nonce: randomUUID(),
      decision: "allow",
      exp: Math.floor(Date.now() / 1_000) + 600,
    }),
    keys.privateKeyPem,
  )

  const accepted = await runDockerCommand(
    createExecutionRequest({ decisionToken: edToken }),
    { spawnCommand: createSpawnStub(spawnCalls), tokenVerification: { kind: "ed25519", publicKeyPem: keys.publicKeyPem } },
  )
  assert.equal(accepted.status, "executed")

  // Downgrade: the same executor, handed an HMAC token, must refuse. If it accepted both, the
  // asymmetric configuration would be cosmetic.
  const hmacToken = createDecisionToken(overrides)
  await assert.rejects(
    () =>
      runDockerCommand(
        createExecutionRequest({ decisionToken: hmacToken }),
        { spawnCommand: createSpawnStub(spawnCalls), tokenVerification: { kind: "ed25519", publicKeyPem: keys.publicKeyPem } },
      ),
    /invalid decision token/u,
  )
})

test("S7: the Ed25519 path still enforces S8 and S9, not just the signature", async () => {
  // A signature that verifies is not authorisation. These prove the same binding checks apply once
  // the token arrives by the asymmetric route.
  const keys = ed25519.generateKeyPair()
  const mintEd = (overrides: Record<string, unknown>) =>
    signDecisionTokenEd25519(
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
        command_hash: canonicalCommandHash(["printf", "hello"], "/workspace"),
        nonce: randomUUID(),
        decision: "allow",
        exp: Math.floor(Date.now() / 1_000) + 600,
        ...overrides,
      }),
      keys.privateKeyPem,
    )
  const deps = {
    tokenVerification: { kind: "ed25519" as const, publicKeyPem: keys.publicKeyPem },
  }

  // S8: a substituted command under a valid signature.
  await assert.rejects(
    () =>
      runDockerCommand(
        createExecutionRequest({
          decisionToken: mintEd({}),
          argv: ["rm", "-rf", "/workspace/important"],
        }),
        { ...deps, spawnCommand: createSpawnStub([]) },
      ),
    /decision token command mismatch/u,
  )

  // S9: a replay under a valid signature.
  const nonceStore = new InMemoryDecisionNonceStore()
  const replayRequest = createExecutionRequest({ decisionToken: mintEd({}) })
  await runDockerCommand(replayRequest, { ...deps, nonceStore, spawnCommand: createSpawnStub([]) })
  await assert.rejects(
    () => executeDockerCommand(replayRequest, { ...deps, nonceStore, spawnCommand: createSpawnStub([]) }),
    /decision token already used/u,
  )

  // S12: an expired token under a valid signature.
  await assert.rejects(
    () =>
      runDockerCommand(
        createExecutionRequest({ decisionToken: mintEd({ exp: Math.floor(Date.now() / 1_000) - 1 }) }),
        { ...deps, spawnCommand: createSpawnStub([]) },
      ),
    /decision token expired/u,
  )
})

test("S7: a token signed by an untrusted key is refused even when well formed", async () => {
  const trusted = ed25519.generateKeyPair()
  const attacker = ed25519.generateKeyPair()
  const token = signDecisionTokenEd25519(
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
      command_hash: canonicalCommandHash(["printf", "hello"], "/workspace"),
      nonce: randomUUID(),
      decision: "allow",
      exp: Math.floor(Date.now() / 1_000) + 600,
    }),
    attacker.privateKeyPem,
  )

  await assert.rejects(
    () =>
      runDockerCommand(
        createExecutionRequest({ decisionToken: token }),
        {
          spawnCommand: createSpawnStub([]),
          tokenVerification: { kind: "ed25519", publicKeyPem: trusted.publicKeyPem },
        },
      ),
    /invalid decision token/u,
  )
})
