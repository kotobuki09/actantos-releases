import assert from "node:assert/strict"
import test from "node:test"

import {
  dockerRegistersRunsc,
  isRunscAvailable,
  isSandboxRuntimeRequired,
  isStrictSandboxMode,
  resolveSandboxRuntimeFlags,
  SandboxRuntimeUnavailableError,
} from "./sandbox-runtime.ts"

/** Run a body with a controlled environment, restoring whatever was there before. */
const withEnv = (
  overrides: Record<string, string | undefined>,
  body: () => void,
): void => {
  const previous = new Map<string, string | undefined>()

  for (const [key, value] of Object.entries(overrides)) {
    previous.set(key, process.env[key])

    if (value === undefined) {
      delete process.env[key]
    } else {
      process.env[key] = value
    }
  }

  try {
    body()
  } finally {
    for (const [key, value] of previous) {
      if (value === undefined) {
        delete process.env[key]
      } else {
        process.env[key] = value
      }
    }
  }
}

const CLEARED = {
  ACTANTOS_USE_GVISOR: undefined,
  ACTANTOS_GVISOR_STRICT: undefined,
  NODE_ENV: undefined,
}

test("sandbox runtime is not required unless ACTANTOS_USE_GVISOR is exactly \"true\"", () => {
  withEnv({ ...CLEARED, ACTANTOS_USE_GVISOR: "false" }, () => {
    assert.equal(isSandboxRuntimeRequired(), false)
    assert.deepEqual(resolveSandboxRuntimeFlags(() => false), [])
  })

  withEnv({ ...CLEARED, ACTANTOS_USE_GVISOR: "1" }, () => {
    assert.equal(isSandboxRuntimeRequired(), false)
  })

  withEnv({ ...CLEARED, ACTANTOS_USE_GVISOR: "TRUE" }, () => {
    assert.equal(isSandboxRuntimeRequired(), false)
  })

  withEnv({ ...CLEARED, ACTANTOS_USE_GVISOR: "true" }, () => {
    assert.equal(isSandboxRuntimeRequired(), true)
  })
})

test("S12: a required but unavailable runtime is refused, never downgraded", () => {
  withEnv({ ...CLEARED, ACTANTOS_USE_GVISOR: "true" }, () => {
    assert.throws(
      () => resolveSandboxRuntimeFlags(() => false),
      (error: unknown) => {
        assert.ok(error instanceof SandboxRuntimeUnavailableError)
        assert.match((error as Error).message, /runsc/)
        // The message must not describe a fallback that no longer happens.
        assert.equal(/will fall back/i.test((error as Error).message), false)
        return true
      },
    )
  })
})

test("a required and available runtime yields the --runtime runsc flags", () => {
  withEnv({ ...CLEARED, ACTANTOS_USE_GVISOR: "true" }, () => {
    // Both probes injected. This test used to pass a single `() => true` and assert the flags,
    // which asserted the behaviour that was wrong: a host with the gVisor binary but a daemon
    // that never registered the runtime satisfies one probe, not the capability. Injecting both
    // keeps the test's subject (the flags) while dropping the false premise (one probe is enough).
    assert.deepEqual(resolveSandboxRuntimeFlags(() => true, () => true), [
      "--runtime",
      "runsc",
    ])
  })
})

test("availability is not probed when gVisor was not requested", () => {
  withEnv({ ...CLEARED, ACTANTOS_USE_GVISOR: undefined }, () => {
    let probed = false

    resolveSandboxRuntimeFlags(() => {
      probed = true
      return false
    })

    assert.equal(probed, false)
  })
})

test("isRunscAvailable uses the injected check when given one", () => {
  assert.equal(isRunscAvailable(() => true, () => true), true)
  assert.equal(isRunscAvailable(() => false, () => true), false)
})

test("gVisor is unavailable when the binary is on PATH but the daemon never registered it", () => {
  // This is the real state of a stock install, and it is what the single-check version got wrong:
  // the binary probe passes, the executor emits `--runtime=runsc`, and the failure arrives later
  // from the daemon as an opaque error instead of here, where the message can name the cause.
  assert.equal(isRunscAvailable(() => true, () => false), false)
})

test("gVisor is unavailable when the daemon has it but the binary is not on PATH", () => {
  assert.equal(isRunscAvailable(() => false, () => true), false)
})

test("S12: a required but unregistered runtime refuses at the gate, not at the daemon", () => {
  withEnv({ ...CLEARED, ACTANTOS_USE_GVISOR: "true" }, () => {
    assert.throws(
      () => resolveSandboxRuntimeFlags(() => true, () => false),
      (error: unknown) =>
        error instanceof SandboxRuntimeUnavailableError &&
        /would silently weaken isolation/u.test(error.message),
    )
  })
})

test("the refusal names which precondition failed, because the fixes differ", () => {
  // "install gVisor" and "register the runtime in daemon.json" are different instructions. A gate
  // that reported only "unavailable" would send an operator to the wrong one, so each refusal
  // carries the reason its own precondition failed.
  withEnv({ ...CLEARED, ACTANTOS_USE_GVISOR: "true" }, () => {
    assert.throws(
      () => resolveSandboxRuntimeFlags(() => false, () => true),
      /not found on PATH/u,
    )
    assert.throws(
      () => resolveSandboxRuntimeFlags(() => true, () => false),
      /daemon has no runtime registered.*daemon\.json/us,
    )
  })
})

test("a host that is genuinely ready passes both checks and yields the runsc flags", () => {
  withEnv({ ...CLEARED, ACTANTOS_USE_GVISOR: "true" }, () => {
    assert.deepEqual(resolveSandboxRuntimeFlags(() => true, () => true), [
      "--runtime",
      "runsc",
    ])
  })
})

test("the daemon runtime registry is parsed against its real shape, not a guessed one", () => {
  // `.Runtimes` is an object keyed by the name `--runtime` accepts. Verified against a live
  // `docker info` on this machine, which renders keys `io.containerd.runc.v2`, `nvidia` and
  // `runc`. An earlier array-shaped guess would have reported "no runsc" for the wrong reason on
  // every host, including one that had it.
  const registered = dockerRegistersRunsc(
    JSON.stringify({ "io.containerd.runc.v2": { path: "runc" }, runc: { path: "runc" } }),
  )
  assert.equal(registered, false)

  assert.equal(dockerRegistersRunsc(JSON.stringify({ runsc: { path: "runsc" } })), true)
  assert.equal(
    dockerRegistersRunsc(
      JSON.stringify({ runc: { path: "runc" }, runsc: { path: "/usr/local/bin/runsc" } }),
    ),
    true,
  )

  // A daemon whose `runc` path merely *mentions* runsc has not registered a runsc runtime.
  assert.equal(
    dockerRegistersRunsc(JSON.stringify({ runc: { path: "/usr/bin/runsc-wrapper" } })),
    false,
  )

  // Shapes the daemon does not produce must not satisfy the gate.
  assert.equal(dockerRegistersRunsc("not json"), false)
  assert.equal(dockerRegistersRunsc("null"), false)
  assert.equal(dockerRegistersRunsc("[]"), false)
  assert.equal(dockerRegistersRunsc('"runsc"'), false)
  assert.equal(dockerRegistersRunsc(""), false)
  assert.equal(dockerRegistersRunsc('{"__proto__":{"runsc":{}}}'), false)
})

test("strict mode is on when asked explicitly or in production", () => {
  withEnv({ ...CLEARED, ACTANTOS_GVISOR_STRICT: "true", NODE_ENV: undefined }, () => {
    assert.equal(isStrictSandboxMode(), true)
  })

  withEnv({ ...CLEARED, ACTANTOS_GVISOR_STRICT: undefined, NODE_ENV: "production" }, () => {
    assert.equal(isStrictSandboxMode(), true)
  })

  withEnv({ ...CLEARED, ACTANTOS_GVISOR_STRICT: "false", NODE_ENV: "development" }, () => {
    assert.equal(isStrictSandboxMode(), false)
  })
})

test("strict mode is off by default in development", () => {
  withEnv({ ...CLEARED }, () => {
    assert.equal(isStrictSandboxMode(), false)
  })
})