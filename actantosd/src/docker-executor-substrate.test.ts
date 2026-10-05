import assert from "node:assert/strict"
import { execFileSync } from "node:child_process"
import { randomUUID } from "node:crypto"
import test from "node:test"

import { createDecisionConstraints } from "./decision-constraints.ts"
import { canonicalCommandHash } from "./decision-command.ts"
import { signDecisionTokenEd25519 } from "./decision-token-signature.ts"
import { executeDockerCommand } from "./docker-executor.ts"
import { InMemoryDecisionNonceStore } from "./decision-nonce-store.ts"
import { EGRESS_CELL_NETWORK } from "./v2/egress-cell.ts"
import { canonicalHash, signDecisionToken } from "./hash.ts"
import { ed25519 } from "./v2/signature.ts"

/**
 * The command binding, proven against a real container.
 *
 * `docker-executor.test.ts` asserts the planned argv against a recorded command. That is the
 * right check for the decision logic, and it is not the same claim: it proves the executor
 * *decided* to refuse, not that a running container is subject to that decision. These tests
 * start real containers, so the claim is about the substrate.
 *
 * Gated behind `ACTANTOS_SUBSTRATE_TESTS=1` like the database tests, because they need a working
 * Docker daemon and pull an image. Run with `npm run test:substrate`.
 *
 * What these tests do NOT establish: anything about gVisor. `--runtime runsc` is checked for
 * presence by `docker-executor.test.ts`; if runsc is installed the flag below is added by the
 * real executor, and these tests still pass, which is the point — they are testing the binding,
 * not the runtime.
 */

const SUBSTRATE_PASS = process.env["ACTANTOS_SUBSTRATE_TESTS"] === "1"
const dockerAvailable = (() => {
  if (!SUBSTRATE_PASS) {
    return false
  }
  try {
    execFileSync("docker", ["version", "--format", "{{.Server.Version}}"], { stdio: "ignore" })
    return true
  } catch {
    return false
  }
})()

const skip = !dockerAvailable
const todo = skip
  ? "run `npm run test:substrate` on a host with a working Docker daemon — this needs real containers"
  : undefined

const secret = "docker-substrate-test-secret"
const IMAGE = "alpine:3.20"
const WORKSPACE = process.cwd().replace(/\\/gu, "/")

const constraints = createDecisionConstraints({
  networkMode: "none",
  timeoutMs: 20_000,
  maxOutputBytes: 4_000,
})

/**
 * The claim body a decision token carries.
 *
 * Extracted so the HMAC and Ed25519 paths below sign byte-identical claims. A test that built
 * the Ed25519 payload separately could differ in some field the HMAC path does not set, and the
 * refusal it asserts would then prove that difference rather than the signature scheme.
 */
const decisionPayload = (argv: readonly string[], overrides: Record<string, unknown> = {}): string =>
  JSON.stringify({
    decision_id: "dec_substrate_001",
    tool_call_id: "tc_substrate_001",
    request_id: "req_substrate_001",
    tenant_id: "t_substrate",
    agent_id: "pi_substrate",
    session_id: "s_substrate",
    tool_name: "guarded_bash",
    scope_hash: "scope-substrate",
    constraints_hash: canonicalHash(constraints),
    command_hash: canonicalCommandHash(argv, WORKSPACE),
    nonce: randomUUID(),
    decision: "allow",
    exp: Math.floor(Date.now() / 1_000) + 600,
    ...overrides,
  })

const mintToken = (argv: readonly string[], overrides: Record<string, unknown> = {}): string =>
  signDecisionToken(decisionPayload(argv, overrides), secret)

const baseRequest = (argv: readonly string[]) => ({
  decisionToken: mintToken(argv),
  hmacSecret: secret,
  requestId: "req_substrate_001",
  tenantId: "t_substrate",
  agentId: "pi_substrate",
  sessionId: "s_substrate",
  toolName: "guarded_bash",
  scopeHash: "scope-substrate",
  workspacePath: WORKSPACE,
  argv,
  networkMode: "none" as const,
  timeoutMs: constraints.timeout_ms,
  maxOutputBytes: constraints.max_output_bytes,
})

test("substrate: the authorized command really runs in the container", { skip: todo }, async () => {
  const argv = ["printf", "actantos-substrate-ok"]

  const result = await executeDockerCommand(
    baseRequest(argv) as never,
    { checkRunsc: () => false, nonceStore: new InMemoryDecisionNonceStore() },
  )

  assert.equal(result.status, "executed")
  assert.match(result.stdout, /actantos-substrate-ok/u)
})

test("substrate: a substituted destructive command is refused and never reaches a container", { skip: todo }, async () => {
  // Mint for a harmless command, then execute a different one against the same token.
  const authorized = ["printf", "harmless"]
  const substituted = ["sh", "-c", "touch /tmp/pwned-substrate-marker"]

  await assert.rejects(
    () =>
      executeDockerCommand(
        { ...baseRequest(authorized), argv: substituted } as never,
        { checkRunsc: () => false, nonceStore: new InMemoryDecisionNonceStore() },
      ),
    /decision token command mismatch/u,
  )

  // The authorized command still works, so the refusal above was about the substitution and not
  // about the environment.
  const result = await executeDockerCommand(
    baseRequest(authorized) as never,
    { checkRunsc: () => false, nonceStore: new InMemoryDecisionNonceStore() },
  )
  assert.equal(result.status, "executed")
})

test("substrate: the container cannot reach the network under network_mode none", { skip: todo }, async () => {
  // `getent hosts` and a direct connect both fail without a network. Any success means the
  // isolation the token asserts is not the isolation the container got.
  const argv = ["sh", "-c", "getent hosts example.com || echo DNS-FAILED"]

  const result = await executeDockerCommand(
    baseRequest(argv) as never,
    { checkRunsc: () => false, nonceStore: new InMemoryDecisionNonceStore() },
  )

  assert.equal(result.status, "executed")
  assert.match(result.stdout, /DNS-FAILED/u)
  assert.doesNotMatch(result.stdout, /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/u)
})

test("substrate: the container runs as a non-root uid", { skip: todo }, async () => {
  const result = await executeDockerCommand(
    baseRequest(["id", "-u"]) as never,
    { checkRunsc: () => false, nonceStore: new InMemoryDecisionNonceStore() },
  )

  assert.equal(result.status, "executed")
  // 1001:1001 is what the executor requests. Root would print 0.
  assert.equal(result.stdout.trim(), "1001")
})

test("substrate: the container root filesystem is read-only", { skip: todo }, async () => {
  // The probe location and the assertion are both load-bearing, and both were wrong at first.
  //
  // This test originally wrote to `/root`. That fails for a non-root user whether or not the
  // filesystem is read-only, so it was really asserting `--user` again; deleting `--read-only`
  // from the executor left this suite green. Writing to `/tmp` has the opposite problem, since the
  // executor mounts a writable tmpfs there and the write always succeeds.
  //
  // `/etc` discriminates by *reason*, not by exit code: with `--read-only` the write fails
  // "Read-only file system", without it "Permission denied" because of the uid. Both are rc=1,
  // so only the message distinguishes them.
  // `2>&1` is load-bearing: the executor captures stderr separately, so without it the reason
  // string never reaches stdout and the assertion below cannot see it.
  const argv = ["sh", "-c", "touch /etc/read-only-probe 2>&1; echo rc=$?"]

  const result = await executeDockerCommand(
    baseRequest(argv) as never,
    { checkRunsc: () => false, nonceStore: new InMemoryDecisionNonceStore() },
  )

  assert.equal(result.status, "executed")
  assert.match(
    result.stdout,
    /Read-only file system/u,
    "the write failed without that message, so the refusal came from the uid rather than the read-only flag",
  )
})

test("substrate: an expired token is refused before any container starts", { skip: todo }, async () => {
  const argv = ["printf", "hello"]

  await assert.rejects(
    () =>
      executeDockerCommand(
        {
          ...baseRequest(argv),
          decisionToken: mintToken(argv, { exp: Math.floor(Date.now() / 1_000) - 1 }),
        } as never,
        { checkRunsc: () => false, nonceStore: new InMemoryDecisionNonceStore() },
      ),
    /decision token expired/u,
  )
})

test("substrate: widening the output budget after authorization is refused", { skip: todo }, async () => {
  const argv = ["printf", "hello"]

  await assert.rejects(
    () =>
      executeDockerCommand(
        { ...baseRequest(argv), maxOutputBytes: 10_000_000 } as never,
        { checkRunsc: () => false, nonceStore: new InMemoryDecisionNonceStore() },
      ),
    /decision token constraints mismatch/u,
  )
})

test("substrate: remounting a different host workspace is refused", { skip: todo }, async () => {
  const argv = ["printf", "hello"]

  await assert.rejects(
    () =>
      executeDockerCommand(
        { ...baseRequest(argv), workspacePath: "/" } as never,
        { checkRunsc: () => false, nonceStore: new InMemoryDecisionNonceStore() },
      ),
    /decision token command mismatch/u,
  )
})

test("substrate: a tampered token is refused", { skip: todo }, async () => {
  const argv = ["printf", "hello"]
  const token = mintToken(argv)
  const [encoded, signature] = token.split(".")
  assert.ok(encoded !== undefined && signature !== undefined)

  // Re-encode the payload with an escalated network mode but keep the original signature.
  const payload = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8")) as Record<string, unknown>
  payload["constraints_hash"] = canonicalHash(
    createDecisionConstraints({ networkMode: "egress_proxy", timeoutMs: 20_000, maxOutputBytes: 4_000 }),
  )
  const forged = `${Buffer.from(JSON.stringify(payload), "utf8").toString("base64url")}.${signature}`

  await assert.rejects(
    () =>
      executeDockerCommand(
        { ...baseRequest(argv), decisionToken: forged } as never,
        { checkRunsc: () => false, nonceStore: new InMemoryDecisionNonceStore() },
      ),
    /invalid decision token/u,
  )
})

test("substrate: the image actually used is the one the plan names", { skip: todo }, async () => {
  // A git-family command is planned onto a different image with a different entrypoint. Proving
  // that image runs confirms the plan is applied, not merely assembled.
  const argv = ["git", "--version"]

  const result = await executeDockerCommand(
    baseRequest(argv) as never,
    { checkRunsc: () => false, nonceStore: new InMemoryDecisionNonceStore() },
  ).catch((error: unknown) => error as Error)

  // The git image may not be pullable offline. Either it ran and reported a version, or the
  // failure is about the image rather than about authorization.
  if (typeof result === "object" && "status" in result) {
    assert.equal(result.status, "executed")
    assert.match(result.stdout, /git version/u)
  } else {
    assert.match(result.message, /alpine\/git|image/u)
  }
})
test("substrate: one decision token runs one container, and a replay starts nothing", { skip: todo }, async () => {
  // The strongest form of S9 available here. A recorded argv proves the executor *decided* to
  // refuse; this proves a real container does not appear on the second use of a captured token.
  const argv = ["printf", "actantos-replay-probe"]
  const request = baseRequest(argv) as never
  const nonceStore = new InMemoryDecisionNonceStore()

  const first = await executeDockerCommand(request, { checkRunsc: () => false, nonceStore })
  assert.equal(first.status, "executed")
  assert.match(first.stdout, /actantos-replay-probe/u)

  const before = Date.now()
  await assert.rejects(
    () => executeDockerCommand(request, { checkRunsc: () => false, nonceStore }),
    /decision token already used/u,
  )

  // Refused in well under the 1s image-inspect timeout, so no image pull or container start was
  // attempted. Without this the test would also pass if the replay were merely slow.
  assert.ok(Date.now() - before < 1_000, "replay rejection was slow enough to suggest it started something")
})

test("substrate: a token without a nonce is refused rather than exempted", { skip: todo }, async () => {
  // S9's check is the nonce. A token lacking one must not slip through as "no nonce to replay",
  // which would be a bypass an attacker could mint deliberately.
  const argv = ["printf", "actantos-nononce-probe"]
  const request = { ...baseRequest(argv), decisionToken: mintToken(argv, { nonce: "" }) } as never

  await assert.rejects(
    () => executeDockerCommand(request, { checkRunsc: () => false, nonceStore: new InMemoryDecisionNonceStore() }),
    /invalid decision token claims/u,
  )
})

test("substrate: two independently issued tokens for the same command both run", { skip: todo }, async () => {
  // The control for the replay test. Two tokens are two authorisations, so single-use must not
  // degenerate into refusing the same command twice.
  const argv = ["printf", "actantos-two-tokens"]

  for (const _ of [1, 2]) {
    const result = await executeDockerCommand(
      baseRequest(argv) as never,
      { checkRunsc: () => false, nonceStore: new InMemoryDecisionNonceStore() },
    )
    assert.equal(result.status, "executed")
  }
})

test("substrate: an Ed25519-verified token runs a real container", { skip: todo }, async () => {
  // S7 live. The unit file proves the executor accepts an asymmetric token by asserting a
  // recorded argv; this proves the container that argv starts actually runs under a verifier
  // that holds only a public key.
  const keys = ed25519.generateKeyPair()
  const argv = ["printf", "actantos-ed25519-ok"]
  const payload = decisionPayload(argv)

  const result = await executeDockerCommand(
    {
      ...baseRequest(argv),
      decisionToken: signDecisionTokenEd25519(payload, keys.privateKeyPem),
    } as never,
    {
      checkRunsc: () => false,
      nonceStore: new InMemoryDecisionNonceStore(),
      tokenVerification: { kind: "ed25519", publicKeyPem: keys.publicKeyPem },
    },
  )

  assert.equal(result.status, "executed")
  assert.match(result.stdout, /actantos-ed25519-ok/u)
})

test("substrate: an Ed25519-verified executor refuses an HMAC token and no container starts", { skip: todo }, async () => {
  // The downgrade this prevents: an executor configured for Ed25519 must not accept a token
  // signed with a shared secret, because accepting it would let any component holding that
  // secret mint an authorisation. The refusal must come from the signature check specifically,
  // so the token is otherwise identical to the one the test above runs.
  const keys = ed25519.generateKeyPair()
  const argv = ["printf", "actantos-ed25519-downgrade"]

  await assert.rejects(
    () =>
      executeDockerCommand(
        { ...baseRequest(argv), decisionToken: mintToken(argv) } as never,
        {
          checkRunsc: () => false,
          nonceStore: new InMemoryDecisionNonceStore(),
          tokenVerification: { kind: "ed25519", publicKeyPem: keys.publicKeyPem },
        },
      ),
    /invalid decision token/u,
  )
})

test("substrate: a well-formed token signed by an untrusted key is refused", { skip: todo }, async () => {
  // The forgery case. Every claim in the token is well formed and the nonce is fresh, so the
  // only thing standing between this and a running container is the signature.
  const trusted = ed25519.generateKeyPair()
  const attacker = ed25519.generateKeyPair()
  const argv = ["printf", "actantos-ed25519-forgery"]

  await assert.rejects(
    () =>
      executeDockerCommand(
        {
          ...baseRequest(argv),
          decisionToken: signDecisionTokenEd25519(decisionPayload(argv), attacker.privateKeyPem),
        } as never,
        {
          checkRunsc: () => false,
          nonceStore: new InMemoryDecisionNonceStore(),
          tokenVerification: { kind: "ed25519", publicKeyPem: trusted.publicKeyPem },
        },
      ),
    /invalid decision token/u,
  )
})

test("substrate: the egress cell network really is internal, and a workload on it has no route out", { skip: todo }, async () => {
  // S2 live, and the one property in this file with no counterpart in the unit tests at all.
  // The unit file feeds fabricated `docker network inspect` JSON to a stub; here the executor
  // provisions the network itself and the assertions read the daemon's own state back.
  //
  // A non-internal bridge network has a gateway, so "the container could reach the internet" is
  // the failure this rules out. The cell is supposed to be the *only* thing standing between a
  // workload and the open internet, so its being internal is the security property, not a detail.
  const cellConstraints = createDecisionConstraints({
    networkMode: "egress_proxy",
    timeoutMs: 20_000,
    maxOutputBytes: 4_000,
  })
  const argv = ["sh", "-c", "getent hosts example.com || echo DNS-FAILED"]

  // Remove any network a previous run left behind, so `Internal` below describes one this test
  // caused rather than one that happened to exist. A failure here is a refusal to run, not a
  // silent pass, because the next assertion depends on the executor creating it.
  try {
    execFileSync("docker", ["network", "rm", EGRESS_CELL_NETWORK], { stdio: "ignore" })
  } catch {
    // Absent already, which is the state this test wants.
  }

  const result = await executeDockerCommand(
    {
      ...baseRequest(argv),
      decisionToken: mintToken(argv, { constraints_hash: canonicalHash(cellConstraints) }),
      networkMode: "egress_proxy",
    } as never,
    { checkRunsc: () => false, nonceStore: new InMemoryDecisionNonceStore() },
  )

  assert.equal(result.status, "executed")
  assert.match(result.stdout, /DNS-FAILED/u, "a workload on the cell resolved a name, so the cell has egress")
  assert.doesNotMatch(result.stdout, /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/u)

  // The daemon, not the executor's intent. `Internal: false` here would mean the cell was
  // created without --internal even though the container above could not use it.
  const inspected = JSON.parse(
    execFileSync("docker", ["network", "inspect", EGRESS_CELL_NETWORK], { encoding: "utf8" }),
  ) as { Internal?: unknown }[]
  assert.equal(inspected[0]?.Internal, true, "the cell network is not internal, so workloads on it can route out")
})

/*
 * Resource limits, output handling and the timeout — the three things `docker-executor` was
 * recorded as SIMULATED for.
 *
 * The unit tests in `docker-executor.test.ts` assert that the executor *builds* these flags and
 * *calls* these helpers. That is a claim about a string and a function call. Everything below is a
 * claim about a running container, and each test carries a control that removes exactly one thing
 * so that a passing assertion cannot be explained by the daemon's own defaults.
 *
 * The controls run `docker run` directly. They do not go through the executor, because the point
 * of a control is to show what the daemon does *without* the flag under test — routing it through
 * the executor would put the flag back.
 */

/** `docker run` with no ActantOS flags at all: what this daemon does by default. */
const plainDocker = (script: string, extraArgs: readonly string[] = []): string => {
  try {
    return execFileSync("docker", ["run", "--rm", "--network", "none", ...extraArgs, IMAGE, "sh", "-c", script], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    })
  } catch (error) {
    // A non-zero exit is itself an observation for several of these; hand back what ran.
    return `${(error as { stdout?: string }).stdout ?? ""}${(error as { stderr?: string }).stderr ?? ""}`
  }
}

/** The same run through the real executor, so the flag comes from product code and not this test. */
const runThroughExecutor = async (argv: readonly string[]): Promise<{
  readonly stdout: string
  readonly stderr: string
  readonly status: string
  readonly exitCode: number
  readonly stdoutHash: string | null
  readonly redactedPreview: string
}> => {
  const result = await executeDockerCommand(baseRequest(argv) as never, {
    checkRunsc: () => false,
    nonceStore: new InMemoryDecisionNonceStore(),
  })

  return result as never
}

/** One `Cap*`/`NoNewPrivs` line out of `/proc/self/status`, as the kernel reports it. */
const procStatusField = (status: string, field: string): string =>
  new RegExp(`^${field}:\\s*(\\S+)`, "mu").exec(status)?.[1] ?? ""

test("substrate: --cap-drop ALL empties the bounding set, and the non-root user alone does not", { skip: todo }, async () => {
  // The container is also `--user 1001:1001`, and a non-root user has an empty effective set on its
  // own. Asserting `CapEff` here would therefore prove nothing: it is zero either way. The
  // bounding set is the discriminator, because `--cap-drop ALL` is what clears it.
  const result = await runThroughExecutor(["sh", "-c", "grep -E '^Cap(Bnd|Eff)' /proc/self/status"])

  assert.equal(result.status, "executed")
  assert.equal(
    procStatusField(result.stdout, "CapBnd"),
    "0000000000000000",
    "the bounding set still holds capabilities, so --cap-drop ALL did not take effect",
  )

  const control = plainDocker(
    "grep -E '^Cap(Bnd|Eff)' /proc/self/status",
    // Same non-root user, cap-drop deliberately absent.
    ["--user", "1001:1001"],
  )

  assert.notEqual(
    procStatusField(control, "CapBnd"),
    "0000000000000000",
    "this daemon grants no bounding capabilities even without --cap-drop ALL, so the test proves nothing",
  )
})

test("substrate: --security-opt no-new-privileges sets NoNewPrivs, and nothing else here does", { skip: todo }, async () => {
  const result = await runThroughExecutor(["sh", "-c", "grep '^NoNewPrivs' /proc/self/status"])

  assert.equal(result.status, "executed")
  assert.equal(procStatusField(result.stdout, "NoNewPrivs"), "1", "no-new-privileges did not take effect")

  const control = plainDocker("grep '^NoNewPrivs' /proc/self/status", ["--user", "1001:1001"])

  assert.equal(procStatusField(control, "NoNewPrivs"), "0", "NoNewPrivs was already 1 without the flag")
})

test("substrate: --cpus 0.5 reaches the cgroup as a quota of 50000/100000", { skip: todo }, async () => {
  const result = await runThroughExecutor(["sh", "-c", "cat /sys/fs/cgroup/cpu.max"])

  assert.equal(result.status, "executed")
  assert.equal(
    result.stdout.trim(),
    "50000 100000",
    "the cgroup cpu quota is not the 0.5 CPU the executor asked for",
  )

  // The value the executor computes for 0.5, not a literal, so changing the flag breaks the test.
  assert.equal(result.stdout.trim(), `${Math.round(0.5 * 100_000)} 100000`)

  assert.equal(plainDocker("cat /sys/fs/cgroup/cpu.max").trim(), "max 100000")
})

test("substrate: --pids-limit 64 stops a fork storm that succeeds without it", { skip: todo }, async () => {
  // 200 background processes against a limit of 64. The shell gives up on the first failed fork
  // and exits 2, so the container reports a failed execution — the limit showing up as a non-zero
  // exit is the observation, and the reason has to be read out of stderr to be worth anything.
  const script = 'i=0; while [ $i -lt 200 ]; do sleep 1 & i=$((i+1)); done; echo "forked=$i"'

  const result = await runThroughExecutor(["sh", "-c", script])

  assert.equal(result.status, "failed", "200 forks all succeeded under a limit of 64")
  assert.equal(result.exitCode, 2, "the shell exited 0, so nothing stopped it")
  assert.match(result.stderr, /can't fork|Resource temporarily unavailable/u, "the failure was not the pids limit")
  assert.doesNotMatch(result.stdout, /forked=200/u)

  assert.match(plainDocker(script), /forked=200/u, "this daemon refused 200 forks even without --pids-limit")
})

test("substrate: --tmpfs /tmp:size=64m bounds /tmp, which a read-only root filesystem alone would not", { skip: todo }, async () => {
  // 128 MB into a 64 MB tmpfs. The two refusals are different: a read-only root filesystem gives
  // EROFS, and this gives ENOSPC. Getting EROFS would mean the write never reached the tmpfs and
  // the size limit was never exercised.
  //
  // `dd`'s own exit status has to be read straight after it: piping it into `tail` would report
  // tail's status, which is 0 either way and proves nothing.
  const script = 'dd if=/dev/zero of=/tmp/limit-probe bs=1M count=128 2>&1; echo "dd_exit=$?"'

  const result = await runThroughExecutor(["sh", "-c", script])

  assert.equal(result.status, "executed", "the container itself failed, so the limit was never reached")
  assert.match(result.stdout, /No space left on device/u, "/tmp accepted 128 MB despite a 64 MB tmpfs")
  assert.doesNotMatch(result.stdout, /Read-only file system/u, "the write hit the read-only rootfs, so the tmpfs was never exercised")
  assert.match(result.stdout, /dd_exit=1/u)

  assert.match(plainDocker(script), /128\+0 records out[\s\S]*dd_exit=0/u, "this daemon capped /tmp even without --tmpfs")
})

test("substrate: --memory 512m kills a container that holds 700 MB, which survives without it", { skip: todo }, async () => {
  // A cgroup memory limit is charged on pages *held*, so the probe has to hold them: writing to the
  // overlay filesystem does not, because that is reclaimable page cache and a container limited to
  // 512 MB will happily write 200 MB to disk and exit 0. `tr` expands the zeroes into real bytes
  // that the shell then has to keep.
  //
  // This needs a timeout of its own: pushing 700 MB through `tr` takes longer than the 20 s the
  // other tests sign for, and a timeout would arrive before the limit does, which would make this
  // test pass for the wrong reason.
  const script = 'v=$(head -c 700000000 /dev/zero | tr "\\000" "a"); echo "held=${#v}"'
  const roomyConstraints = createDecisionConstraints({
    networkMode: "none",
    timeoutMs: 120_000,
    maxOutputBytes: 4_000,
  })

  const result = (await executeDockerCommand(
    {
      ...baseRequest(["sh", "-c", script]),
      decisionToken: mintToken(["sh", "-c", script], { constraints_hash: canonicalHash(roomyConstraints) }),
      timeoutMs: roomyConstraints.timeout_ms,
    } as never,
    { checkRunsc: () => false, nonceStore: new InMemoryDecisionNonceStore() },
  )) as never as { readonly status: string; readonly exitCode: number; readonly stdout: string }

  assert.equal(result.status, "failed", `a container holding 700 MB under a 512 MB limit reported ${result.status}`)
  assert.equal(result.exitCode, 137, "expected the OOM killer (128 + SIGKILL)")
  assert.doesNotMatch(result.stdout, /held=/u, "the workload finished, so the limit was never reached")

  assert.match(plainDocker(script), /held=700000000/u, "this daemon could not hold 700 MB even without --memory")
})

test("substrate: real output past the budget is truncated, and the full stream is still hashed", { skip: todo }, async () => {
  // 4000 bytes is the budget the token was signed with. A truncation that only happens to a stub
  // would still pass a test that emitted less output than the budget, so this emits ten times it.
  //
  // The marker deliberately avoids the word "truncated": a test that greps its own output for a
  // marker has to be sure the marker is the container's output and not something the tooling said.
  const result = await runThroughExecutor(["sh", "-c", "yes actantos-output-budget-marker | head -c 40000"])

  assert.equal(result.status, "executed")
  assert.equal(Buffer.byteLength(result.stdout, "utf8"), constraints.max_output_bytes)
  assert.match(result.stdout, /actantos-output-budget-marker/u)
  assert.doesNotMatch(result.stdout, /truncat/iu, "something other than the container produced this output")

  // The untruncated stream is what the evidence hash covers; a hash of the truncated text would
  // make the recorded digest depend on the budget rather than on what ran.
  assert.notEqual(result.stdoutHash, null)
  assert.match(result.stdoutHash as string, /^[0-9a-f]{64}$/u)
})

test("substrate: a secret printed by the container is scrubbed from the preview and kept out of it", { skip: todo }, async () => {
  // Two shapes the scrubber recognises: a GitHub token and a `*_SECRET=` assignment. Both are
  // fabricated here and are worthless to anyone.
  const token = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
  const result = await runThroughExecutor([
    "sh",
    "-c",
    `echo "MY_API_SECRET=s3cr3t-value"; echo "token=${token}"`,
  ])

  assert.equal(result.status, "executed")

  // The raw stdout is what ran, and keeping it is deliberate — the evidence record is supposed to
  // be the real output. What must never happen is the *scrubbed* preview carrying the value.
  assert.match(result.stdout, /s3cr3t-value/u, "the container did not print what this test needs it to print")
  assert.match(result.stdout, new RegExp(token, "u"))

  assert.doesNotMatch(result.redactedPreview, /s3cr3t-value/u, "a secret reached the redacted preview")
  assert.doesNotMatch(result.redactedPreview, new RegExp(token, "u"), "a token reached the redacted preview")
  assert.match(result.redactedPreview, /\[REDACTED_GITHUB_TOKEN\]/u)
  assert.match(result.redactedPreview, /MY_API_SECRET=\[REDACTED\]/u)
})

test("substrate: a command that outlives its signed timeout is killed and reported as a timeout", { skip: todo }, async () => {
  // The timeout is signed into the token, so this cannot be widened after authorization — the
  // request below carries the same 3 s the token commits to.
  const shortConstraints = createDecisionConstraints({
    networkMode: "none",
    timeoutMs: 3_000,
    maxOutputBytes: 4_000,
  })

  const started = Date.now()
  const result = (await executeDockerCommand(
    {
      ...baseRequest(["sleep", "120"]),
      decisionToken: mintToken(["sleep", "120"], { constraints_hash: canonicalHash(shortConstraints) }),
      timeoutMs: shortConstraints.timeout_ms,
    } as never,
    { checkRunsc: () => false, nonceStore: new InMemoryDecisionNonceStore() },
  )) as never as { readonly status: string; readonly errorMessage: string }

  const elapsed = Date.now() - started

  assert.equal(result.status, "timeout")
  assert.equal(result.errorMessage, "docker execution timed out")
  // 120 s of sleep did not run. The upper bound is loose because a loaded host is still a loaded
  // host; what it rules out is the 120 s the command asked for.
  assert.ok(elapsed < 60_000, `the timeout took ${String(elapsed)} ms, so the container was not killed`)
})
