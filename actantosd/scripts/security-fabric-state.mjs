// Single source of truth for what is actually verified in this repository, right now.
//
// Security documentation drifted because test counts were transcribed by hand into Markdown
// and never re-derived. This module derives them from the files themselves so the numbers in
// `docs/security-fabric-current-state.json` cannot silently go stale.
//
// Two kinds of fields exist:
//
//   stable   - derived from tracked files. A change means the repository changed.
//   volatile - describes this machine and this moment (commit, clock, hostname).
//
// `security-fabric-state.test.mjs` compares only the stable fields. A test run regenerates
// `generated_at` and the commit moves every time a change is committed, so requiring those to
// match a committed file would make the file impossible to keep.

import { execFileSync } from "node:child_process"
import { existsSync, readFileSync, readdirSync } from "node:fs"
import { join, relative } from "node:path"
import { fileURLToPath } from "node:url"

export const REPO_ROOT = fileURLToPath(new URL("../../", import.meta.url))
export const DAEMON_ROOT = join(REPO_ROOT, "actantosd")
export const BENCH_ROOT = join(REPO_ROOT, "security-bench")

/**
 * Count `test(...)` declarations.
 *
 * This matches the way the existing docs guard counts: a top-level `test(` or an indented one
 * inside a `describe`. It deliberately does not try to be a JavaScript parser.
 *
 * The known limit, measured rather than assumed: a `test(` site inside a `for` loop is counted
 * once here and registered once per iteration by the runner. Today that is exactly one file —
 * `src/v2/security-fuzz.test.ts`, two sites in a three-iteration loop — so the static total is
 * four below what `npm test` reports. Any loop-generated site added later widens that gap
 * silently, which is why the gap is recomputed and published as `runner_overcount` below instead
 * of left to be rediscovered from a mismatch.
 */
export const countTests = (source) => {
  const pattern = /^[ \t]*(?:await[ \t]+)?test\(/gm
  return source.match(pattern)?.length ?? 0
}

/**
 * Count the tests the runner registers beyond what `countTests` sees.
 *
 * A `test(` inside a `for (const x of [...])` body registers once per element while the static
 * count sees it once. Indentation is the discriminator: this codebase writes loop bodies
 * indented past their `for`, so a following line at the loop's own indentation or shallower ends
 * the body. A full parse is deliberately not attempted, for the same reason `countTests` does
 * not parse — this must not become a second, disagreeing view of the source.
 */
export const countLoopGeneratedTests = (source) => {
  const lines = source.split("\n")
  let overcount = 0

  for (let i = 0; i < lines.length; i += 1) {
    const header = lines[i].match(/^([ \t]*)for \([^)]*of \[([^\]]*)\]/)

    if (header === null) {
      continue
    }

    const loopIndent = header[1].length
    const iterations = header[2]
      .split(",")
      .map((entry) => entry.trim())
      .filter((entry) => entry.length > 0).length
    let sites = 0

    for (let j = i + 1; j < lines.length; j += 1) {
      const line = lines[j]

      if (line.trim().length === 0) {
        continue
      }

      if (line.match(/^([ \t]*)/)[1].length <= loopIndent) {
        break
      }

      if (/^[ \t]*(?:await[ \t]+)?test\(/.test(line)) {
        sites += 1
      }
    }

    overcount += sites * (iterations - 1)
  }

  return overcount
}

const listFiles = (directory, extension) => {
  if (!existsSync(directory)) return []
  return readdirSync(directory)
    .filter((name) => name.endsWith(extension))
    .sort()
}

const countDirectory = (directory, extension) => {
  const files = listFiles(directory, extension)
  const perFile = {}
  let total = 0
  let overcount = 0

  for (const name of files) {
    const source = readFileSync(join(directory, name), "utf8")
    const count = countTests(source)
    perFile[name] = count
    total += count
    overcount += countLoopGeneratedTests(source)
  }

  return { total, overcount, perFile }
}

/**
 * Decompose the test suite the same way `npm test` invokes it, so the three groups partition
 * the same files. The groups sum to the static total; `runner_overcount` is what the runner
 * reports on top of it, for the reason given on `countTests` above.
 */
export const collectUnitSuite = () => {
  const daemon = countDirectory(join(DAEMON_ROOT, "src"), ".test.ts")
  const v2 = countDirectory(join(DAEMON_ROOT, "src", "v2"), ".test.ts")
  const scripts = countDirectory(join(DAEMON_ROOT, "scripts"), ".test.mjs")
  const bench = countDirectory(join(BENCH_ROOT, "src"), ".test.ts")

  return {
    daemon_src: daemon.total,
    v2_fabric: v2.total,
    release_scripts: scripts.total,
    daemon_total: daemon.total + v2.total + scripts.total,
    runner_overcount: daemon.overcount + v2.overcount + scripts.overcount,
    security_bench_package: bench.total,
    per_file: {
      "actantosd/src": daemon.perFile,
      "actantosd/src/v2": v2.perFile,
      "actantosd/scripts": scripts.perFile,
      "security-bench/src": bench.perFile,
    },
  }
}

/**
 * Which security substrates the test suite depends on, and how each is exercised.
 *
 * This registry is repository truth and is machine-independent. The three levels are kept
 * strictly separate because collapsing them is how a simulation gets reported as a substrate
 * verification:
 *
 *   REAL_SUBSTRATE - the actual binary or service performs the work.
 *   INTEGRATION     - the production code path runs against a real instance (a real Postgres,
 *                     a real Unix socket), just not a privileged kernel feature.
 *   SIMULATED       - the code path runs, but the dependency is injected as a fake. Real
 *                     coverage of the surrounding logic, zero coverage of the substrate.
 *
 * A test file absent from this registry is either unclassified or fully simulated; the
 * matching test asserts every file that mentions a substrate binary is classified here.
 */
export const SUBSTRATE_REQUIREMENTS = {
  "cedar-pdp": {
    substrate: "cedar",
    level: "REAL_SUBSTRATE",
    test_files: ["src/cedar-provider.test.ts"],
    gated_tests: 4,
    gate: "cedar CLI answers --version",
    note:
      "Without the binary these four tests skip, including the one that shows Cedar enforcing a " +
      "workspace constraint and the one that shows the in-process built-in evaluator agreeing " +
      "with the CLI on every shape. The remaining Cedar tests in this file use FakeCedarProvider " +
      "and prove the fail-closed wiring and the entity attributes, not Cedar itself.",
    measured_exit_codes:
      "cedar-policy-cli 4.13.0: Allow exits 0 with ALLOW; Deny exits 2 with a bare DENY; a parse " +
      "error exits 1 with a × diagnostic; a missing policy file exits 1. A Deny is therefore a " +
      "decision and not an evaluator failure, and the two are told apart by the diagnostic the " +
      "CLI appends, not by the exit code alone.",
  },
  "cedar-fake-provider": {
    // SIMULATED, with the measured divergence recorded rather than the reassuring summary this
    // entry used to carry. It said "FakeCedarProvider permits everything except credential_access.
    // A pass here proves the surrounding v1 wiring, and proves nothing about Cedar authorization
    // semantics." Every clause of that was true and it still let a real defect through.
    substrate: "cedar",
    level: "SIMULATED",
    test_files: [
      "src/cedar-fixture-parity.test.ts",
      "src/audit-chain-verifier.test.ts",
      "src/budget-pipeline.test.ts",
      "src/intercept-service.test.ts",
      "src/mcp-gateway.test.ts",
      "src/policy-bundle-hot-reload.test.ts",
      "src/postgres-repository.test.ts",
      "src/tool-result-service.test.ts",
    ],
    gated_tests: 5,
    gate:
      "cedar-policy-cli on PATH for the five parity tests that evaluate a fixture against the " +
      "real policy; they skip without it. The other two read only the registry file or the " +
      "authorize input and always run. The seven v1 files themselves need nothing and run in the " +
      "ordinary suite",
    note:
      "WHAT WAS MEASURED: FakeCedarProvider does not merely 'permit everything except " +
      "credential_access'. It permits things the shipped policy DENIES, and five of these seven " +
      "files built their 'allow' precondition on exactly such a decision. " +
      "commandFromRequest derives the workspace as dirname(resource.path), so a fixture with " +
      "resource.path = '/workspace' derives the workspace '/', and policies/default.cedar permits " +
      "only resource.path == '' || resource.workspace_path == '/workspace'. Running the real " +
      "cedar-policy-cli 4.13.0 over those fixtures: path '/workspace' -> real=forbid fake=permit; " +
      "'hello.txt' -> real=forbid fake=permit; '/workspace/README.md' -> both permit. " +
      "The consequence was not a false alarm but a false certification -- suites asserting " +
      "'an allowed tool call is audited' on the strength of an authorization production refuses. " +
      "FIXED: audit-chain-verifier, tool-result-service and policy-bundle-hot-reload now declare " +
      "host_workspace_path, so their allow is one the real policy also gives. " +
      "MCP, AND THE GAP IS NOW CLOSED WITHOUT WIDENING THE DEFAULT: src/mcp-gateway.ts derives " +
      "resource.path as '/mcp/<server>/tools/<tool>', which policies/default.cedar confines to " +
      "the approved workspace and therefore denies. That fail-closed default is deliberate and is " +
      "now asserted as such. Two further defects were found while closing it: " +
      "policies/templates/mcp-readonly.cedar shipped INERT, permitting nothing, because it gated " +
      "on Action::\"ReadFile\" and Action::\"ListFiles\" while the gateway emits " +
      "Action::\"tools/call\" for every MCP call; and it could not have expressed read-only-ness " +
      "at all, because buildCedarAuthorizeInput never put the mutation and destructive verdicts " +
      "on the entity. Both fixed: those two attributes are now surfaced additively (a policy that " +
      "ignores them is unaffected), and the template gates on the action the gateway really emits " +
      "plus mutation == false and destructive == false. Real cedar, verified: the template permits " +
      "a read-only non-credential MCP call and refuses the credential, mutating and destructive " +
      "shapes, including one whose readOnlyHint lied. The default still refuses all five. " +
      "Absent mutation/destructive reads as TRUE, so an undetermined status denies; the false " +
      "default was mutation-checked and would have failed open. Selecting this template via " +
      "CEDAR_POLICY_PATH is the explicit act that opens MCP, and it is not the shipped default. " +
      "STILL SIMULATED: what these files prove is the surrounding wiring -- audit chaining, budget " +
      "short-circuit, idempotent replay, approval single-use, dry-run, manifest and SSRF guards -- " +
      "none of which depends on Cedar's answer. Cedar authorization semantics are proved only by " +
      "src/cedar-provider.test.ts against the real binary.",
  },
  "postgres-tenant-rls": {
    substrate: "postgres",
    level: "INTEGRATION",
    test_files: ["src/tenant-isolation.test.ts"],
    gated_tests: 4,
    gate: "DATABASE_URL is set and `npm run test:substrate` was used",
    note: "pg-mem does not implement RLS, so these cannot be run against the in-memory substitute.",
  },
  "sidecar-local-socket": {
    // INTEGRATION. The property under test is that the sidecar is reachable only through a
    // socket a separate process holds, which is what makes it a boundary rather than a function
    // call. A real kernel-provided socket is what carries the frames; there is no fake here.
    substrate: "local_socket",
    level: "INTEGRATION",
    test_files: ["src/v2/sidecar-server.test.ts"],
    gated_tests: 0,
    gate: "none - the platform always provides a local socket, so this never skips",
    note:
      "On POSIX this is a Unix domain socket in a per-user temporary directory and the file is " +
      "created 0600. On Windows `node:net` refuses filesystem socket paths, so it is a named " +
      "pipe instead, which has no filesystem mode; the owner-only assertion is therefore skipped " +
      "on Windows and the test says so rather than passing vacuously. The named-pipe namespace is " +
      "ACL'd per user, but that is a claim about Windows and is not asserted here.",
  },
  "fabric-runtime-wiring": {
    // INTEGRATION. The property under test is not that the gate function works in isolation --
    // `fabric.test.ts` covers that -- but that the dispatching server consults it on a live
    // request, over a live socket, and honours the answer. The gate and the sidecar are real
    // objects in a real process boundary; only the control plane is absent, because a local
    // signed lease is the S11 property and not consulting the control plane is the point.
    substrate: "local_socket",
    level: "INTEGRATION",
    test_files: ["src/v2/fabric.test.ts", "src/v2/fabric-runtime.test.ts"],
    gated_tests: 0,
    gate: "none - the socket, the sidecar and the server are all constructed in-process",
    note:
      "These tests do not read ACTANTOS_FABRIC_MODE; they inject the mode, because the mode is " +
      "process-scoped by design (the agent controls the request, not the operator's environment). " +
      "The env-to-gate path in src/index.ts is therefore covered by startup-time failure tests only, " +
      "not by an end-to-end request. No system-level egress or Tetragon policy is verified here.",
  },
  "docker-internal-cell-network": {
    // REAL_SUBSTRATE, and the only entry here that establishes a property of the Docker topology
    // rather than of a decision. The cell's claim is that the workload has no route out except
    // the proxy, and that is a property of an `--internal` network — a property no TypeScript in
    // this repository can hold or break on its own. Asserting it against `egress-proxy.ts` alone
    // would be asserting that the code is correct while saying nothing about whether the code is
    // reachable.
    substrate: "docker",
    level: "REAL_SUBSTRATE",
    test_files: ["src/v2/egress-proxy-topology.test.ts"],
    gated_tests: 4,
    gate: "a usable Docker daemon; without one these four tests skip",
    note:
      "Runs real containers and observes what the kernel does: no HTTPS egress, no raw-socket " +
      "egress, no route to 169.254.169.254, SERVFAIL from the embedded resolver for any name the " +
      "cell does not host, and a peer reachable by name and by IP so the blocked cases are not " +
      "just a dead network. These take about 10s and are the slowest tests in the suite. They do " +
      "NOT start the proxy itself — the proxy is proved separately in egress-proxy.test.ts, and " +
      "the assertion that the proxy is the cell's only route is a deployment property recorded in " +
      "docs/ARCHITECTURE_V2.md, not something these tests check.",
  },
  "postgres-replay-guard": {
    // REAL_SUBSTRATE, unlike the sibling entry above. The load-bearing claim here is that a real
    // PostgreSQL server makes the first use exclusive, and that is exactly what runs. RLS on
    // v2_replay_guard is applied by the migration but not exercised, because the test connection
    // is the migration superuser; that gap is recorded in the note below rather than hidden.
    substrate: "postgres",
    level: "REAL_SUBSTRATE",
    test_files: ["src/v2/replay-store.test.ts", "src/v2/effect-gateway-replay.test.ts"],
    gated_tests: 15,
    gate: "DATABASE_URL is set and `npm run test:substrate` was used",
    note:
      "Atomic first use (S9) depends on INSERT ... ON CONFLICT DO NOTHING, which pg-mem does " +
      "not implement, so in-memory cannot demonstrate it. Tenant isolation is proven at the " +
      "application layer, not by the row-level security policy.",
  },
  "postgres-evidence-store": {
    // REAL_SUBSTRATE. Append order is the security property: record N+1's prev_hash is record N's
    // hash, so two writers appending the same tenant at once would produce two different chains.
    // Only a real server provides the advisory lock that serialises them, and only a real server
    // provides BEFORE UPDATE OR DELETE triggers and enforced RLS. pg-mem has neither, so this
    // cannot be demonstrated in memory.
    substrate: "postgres",
    level: "REAL_SUBSTRATE",
    test_files: ["src/v2/evidence-store.test.ts"],
    gated_tests: 14,
    gate: "DATABASE_URL is set and `npm run test:substrate` was used",
    note:
      "Durability, single-writer append order, append-only enforcement and tenant isolation (S13) " +
      "all need a real PostgreSQL server. RLS here is exercised as an ordinary role via SET LOCAL " +
      "ROLE, which is the only way to prove it: a superuser bypasses RLS outright.",
  },
  "postgres-effect-journal": {
    // REAL_SUBSTRATE. The state machine is pure and tested without a database, but what makes it
    // trustworthy is that the database enforces the same transitions independently. A bug in the
    // process that is supposed to be enforcing them is precisely the situation where only a
    // second, non-application line of defence counts.
    substrate: "postgres",
    level: "REAL_SUBSTRATE",
    test_files: ["src/v2/effect-commit.test.ts"],
    gated_tests: 10,
    gate: "DATABASE_URL is set and `npm run test:substrate` was used",
    note:
      "The transition table, the immutability of action_digest, the finality of a terminal " +
      "outcome and the no-delete rule are BEFORE UPDATE OR DELETE triggers, which pg-mem does " +
      "not implement. Tenant isolation is exercised as an ordinary role via SET LOCAL ROLE.",
  },
  "gvisor-sandbox": {
    substrate: "gvisor_runsc",
    // REAL_SUBSTRATE. This host does run gVisor, through a second isolated dockerd inside the
    // WSL2 Ubuntu-24.04 distro that has runsc registered. The earlier NOT_RUN was accurate about
    // Docker Desktop's daemon and wrong about the machine: the gate probes whichever daemon
    // DOCKER_HOST names, so pointing it at the gVisor one is enough.
    level: "REAL_SUBSTRATE",
    test_files: [
      "src/sandbox-runtime.test.ts",
      "src/docker-executor.test.ts",
      "src/server-startup-sandbox.test.ts",
      "src/gvisor-sandbox-substrate.test.ts",
    ],
    gated_tests: 9,
    gate:
      "ACTANTOS_SUBSTRATE_TESTS=1 and ACTANTOS_GVISOR_DOCKER_HOST naming a daemon whose " +
      "`docker info --format {{json .Runtimes}}` lists a runsc entry; on this machine that is " +
      "the isolated dockerd in WSL2 Ubuntu-24.04 at tcp://127.0.0.1:23750, running " +
      "runsc release-20260928.0. Docker Desktop's own daemon still has no runsc, so these skip",
    // Two of these nine sites are runtime skips rather than gate skips, and both are host facts.
    runtime_skips: [
      {
        test: "the gate still refuses when the live daemon has no runsc",
        reason:
          "the test compares against whatever DOCKER_HOST names when it is unset. The Windows " +
          "client's default is Docker Desktop, which has no runsc, so it runs there. Inside WSL " +
          "the default is a unix:///var/run/docker.sock that does not exist — that distro's daemon " +
          "is reachable only over TCP — so there is no runsc-free daemon to compare against and it " +
          "skips rather than reporting a product defect that is a property of the host.",
      },
      {
        test: "the executor's own runsc probe is what adds the flag, with nothing injected",
        reason:
          "this one deliberately passes no checkRunsc, so the executor's own `which runsc` decides. " +
          "runsc is installed in WSL2 and is not on the Windows PATH, so it runs under WSL and " +
          "skips on Windows. That asymmetry is the point: injecting the gate as () => true would " +
          "have proved the argv rather than the wiring.",
      },
    ],
    note:
      "Proven against a real daemon: the same image and daemon run on two different kernels " +
      "depending only on the runtime flag — /proc/version reads 6.18.33.2-microsoft-standard-WSL2 " +
      "under the default runtime and 4.19.0-gvisor under runsc, and dmesg returns gVisor's own " +
      "boot log where the host ring buffer is refused. That difference is what shows the flag is " +
      "honoured rather than ignored. The executor's real spawn path is included: it runs a " +
      "container through runsc and the container's own /proc/version is read back through the " +
      "bind mount, so dropping --runtime runsc fails the test rather than passing it quietly. " +
      "Egress is NOT claimed here: this daemon's bridge has no external route for either runtime, " +
      "so blocked egress here cannot be attributed to gVisor's netstack.",
  },
  "decision-execution": {
    // The production caller for the executor, which until this existed had none. Everything in
    // this path is ordinary in-process code; the container it starts is covered by
    // docker-container-execution and the replay claim by postgres-replay-guard, so this entry is
    // about the wiring between them rather than about any substrate of its own.
    substrate: "local_process",
    level: "INTEGRATION",
    test_files: ["src/decision-execution.test.ts", "src/execution-routes.test.ts"],
    gated_tests: 0,
    gate:
      "none - the lookup and the spawn are injected; the durable nonce store and the Ed25519 " +
      "verifier are the same implementations the production path constructs",
    note:
      "Reads a stored authorization back from PostgreSQL, refuses anything that is not a live " +
      "allow, and spends the token through the real executeDockerCommand. Identity comes from " +
      "the record rather than from the caller, so assertClaimsMatch compares a signature against " +
      "an independent row instead of against itself; argv and workspace_path come from the caller " +
      "and are the S8 surface. Refuses to construct with an HMAC verifier (S7) and refuses a " +
      "stored HMAC token by name rather than falling back. Constraints are read from the record " +
      "and bound by constraints_hash, so a tampered row cannot widen egress. The route is " +
      "registered only under ACTANTOS_DECISION_EXECUTION=1 and never on a control plane, and a " +
      "test asserts the route is absent otherwise. Does NOT prove that a container started this " +
      "way is genuinely isolated, or that the Ed25519 private key stays off the executor host.",
  },
  "docker-executor": {
    // REAL_SUBSTRATE. This entry was SIMULATED with three items of residue itemised in it, and all
    // three are now closed rather than waived. What changed is that the flags are no longer only
    // asserted as strings: each one is executed on a real container and its effect is read back
    // from inside that container.
    //
    // The three that were open, and what closed each:
    //
    //  1. "the argv strings for --cap-drop ALL, --security-opt no-new-privileges, --memory,
    //      --cpus, --pids-limit and --tmpfs, whose effects inside a container are unobserved".
    //     Nine tests in docker-executor-substrate.test.ts run these through the real executor and
    //     read the consequence from inside the container: the bounding set in /proc/self/status,
    //     NoNewPrivs, the cgroup's cpu.max, the fork limit, the tmpfs ENOSPC, and the OOM killer.
    //     Every one carries a control that removes exactly that flag and asserts the effect is
    //     gone, so a daemon that defaults to the safe value cannot make the test pass vacuously.
    //
    //  2. "output truncation, secret redaction and the timeout path, which are asserted against a
    //      fabricated stdout rather than a real process exit". Also closed: a container emitting ten
    //      times the signed budget is truncated to the budget and the untruncated stream is still
    //      hashed; a container printing token-shaped and SECRET=-shaped strings has them scrubbed
    //      from the preview; and a container outliving its signed timeout is killed and reported as
    //      a timeout rather than allowed to finish.
    //
    //  3. "the gVisor --runtime runsc flag plumbing, which is environment-variable and stub-driven".
    //     The flag itself was already proved end to end in gvisor-sandbox-substrate.test.ts — the
    //     executor runs a container whose /proc/version reads the gVisor kernel. What was left was
    //     that the gate was always injected as `() => true`, so nothing showed the executor's own
    //     `which runsc` was what turned the flag on. That file now runs on both hosts, and a test
    //     there passes no `checkRunsc` at all, so production code decides and the container is
    //     still observed running under gVisor.
    //
    // All nine flag/output mutations were checked: deleting each flag, or disabling truncation,
    // redaction or the timeout kill, fails exactly one test and leaves the rest green. Making
    // resolveSandboxRuntimeFlags return no flag at all fails the gVisor probe test.
    substrate: "docker",
    level: "REAL_SUBSTRATE",
    test_files: ["src/docker-executor.test.ts", "src/docker-command-plan.test.ts", "src/decision-command.test.ts"],
    gated_tests: 0,
    gate: "none in these three files — they still assert against a recorded command, which is the right check for the decision logic. The live counterparts are in docker-container-execution below and gvisor-sandbox above.",
    note:
      "Container argv is asserted against a recorded command, not against a live container. " +
      "docker-command-plan.test.ts asserts argv construction only and runs no container. " +
      "Backed live in docker-container-execution below: command substitution and workspace remount " +
      "(S8); expiry, tampering and claim-binding (S12); single-use and the nonce claim (S9); " +
      "--network none isolation and the internal egress cell (S2); non-root uid and read-only " +
      "rootfs; the whole Ed25519 path including the HMAC-downgrade and untrusted-key refusals " +
      "(S7); and every resource limit and output rule listed above. Backed live in " +
      "gvisor-sandbox above: the --runtime runsc flag, including the executor's own probe for it. " +
      "NOT claimed: that these limits hold on a daemon that ignores them. Each test's control says " +
      "what the daemon does without the flag, and a daemon that shipped the unsafe default would " +
      "make the control fail rather than the test pass.",
  },
  "pi-adapter-shell-executor": {
    substrate: "docker",
    level: "REAL_SUBSTRATE",
    test_files: [
      "../packages/pi-adapter/src/shell_executor.test.ts",
      "../packages/pi-adapter/src/shell_executor_substrate.test.ts",
    ],
    gated_tests: 8,
    gate: "ACTANTOS_SUBSTRATE_TESTS=1 and a working Docker daemon — needs real containers and pulls alpine",
    note:
      "Enforces the same command/constraints/expiry/single-use binding as docker-executor, and " +
      "its drift guards import the actantosd implementations to prove the restated digests " +
      "match. The substrate file starts real containers on this path, which is the point of " +
      "running the fork: two executors agreeing on recorded argv can still disagree about what " +
      "Docker receives. Says nothing about gVisor: checkRunsc is stubbed to false.",
    // One test in this package skips on this host for a platform reason, not a substrate one.
    host_skips: [
      {
        test: "guarded_read.test.ts — a symlink to a credential file is resolved before the decision",
        reason:
          "creating a file symlink returns EPERM on Windows without Developer Mode or elevation. " +
          "The test probes the capability rather than the platform name and runs wherever symlinks " +
          "can be created. It is skipped, not passing: the symlink-resolution path is unexercised " +
          "here and no other test covers it.",
      },
    ],
  },
  "docker-container-execution": {
    // REAL_SUBSTRATE, unlike docker-executor above. That entry asserts the planned argv against a
    // recorded command, which proves the executor decided to refuse. It cannot show that a running
    // container is subject to that decision, which is the claim S8 actually needs. These start
    // real containers, so a substituted command is refused with a live Docker daemon behind it.
    substrate: "docker",
    level: "REAL_SUBSTRATE",
    test_files: ["src/docker-executor-substrate.test.ts"],
    gated_tests: 26,
    gate: "ACTANTOS_SUBSTRATE_TESTS=1 and a working Docker daemon — needs real containers and pulls alpine",
    note:
      "Proves the bound command runs, that a substituted one is refused with Docker live, that " +
      "--network none leaves no resolution, that the container is non-root with a read-only " +
      "root filesystem, and that one decision token yields one container. Added since: the " +
      "Ed25519 verifier end to end (an Ed25519-signed token starts a real container, an HMAC " +
      "token under the same verifier is refused, and a well-formed token signed by an untrusted " +
      "key is refused), and the egress cell — the executor provisions actantos_egress_cell and " +
      "the test reads `Internal: true` back from the daemon while a workload on it fails to " +
      "resolve a name. Both were mutation-checked against the product code. Says nothing about " +
      "gVisor: runsc is stubbed via checkRunsc. The nonce store is in-process, so this does not " +
      "show replay resistance across an executor restart.",
  },
  "tetragon-runtime": {
    substrate: "tetragon_ebpf",
    // REAL_SUBSTRATE, and this entry used to be wrong in the opposite direction. It said NOT_RUN
    // because no event had ever been observed -- but the probe was reading the agent's stdout,
    // and Tetragon exports to /var/log/tetragon/tetragon.log. Reading the exporter showed the
    // substrate working the whole time. Separately, running the policy this repository actually
    // emits against a live agent found a defect in the emitter itself.
    //
    // What was measured, on Tetragon v1.7.1 over kernel 6.18.33.2-microsoft-standard-WSL2:
    //
    //  1. The emitted policy was REJECTED outright -- `writeMatchValues error: MatchArgs type
    //     linux_binprm unsupported`, and the same for the file hook. `operator: Mask` is not a
    //     loadable selector on those argument types, so the policy could not be installed on any
    //     current agent. Fixed to `operator: Equal`, which loads and is exact -- and is what
    //     `deniedBinaries` means anyway: an absolute path, not a mask.
    //  2. Events DO arrive on this kernel. `security_bprm_check` fired in the hundreds and
    //     `security_file_permission` in the thousands once the exporter was read. The earlier
    //     claim that the LSM hook "is never called here" and that a `tcp_connect` kprobe
    //     "emits nothing" were both artifacts of grepping the wrong stream.
    //  3. The selector is exact, not merely present: three `touch` runs produced exactly three
    //     events, against 130 for the same policy with no selector and 75 with `Prefix`.
    //
    // What is still NOT claimed: the built-in base sensor fails to load on this kernel
    // (`__x64_sys_getcpu() is not modifiable`), so the `process_exec` shape is not observed here.
    // The two probes this repository's policy selects are kprobes on real symbols and do fire.
    // No invariant is claimed from the exec-sensor stream, and `deniedWritePaths` has no runtime
    // signal path at all: security_file_permission events are parsed but deliberately not
    // classified, because turning a path write into a policy violation is not something this
    // adapter has measured.
    level: "REAL_SUBSTRATE",
    test_files: ["src/cli-emit-tetragon.test.ts", "src/v2/tetragon-substrate.test.ts"],
    gated_tests: 5,
    gate:
      "ACTANTOS_SUBSTRATE_TESTS=1 and a real Tetragon agent on a kernel where the emitted " +
      "policy loads. tetragon-substrate.test.ts writes toTracingPolicyYaml(buildTracingPolicy()) " +
      "to disk and loads THAT -- a hand-written policy would prove Tetragon works and would " +
      "prove nothing about this code -- then runs real binaries and reads the exporter at " +
      "/var/log/tetragon/tetragon.log, not the agent's stdout. It skips with 'tetragon refused " +
      "the policy this repository emits' if the agent rejects it, and with 'tetragon emitted " +
      "no events on this kernel' if the policy loads but nothing arrives. Those are different " +
      "failures and are gated separately.",
    note:
      "RUN here: five of five, skipped zero, against a live Tetragon v1.7.1 loading this " +
      "repository's unmodified policy output. One asserts the agent accepts the policy and " +
      "attaches a generic_kprobe sensor; one asserts exported lines reach the adapter as " +
      "process_kprobe events; one asserts a real denied-binary exec becomes an S3 " +
      "denied_binary_exec signal; one is the negative control that /bin/ls produces no signal; " +
      "and one asserts the kernel-side selector itself discriminates -- three touch runs and " +
      "three ls runs yield exactly three events -- so the classification tests cannot be " +
      "satisfied by an adapter filtering a stream that was never filtered. " +
      "A second defect was fixed alongside the Mask operator: the adapter modelled only " +
      "process_exec, which is emitted by the built-in base sensor, so it could not consume the " +
      "events its own policy selects. Every security_bprm_check line was classified 'unmodelled' " +
      "and dropped. process_kprobe is now parsed and security_bprm_check classified, using the " +
      "kernel-reported linux_binprm_arg.path rather than the cached process.binary -- the hook " +
      "exists precisely because the cached value can be stale. The real captured event shapes " +
      "are pinned in runtime-events.test.ts, including the negative case that a bprm event with " +
      "its path stripped must not be classified from process.binary. " +
      "Mutation-verified, and the results are not uniform. Restoring the Mask operator makes " +
      "all five tests FAIL. Treating kprobe events as unmodelled -- the old behaviour -- fails " +
      "one. Reading the cached process.binary instead of the kernel-reported binprm path fails " +
      "one. Removing the adapter's own deny-list check is NOT caught here: the policy's BPF " +
      "selector already filters to the denied binary, so the adapter check is redundant on this " +
      "path rather than absent. The unit suite catches that one (runtime-events.test.ts asserts " +
      "a bprm event naming an allowed binary produces no signal), which is recorded rather than " +
      "papered over. " +
      "A first version of this file had a worse defect, also found by mutation: using the " +
      "emitted policy for the capability probe meant a regression that made the policy " +
      "unloadable turned every test into a SKIP rather than a failure (pass=0 fail=0 skipped=5). " +
      "The gate now probes substrate availability with a separate known-good policy, and each " +
      "test asserts the emitted policy is accepted as a test failure. " +
      "Nothing in S1-S14 depends on this layer, and that remains the reason a substrate failure " +
      "here is a gap in evidence rather than a security regression.",
  },
  "spire-workload-identity": {
    // REAL_SUBSTRATE. This entry used to claim REAL_SUBSTRATE with five gated tests that had never
    // executed — the gate probed `spire-server version`, which is not a subcommand and exits 127
    // even where SPIRE is installed. A label with nothing behind it. It was then corrected down to
    // SIMULATED, because running it against a real SPIRE 1.15.3 trust domain showed the client
    // could not interoperate with SPIRE at all. Four independent defects, each measured:
    //
    //   1. Transport. The Workload API is gRPC over a Unix socket and does not answer HTTP/1.1:
    //      the GET this client used to send got the connection reset. `requestSvid` called
    //      `GET /workload-api/jwt-svid`, which no SPIRE version serves.
    //   2. Algorithm. SPIRE signs JWT-SVIDs with ES256. VERIFY_ALGORITHMS whitelisted Ed25519 and
    //      RS256 only, so a genuine SVID was refused as `unsupported_algorithm`.
    //   3. Issuer. SPIRE emits no `iss` claim. `verifyJwtSvid` required one equal to
    //      `spiffe://<trust domain>`, so every genuine SVID would be refused as
    //      `wrong_trust_domain` next.
    //   4. ECDSA encoding. JWS specifies raw R||S; node:crypto's verify only accepts DER. Adding
    //      ES256 to the table would not have been sufficient on its own.
    //
    // All four are fixed and the fixes are proven against the live trust domain, not against a
    // stub: `src/v2/spiffe-workload-api.ts` speaks the agent's actual gRPC (method
    // `/SpiffeWorkloadAPI/FetchJWTSVID`, the header `workload.spiffe.io: true`, `JWTSVIDRequest`
    // field numbers 1 and 2 — all measured on the agent, since a wrong field number is answered
    // with a plausible SPIFFE ID error rather than a parse error), and `rawEcdsaToDer` re-encodes
    // the signature before handing it to node:crypto. The trust domain is now read from the
    // subject SPIFFE ID, which is where SPIRE puts it, and a disagreeing `iss` is still refused.
    //
    // What is still not claimed: on a host without a Unix socket for the Workload API — every
    // Windows machine — these eleven tests skip, because SPIRE's socket cannot exist there. The
    // `spire_workload_api` field in `substrate_run` reports that, and this entry's gate says so.
    substrate: "spire",
    level: "REAL_SUBSTRATE",
    test_files: ["src/v2/spire-substrate.test.ts"],
    gated_tests: 11,
    gate:
      "spire-server and spire-agent are on PATH, ACTANTOS_SPIRE_SPIFFE_ID / " +
      "ACTANTOS_SPIRE_TRUST_DOMAIN / ACTANTOS_SPIRE_JWKS_URI name a running trust domain, and " +
      "ACTANTOS_SPIRE_WORKLOAD_SOCKET (or a unix:// ACTANTOS_SPIRE_WORKLOAD_API) is the agent's " +
      "Workload API socket. The socket is the binding constraint: the Workload API is gRPC over a " +
      "Unix domain socket, so on Windows these tests always skip no matter what is installed.",
    note:
      "RUN here against a live SPIRE 1.15.3 trust domain (server, join-token-attested agent, a " +
      "registration entry for t_spire/pi_demo, and a bundle endpoint publishing the trust " +
      "domain's JWKS): eleven of eleven pass, skipped zero. One obtains an SVID through this " +
      "project's own gRPC client rather than through spire-agent's CLI, and asserts it is the " +
      "identity that was asked for; one verifies it against the trust domain's published key; " +
      "one asserts SPIRE still signs ES256 with no `iss`, so a change in either is reported " +
      "rather than absorbed; one proves the raw JWS signature does NOT verify unconverted while " +
      "the product's own conversion does, so the DER step cannot quietly become a pass-through; " +
      "one issues a real identity through the provider; one asserts the trust domain refuses an " +
      "SVID for a workload with no entry for it, which is the S4 claim itself; and one asserts " +
      "this client's SVID names the same subject and audience as SPIRE's own client's. " +
      "One honest limit: dropping the subject trust-domain check entirely leaves this suite " +
      "green, because a well-behaved authority only ever issues for its own trust domain. That " +
      "property is covered in src/v2/workload-identity-provider.test.ts, which asserts a " +
      "foreign-domain subject is refused. The gated file is src/v2/spire-substrate.test.ts.",
  },
  "production-credential-providers": {
    // INTEGRATION, and the distinction matters more here than anywhere else in this file.
    // The request signing is real: RS256 for a GitHub App JWT and AWS Signature Version 4
    // for AssumeRole, both from node:crypto, and the SigV4 implementation is pinned to
    // AWS's published known-answer vector so it is conformant rather than merely
    // self-consistent. The HTTP is real. What is NOT real is github.com, AWS and Vault:
    // the far end in every test is a loopback server in the test file.
    //
    // So this entry proves the provider speaks each vendor's protocol correctly and that a
    // credential cannot escape through the broker. It does not prove any vendor accepts
    // these requests, that an App key is correctly provisioned, or that an IAM trust policy
    // permits the assumed role. Those need a real account and are NOT RUN here.
    substrate: "local_http",
    level: "INTEGRATION",
    test_files: [
      "src/v2/provider-signing.test.ts",
      "src/v2/providers-production.test.ts",
    ],
    gated_tests: 0,
    gate: "none - node:crypto and a loopback HTTP server are always available",
    note:
      "Real sockets, real HTTP, real RSA and HMAC signatures. The SigV4 signer is checked " +
      "against AWS's published get-vanilla signature and the documented key-derivation " +
      "chain, and the test server rebuilds the signature from the bytes it received rather " +
      "than trusting the signer. NOT RUN against github.com, AWS or Vault: vendor " +
      "acceptance, App key provisioning and IAM trust-policy correctness are unverified.",
  },
  "jwt-svid-verification": {
    // INTEGRATION. Real crypto, real HTTP, real sidecar — but the trust domain is a local server,
    // so what is proven is the verification and enforcement path, not SPIRE's issuing behaviour.
    substrate: "local_socket",
    level: "INTEGRATION",
    test_files: [
      "src/v2/workload-identity-provider.test.ts",
      "src/v2/spire-identity-runtime.test.ts",
    ],
    gated_tests: 0,
    gate: "none - node:crypto and a local HTTP server are always available",
    note:
      "Every SVID in this suite is signed by a key the test itself generated, and every JWKS is " +
      "served by a test HTTP server. That makes the verification and the sidecar's enforcement of " +
      "it real, and makes SPIRE itself absent. Reading these as evidence that SPIRE issues " +
      "correct SVIDs would be wrong; see spire-workload-identity above.",
  },
  "property-based-fuzzing": {
    // REAL_SUBSTRATE in the only sense that matters here: it needs nothing but node and
    // fast-check, so it runs in the default suite on every machine and in CI.
    //
    // The seed is fixed, so a failure reproduces exactly. That is the whole point — a fuzzer
    // whose findings differ per machine is a fuzzer whose findings get ignored.
    substrate: "none",
    level: "REAL_SUBSTRATE",
    test_files: ["src/v2/security-fuzz.test.ts"],
    gated_tests: 0,
    gate: "none - fast-check is a devDependency and needs no external service",
    note:
      "Property-based fuzzing of the verifiers that stand between the network and an allow: " +
      "signed bundle, security context envelope and revocation snapshot. The property is " +
      "that acceptance is a pure function of the canonical bytes, in both directions, so " +
      "the suite cannot be satisfied by a verifier that refuses everything. Also covers " +
      "arbitrary JSON/string/object refusal without throwing, re-signing with an untrusted " +
      "key, and the scope algebra behind S6. It found one real defect: the network target " +
      "guard recursed without bound and could be crashed by agent-controlled arguments.",
  },
  "key-rotation": {
    // REAL_SUBSTRATE. Ed25519 from node:crypto and a keyring the test itself constructs, so this
    // runs everywhere. What it demonstrates is the rotation *mechanism* working end to end.
    //
    // What it does NOT demonstrate is that any deployment has rotated a key, or that the
    // operator tooling to do so safely exists. There is no key-vault integration here: a private
    // key still arrives as a PEM in an environment variable.
    substrate: "none",
    level: "REAL_SUBSTRATE",
    test_files: ["src/v2/keyring.test.ts"],
    gated_tests: 0,
    gate: "none - ed25519 keypairs are generated in-process",
    note:
      "An issuer could not rotate at all before this: one issuer id mapped to exactly one PEM " +
      "with no validity window, captured at construction. Both failure modes surfaced as " +
      "invalid_signature under one unchanging issuer id, so a rotation and a forgery were " +
      "indistinguishable. Tests cover the overlap window in both directions, retirement of " +
      "the old key, and the two properties rotation must not break: a running lease keeps its " +
      "anti-rollback floor across setTrustedKeys, and withdrawing keys neither tears down an " +
      "active lease nor clears an applied revocation list.",
  },
  "post-quantum-signatures": {
    // REAL_SUBSTRATE. The measurements run against node:crypto and OpenSSL 3.5.7 on the host, so
    // they run in the default suite on every machine with this runtime and in CI.
    //
    // What this entry is NOT is a migration. `registerSignatureAlgorithm` is called from nowhere
    // in `src/`, and a test enforces that, so the fabric still accepts Ed25519 only. What the
    // tests establish is that the measurement is real and that the experiment did not widen what
    // the live verifiers accept.
    substrate: "none",
    level: "REAL_SUBSTRATE",
    test_files: ["src/v2/pq-signature.test.ts"],
    gated_tests: 0,
    gate: "none - ML-DSA and SLH-DSA keys are PEM fixtures checked in with the test",
    note:
      "Phase P experiment 1. Measured ML-DSA-44, ML-DSA-65 and SLH-DSA-SHA2-128s against " +
      "Ed25519 through node:crypto: sizes, sign and verify latency, and key generation. Two " +
      "results matter. Verification is not a migration risk -- ML-DSA verifies faster than " +
      "Ed25519 on the multi-kilobyte canonical JSON this fabric signs. And ML-DSA cannot " +
      "generate a key on this runtime at all, so a lattice migration is blocked on where the " +
      "issuer key comes from, while the hash-based family has a complete path today. The tests " +
      "assert that a cryptographically VALID ML-DSA and SLH-DSA signed policy bundle and " +
      "revocation snapshot are refused as unsupported_algorithm, and that no source file calls " +
      "registerSignatureAlgorithm. Nothing about hybrid construction, key agility, or whether " +
      "hash-based assumptions fit this threat model was settled; those are decisions.",
  },
  "wasi-containment": {
    // REAL_SUBSTRATE, with one qualification. The guest is a real wasm32-wasip1 binary and the
    // containment is enforced by Node's real WASI implementation, so the measurement is of the
    // actual mechanism rather than a model of it.
    //
    // The compiled module is checked in so the file runs without a Rust toolchain. It is built
    // from `experiments/wasi-guest/src/main.rs` and the header of the test gives the rebuild
    // command; a stale artifact would show up as a failed assertion, not as a silent pass.
    substrate: "none",
    level: "REAL_SUBSTRATE",
    test_files: ["src/v2/wasi-containment.test.ts"],
    gated_tests: 0,
    gate: "none - the guest binary is checked in and node:wasi is in the runtime",
    note:
      "Phase P experiment 2. Measured what WASI actually contains: traversal out of a " +
      "preopened directory is refused as ENOTCAPABLE and is distinguishable from ENOENT, " +
      "absolute host paths do not exist in the guest namespace, there are no socket syscalls " +
      "at all, and the environment is empty unless the host passes it. Two weakenings were " +
      "found and asserted rather than discovered later: Node's WASI has no read-only preopen, " +
      "so a preopened directory is writable, and fd_readdir is unimplemented, so a guest cannot " +
      "enumerate what it was given. The conclusion is directional and is the reason WASI was " +
      "not adopted: WASI contains a guest from its host, and every one of those properties " +
      "depends on the import object the host chose. This project's premise is that the host " +
      "is already compromised, so the boundary WASI enforces is not the one that matters, and " +
      "WASI provides no workload identity, so it cannot satisfy S4 on its own.",
  },
  "confidential-computing": {
    // NOT_IMPLEMENTED. There is no code, no test, and no configuration in this repository for
    // AMD SEV-SNP, Intel TDX or any other confidential-computing substrate.
    //
    // The entry exists so the report can say "NOT RUN, and here is exactly what would be
    // required" rather than saying nothing at all, which would read as an oversight instead of as
    // a decision.
    // The hardware claim was an assertion ("predates TDX") until it was read out of CPUID. It is
    // now a measurement, and it is stronger than the assertion was: TME is also absent, and TME is
    // what Intel TDX is built on. So this CPU cannot run TDX not merely because it is a
    // generation too early but because the required substrate feature is not implemented at all.
    substrate: "none",
    level: "NOT_IMPLEMENTED",
    test_files: [],
    gated_tests: 0,
    gate: "requires SEV-SNP or TDX hardware, which this machine does not have — measured, see note",
    note:
      "Phase P experiment 3, NOT RUN. Nothing was measured because there is nothing here to " +
      "measure, and the hardware that would make it measurable is absent. Measured on this host " +
      "with cpuid, not inferred from the marketing name: " +
      "leaf 7 subleaf 0 ECX = 0x00400784, so TDX (bit 20) = 0 and TME (bit 5) = 0; and the AMD " +
      "leaf 0x8000001F is not supported at all (max extended leaf = 0x80000008), so there is no " +
      "SEV or SEV-SNP capability on this part. The CPU is a 12th Gen Intel Core i7-12700K, family " +
      "6 model 151 (Raptor Lake), and VT-x is not even exposed to the OS " +
      "(Win32_Processor.VirtualizationFirmwareEnabled = False). Separately confirmed: there is no " +
      "SEV, TDX or attestation code, test or configuration anywhere in the tree — the only matches " +
      "for those terms are this documentation and unrelated CONFIDENTIAL data_clearance values. " +
      "What closing this would take: a machine with an AMD EPYC 9004 (Milan, SEV-SNP) or Intel " +
      "Sapphire Rapids (TDX); a confidential VM whose owner policy is attested before any guest " +
      "code runs; a measurement value bound to that policy; and an attestation client that " +
      "verifies the chain to an AMD or Intel root of trust. Only then would the property be " +
      "testable: that the policy bundle signing key and the policy lease are unreadable by " +
      "anything outside the enclave, including the hypervisor and the host kernel. Until that " +
      "exists the project's stated scope applies unchanged -- baseline v2 does not claim " +
      "protection after host-kernel or root compromise -- and confidential computing is the only " +
      "technology that would change that sentence. An itemized waiver covering exactly this gap " +
      "is drafted in docs/OPEN_WAIVERS.md and is unsigned; this entry is the only one in the file " +
      "that cannot be closed by any test on any host reachable from here.",
  },
}

/**
 * Which security substrates this machine can actually exercise.
 *
 * A substrate is only reported available if its binary is on PATH *and* answers a version
 * query. Presence of a file is not evidence that the substrate works, so nothing here claims
 * more than "the command responded".
 */
const probeBinary = (binary, args = ["--version"]) => {
  try {
    const output = execFileSync(binary, args, {
      encoding: "utf8",
      timeout: 5000,
      stdio: ["ignore", "pipe", "pipe"],
    })
    return { available: true, version: output.trim().split("\n")[0] ?? "" }
  } catch {
    return { available: false, version: null }
  }
}

/**
 * Ask the Docker daemon whether it registers a `runsc` runtime.
 *
 * This is the same question `resolveSandboxRuntimeFlags` asks, answered the same way, because
 * the two must not disagree: the state file would otherwise report a runtime as absent while
 * the executor is running containers under it. `ACTANTOS_GVISOR_DOCKER_HOST` selects the daemon,
 * matching the gate the substrate test uses.
 */
const probeGvisorRuntime = () => {
  const host = process.env["ACTANTOS_GVISOR_DOCKER_HOST"]
  const env = { ...process.env }
  if (typeof host === "string" && host !== "") {
    env["DOCKER_HOST"] = host
  }
  try {
    const output = execFileSync("docker", ["info", "--format", "{{json .Runtimes}}"], {
      encoding: "utf8",
      timeout: 10_000,
      stdio: ["ignore", "pipe", "pipe"],
      env,
    })
    const parsed = JSON.parse(output)
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      return { available: false, version: null }
    }
    if (!Object.hasOwn(parsed, "runsc")) {
      return { available: false, version: null }
    }
    return { available: true, version: `daemon runtime runsc (${env["DOCKER_HOST"] ?? "default daemon"})` }
  } catch {
    return { available: false, version: null }
  }
}

/**
 * Connect to PostgreSQL and ask it for its version.
 *
 * `DATABASE_URL` being set is not evidence that a server exists, is accepting connections, or
 * is the version the tests assume. This runs in a child process so the probe stays synchronous
 * and cannot leave a pool open in the caller.
 */
const probePostgres = () => {
  const connectionString = process.env["DATABASE_URL"]
  if (typeof connectionString !== "string" || connectionString === "") {
    return { available: false, version: null }
  }

  const program =
    'import pg from "pg";' +
    'const pool = new pg.Pool({ connectionString: process.env["DATABASE_URL"], connectionTimeoutMillis: 3000 });' +
    'const result = await pool.query("select version()");' +
    'process.stdout.write(String(result.rows[0].version).split(" ")[1]);' +
    'await pool.end();'

  try {
    const output = execFileSync(process.execPath, ["--input-type=module", "-e", program], {
      cwd: DAEMON_ROOT,
      encoding: "utf8",
      timeout: 15000,
      stdio: ["ignore", "pipe", "pipe"],
    })
    return { available: true, version: output.trim() }
  } catch {
    return { available: false, version: null }
  }
}

export const collectSubstrates = () => {
  const isLinux = process.platform === "linux"
  const cedar = probeBinary(process.env["CEDAR_CLI_PATH"] ?? "cedar")
  // Whether gVisor is usable is a question about the daemon, not about this machine's PATH. The
  // runsc binary lives in the WSL2 distro while the state file is generated on Windows, so a
  // PATH probe reports false on a host that can run gVisor perfectly well. Ask the daemon the
  // same question the executor's gate asks, honouring ACTANTOS_GVISOR_DOCKER_HOST.
  const gvisorRegistry = probeGvisorRuntime()
  const runsc = gvisorRegistry.available
    ? { available: true, version: gvisorRegistry.version }
    : probeBinary("runsc")
  const tetra = probeBinary("tetra", ["version"])
  const spire = probeBinary("spire-server")
  const docker = probeBinary("docker", ["version", "--format", "{{.Server.Version}}"])
  const postgres = probePostgres()
  const spireSocket = "/run/spire/sockets/agent.sock"

  const substrates = {
    cedar: cedar.available,
    gvisor_runsc: runsc.available,
    tetragon_ebpf: tetra.available,
    spire: spire.available,
    docker: docker.available,
    postgres: postgres.available,
    // Every platform this runs on provides one — a Unix domain socket on POSIX, a named pipe
    // on Windows. It is listed rather than assumed so the `unavailable` computation below has
    // a real key to read, instead of silently treating an unregistered substrate as missing.
    local_socket: true,
    // A loopback HTTP server binding an ephemeral port needs no installation either. It is
    // listed so the production provider tests are not reported as skipped: they exercise
    // real HTTP, but against a local far end rather than a vendor. See the registry entry.
    local_http: true,
  }

  // Which gated tests could not run here. Each entry counts tests that *exist but did not
  // execute*; none of them is a passing test.
  // NOT_RUN is included alongside REAL_SUBSTRATE and INTEGRATION because a NOT_RUN group can
  // still have tests waiting on a substrate. SIMULATED is included for the same reason: a group
  // can be simulated *and* carry gated tests that did not run here — spire-workload-identity is
  // exactly that, five tests that only execute against a live trust domain. Excluding either
  // level would let a group claim gated tests while reporting nothing as unavailable, which is
  // the exact gap security-fabric-state.test.mjs exists to close.
  const unavailable = Object.entries(SUBSTRATE_REQUIREMENTS)
    .filter(([, r]) =>
      r.level === "REAL_SUBSTRATE" ||
      r.level === "INTEGRATION" ||
      r.level === "NOT_RUN" ||
      r.level === "SIMULATED"
    )
    .filter(([, r]) => !(r.substrate in substrates ? substrates[r.substrate] : false))
    .map(([name, r]) => ({
      group: name,
      substrate: r.substrate,
      tests_not_run: r.gated_tests,
      gate: r.gate,
    }))

  return {
    platform: process.platform,
    // The SPIFFE Workload API is a Unix socket. It cannot exist on Windows, so a Windows
    // machine can never run SPIRE-backed identity, no matter what is installed.
    spire_workload_api: isLinux && existsSync(spireSocket) && spire.available,
    postgres_integration: postgres.available,
    substrates,
    substrate_versions: {
      cedar: cedar.version,
      gvisor_runsc: runsc.version,
      tetragon_ebpf: tetra.version,
      spire: spire.version,
      docker: docker.version,
      postgres: postgres.version,
    },
    substrate_tests_unavailable: unavailable,
    substrate_tests_actually_run: unavailable.length === 0,
  }
}

/**
 * Parse `security-bench/src/bench.ts` for its scenario count and the prohibited-effect tally.
 *
 * The benchmark prints these on one line each. Reading them from a real run is better than
 * counting scenarios in source, because the header is printed by the same code that executed
 * the scenarios. When no run output is supplied the counts are null and the caller is expected
 * to say so rather than guess.
 */
export const parseBenchOutput = (output) => {
  if (typeof output !== "string" || output.trim() === "") {
    // Empty or absent output is not a clean run. Reporting zero prohibited effects here would
    // manufacture the single most important number in this document.
    return {
      ran: false,
      scenarios: null,
      passed: null,
      failed: null,
      attacks: null,
      controls: null,
      prohibited_external_effects: null,
    }
  }

  const header = output.match(/security-bench:\s*(\d+)\/(\d+)\s*passed,\s*(\d+)\s*failed\s*\((\d+)\s*attacks?,\s*(\d+)\s*controls?\)/u)
  const prohibited = output.match(/prohibited external effects observed:\s*(\d+)/u)

  return {
    ran: true,
    scenarios: header === null ? null : Number(header[1]),
    passed: header === null ? null : Number(header[1]),
    failed: header === null ? null : Number(header[3]),
    attacks: header === null ? null : Number(header[4]),
    controls: header === null ? null : Number(header[5]),
    prohibited_external_effects: prohibited === null ? null : Number(prohibited[1]),
  }
}

/**
 * Every invariant claim the repository makes, and the file that carries it.
 *
 * These are read from `SECURITY_INVARIANTS.md` rather than restated here, so adding an
 * invariant row without a test file — or citing a test file that does not exist — is
 * detectable. See the two matching assertions in the test file.
 */
export const collectInvariantCitations = () => {
  const matrixPath = join(REPO_ROOT, "docs", "SECURITY_INVARIANTS.md")
  if (!existsSync(matrixPath)) return []

  const citations = []
  // Split on CRLF as well as LF. In JavaScript `.` does not match a carriage return, so a file
  // saved with Windows line endings fails `(.+)$` on every row and silently reports zero
  // invariants instead of an error.
  for (const line of readFileSync(matrixPath, "utf8").split(/\r?\n/u)) {
    const row = /^\|\s*\*{0,2}(S\d+)\*{0,2}\s*\|(.+)$/u.exec(line)
    if (row === null) continue

    const files = [...row[2].matchAll(/([\w.-]+\.test\.[cm]?[jt]s)/gu)].map((m) => m[1])
    citations.push({ invariant: row[1], test_files: files })
  }

  return citations
}

const readJson = (path) => JSON.parse(readFileSync(path, "utf8"))

const gitCommit = () => {
  try {
    return execFileSync("git", ["rev-parse", "HEAD"], {
      cwd: REPO_ROOT,
      encoding: "utf8",
      timeout: 10000,
      stdio: ["ignore", "pipe", "pipe"],
    }).trim()
  } catch {
    return null
  }
}

/**
 * Build the full state document.
 *
 * `benchOutput` must come from a real `npm run bench` in the same tree. Passing null records
 * that the benchmark was not run, which is a truthful state; fabricating zero would not be.
 */
export const collectState = ({ benchOutput = null, generatedAt = new Date() } = {}) => {
  const packageJson = readJson(join(DAEMON_ROOT, "package.json"))
  const maturityTruth = readJson(join(DAEMON_ROOT, "release-maturity-truth.json"))
  const unitSuite = collectUnitSuite()
  const substrates = collectSubstrates()
  const bench = parseBenchOutput(benchOutput)
  const citations = collectInvariantCitations()

  // An invariant that cites no test file is a claim with nothing behind it.
  const uncited = citations.filter((c) => c.test_files.length === 0).map((c) => c.invariant)

  return {
    // --- volatile: describes this moment, not the repository ---
    generated_at: generatedAt.toISOString(),
    commit: gitCommit(),
    environment: {
      node: process.version,
      platform: process.platform,
      arch: process.arch,
      hostname: process.platform === "win32" ? "windows" : process.env["HOSTNAME"] ?? "posix",
    },

    // --- stable: derived from tracked files ---
    schema_version: 1,
    product: {
      package_name: packageJson.name,
      package_version: packageJson.version,
      maturity_label: maturityTruth.maturity_label,
      release_tag: maturityTruth.release_tag,
      validation_class: maturityTruth.validation_class,
      // Deliberately not "production-qualified". Nothing in this repository qualifies it.
      active_implementation_maturity: "implemented",
    },
    unit_suite: unitSuite,
    security_bench: {
      scenarios: bench.scenarios,
      passed: bench.passed,
      failed: bench.failed,
      attacks: bench.attacks,
      controls: bench.controls,
      prohibited_external_effects: bench.prohibited_external_effects,
      ran: bench.ran,
      package_self_tests: unitSuite.security_bench_package,
    },
    // Repository truth: which substrate each test group needs, and at what level.
    substrate_requirements: SUBSTRATE_REQUIREMENTS,
    // Machine truth: what this particular run actually had. Never compared against a
    // committed file, because a contributor's machine legitimately differs.
    substrate_run: substrates,
    invariants: {
      declared: citations.length,
      cited_without_tests: uncited,
    },
  }
}

/** Fields that must match a committed file exactly. Everything else is machine-specific. */
export const STABLE_FIELDS = [
  "schema_version",
  "product",
  "unit_suite",
  "substrate_requirements",
  "invariants",
]

/**
 * The part of the document that a test can hold the committed file to.
 *
 * `substrate_run` is excluded on purpose. A developer with Cedar installed would otherwise fail
 * CI against a file generated on a machine without it, which teaches people to ignore the check.
 */
export const stableView = (state) => {
  const view = {}

  for (const field of STABLE_FIELDS) view[field] = state[field]
  view.security_bench = state.security_bench

  return view
}

export const statePath = () => join(REPO_ROOT, "docs", "security-fabric-current-state.json")

export const relativeToRepo = (path) => relative(REPO_ROOT, path).split("\\").join("/")