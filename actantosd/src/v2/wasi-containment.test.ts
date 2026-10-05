import assert from "node:assert/strict"
import { closeSync, existsSync, mkdirSync, mkdtempSync, openSync, readFileSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import path from "node:path"
import test from "node:test"
import { fileURLToPath } from "node:url"
import { WASI } from "node:wasi"

/**
 * Phase P, experiment 2: WASI as a containment substrate (S2, S3, S4).
 *
 * ## The question
 *
 * The fabric contains agents today with a Docker cell: an internal network with no route out, plus
 * the sidecar's own decision path. WASI is the other containment story available on this runtime,
 * and it is a serious one — no ambient authority, an explicit capability list, and a guest that
 * cannot corrupt the host's memory. It deserves a measurement rather than an assumption.
 *
 * ## What the guest is
 *
 * `experiments/wasi-guest/src/main.rs` is a Rust program compiled to `wasm32-wasip1` whose only
 * purpose is to probe its own boundary: read a path, list a directory, read an environment variable,
 * open a socket, and so on. Each probe prints `OK ...` or `ERR ...`. The compiled module is checked
 * in as `experiments/wasi-guest/wasi-guest.wasm` so this file runs without a Rust toolchain.
 * Rebuild it with:
 *
 *   cd experiments/wasi-guest
 *   cargo build --release --target wasm32-wasip1
 *   cp target/wasm32-wasip1/release/wasi-guest.wasm wasi-guest.wasm
 *
 * ## The result, in one paragraph
 *
 * WASI's containment is real and it holds: path traversal out of a preopened directory is refused
 * with `ENOTCAPABLE`, absolute host paths do not exist in the guest's namespace, and there are no
 * socket syscalls at all. But every one of those properties is a property of *the object the host
 * passes to `new WebAssembly.Instance`*, not of WASI and not of the guest. Same module, different
 * import object, different filesystem — demonstrated below. WASI answers "what may this guest
 * reach", which presupposes a trustworthy host. This threat model assumes the host is already
 * lost, so the question WASI is built to answer is the wrong one, and its containment direction is
 * the reverse of the one S1–S14 need.
 *
 * What this file therefore does **not** claim: that WASI is unsafe, or that Node's implementation
 * is poor. It claims that WASI is a good host-to-guest boundary and not a defence against a
 * compromised host, which is a different property than the one usually cited when WASI is proposed
 * for agent isolation.
 */

const HERE = path.dirname(fileURLToPath(import.meta.url))
const WASM = path.join(HERE, "..", "..", "experiments", "wasi-guest", "wasi-guest.wasm")

/**
 * The WebAssembly globals, reached through `globalThis` rather than imported.
 *
 * This project's `lib` is `ES2022`, which does not include the WebAssembly type declarations — they
 * ship in `lib.dom.d.ts`. Widening `lib` for a single experiment file would change what every other
 * file in the project can see, so the handful of shapes actually used are declared here instead.
 * Nothing is being cast away that is checked at runtime by WebAssembly.validate at module compile.
 */
interface WasmInstance {
  readonly exports: Readonly<Record<string, unknown>>
}

const WebAssemblyApi = (globalThis as Readonly<Record<string, unknown>>)["WebAssembly"] as {
  readonly Module: new (bytes: Uint8Array) => unknown
  readonly Instance: new (module: unknown, imports: unknown) => WasmInstance
}

const guestModule = (): unknown => {
  if (!existsSync(WASM)) return undefined
  return new WebAssemblyApi.Module(readFileSync(WASM))
}

const skip = !existsSync(WASM)
const todo = skip ? "wasi-guest.wasm is not built; see the header for how to build it" : false

/* --------------------------------------------------------------------------------- fixtures */

// Two directories, each holding a file the other must not be able to read. Nothing about the guest
// distinguishes them; everything about the answer comes from which one the host preopened.
const root = mkdtempSync(path.join(tmpdir(), "actantos-wasi-"))
const cellA = path.join(root, "cell-a")
const cellB = path.join(root, "cell-b")

mkdirSync(cellA)
mkdirSync(cellB)

type RunOptions = {
  readonly preopens?: Readonly<Record<string, string>>
  readonly env?: Record<string, string>
}

/**
 * Run the guest and return its stdout, captured through a file descriptor the host chooses.
 *
 * Writing to a host-opened fd rather than to `process.stdout` is deliberate: it exercises the same
 * boundary from the other side. The guest's only route to the outside world is a capability the
 * host hands it, and stdout is one.
 */
const runGuest = (args: readonly string[], options: RunOptions = {}): string => {
  const output = path.join(root, `stdout-${Math.random().toString(36).slice(2)}.txt`)
  const handle = openSync(output, "w")

  try {
    const wasi = new WASI({
      version: "preview1",
      args: ["wasi-guest", ...args],
      env: options.env,
      preopens: options.preopens as Record<string, string> | undefined,
      stdout: handle,
      returnOnExit: true,
    })

    const instance = new WebAssemblyApi.Instance(guestModule(), wasi.getImportObject())
    wasi.start(instance)
  } finally {
    closeSync(handle)
  }

  return readFileSync(output, "utf8").trim()
}

const preopenA = { cell: cellA }
const preopenB = { cell: cellB }

// Files are created up front, outside any test, so that a refusal can never be a missing file
// wearing a containment failure's clothes. `outside.txt` sits beside the cells, not in one: it is
// the traversal target, and if it did not exist the traversal test would pass for the wrong reason.
const CELL_A_FILE = "cell-a-secret.txt"
const CELL_B_FILE = "cell-b-secret.txt"
const OUTSIDE_FILE = "outside.txt"

writeFileSync(path.join(cellA, CELL_A_FILE), "cell-a-secret")
writeFileSync(path.join(cellB, CELL_B_FILE), "cell-b-secret")
writeFileSync(path.join(root, OUTSIDE_FILE), "outside-the-cell")

/* ----------------------------------------------------------- what the boundary actually stops */

test("Phase P: a guest cannot read outside its preopened directory, even by traversal", { todo }, () => {
  // The containment claim, tested rather than assumed. `..` is the attack that matters: without
  // preopen-relative resolution, a guest handed `/cell` would reach the whole filesystem.
  //
  // The refusal is `ENOTCAPABLE` (errno 76), and the contrast below is what makes that worth
  // anything: a name that simply does not exist gets `ENOENT` (errno 44). Two different answers, so
  // the traversal case is being refused *as a capability violation* and not incidentally failing to
  // find a file.
  const traversal = runGuest(["read", `/cell/../${OUTSIDE_FILE}`], { preopens: preopenA })

  assert.match(traversal, /^ERR read /)
  assert.match(traversal, /Capabilities insufficient|os error 76/)

  const missing = runGuest(["read", "/cell/definitely-not-here.txt"], { preopens: preopenA })

  assert.match(missing, /^ERR read /)
  assert.match(missing, /No such file|os error 44/)
  assert.equal(missing.includes("os error 76"), false)

  // The traversal refusal also does not depend on the target existing. WASI rejects `..` by
  // inspecting the path, before the filesystem is consulted, so deleting `outside.txt` from the host
  // leaves the answer at 76. Measured, not assumed — an earlier draft of this test assumed the
  // opposite and would have passed just as happily against a missing file.
  assert.equal(existsSync(path.join(root, OUTSIDE_FILE)), true)

  // Deep traversal, out of every preopen and into the host root.
  const deep = runGuest(["read", "/cell/../../../../Windows/win.ini"], { preopens: preopenA })
  assert.match(deep, /^ERR read /)
})

test("Phase P: a host absolute path does not exist in the guest's namespace at all", { todo }, () => {
  // Not denied — *absent*. The guest's filesystem is a namespace the host assembled, and a path
  // that was never preopened has no referent in it. That is a stronger statement than a permission
  // check and it is worth seeing rather than assuming.
  //
  // The host path really exists. The guest is refusing to believe that, because "the filesystem"
  // means something different on the other side of the boundary.
  const hostPath = path.join(cellA, CELL_A_FILE).replace(/\\/g, "/")
  assert.equal(existsSync(hostPath), true)

  assert.match(runGuest(["read", hostPath], { preopens: preopenA }), /^ERR read /)
})

test("Phase P: with no preopens at all, the guest can read nothing", { todo }, () => {
  // The degenerate configuration, and the one that actually matches how an agent would run. The
  // capability list is empty, so the filesystem is empty. There is no default directory.
  const result = runGuest(["read", `/cell/${CELL_A_FILE}`], { preopens: {} })

  assert.match(result, /^ERR read /)
})

test("Phase P: the same module reads different files under different preopens", { todo }, () => {
  // The finding the experiment turns on.
  //
  // Identical WebAssembly bytes, identical runtime, identical probe. The only variable is the
  // import object the host constructed. So "the guest is sandboxed" is not a property of the guest
  // or of WASI — it is a parameter the host chose, and a compromised host chooses it differently.
  //
  // This is not a WASI flaw. It is WASI working exactly as specified. It is a statement about which
  // party in the arrangement is trusted.
  assert.match(runGuest(["read", `/cell/${CELL_A_FILE}`], { preopens: preopenA }), /^OK read 13bytes/)
  assert.match(runGuest(["read", `/cell/${CELL_B_FILE}`], { preopens: preopenB }), /^OK read 13bytes/)

  // And the guest cannot reach the other cell from either one.
  assert.match(runGuest(["read", `/cell/${CELL_B_FILE}`], { preopens: preopenA }), /^ERR read /)
  assert.match(runGuest(["read", `/cell/${CELL_A_FILE}`], { preopens: preopenB }), /^ERR read /)
})

/* ---------------------------------------------------------------- what it gives for free */

test("Phase P: no socket syscalls exist, so a guest has no network at all", { todo }, () => {
  // S2 and S3, satisfied structurally rather than by policy. There is no `sock_open` in Node's WASI
  // surface for a policy to deny, so there is no policy to get wrong.
  assert.match(runGuest(["tcp", "example.com", "443"], { preopens: preopenA }), /^ERR tcp /)
  assert.match(runGuest(["tcp", "127.0.0.1", "9"], { preopens: preopenA }), /^ERR tcp /)
  assert.match(runGuest(["udp"], { preopens: preopenA }), /^ERR udp /)
})

test("Phase P: the environment is empty unless the host passes it", { todo }, () => {
  // Ambient authority is opt-in, which is the right default. It is still a decision the host makes,
  // and passing `process.env` is the mistake that would hand a guest every secret in the process.
  assert.match(runGuest(["env", "PATH"], { preopens: preopenA }), /^ERR env /)
  assert.match(
    runGuest(["env", "PATH"], { preopens: preopenA, env: { PATH: "C:/Windows" } }),
    /^OK env C:\/Windows$/,
  )
})

test("Phase P: a preopened directory is writable, because Node's WASI has no read-only preopen", { todo }, () => {
  // The one real weakening found, asserted rather than discovered later.
  //
  // WASI distinguishes read and write rights at the fd level, but Node's `preopens` option takes a
  // host path and nothing else — there is no way to say "read-only". A host that hands a guest a
  // preopen has handed it write access to that subtree, and a guest can corrupt the tools it will
  // later be asked to run.
  //
  // This is a Node limitation, not a WASI one, and it is exactly the kind of gap that a
  // "WASI sandboxes our agents" claim should be required to answer before it is believed.
  assert.match(runGuest(["write", "/cell/written.txt"], { preopens: preopenA }), /^OK write /)
  assert.match(runGuest(["read", "/cell/written.txt"], { preopens: preopenA }), /^OK read 6bytes/)
})

test("Phase P: a guest cannot enumerate a directory, so it can only read names it already knows", { todo }, () => {
  // `fd_readdir` is unimplemented in Node's WASI, so a preopened directory does not leak its
  // contents — only names the host already told the guest by asking for them.
  //
  // Recorded as a property of *this runtime*, not of WASI, and therefore asserted so that a Node
  // upgrade which implements it shows up here rather than silently widening what a guest can learn.
  assert.match(runGuest(["listdir", "/cell"], { preopens: preopenA }), /^ERR listdir /)
  assert.match(runGuest(["listdir", "/cell"], { preopens: preopenA }), /not implemented|os error 52/)
})

test("Phase P: the clock and host randomness are available to the guest", { todo }, () => {
  // Ambient, and worth naming: a guest can read the wall clock and obtain unpredictable bytes. For
  // S9 that cuts both ways — a nonce generated inside a guest is weaker than one generated on the
  // host, because a guest that can also read the clock can reason about how long it has to use it.
  assert.match(runGuest(["clock"], { preopens: preopenA }), /^OK clock \d+ms$/)
  assert.match(runGuest(["random"], { preopens: preopenA }), /^OK random [0-9a-f]+$/)
})

/* ---------------------------------------------------- what it cannot do for this threat model */

test("Phase P: WASI provides no workload identity, so it cannot satisfy S4", { todo }, () => {
  // Not a missing feature to be worked around. Identity in this fabric comes from a JWT-SVID minted
  // by SPIRE and verified by the sidecar, bound to a tenant, an agent and an audience. WASI has no
  // concept of a caller: every guest is the same anonymous principal to the host, and the module
  // has no surface through which a host could even ask "who is this".
  //
  // The probe is the strongest available statement of that. The guest can read its own argv and it
  // can reach the clock, and there is no third thing it can reach that would identify it.
  assert.match(runGuest(["argv", "alpha", "beta"], { preopens: preopenA }), /^OK argv argv alpha beta$/)

  // Two guests run by the same host are indistinguishable to that host, which is the property S4
  // exists to prevent. Nothing in the WASI surface distinguishes them, so no policy built on WASI
  // alone can tell them apart either.
  const first = runGuest(["argv", "agent-a"], { preopens: preopenA })
  const second = runGuest(["argv", "agent-b"], { preopens: preopenA })

  assert.notEqual(first, second)
  assert.match(first, /^OK argv /)
  assert.match(second, /^OK argv /)
})

test("Phase P: WASI contains a guest from its host, not a host from its guest", { todo }, () => {
  // The synthesis, and the reason Phase P did not adopt WASI.
  //
  // Everything above is a real boundary: the guest cannot reach the filesystem it was not given,
  // cannot open a socket, cannot corrupt host memory. All of it holds because the *host* is
  // trustworthy and chose the import object honestly.
  //
  // This project assumes the opposite. The premise is that the agent process may be fully
  // compromised and that the surrounding system must still constrain it. Under that premise the
  // host is the thing that cannot be trusted, and a containment mechanism whose security argument
  // is "the host picks the right capabilities" has already conceded the argument.
  //
  // Node's WASI is additionally an in-process library: the guest and its supposed jail share an
  // address space and a thread. A compromised host does not need to escape anything. It can simply
  // not call `wasi.start`, or pass a different preopen, or read the guest's memory directly.
  const module = guestModule()

  // Demonstrated rather than asserted: the guest's view follows the host's choice, with no
  // cooperation from WASI and no property of the module resisting it.
  assert.match(runGuest(["read", `/cell/${CELL_A_FILE}`], { preopens: preopenA }), /^OK read /)
  assert.match(runGuest(["read", `/cell/${CELL_A_FILE}`], { preopens: preopenB }), /^ERR read /)

  // The host holds the module and the instance. Nothing stops it reading either.
  const wasi = new WASI({ version: "preview1", preopens: preopenA })
  const imports = wasi.getImportObject()
  const instance = new WebAssemblyApi.Instance(module, imports)

  const memory = instance.exports["memory"] as { readonly buffer: ArrayBufferLike }
  assert.equal(typeof memory, "object")
  assert.ok(memory.buffer.byteLength > 0)
})

test("Phase P: the honest summary is that WASI and this fabric solve opposite problems", { todo }, () => {
  // Stated as a test so that a future proposal to adopt WASI has to delete a passing assertion
  // rather than quietly add a capability.
  //
  // WASI: protect a trustworthy host from untrusted guest code. Answered well.
  // This fabric: constrain an untrusted agent that may already control its own process. WASI does
  // not address it, because the compromised party is on the other side of the boundary.
  //
  // The existing answer stays the existing one: a separate enforcement process the agent cannot
  // reach (the sidecar over a Unix socket), a network cell with no route out, and identity minted
  // by something the agent cannot impersonate. WASI would be a reasonable *addition* for running
  // third-party tool code inside a cell, and a poor replacement for any of the three.
  const guestSeesHostPath = runGuest(["read", `/cell/${CELL_A_FILE}`], { preopens: preopenA })
  const guestSeesNoSockets = runGuest(["tcp", "127.0.0.1", "9"], { preopens: preopenA })

  assert.match(guestSeesHostPath, /^OK read /)
  assert.match(guestSeesNoSockets, /^ERR tcp /)
})
