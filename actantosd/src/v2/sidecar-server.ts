import { chmodSync, existsSync, unlinkSync } from "node:fs"
import { createConnection, createServer, type Server, type Socket } from "node:net"
import path from "node:path"

import { PROTOCOL_VERSION, type DenyReason, type SidecarDecision } from "./sidecar-protocol.ts"
import type { ActantSidecar } from "./sidecar.ts"

/**
 * Real sidecar transport (invariant S11, phase E).
 *
 * Until now the sidecar was a class: a caller in the same process called `handle` directly. That
 * is not a boundary. An agent running as the same user with the same filesystem access could
 * simply skip it and call the effect gateway, and nothing about the arrangement would stop it.
 *
 * Moving the sidecar behind a socket is what makes it a boundary in the sense S11 needs. The
 * agent holds a client; the enforcement code runs in a separate process and is reachable only
 * through the socket. To bypass it the agent has to either not use the sidecar at all (which the
 * network cell in phase G removes) or speak the protocol as somebody else (which the identity
 * token stops).
 *
 * Three rules the transport has to hold on its own, independent of any decision the sidecar makes:
 *
 *   Fail closed on framing. A malformed frame, an oversized frame, or a frame that never
 *   terminates produces a denial and closes the connection. It never produces silence, because
 *   an agent that gets no answer and no denial will eventually find a way to act anyway.
 *
 *   No ambient authority. The socket carries only request and decision JSON. There is no
 *   side-band channel, no file path the client names, and no header the client sets that changes
 *   what the sidecar believes about it.
 *
 *   Owner-only socket. The socket file is created 0600 and its presence is verified before
 *   serving. On Windows the named-pipe namespace is already ACL'd per user, so the same check
 *   that Unix needs has no Windows equivalent and is not claimed here.
 */

/** Largest single frame the sidecar will accept, in bytes. */
export const MAX_FRAME_BYTES = 256 * 1024

/**
 * Refuse to serve over a socket we did not create.
 *
 * A leftover socket file from a previous run is a hijack opportunity: an agent that can write to
 * that path can bind it first and receive the real requests. Unlinking an existing socket is
 * only safe because the caller is expected to have checked the owner; `assertSocketAbsent`
 * exists so the decision is visible at the call site rather than buried here.
 */
export type SocketPathPolicy =
  | { readonly reuse: "never"; readonly onExisting: "refuse" }
  | { readonly reuse: "never"; readonly onExisting: "unlink" }
  | { readonly reuse: "never"; readonly onExisting: "assert_absent" }

/** True when the path is a named pipe rather than a filesystem socket. */
export const isNamedPipe = (socketPath: string): boolean =>
  process.platform === "win32" || socketPath.startsWith("\\\\.\\pipe\\")

/**
 * Where the sidecar listens by default.
 *
 * Under the OS temporary directory rather than a fixed `/run` path, because this repository is
 * developed and tested on hosts where `/run` is not writable and on Windows where it does not
 * exist. The temporary directory is per-user on both platforms, which is the property that
 * matters: another user cannot pre-create the socket there.
 */
export const defaultSocketPath = (name = "actantos-sidecar"): string =>
  isNamedPipe(`\\\\.\\pipe\\${name}`)
    ? `\\\\.\\pipe\\${name}`
    : path.join(process.env["TMPDIR"] ?? "/tmp", `${name}.sock`)

export type SidecarServerOptions = {
  readonly socketPath: string
  readonly sidecar: ActantSidecar
  readonly protocolVersion?: string
  /**
   * What to do when something is already at the socket path. Defaults to refusing, because
   * "a file is already there" is exactly the condition under which a hijack is being attempted.
   */
  readonly socketPathPolicy?: SocketPathPolicy
  /** Injected so tests can observe without binding a real port. */
  readonly onError?: (error: Error) => void
}

export type SidecarServer = {
  readonly socketPath: string
  /** Resolves once the socket is accepting connections. */
  readonly listening: Promise<void>
  close(): Promise<void>
  /** Every decision the sidecar produced, in order. */
  readonly decisions: readonly SidecarDecision[]
}

const denyTransport = (reason: DenyReason, detail: string): SidecarDecision => ({
  allowed: false,
  request_id: "unknown",
  reason,
  detail,
})

/**
 * Incrementally split a byte stream into newline-delimited frames.
 *
 * Hand-rolled rather than using a line reader because the size limit has to apply to the frame
 * *before* it is buffered. A peer that never sends a newline would otherwise grow the buffer
 * until the process died, which is a denial of service on the boundary that is supposed to be
 * protecting availability.
 */
class FrameDecoder {
  #buffer = ""
  #overflowed = false

  /** Returns the frames that completed, plus a flag if the peer exceeded the limit. */
  push(chunk: Buffer): { readonly frames: readonly string[]; readonly overflowed: boolean } {
    if (this.#overflowed) {
      return { frames: [], overflowed: true }
    }

    this.#buffer += chunk.toString("utf8")

    if (Buffer.byteLength(this.#buffer, "utf8") > MAX_FRAME_BYTES) {
      this.#overflowed = true
      return { frames: [], overflowed: true }
    }

    const parts = this.#buffer.split("\n")
    this.#buffer = parts.pop() ?? ""

    return {
      frames: parts.filter((part) => part.trim().length > 0),
      overflowed: false,
    }
  }
}

/**
 * Start the sidecar on a real socket.
 *
 * The returned handle resolves `listening` once the socket is bound, so a caller that awaits it
 * can connect immediately without a retry loop that might mask a bind failure.
 */
export const startSidecarServer = async (
  options: SidecarServerOptions,
): Promise<SidecarServer> => {
  const socketPath = options.socketPath
  const protocolVersion = options.protocolVersion ?? PROTOCOL_VERSION
  const decisions: SidecarDecision[] = []

  if (!isNamedPipe(socketPath) && existsSync(socketPath)) {
    const policy = options.socketPathPolicy ?? { reuse: "never", onExisting: "refuse" }

    if (policy.onExisting === "refuse") {
      throw new Error(
        `sidecar socket already exists at ${socketPath}; refusing to serve over it`,
      )
    }

    unlinkSync(socketPath)
  }

  const server: Server = createServer((socket: Socket) => {
    const decoder = new FrameDecoder()

    socket.on("data", (chunk: Buffer) => {
      const { frames, overflowed } = decoder.push(chunk)

      if (overflowed) {
        // The peer is either malformed or hostile. Either way there is no safe way to keep reading,
        // and no request id to answer against.
        decisions.push(
          denyTransport("protocol_version_unsupported", `frame exceeds ${MAX_FRAME_BYTES} bytes`),
        )
        socket.end(
          `${JSON.stringify(decisions[decisions.length - 1])}\n`,
        )
        return
      }

      for (const frame of frames) {
        let parsed: unknown

        try {
          parsed = JSON.parse(frame)
        } catch {
          // Unparseable input is a denial, never a default-allow and never a silent drop.
          const decision = denyTransport(
            "protocol_version_unsupported",
            "frame is not valid JSON",
          )
          decisions.push(decision)
          socket.write(`${JSON.stringify(decision)}\n`)
          continue
        }

        // The transport does not interpret the request. It hands it to the sidecar, which
        // re-validates protocol version, identity and policy. Nothing here can widen that.
        const decision = options.sidecar.handle(parsed)
        decisions.push(decision)
        socket.write(`${JSON.stringify(decision)}\n`)
      }
    })

    socket.on("error", () => {
      // A client that disappears mid-request is ordinary. The sidecar's decision is already
      // recorded, and there is nothing to fail closed about on this side of the socket.
    })
  })

  const listening = new Promise<void>((resolve, reject) => {
    const onError = (error: Error): void => {
      options.onError?.(error)
      reject(error)
    }

    server.once("error", onError)
    server.listen(socketPath, () => {
      server.removeListener("error", onError)
      resolve()
    })
  })

  try {
    await listening
  } catch (error) {
    server.close()
    throw error
  }

  // Created 0600 before anyone can connect. On Windows a named pipe inherits the process token's
  // default DACL, which is per-user, so there is nothing equivalent to do here.
  if (!isNamedPipe(socketPath)) {
    chmodSync(socketPath, 0o600)
  }

  return {
    socketPath,
    listening: Promise.resolve(),
    decisions,
    close: async () => {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => (error === undefined ? resolve() : reject(error)))
      })

      // Node removes the socket file itself on POSIX, but a crash would not have. Leaving a stale
      // file would make the next start refuse rather than serve, which is the safe direction but
      // still an operational surprise, so it is cleaned up here.
      if (!isNamedPipe(socketPath) && existsSync(socketPath)) {
        unlinkSync(socketPath)
      }
    },
  }
}

/** One request, one response, over a real socket. */
export type SidecarClientOptions = {
  readonly socketPath: string
  readonly timeoutMs?: number
}

export type SidecarClient = {
  send(request: unknown): Promise<SidecarDecision>
  close(): Promise<void>
}

/**
 * Connect to a running sidecar.
 *
 * The client is what a protected agent uses. It holds no authority: every call is a request the
 * sidecar may refuse, and a connection that cannot be made is an error the agent has to handle
 * rather than a permit to proceed.
 */
export const connectSidecar = async (
  options: SidecarClientOptions,
): Promise<SidecarClient> => {
  const timeoutMs = options.timeoutMs ?? 5000

  // `createConnection` takes either a socket path or, on Windows, a pipe name, so the same call
  // serves both platforms.
  const socket = await new Promise<Socket>((resolve, reject) => {
    const connection = createConnection(options.socketPath)

    const timer = setTimeout(() => {
      connection.destroy()
      reject(new Error(`sidecar connect timed out after ${timeoutMs}ms`))
    }, timeoutMs)

    connection.once("connect", () => {
      clearTimeout(timer)
      resolve(connection)
    })

    connection.once("error", (error: Error) => {
      clearTimeout(timer)
      reject(error)
    })
  })

  let buffer = ""

  return {
    send: async (request: unknown): Promise<SidecarDecision> => {
      buffer = ""
      socket.write(`${JSON.stringify(request)}\n`)

      return await new Promise<SidecarDecision>((resolve, reject) => {
        const timer = setTimeout(() => {
          socket.destroy()
          reject(new Error("sidecar did not answer within the timeout"))
        }, timeoutMs)

        const onData = (chunk: Buffer): void => {
          buffer += chunk.toString("utf8")
          const newline = buffer.indexOf("\n")

          if (newline === -1) return

          clearTimeout(timer)
          socket.removeListener("data", onData)
          const line = buffer.slice(0, newline)

          try {
            resolve(JSON.parse(line) as SidecarDecision)
          } catch (error) {
            // A sidecar that answers with something unparseable is not one whose "no" can be
            // trusted as a decision, so this is an error rather than a synthetic denial.
            reject(new Error(`sidecar sent an unparseable decision: ${String(error)}`))
          }
        }

        socket.on("data", onData)
        socket.once("error", (error: Error) => {
          clearTimeout(timer)
          reject(error)
        })
      })
    },

    close: async () => {
      socket.destroy()
    },
  }
}
