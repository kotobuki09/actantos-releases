import { connect, type ClientHttp2Session } from "node:http2"
import net from "node:net"

/**
 * A minimal client for the SPIFFE Workload API, which is what a SPIRE agent serves.
 *
 * ## Why this exists
 *
 * The Workload API is gRPC over a Unix domain socket. It does not answer HTTP/1.1: a GET to the
 * agent's socket is met with a connection reset, so `fetch` — which cannot open a Unix socket
 * anyway — is not a way to reach it. This module speaks the actual protocol using Node's own
 * HTTP/2 and socket primitives.
 *
 * The wire format is deliberately tiny. It is not a general protobuf implementation: it encodes
 * and decodes exactly the three messages `FetchJWTSVID` uses, and refuses anything it does not
 * recognise. Nothing here decides trust. The values it returns are verified by
 * `verifyJwtSvid`, which is where the security decision lives.
 *
 * ## What was measured, not assumed
 *
 * Every constant below was read off a live SPIRE 1.15.3 agent, not from documentation:
 *
 *   - the method is `POST /SpiffeWorkloadAPI/FetchJWTSVID` (a service prefix, not a dotted name;
 *     `FetchJWTSVID.FetchJWTSVID` is refused as a malformed method);
 *   - every request must carry the header `workload.spiffe.io: true` — literally the string
 *     `true`, not a configured secret. The agent refuses the call with
 *     `security header missing from request` without it, and SPIRE 1.15.3 has no configuration
 *     key for the value;
 *   - `JWTSVIDRequest` numbers `audience` as 1 and `spiffe_id` as 2. Swapping them makes the
 *     agent answer `invalid requested SPIFFE ID: scheme is missing or invalid`, which is how the
 *     ordering was established;
 *   - the response is `JWTSVIDResponse { repeated JWTSVID svids = 1 }` and each `JWTSVID` is
 *     `{ string spiffe_id = 1; string svid = 2; string hint = 3 }`.
 */

/** SPIRE's default Workload API socket, as shipped by spire-agent. */
export const DEFAULT_WORKLOAD_SOCKET = "/run/spire/sockets/agent.sock"

/** The header SPIRE requires on every Workload API call. Its value is the literal string `true`. */
const SECURITY_HEADER = "workload.spiffe.io"

const FETCH_JWT_SVID = "/SpiffeWorkloadAPI/FetchJWTSVID"

export type WorkloadApiFailure = "workload_api_unreachable" | "no_svid_offered" | "workload_api_error"

export type WorkloadApiSvid = {
  readonly spiffeId: string
  /** The JWT-SVID in JWS compact serialisation. */
  readonly jwt: string
  readonly hint: string
}

export type FetchJwtSvidResult =
  | { readonly ok: true; readonly svids: readonly WorkloadApiSvid[] }
  | { readonly ok: false; readonly failure: WorkloadApiFailure; readonly detail: string }

export type FetchJwtSvidOptions = {
  /** Path to the agent's Workload API Unix socket. */
  readonly socketPath: string
  /** The SPIFFE ID to request. Omit to request every SVID the workload is entitled to. */
  readonly spiffeId?: string | undefined
  /** The audience the SVID is intended for. */
  readonly audience: readonly string[]
  readonly timeoutMs?: number
  /**
   * Refuse a response larger than this. SPIRE caps its own responses with `workload_size_limit`;
   * this is the client-side counterpart, so a hostile or broken agent cannot make the daemon
   * buffer without limit.
   */
  readonly maxResponseBytes?: number
  /** Overrides how the session is opened. See `SessionFactory`. */
  readonly createSession?: SessionFactory | undefined
}

/**
 * Opens the HTTP/2 session the request is sent over.
 *
 * This exists as a seam because the Workload API's real transport is a Unix domain socket, and
 * a Unix socket cannot be listened on at all on some hosts — Windows returns `EACCES`. Without a
 * seam the gRPC request path (method, headers, status handling, framing) could only be exercised
 * where a socket can be created, which would leave the code that talks to SPIRE tested on exactly
 * the hosts where a failure is hardest to notice. The tests supply a TCP session to a stand-in
 * agent; everything above this function is unchanged by that substitution.
 */
export type SessionFactory = (options: { readonly socketPath: string }) => ClientHttp2Session

const connectOverUnixSocket: SessionFactory = ({ socketPath }) =>
  connect("http://localhost", { createConnection: () => net.connect(socketPath) })

// --- protobuf wire format, scoped to the messages this call uses ---------------------------
//
// Only what `JWTSVIDRequest`, `JWTSVIDResponse` and `JWTSVID` need: varints and length-delimited
// fields. Every field in those three messages is wire type 2, so no other encoding appears here.

const encodeVarint = (value: number): Buffer => {
  const bytes: number[] = []
  let remaining = value

  do {
    let byte = remaining & 0x7f
    remaining = Math.floor(remaining / 128)
    if (remaining > 0) byte |= 0x80
    bytes.push(byte)
  } while (remaining > 0)

  return Buffer.from(bytes)
}

/** A length-delimited field: the tag, the length as a varint, then the payload. */
const encodeLengthDelimited = (fieldNumber: number, payload: Buffer): Buffer =>
  Buffer.concat([encodeVarint((fieldNumber << 3) | 2), encodeVarint(payload.length), payload])

/**
 * Build a `JWTSVIDRequest`.
 *
 * Field 1 is `repeated string audience` and field 2 is `string spiffe_id`; proto3 omits empty
 * fields, so an unset `spiffe_id` is simply left out and the agent returns every SVID the caller
 * is entitled to.
 */
export const encodeFetchJwtSvidRequest = (options: {
  readonly spiffeId?: string | undefined
  readonly audience: readonly string[]
}): Buffer => {
  const parts: Buffer[] = []

  for (const audience of options.audience) {
    parts.push(encodeLengthDelimited(1, Buffer.from(audience, "utf8")))
  }

  if (options.spiffeId !== undefined) {
    parts.push(encodeLengthDelimited(2, Buffer.from(options.spiffeId, "utf8")))
  }

  return Buffer.concat(parts)
}

/**
 * A cursor over a protobuf message.
 *
 * Every read is bounds-checked. A short buffer raises rather than yielding a truncated value,
 * because a partially-decoded SVID that then failed to verify would be reported as a signature
 * problem when the real fault is a malformed response.
 */
class ProtoReader {
  #buffer: Buffer
  #offset = 0

  constructor(buffer: Buffer) {
    this.#buffer = buffer
  }

  get done(): boolean {
    return this.#offset >= this.#buffer.length
  }

  varint(): number {
    let result = 0
    let shift = 1

    for (let i = 0; i < 10; i += 1) {
      if (this.#offset >= this.#buffer.length) throw new Error("varint ran past the end of the message")
      const byte = this.#buffer[this.#offset] as number
      this.#offset += 1
      result += (byte & 0x7f) * shift
      if ((byte & 0x80) === 0) return result
      shift *= 128
    }

    throw new Error("varint longer than 10 bytes")
  }

  bytes(): Buffer {
    const length = this.varint()
    const end = this.#offset + length

    if (end > this.#buffer.length) throw new Error("length-delimited field ran past the end of the message")

    const out = this.#buffer.subarray(this.#offset, end)
    this.#offset = end
    return out
  }
}

/** Decode a `JWTSVIDResponse` into the SVIDs it carries. Unknown fields are skipped, not guessed at. */
export const decodeFetchJwtSvidResponse = (message: Buffer): WorkloadApiSvid[] => {
  const reader = new ProtoReader(message)
  const svids: WorkloadApiSvid[] = []

  while (!reader.done) {
    const tag = reader.varint()
    const field = tag >>> 3
    const wireType = tag & 0x07

    if (field !== 1 || wireType !== 2) {
      // `JWTSVIDResponse` has only `svids`. Anything else is not part of this contract, and
      // skipping it blindly could mis-frame a later field, so the message is refused instead.
      throw new Error(`unexpected field ${field} with wire type ${wireType} in JWTSVIDResponse`)
    }

    const entry = new ProtoReader(reader.bytes())
    let spiffeId = ""
    let jwt = ""
    let hint = ""

    while (!entry.done) {
      const innerTag = entry.varint()
      const innerField = innerTag >>> 3
      const innerWireType = innerTag & 0x07

      if (innerWireType !== 2) throw new Error(`unexpected wire type ${innerWireType} in JWTSVID`)

      const value = entry.bytes().toString("utf8")

      if (innerField === 1) spiffeId = value
      else if (innerField === 2) jwt = value
      else if (innerField === 3) hint = value
    }

    svids.push({ spiffeId, jwt, hint })
  }

  return svids
}

/** Frame a message for gRPC: one compression byte, then the length as a 32-bit big-endian int. */
const frameGrpcMessage = (message: Buffer): Buffer => {
  const header = Buffer.alloc(5)
  header.writeUInt32BE(message.length, 1)
  return Buffer.concat([header, message])
}

/**
 * Read a gRPC response body.
 *
 * A response may be several length-delimited messages; only the first is read, which is all
 * `FetchJWTSVID` sends. A compression flag other than 0 would mean the body is not the plaintext
 * protobuf this decodes, so it is refused rather than misread.
 */
const decodeGrpcFrame = (body: Buffer): Buffer => {
  if (body.length === 0) return Buffer.alloc(0)
  if (body.length < 5) throw new Error("gRPC body is shorter than its frame header")

  const compressed = body[0] as number
  if (compressed !== 0) throw new Error(`gRPC body is compressed (flag ${compressed}) and is not supported`)

  const length = body.readUInt32BE(1)
  if (body.length < 5 + length) throw new Error("gRPC frame declares more bytes than the body carries")

  return body.subarray(5, 5 + length)
}

type RawResponse = {
  readonly httpStatus: number | undefined
  readonly grpcStatus: number | undefined
  readonly grpcMessage: string
  readonly body: Buffer
}

const callFetchJwtSvid = (
  socketPath: string,
  request: Buffer,
  timeoutMs: number,
  maxResponseBytes: number,
  createSession: SessionFactory,
): Promise<RawResponse> =>
  new Promise((resolve, reject) => {
    let session: ClientHttp2Session
    let settled = false

    const finish = (action: () => void): void => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      action()
    }

    const timer = setTimeout(() => {
      finish(() => {
        session.destroy()
        reject(new Error(`the Workload API did not answer within ${timeoutMs}ms`))
      })
    }, timeoutMs)

    try {
      session = createSession({ socketPath })
    } catch (error) {
      finish(() => reject(error instanceof Error ? error : new Error(String(error))))
      return
    }

    session.on("error", (error: Error) => finish(() => reject(error)))

    const stream = session.request({
      ":method": "POST",
      ":path": FETCH_JWT_SVID,
      "content-type": "application/grpc",
      [SECURITY_HEADER]: "true",
      te: "trailers",
    })

    const chunks: Buffer[] = []
    let received = 0
    let httpStatus: number | undefined
    // gRPC may answer with the status in the headers (a "trailers-only" response) or in the
    // trailers. Both are read; neither is assumed.
    let grpcStatus: number | undefined
    let grpcMessage = ""

    const recordStatus = (headers: Record<string, unknown>): void => {
      const status = headers["grpc-status"]
      if (typeof status === "string" && /^\d+$/u.test(status)) grpcStatus = Number(status)
      const message = headers["grpc-message"]
      if (typeof message === "string") grpcMessage = message
    }

    stream.on("response", (headers) => {
      httpStatus = typeof headers[":status"] === "number" ? (headers[":status"] as number) : undefined
      recordStatus(headers as Record<string, unknown>)
    })

    stream.on("trailers", (trailers) => recordStatus(trailers as Record<string, unknown>))

    stream.on("data", (chunk: Buffer) => {
      received += chunk.length

      if (received > maxResponseBytes) {
        finish(() => {
          stream.destroy()
          session.destroy()
          reject(new Error(`the Workload API response exceeded ${maxResponseBytes} bytes`))
        })
        return
      }

      chunks.push(chunk)
    })

    stream.on("error", (error: Error) => finish(() => reject(error)))

    stream.on("end", () =>
      finish(() => {
        session.close()
        resolve({
          httpStatus,
          grpcStatus,
          grpcMessage,
          body: Buffer.concat(chunks),
        })
      }),
    )

    stream.end(frameGrpcMessage(request))
  })

/**
 * The gRPC status codes this client distinguishes.
 *
 * `PermissionDenied` is the one an operator will actually meet: SPIRE answers it when the calling
 * process is not entitled to the requested identity, which is precisely the case node attestation
 * exists to prevent. It is called out rather than folded into a generic error so a test can assert
 * that a second workload is refused for the right reason.
 */
const GRPC_PERMISSION_DENIED = 7
const GRPC_NOT_FOUND = 5
const GRPC_UNAUTHENTICATED = 16
const GRPC_RESOURCE_EXHAUSTED = 8

/**
 * Fetch JWT-SVIDs from a SPIRE agent.
 *
 * Every failure is a refusal. A response that cannot be decoded, is too large, times out, or
 * carries a non-OK gRPC status produces a failure code rather than a partial result — an SVID the
 * client could not fully read is an SVID it will not present.
 */
export const fetchJwtSvid = async (options: FetchJwtSvidOptions): Promise<FetchJwtSvidResult> => {
  const timeoutMs = options.timeoutMs ?? 10_000
  const maxResponseBytes = options.maxResponseBytes ?? 1024 * 1024

  const request = encodeFetchJwtSvidRequest({
    spiffeId: options.spiffeId,
    audience: options.audience,
  })

  let response: RawResponse

  try {
    response = await callFetchJwtSvid(
      options.socketPath,
      request,
      timeoutMs,
      maxResponseBytes,
      options.createSession ?? connectOverUnixSocket,
    )
  } catch (error) {
    return {
      ok: false,
      failure: "workload_api_unreachable",
      detail: error instanceof Error ? error.message : "the Workload API request failed",
    }
  }

  if (response.httpStatus !== undefined && response.httpStatus !== 200) {
    return {
      ok: false,
      failure: "workload_api_unreachable",
      detail: `the Workload API answered HTTP ${response.httpStatus}`,
    }
  }

  if (response.grpcStatus !== undefined && response.grpcStatus !== 0) {
    const detail = `gRPC status ${response.grpcStatus}${response.grpcMessage === "" ? "" : `: ${response.grpcMessage}`}`

    if (response.grpcStatus === GRPC_PERMISSION_DENIED) return { ok: false, failure: "no_svid_offered", detail }
    if (response.grpcStatus === GRPC_NOT_FOUND) return { ok: false, failure: "no_svid_offered", detail }
    if (response.grpcStatus === GRPC_UNAUTHENTICATED) return { ok: false, failure: "workload_api_unreachable", detail }
    if (response.grpcStatus === GRPC_RESOURCE_EXHAUSTED) return { ok: false, failure: "workload_api_unreachable", detail }

    return { ok: false, failure: "workload_api_error", detail }
  }

  let svids: WorkloadApiSvid[]

  try {
    svids = decodeFetchJwtSvidResponse(decodeGrpcFrame(response.body))
  } catch (error) {
    return {
      ok: false,
      failure: "workload_api_error",
      detail: error instanceof Error ? error.message : "the Workload API response could not be decoded",
    }
  }

  // An SVID with no JWT in it cannot be presented, so it is dropped rather than returned and
  // discovered later. `no_svid_offered` is the honest report: the agent offered nothing usable.
  const usable = svids.filter((svid) => svid.jwt.split(".").length === 3)

  if (usable.length === 0) {
    return { ok: false, failure: "no_svid_offered", detail: "the Workload API returned no JWT-SVID" }
  }

  return { ok: true, svids: usable }
}
