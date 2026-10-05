import assert from "node:assert/strict"
import { createServer, connect, type ClientHttp2Session, type Http2Server } from "node:http2"
import { after, test } from "node:test"

import {
  decodeFetchJwtSvidResponse,
  encodeFetchJwtSvidRequest,
  fetchJwtSvid,
} from "./spiffe-workload-api.ts"

/**
 * The Workload API is gRPC over a Unix socket, and the field numbers and header below were read
 * off a live SPIRE 1.15.3 agent rather than taken from a spec. These tests exist because getting
 * them wrong is silent: a request built with `spiffe_id` as field 1 is answered
 * `invalid requested SPIFFE ID: scheme is missing or invalid`, not by a parse error, so a codec
 * that quietly disagrees with the agent looks like it is working right up until it is not.
 *
 * The stand-in agent below is a real HTTP/2 server speaking real gRPC framing. Only the socket
 * type is substituted — see `SessionFactory` — because a Unix socket cannot be listened on at all
 * on Windows. Everything the client does above the connection is the code that talks to SPIRE.
 */

const AUDIENCE = "actantos"
const SPIFFE_ID = "spiffe://actantos.local/tenant/t_spire/agent/pi_demo"
const JWT = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln"

type ObservedRequest = {
  readonly path: string
  readonly headers: Record<string, string | string[] | undefined>
  readonly message: Buffer
}

const servers: Http2Server[] = []

after(() => {
  for (const server of servers) server.close()
})

/** Read a gRPC-framed protobuf message off the wire. */
const unframe = (body: Buffer): Buffer => {
  assert.equal(body[0], 0, "the client sent a compressed gRPC frame")
  const length = body.readUInt32BE(1)
  return body.subarray(5, 5 + length)
}

type StubAgent = {
  readonly url: string
  readonly observed: () => ObservedRequest
}

/**
 * Start a stand-in Workload API on a TCP port.
 *
 * `respond` receives the decoded request message and returns what to send back, so each test
 * decides its own gRPC status and body. The status goes in the trailers, which is where gRPC puts
 * it and where the client looks.
 */
const startStubAgent = async (
  respond: (request: Buffer) => { grpcStatus: number; grpcMessage?: string; body?: Buffer },
): Promise<StubAgent> => {
  let observed: ObservedRequest | undefined

  const server = createServer()
  servers.push(server)

  await new Promise<void>((resolve) => {
    server.listen(0, "127.0.0.1", resolve)
  })

  server.on("stream", (stream, headers) => {
    const chunks: Buffer[] = []
    stream.on("data", (chunk: Buffer) => chunks.push(chunk))
    stream.on("end", () => {
      observed = {
        path: String(headers[":path"]),
        headers: headers as Record<string, string | string[] | undefined>,
        message: unframe(Buffer.concat(chunks)),
      }

      const reply = respond(observed.message)

      stream.respond({ "content-type": "application/grpc" }, { waitForTrailers: true })
      stream.on("wantTrailers", () => {
        stream.sendTrailers({
          "grpc-status": String(reply.grpcStatus),
          "grpc-message": reply.grpcMessage ?? "",
        })
      })
      stream.write(reply.body ?? Buffer.alloc(0))
      stream.end()
    })
  })

  const address = server.address()
  assert.ok(address !== null && typeof address === "object", "the stub agent did not bind a port")

  return {
    url: `http://127.0.0.1:${address.port}`,
    observed: () => {
      assert.ok(observed !== undefined, "the client never sent a request")
      return observed
    },
  }
}

/** A session factory that speaks to the stand-in agent instead of a Unix socket. */
const overTcp =
  (url: string) =>
  (): ClientHttp2Session =>
    connect(url)

const encodeLengthDelimited = (fieldNumber: number, payload: Buffer): Buffer => {
  const tag = Buffer.from([(fieldNumber << 3) | 2])
  return Buffer.concat([tag, Buffer.from([payload.length]), payload])
}

/** Build a `JWTSVIDResponse` the way the agent does. */
const encodeResponse = (svids: readonly { spiffeId: string; jwt: string; hint?: string }[]): Buffer => {
  const entries = svids.map((svid) => {
    const parts = [
      encodeLengthDelimited(1, Buffer.from(svid.spiffeId)),
      encodeLengthDelimited(2, Buffer.from(svid.jwt)),
      ...(svid.hint === undefined ? [] : [encodeLengthDelimited(3, Buffer.from(svid.hint))]),
    ]
    return encodeLengthDelimited(1, Buffer.concat(parts))
  })

  return Buffer.concat(entries)
}

const frame = (message: Buffer): Buffer => {
  const header = Buffer.alloc(5)
  header.writeUInt32BE(message.length, 1)
  return Buffer.concat([header, message])
}

test("the client asks for the SPIFFE ID and audience in the fields the agent actually reads", async () => {
  // `JWTSVIDRequest` numbers `audience` as 1 and `spiffe_id` as 2. Swapping them produces a
  // well-formed message with an empty SPIFFE ID, which the agent answers with
  // `invalid requested SPIFFE ID` rather than a parse error — so this asserts the exact bytes.
  const agent = await startStubAgent(() => ({
    grpcStatus: 0,
    body: frame(encodeResponse([{ spiffeId: SPIFFE_ID, jwt: JWT }])),
  }))

  await fetchJwtSvid({
    socketPath: "unused",
    createSession: overTcp(agent.url),
    spiffeId: SPIFFE_ID,
    audience: [AUDIENCE],
  })

  const request = agent.observed()
  const expected = Buffer.concat([
    encodeLengthDelimited(1, Buffer.from(AUDIENCE)),
    encodeLengthDelimited(2, Buffer.from(SPIFFE_ID)),
  ])

  assert.deepEqual(request.message, expected)
})

test("the client sends the method path and security header SPIRE requires", async () => {
  const agent = await startStubAgent(() => ({
    grpcStatus: 0,
    body: frame(encodeResponse([{ spiffeId: SPIFFE_ID, jwt: JWT }])),
  }))

  await fetchJwtSvid({
    socketPath: "unused",
    createSession: overTcp(agent.url),
    spiffeId: SPIFFE_ID,
    audience: [AUDIENCE],
  })

  const request = agent.observed()

  // A dotted `SpiffeWorkloadAPI.FetchJWTSVID` is refused as a malformed method name.
  assert.equal(request.path, "/SpiffeWorkloadAPI/FetchJWTSVID")
  // SPIRE refuses the call outright without this header, and its value is the literal `true`.
  assert.equal(request.headers["workload.spiffe.io"], "true")
})

test("a SVID offered by the agent is returned", async () => {
  const agent = await startStubAgent(() => ({
    grpcStatus: 0,
    body: frame(encodeResponse([{ spiffeId: SPIFFE_ID, jwt: JWT, hint: "internal" }])),
  }))

  const result = await fetchJwtSvid({
    socketPath: "unused",
    createSession: overTcp(agent.url),
    spiffeId: SPIFFE_ID,
    audience: [AUDIENCE],
  })

  assert.equal(result.ok, true)
  assert.ok(result.ok)
  assert.equal(result.svids.length, 1)
  assert.equal(result.svids[0]?.jwt, JWT)
  assert.equal(result.svids[0]?.spiffeId, SPIFFE_ID)
  assert.equal(result.svids[0]?.hint, "internal")
})

test("a permission-denied agent yields no SVID, which is how one workload is kept from another's identity", async () => {
  // SPIRE answers PERMISSION_DENIED when the calling process is not entitled to the identity it
  // asked for. This is the case node attestation exists to produce, so it must be a refusal and
  // not an error that a caller could mistake for "try another identity source".
  const agent = await startStubAgent(() => ({ grpcStatus: 7, grpcMessage: "no identity issued" }))

  const result = await fetchJwtSvid({
    socketPath: "unused",
    createSession: overTcp(agent.url),
    spiffeId: "spiffe://actantos.local/tenant/t_spire/agent/somebody_else",
    audience: [AUDIENCE],
  })

  assert.equal(result.ok, false)
  assert.ok(!result.ok)
  assert.equal(result.failure, "no_svid_offered")
})

test("a non-OK gRPC status is a failure and never a token", async () => {
  const agent = await startStubAgent(() => ({
    grpcStatus: 16,
    body: frame(encodeResponse([{ spiffeId: SPIFFE_ID, jwt: JWT }])),
  }))

  const result = await fetchJwtSvid({
    socketPath: "unused",
    createSession: overTcp(agent.url),
    spiffeId: SPIFFE_ID,
    audience: [AUDIENCE],
  })

  // The agent sent a perfectly good SVID alongside a failure status. The status wins: reading the
  // body anyway would mean an agent that failed a call could still hand this process an identity.
  assert.equal(result.ok, false)
  assert.ok(!result.ok)
  assert.equal(result.failure, "workload_api_unreachable")
})

test("a response that cannot be decoded is a failure, not a partial token", async () => {
  const agent = await startStubAgent(() => ({
    grpcStatus: 0,
    // A length-delimited field that claims more bytes than the message carries.
    body: frame(Buffer.from([0x0a, 0x7f, 0x01])),
  }))

  const result = await fetchJwtSvid({
    socketPath: "unused",
    createSession: overTcp(agent.url),
    spiffeId: SPIFFE_ID,
    audience: [AUDIENCE],
  })

  assert.equal(result.ok, false)
  assert.ok(!result.ok)
  assert.equal(result.failure, "workload_api_error")
})

test("an SVID entry with no JWT in it is not offered as an identity", async () => {
  const agent = await startStubAgent(() => ({
    grpcStatus: 0,
    body: frame(encodeResponse([{ spiffeId: SPIFFE_ID, jwt: "" }])),
  }))

  const result = await fetchJwtSvid({
    socketPath: "unused",
    createSession: overTcp(agent.url),
    spiffeId: SPIFFE_ID,
    audience: [AUDIENCE],
  })

  assert.equal(result.ok, false)
  assert.ok(!result.ok)
  assert.equal(result.failure, "no_svid_offered")
})

test("a response larger than the client's cap is refused rather than buffered", async () => {
  const agent = await startStubAgent(() => ({
    grpcStatus: 0,
    body: frame(Buffer.alloc(4096, 0x41)),
  }))

  const result = await fetchJwtSvid({
    socketPath: "unused",
    createSession: overTcp(agent.url),
    spiffeId: SPIFFE_ID,
    audience: [AUDIENCE],
    maxResponseBytes: 256,
  })

  assert.equal(result.ok, false)
  assert.ok(!result.ok)
  assert.match(result.detail, /exceeded 256 bytes/u)
})

test("an agent that does not answer is unreachable, so the caller refuses closed", async () => {
  const agent = await startStubAgent(() => ({ grpcStatus: 0, body: Buffer.alloc(0) }))
  const url = agent.url

  servers[servers.length - 1]?.close()
  await new Promise((resolve) => setTimeout(resolve, 50))

  const result = await fetchJwtSvid({
    socketPath: "unused",
    createSession: overTcp(url),
    spiffeId: SPIFFE_ID,
    audience: [AUDIENCE],
    timeoutMs: 2_000,
  })

  assert.equal(result.ok, false)
  assert.ok(!result.ok)
  assert.equal(result.failure, "workload_api_unreachable")
})

test("a socket that is not there is unreachable rather than a crash", async () => {
  const result = await fetchJwtSvid({
    // No stand-in agent and no seam: this is the real Unix-socket transport failing to connect.
    socketPath: "/nonexistent/actantos-workload-api.sock",
    spiffeId: SPIFFE_ID,
    audience: [AUDIENCE],
    timeoutMs: 2_000,
  })

  assert.equal(result.ok, false)
  assert.ok(!result.ok)
  assert.equal(result.failure, "workload_api_unreachable")
})

test("the request codec leaves out an unset spiffe_id so every entitled SVID comes back", () => {
  const encoded = encodeFetchJwtSvidRequest({ audience: [AUDIENCE] })

  assert.deepEqual(encoded, encodeLengthDelimited(1, Buffer.from(AUDIENCE)))
})

test("every audience the caller names is sent", () => {
  const encoded = encodeFetchJwtSvidRequest({ audience: ["one", "two"] })

  assert.deepEqual(
    encoded,
    Buffer.concat([
      encodeLengthDelimited(1, Buffer.from("one")),
      encodeLengthDelimited(1, Buffer.from("two")),
    ]),
  )
})

test("a response carrying several SVIDs decodes all of them", () => {
  const decoded = decodeFetchJwtSvidResponse(
    encodeResponse([
      { spiffeId: SPIFFE_ID, jwt: JWT },
      { spiffeId: "spiffe://actantos.local/tenant/t_spire/agent/other", jwt: `${JWT}x` },
    ]),
  )

  assert.equal(decoded.length, 2)
  assert.equal(decoded[1]?.jwt, `${JWT}x`)
})