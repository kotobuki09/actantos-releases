import assert from "node:assert/strict"
import { createHmac } from "node:crypto"
import { createServer } from "node:http"
import test from "node:test"

import { buildServer } from "./server.ts"
import { createTestDatabase } from "./test-database.ts"
import { PostgresToolCallRepository } from "./tool-call-repository.ts"

const createWebhookReceiver = async (): Promise<{
  readonly url: string
  readonly received: Promise<{
    readonly headers: Record<string, string | string[] | undefined>
    readonly body: string
  }>
  readonly close: () => Promise<void>
}> => {
  let resolveReceived: ((value: {
    readonly headers: Record<string, string | string[] | undefined>
    readonly body: string
  }) => void) | undefined
  const received = new Promise<{
    readonly headers: Record<string, string | string[] | undefined>
    readonly body: string
  }>((resolve) => {
    resolveReceived = resolve
  })

  const server = createServer((request, response) => {
    let body = ""
    request.setEncoding("utf8")
    request.on("data", (chunk) => {
      body += chunk
    })
    request.on("end", () => {
      resolveReceived?.({
        headers: request.headers,
        body,
      })
      response.writeHead(202, { "content-type": "application/json" })
      response.end(JSON.stringify({ ok: true }))
    })
  })

  await new Promise<void>((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve())
  })

  const address = server.address()
  if (address === null || typeof address === "string") {
    throw new Error("expected tcp address")
  }

  return {
    url: `http://127.0.0.1:${String(address.port)}/receiver`,
    received,
    close: async () =>
      new Promise<void>((resolve, reject) => {
        server.close((error) => {
          if (error === undefined) {
            resolve()
            return
          }
          reject(error)
        })
      }),
  }
}

test("POST /v1/webhooks/evidence delivers a signed evidence event", async () => {
  const database = await createTestDatabase()
  const server = buildServer({
    hmacSecret: "test-secret",
    repository: new PostgresToolCallRepository(database),
    database,
  })
  await server.ready()

  const interceptResponse = await server.inject({
    method: "POST",
    url: "/v1/intercept/tool-call",
    payload: {
      request_id: "req_webhook_allow_0001",
      tenant_id: "t_demo",
      agent: {
        id: "pi_demo",
        runtime_type: "pi",
        environment: "dev",
        risk_tier: "low",
      },
      subject: {
        user_id: "u_demo",
        role: "developer",
      },
      session: {
        id: "s_demo",
        cwd: "/workspace",
        budget_remaining_cents: 10_000,
      },
      tool: {
        kind: "file",
        name: "guarded_read",
        operation: "ReadFile",
        schema_hash: "",
      },
      resource: {
        id: "/workspace/README.md",
        kind: "file",
        path: "/workspace/README.md",
      },
      action: {
        operation: "ReadFile",
        args: { path: "/workspace/README.md" },
      },
      normalized: {
        verb: "read",
        mutation: false,
        destructive: false,
        network: false,
        credential_access: false,
        risk_class: "low",
      },
    },
  })

  assert.equal(interceptResponse.statusCode, 200)

  const receiver = await createWebhookReceiver()
  const deliveryResponse = await server.inject({
    method: "POST",
    url: "/v1/webhooks/evidence",
    payload: {
      tenant_id: "t_demo",
      session_id: "s_demo",
      destination_url: receiver.url,
    },
  })

  assert.equal(deliveryResponse.statusCode, 200)
  assert.equal(deliveryResponse.json().delivered, true)
  assert.equal(deliveryResponse.json().status_code, 202)

  const received = await receiver.received
  const signature = received.headers["x-actantos-signature"]
  assert.equal(typeof signature, "string")
  assert.equal(received.headers["x-actantos-event"], "evidence.exported")

  const expectedSignature = createHmac("sha256", "test-secret")
    .update(received.body)
    .digest("hex")
  assert.equal(signature, `sha256=${expectedSignature}`)

  const payload = JSON.parse(received.body) as {
    readonly event: string
    readonly tenant_id: string
    readonly session_id: string | null
    readonly evidence: {
      readonly summary: {
        readonly decision_count: number
      }
    }
  }
  assert.equal(payload.event, "evidence.exported")
  assert.equal(payload.tenant_id, "t_demo")
  assert.equal(payload.session_id, "s_demo")
  assert.equal(payload.evidence.summary.decision_count >= 1, true)

  await receiver.close()
  await server.close()
  await database.close()
})
