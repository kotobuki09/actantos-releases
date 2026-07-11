import { createHmac, randomUUID } from "node:crypto"

export type SiemConnectorKind = "webhook" | "splunk_hec"

export type SiemConnectorConfig = {
  readonly id: string
  readonly tenantId: string
  readonly kind: SiemConnectorKind
  readonly endpoint: string
  readonly secretRef: string
  readonly secretValue: string
  readonly enabled: boolean
  readonly paused: boolean
}

export type SiemDeliveryAttempt = {
  readonly id: string
  readonly connectorId: string
  readonly eventId: string
  readonly status: "delivered" | "retry" | "auth_failed" | "rejected" | "dead_letter"
  readonly httpStatus?: number
  readonly error?: string
  readonly signature: string
  readonly attemptedAt: string
}

export type SiemDeliveryRequest = {
  readonly eventId: string
  readonly tenantId: string
  readonly body: Readonly<Record<string, unknown>>
}

const isPrivateOrMetadata = (endpoint: string): boolean => {
  try {
    const hostname = new URL(endpoint).hostname.toLowerCase()
    return (
      hostname === "localhost" ||
      hostname === "metadata" ||
      hostname === "metadata.google.internal" ||
      hostname === "127.0.0.1" ||
      hostname.startsWith("10.") ||
      hostname.startsWith("192.168.") ||
      hostname.startsWith("169.254.") ||
      /^172\.(1[6-9]|2\d|3[0-1])\./.test(hostname)
    )
  } catch {
    return true
  }
}

export const signSiemPayload = (
  secret: string,
  timestamp: string,
  body: string,
): string => createHmac("sha256", secret).update(`${timestamp}.${body}`).digest("hex")

export type SiemTransport = (input: {
  readonly endpoint: string
  readonly headers: Readonly<Record<string, string>>
  readonly body: string
}) => Promise<{ readonly status: number; readonly body: string }>

export const createSiemDispatcher = (transport: SiemTransport) => {
  const attempts: SiemDeliveryAttempt[] = []

  return {
    attempts,
    async deliver(
      connector: SiemConnectorConfig,
      request: SiemDeliveryRequest,
    ): Promise<SiemDeliveryAttempt> {
      const attemptedAt = new Date().toISOString()
      const timestamp = String(Math.floor(Date.now() / 1000))
      const body = JSON.stringify(request.body)
      const signature = signSiemPayload(connector.secretValue, timestamp, body)

      if (!connector.enabled || connector.paused) {
        const attempt: SiemDeliveryAttempt = {
          id: randomUUID(),
          connectorId: connector.id,
          eventId: request.eventId,
          status: "rejected",
          error: "connector_paused_or_disabled",
          signature,
          attemptedAt,
        }
        attempts.push(attempt)
        return attempt
      }

      if (request.tenantId !== connector.tenantId) {
        const attempt: SiemDeliveryAttempt = {
          id: randomUUID(),
          connectorId: connector.id,
          eventId: request.eventId,
          status: "rejected",
          error: "tenant_mismatch",
          signature,
          attemptedAt,
        }
        attempts.push(attempt)
        return attempt
      }

      if (!connector.endpoint.startsWith("https://") || isPrivateOrMetadata(connector.endpoint)) {
        const attempt: SiemDeliveryAttempt = {
          id: randomUUID(),
          connectorId: connector.id,
          eventId: request.eventId,
          status: "rejected",
          error: "endpoint_not_allowlisted",
          signature,
          attemptedAt,
        }
        attempts.push(attempt)
        return attempt
      }

      if (body.length > 256_000) {
        const attempt: SiemDeliveryAttempt = {
          id: randomUUID(),
          connectorId: connector.id,
          eventId: request.eventId,
          status: "rejected",
          error: "payload_too_large",
          signature,
          attemptedAt,
        }
        attempts.push(attempt)
        return attempt
      }

      const headers: Record<string, string> = {
        "content-type": "application/json",
        "x-actantos-timestamp": timestamp,
        "x-actantos-signature": signature,
        "x-actantos-event-id": request.eventId,
      }
      if (connector.kind === "splunk_hec") {
        headers["authorization"] = `Splunk ${connector.secretValue}`
      }

      const response = await transport({ endpoint: connector.endpoint, headers, body })
      let status: SiemDeliveryAttempt["status"] = "delivered"
      if (response.status === 401 || response.status === 403) status = "auth_failed"
      else if (response.status === 429 || response.status >= 500) status = "retry"
      else if (response.status >= 400) status = "rejected"

      const attempt: SiemDeliveryAttempt = {
        id: randomUUID(),
        connectorId: connector.id,
        eventId: request.eventId,
        status,
        httpStatus: response.status,
        signature,
        attemptedAt,
        ...(status === "delivered" ? {} : { error: `http_${response.status}` }),
      }
      attempts.push(attempt)
      return attempt
    },
  }
}
