import { createHmac, timingSafeEqual } from "node:crypto"

export type ApprovalChannelKind = "web" | "slack" | "webhook" | "teams"

export type ApprovalChannel =
  | { readonly kind: "web"; readonly enabled: boolean }
  | { readonly kind: "slack"; readonly enabled: boolean }
  | { readonly kind: "teams"; readonly enabled: boolean }
  | {
      readonly kind: "webhook"
      readonly enabled: boolean
      readonly target_url: string
      readonly secret: string
    }

export type ApprovalRequiredEvent = {
  readonly approval_id: string
  readonly tenant_id: string
  readonly request_id: string
  readonly reason_code: string
  readonly agent_id: string
  readonly session_id: string
}

const defaultChannels: readonly ApprovalChannel[] = [
  { kind: "web", enabled: true },
  { kind: "slack", enabled: false },
  { kind: "teams", enabled: false },
]

/** In-process channel config (Stage 2); replace with DB when multi-tenant config ships. */
let channelState: ApprovalChannel[] = [...defaultChannels]

export const listApprovalChannels = (): readonly ApprovalChannel[] => channelState

export const resetApprovalChannelsForTests = (): void => {
  channelState = [...defaultChannels]
}

export const setApprovalChannels = (channels: readonly ApprovalChannel[]): readonly ApprovalChannel[] => {
  channelState = [...channels]
  return channelState
}

export const verifyWebhookChannelSecret = (secret: string): boolean => {
  const webhook = channelState.find((channel) => channel.kind === "webhook" && channel.enabled)
  if (webhook === undefined || webhook.kind !== "webhook") {
    return false
  }
  const expected = Buffer.from(webhook.secret)
  const provided = Buffer.from(secret)
  if (expected.length !== provided.length) {
    return false
  }
  return timingSafeEqual(expected, provided)
}

export const signWebhookPayload = (secret: string, body: string): string =>
  createHmac("sha256", secret).update(body).digest("hex")

export type FetchLike = (
  url: string,
  init: { readonly method: string; readonly headers: Record<string, string>; readonly body: string },
) => Promise<{ readonly ok: boolean; readonly status: number }>

/** Deliver approval_required events to enabled non-web channels (S2-3). */
export const notifyApprovalChannels = async (
  event: ApprovalRequiredEvent,
  options: { readonly fetchImpl?: FetchLike } = {},
): Promise<readonly { readonly kind: ApprovalChannelKind; readonly delivered: boolean }[]> => {
  const fetchImpl = options.fetchImpl ?? (globalThis.fetch as FetchLike | undefined)
  const results: { kind: ApprovalChannelKind; delivered: boolean }[] = []

  for (const channel of channelState) {
    if (!channel.enabled || channel.kind === "web") {
      continue
    }
    if (channel.kind === "webhook") {
      if (fetchImpl === undefined) {
        results.push({ kind: "webhook", delivered: false })
        continue
      }
      const body = JSON.stringify({
        type: "approval_required",
        ...event,
        decide_path: `/v1/approvals/channels/webhook/decide`,
      })
      const signature = signWebhookPayload(channel.secret, body)
      try {
        const response = await fetchImpl(channel.target_url, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-actantos-signature": signature,
          },
          body,
        })
        results.push({ kind: "webhook", delivered: response.ok })
      } catch {
        results.push({ kind: "webhook", delivered: false })
      }
      continue
    }
    // Slack/Teams adapters reserved — Stage 2 ships webhook as the non-web path.
    results.push({ kind: channel.kind, delivered: false })
  }

  return results
}
