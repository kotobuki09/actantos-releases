import type { ToolCallInterceptionRequest } from "./contracts.ts"

export type UrlTargetGuardResult =
  | { readonly allowed: true }
  | {
      readonly allowed: false
      readonly reason: string
      readonly reasonCode: "policy_forbid"
    }

export interface UrlTargetGuard {
  evaluate(request: ToolCallInterceptionRequest): Promise<UrlTargetGuardResult>
}

const getActionUrl = (request: ToolCallInterceptionRequest): string | undefined => {
  const candidate = request.action.args?.["url"]
  return typeof candidate === "string" ? candidate : undefined
}

const isRfc1918Ipv4 = (hostname: string): boolean => {
  if (/^10\./.test(hostname)) {
    return true
  }
  if (/^192\.168\./.test(hostname)) {
    return true
  }

  const match = /^172\.(\d{1,3})\./.exec(hostname)
  if (match === null) {
    return false
  }

  const secondOctet = Number.parseInt(match[1] ?? "", 10)
  return secondOctet >= 16 && secondOctet <= 31
}

const normalizeHostname = (hostname: string): string => {
  const normalized = hostname.toLowerCase()
  if (normalized.startsWith("[") && normalized.endsWith("]")) {
    return normalized.slice(1, -1)
  }
  return normalized
}

const isPrivateOrLinkLocalIpv6 = (hostname: string): boolean =>
  hostname === "::1" ||
  /^fc/i.test(hostname) ||
  /^fd/i.test(hostname) ||
  /^fe[89a-f]/i.test(hostname)

const isBlockedHostname = (hostname: string): boolean => {
  const normalized = normalizeHostname(hostname)

  return (
    normalized === "localhost" ||
    normalized === "0.0.0.0" ||
    normalized === "metadata.google.internal" ||
    normalized === "metadata" ||
    /^127\./.test(normalized) ||
    /^169\.254\./.test(normalized) ||
    isRfc1918Ipv4(normalized) ||
    isPrivateOrLinkLocalIpv6(normalized)
  )
}

export class DefaultUrlTargetGuard implements UrlTargetGuard {
  async evaluate(
    request: ToolCallInterceptionRequest,
  ): Promise<UrlTargetGuardResult> {
    const candidateUrl = request.resource.url ?? getActionUrl(request)

    if (candidateUrl === undefined) {
      return { allowed: true }
    }

    let parsedUrl: URL

    try {
      parsedUrl = new URL(candidateUrl)
    } catch {
      return {
        allowed: false,
        reason: "URL target is invalid",
        reasonCode: "policy_forbid",
      }
    }

    if (isBlockedHostname(parsedUrl.hostname)) {
      return {
        allowed: false,
        reason: "URL target is blocked by the SSRF policy",
        reasonCode: "policy_forbid",
      }
    }

    return { allowed: true }
  }
}
