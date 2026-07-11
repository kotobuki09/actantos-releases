import { createHmac, timingSafeEqual } from "node:crypto"

import { canonicalHash, canonicalStringify, toJsonValue } from "./hash.ts"

export type IsolationProviderName = "docker" | "gvisor" | "fake"

export type ExecutionCredentialGrant = {
  readonly reference: string
  readonly audience: string
  readonly maxTtlSeconds: number
}

export type ExecutionSpec = {
  readonly tenantId: string
  readonly agentId: string
  readonly sessionId: string
  readonly toolCallId: string
  readonly requestId: string
  readonly provider: IsolationProviderName
  readonly imageDigest: string
  readonly workspacePath: string
  readonly argv: readonly string[]
  readonly networkMode: "none" | "egress_proxy"
  readonly networkAllowlist: readonly string[]
  readonly timeoutMs: number
  readonly maxOutputBytes: number
  readonly readOnlyRoot: boolean
  readonly credentialGrants: readonly ExecutionCredentialGrant[]
  readonly exp: number
}

export type ExecutionResult = {
  readonly status: "executed" | "failed" | "timeout" | "denied"
  readonly exitCode: number
  readonly stdout: string
  readonly stderr: string
  readonly provider: IsolationProviderName
  readonly startedAt: string
  readonly finishedAt: string
  readonly errorMessage?: string
}

export interface IsolationProvider {
  readonly name: IsolationProviderName
  execute(spec: ExecutionSpec): Promise<ExecutionResult>
  readiness(): Promise<{ readonly ready: boolean; readonly reason?: string }>
}

export type SignedExecutionToken = {
  readonly payload: string
  readonly signature: string
}

const usedTokenIds = new Set<string>()

export const clearUsedExecutionTokens = (): void => {
  usedTokenIds.clear()
}

export const signExecutionSpec = (spec: ExecutionSpec, secret: string): SignedExecutionToken => {
  const payload = Buffer.from(canonicalStringify(toJsonValue(spec)), "utf8").toString("base64url")
  const signature = createHmac("sha256", secret).update(payload).digest("base64url")
  return { payload, signature }
}

export const verifyAndConsumeExecutionToken = (
  token: SignedExecutionToken,
  secret: string,
  nowSeconds: number = Math.floor(Date.now() / 1000),
): ExecutionSpec => {
  const expected = createHmac("sha256", secret).update(token.payload).digest("base64url")
  const expectedBuf = Buffer.from(expected)
  const providedBuf = Buffer.from(token.signature)
  if (expectedBuf.length !== providedBuf.length || !timingSafeEqual(expectedBuf, providedBuf)) {
    throw new Error("invalid execution token signature")
  }

  const spec = JSON.parse(Buffer.from(token.payload, "base64url").toString("utf8")) as ExecutionSpec
  if (spec.exp <= nowSeconds) {
    throw new Error("execution token expired")
  }

  const tokenId = canonicalHash({
    tenantId: spec.tenantId,
    toolCallId: spec.toolCallId,
    requestId: spec.requestId,
    exp: spec.exp,
  })
  if (usedTokenIds.has(tokenId)) {
    throw new Error("execution token already consumed")
  }
  usedTokenIds.add(tokenId)
  return spec
}

export const createFakeIsolationProvider = (): IsolationProvider & {
  readonly invocations: ExecutionSpec[]
} => {
  const invocations: ExecutionSpec[] = []
  return {
    name: "fake",
    invocations,
    async readiness() {
      return { ready: true }
    },
    async execute(spec) {
      invocations.push(spec)
      const startedAt = new Date().toISOString()
      return {
        status: "executed",
        exitCode: 0,
        stdout: "ok",
        stderr: "",
        provider: "fake",
        startedAt,
        finishedAt: new Date().toISOString(),
      }
    },
  }
}

export const createDockerIsolationProvider = (
  run: (spec: ExecutionSpec) => Promise<ExecutionResult> = async () => ({
    status: "executed",
    exitCode: 0,
    stdout: "",
    stderr: "",
    provider: "docker",
    startedAt: new Date().toISOString(),
    finishedAt: new Date().toISOString(),
  }),
): IsolationProvider => ({
  name: "docker",
  async readiness() {
    return { ready: true, reason: "development_compatibility_provider" }
  },
  async execute(spec) {
    if (spec.provider !== "docker") {
      return {
        status: "denied",
        exitCode: 126,
        stdout: "",
        stderr: "provider mismatch",
        provider: "docker",
        startedAt: new Date().toISOString(),
        finishedAt: new Date().toISOString(),
        errorMessage: "docker provider rejected non-docker spec",
      }
    }
    return run(spec)
  },
})
