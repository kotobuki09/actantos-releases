import { createHash } from "node:crypto"
import fs from "node:fs"
import path from "node:path"

import { ApprovalRequired, GuardedAccessDenied } from "./errors.ts"
import {
  createRequestId,
  postInterceptDecision,
  postToolResult,
  type InterceptDependencies,
  type ToolResultRequest,
} from "./intercept_client.ts"

export type GuardedWriteDependencies = InterceptDependencies

const CREDENTIAL_FILE_NAMES = [".env", ".npmrc", ".pypirc", ".git-credentials", "auth.json"] as const
const CREDENTIAL_DIRECTORY_NAMES = [".aws", ".ssh", ".config/gcloud"] as const

type CanonicalWriteTarget = {
  readonly canonicalRoot: string
  readonly canonicalParent: string
  readonly canonicalPath: string
}

const sha256Text = (value: string): string =>
  createHash("sha256").update(value, "utf8").digest("hex")

const scrubSensitiveText = (value: string): string =>
  value
    .replaceAll(/ghp_[A-Za-z0-9]+/g, "[REDACTED_GITHUB_TOKEN]")
    .replaceAll(/SECRET=[^\s]+/g, "SECRET=[REDACTED]")
    .replaceAll(/AWS_[A-Z_]+=([^\s]+)/g, (_match, _capture) => "AWS_[REDACTED]=[REDACTED]")

const assertWithinWorkspaceRoot = (canonicalRoot: string, canonicalPath: string): void => {
  const relativePath = path.relative(canonicalRoot, canonicalPath)
  if (relativePath.startsWith("..") || path.isAbsolute(relativePath)) {
    throw new GuardedAccessDenied("canonicalization_failed")
  }
}

const canonicalizeWriteTarget = (workspaceRoot: string, cwd: string, userInputPath: string): CanonicalWriteTarget => {
  const absolutePath = path.resolve(cwd, userInputPath)
  const absoluteParent = path.dirname(absolutePath)

  let canonicalRoot: string
  let canonicalParent: string

  try {
    canonicalRoot = fs.realpathSync(workspaceRoot)
    canonicalParent = fs.realpathSync(absoluteParent)
  } catch {
    throw new GuardedAccessDenied("canonicalization_failed")
  }

  assertWithinWorkspaceRoot(canonicalRoot, canonicalParent)

  const targetName = path.basename(absolutePath)
  const canonicalPath = path.join(canonicalParent, targetName)

  if (fs.existsSync(absolutePath)) {
    const existingCanonicalPath = fs.realpathSync(absolutePath)
    assertWithinWorkspaceRoot(canonicalRoot, existingCanonicalPath)
    return { canonicalRoot, canonicalParent, canonicalPath: existingCanonicalPath }
  }

  assertWithinWorkspaceRoot(canonicalRoot, canonicalPath)

  return { canonicalRoot, canonicalParent, canonicalPath }
}

const isCredentialPath = (canonicalPath: string): boolean => {
  const normalizedPath = canonicalPath.replaceAll("\\", "/").toLowerCase()
  const fileName = path.posix.basename(normalizedPath)

  if (CREDENTIAL_FILE_NAMES.some((credentialFileName) => credentialFileName === fileName)) {
    return true
  }

  if (fileName.startsWith(".env.")) {
    return true
  }

  return CREDENTIAL_DIRECTORY_NAMES.some((directoryName) =>
    normalizedPath.includes(`/${directoryName}/`),
  )
}

const toWorkspaceLogicalPath = (canonicalRoot: string, canonicalPath: string): string => {
  const relativePath = path.relative(canonicalRoot, canonicalPath)
  if (relativePath.length === 0) {
    return "/workspace"
  }
  return `/workspace/${relativePath.replaceAll("\\", "/")}`
}

const nowIso = (): string => new Date().toISOString()

const createBlockedToolResultPayload = (
  requestId: string,
  decisionId: string,
  error: GuardedAccessDenied | ApprovalRequired,
): ToolResultRequest => {
  return {
    request_id: requestId,
    decision_id: decisionId,
    tool_kind: "file",
    status: "blocked",
    started_at: nowIso(),
    finished_at: nowIso(),
    result: { error_message: error.message },
  }
}

const createExecutedToolResultPayload = (
  requestId: string,
  decisionId: string,
  decisionToken: string,
  content: string,
  startedAt: string,
  finishedAt: string,
): ToolResultRequest => ({
  request_id: requestId,
  decision_id: decisionId,
  decision_token: decisionToken,
  tool_kind: "file",
  status: "executed",
  started_at: startedAt,
  finished_at: finishedAt,
  result: {
    stdout_hash: sha256Text(content),
    redacted_preview: scrubSensitiveText(content).slice(0, 200),
  },
})

const reverifyWriteTarget = (
  target: CanonicalWriteTarget,
  cwd: string,
  userInputPath: string,
): string => {
  const absolutePath = path.resolve(cwd, userInputPath)
  const absoluteParent = path.dirname(absolutePath)

  let reverifiedParent: string
  try {
    reverifiedParent = fs.realpathSync(absoluteParent)
  } catch {
    throw new GuardedAccessDenied("canonicalization_failed")
  }

  if (reverifiedParent !== target.canonicalParent) {
    throw new GuardedAccessDenied("canonicalization_failed")
  }

  if (fs.existsSync(absolutePath)) {
    const existingCanonicalPath = fs.realpathSync(absolutePath)
    assertWithinWorkspaceRoot(target.canonicalRoot, existingCanonicalPath)
    if (existingCanonicalPath !== target.canonicalPath) {
      throw new GuardedAccessDenied("canonicalization_failed")
    }
    return existingCanonicalPath
  }

  assertWithinWorkspaceRoot(target.canonicalRoot, target.canonicalPath)
  return target.canonicalPath
}

export const guardedWrite = async (
  dependencies: GuardedWriteDependencies,
  userInputPath: string,
  content: string,
): Promise<void> => {
  const target = canonicalizeWriteTarget(
    dependencies.workspaceRoot,
    dependencies.session.cwd,
    userInputPath,
  )
  const logicalPath = toWorkspaceLogicalPath(target.canonicalRoot, target.canonicalPath)
  const requestId = createRequestId(dependencies)
  const credentialAccess = isCredentialPath(target.canonicalPath)
  const interceptDecision = await postInterceptDecision(
    dependencies,
    {
      requestId,
      tool: {
        kind: "file",
        name: "guarded_write",
        operation: "WriteFile",
      },
      resource: {
        id: logicalPath,
        kind: "file",
        path: logicalPath,
      },
      action: {
        operation: "WriteFile",
        args: {
          path: logicalPath,
          bytes: Buffer.byteLength(content, "utf8"),
        },
      },
      normalized: {
        verb: "write",
        mutation: true,
        destructive: false,
        network: false,
        credential_access: credentialAccess,
        risk_class: credentialAccess ? "critical" : "medium",
      },
    },
  )

  switch (interceptDecision.decision) {
    case "allow": {
      if (interceptDecision.decision_token === undefined) {
        throw new Error("allow decision did not include a decision_token")
      }

      const startedAt = nowIso()
      const reverifiedPath = reverifyWriteTarget(
        target,
        dependencies.session.cwd,
        userInputPath,
      )
      await fs.promises.writeFile(reverifiedPath, content, "utf8")
      const finishedAt = nowIso()

      await postToolResult(
        dependencies,
        createExecutedToolResultPayload(
          requestId,
          interceptDecision.decision_id,
          interceptDecision.decision_token,
          content,
          startedAt,
          finishedAt,
        ),
      )
      return
    }
    case "deny": {
      const error = new GuardedAccessDenied(
        interceptDecision.reason_code,
        interceptDecision.reason,
        interceptDecision.decision_id,
        requestId,
      )
      await postToolResult(dependencies, createBlockedToolResultPayload(requestId, interceptDecision.decision_id, error))
      throw error
    }
    case "approval_required": {
      const error = new ApprovalRequired(
        interceptDecision.approval.approval_id,
        interceptDecision.approval.approval_id,
        interceptDecision.reason_code,
        interceptDecision.reason,
        interceptDecision.decision_id,
        requestId,
      )
      await postToolResult(dependencies, createBlockedToolResultPayload(requestId, interceptDecision.decision_id, error))
      throw error
    }
  }
}

export const createGuardedWrite = (dependencies: GuardedWriteDependencies) => {
  return async (userInputPath: string, content: string): Promise<void> =>
    guardedWrite(dependencies, userInputPath, content)
}
