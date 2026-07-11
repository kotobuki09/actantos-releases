import fs from "node:fs"
import { createHash } from "node:crypto"
import path from "node:path"

import { ApprovalRequired, GuardedAccessDenied } from "./errors.ts"
import {
  createRequestId,
  postInterceptDecision,
  postToolResult,
  type InterceptDependencies,
  type ToolResultRequest,
} from "./intercept_client.ts"

export type GuardedReadDependencies = InterceptDependencies

const CREDENTIAL_FILE_NAMES = [
  ".env",
  ".npmrc",
  ".pypirc",
  ".git-credentials",
  "auth.json",
] as const

const CREDENTIAL_DIRECTORY_NAMES = [".aws", ".ssh", ".config/gcloud"] as const

const sha256Text = (value: string): string =>
  createHash("sha256").update(value, "utf8").digest("hex")

const scrubSensitiveText = (value: string): string =>
  value
    .replaceAll(/ghp_[A-Za-z0-9]+/g, "[REDACTED_GITHUB_TOKEN]")
    .replaceAll(/SECRET=[^\s]+/g, "SECRET=[REDACTED]")
    .replaceAll(/AWS_[A-Z_]+=([^\s]+)/g, (_match, _capture) => "AWS_[REDACTED]=[REDACTED]")

const buildPreview = (content: string): string =>
  scrubSensitiveText(content).slice(0, 200)

const canonicalizePath = (
  workspaceRoot: string,
  cwd: string,
  userInputPath: string,
): { readonly canonicalRoot: string; readonly canonicalPath: string } => {
  const absolutePath = path.resolve(cwd, userInputPath)

  let canonicalRoot: string
  let canonicalPath: string

  try {
    canonicalRoot = fs.realpathSync(workspaceRoot)
    canonicalPath = fs.realpathSync(absolutePath)
  } catch {
    throw new GuardedAccessDenied("canonicalization_failed")
  }

  assertWithinWorkspaceRoot(canonicalRoot, canonicalPath)
  return { canonicalRoot, canonicalPath }
}

const assertWithinWorkspaceRoot = (
  canonicalRoot: string,
  canonicalPath: string,
): void => {
  const relativePath = path.relative(canonicalRoot, canonicalPath)
  if (relativePath.startsWith("..") || path.isAbsolute(relativePath)) {
    throw new GuardedAccessDenied("canonicalization_failed")
  }
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

const toWorkspaceLogicalPath = (
  canonicalRoot: string,
  canonicalPath: string,
): string => {
  const relativePath = path.relative(canonicalRoot, canonicalPath)
  if (relativePath.length === 0) {
    return "/workspace"
  }
  return `/workspace/${relativePath.replaceAll("\\", "/")}`
}

const createBlockedToolResultPayload = (
  requestId: string,
  decisionId: string,
  error: GuardedAccessDenied | ApprovalRequired,
): ToolResultRequest => {
  const timestamp = new Date().toISOString()

  return {
    request_id: requestId,
    decision_id: decisionId,
    tool_kind: "file",
    status: "blocked",
    started_at: timestamp,
    finished_at: timestamp,
    result: {
      error_message: error.message,
    },
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
    redacted_preview: buildPreview(content),
  },
})

export const guardedRead = async (
  dependencies: GuardedReadDependencies,
  userInputPath: string,
): Promise<string> => {
  const { canonicalRoot, canonicalPath } = canonicalizePath(
    dependencies.workspaceRoot,
    dependencies.session.cwd,
    userInputPath,
  )
  const logicalPath = toWorkspaceLogicalPath(canonicalRoot, canonicalPath)
  const requestId = createRequestId(dependencies)
  const credentialAccess = isCredentialPath(canonicalPath)
  const interceptDecision = await postInterceptDecision(
    dependencies,
    {
      requestId,
      tool: {
        kind: "file",
        name: "guarded_read",
        operation: "ReadFile",
      },
      resource: {
        id: logicalPath,
        kind: "file",
        path: logicalPath,
      },
      action: {
        operation: "ReadFile",
        args: {
          path: logicalPath,
        },
      },
      normalized: {
        verb: "read",
        mutation: false,
        destructive: false,
        network: false,
        credential_access: credentialAccess,
        risk_class: "low",
      },
    },
  )

  switch (interceptDecision.decision) {
    case "allow": {
      const startedAt = new Date().toISOString()
      let reverifiedPath: string

      try {
        reverifiedPath = fs.realpathSync(
          path.resolve(dependencies.session.cwd, userInputPath),
        )
      } catch {
        throw new GuardedAccessDenied("canonicalization_failed")
      }

      assertWithinWorkspaceRoot(canonicalRoot, reverifiedPath)
      if (reverifiedPath !== canonicalPath) {
        const error = new GuardedAccessDenied(
          "canonicalization_failed",
          "guarded access denied (canonicalization_failed)",
          interceptDecision.decision_id,
          requestId,
        )
        await postToolResult(
          dependencies,
          createBlockedToolResultPayload(requestId, interceptDecision.decision_id, error),
        )
        throw error
      }

      const content = await fs.promises.readFile(reverifiedPath, "utf8")
      const finishedAt = new Date().toISOString()

      if (interceptDecision.decision_token === undefined) {
        throw new Error("allow decision did not include a decision_token")
      }

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

      return content
    }
    case "deny": {
      const error = new GuardedAccessDenied(
        interceptDecision.reason_code,
        interceptDecision.reason,
        interceptDecision.decision_id,
        requestId,
      )
      await postToolResult(
        dependencies,
        createBlockedToolResultPayload(requestId, interceptDecision.decision_id, error),
      )
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
      await postToolResult(
        dependencies,
        createBlockedToolResultPayload(requestId, interceptDecision.decision_id, error),
      )
      throw error
    }
  }
}

export const createGuardedRead = (dependencies: GuardedReadDependencies) => {
  return async (userInputPath: string): Promise<string> =>
    guardedRead(dependencies, userInputPath)
}
