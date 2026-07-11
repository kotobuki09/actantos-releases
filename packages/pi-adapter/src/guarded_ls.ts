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

export type GuardedLsDependencies = InterceptDependencies

const CREDENTIAL_FILE_NAMES = [".env", ".npmrc", ".pypirc", ".git-credentials", "auth.json"] as const
const CREDENTIAL_DIRECTORY_NAMES = [".aws", ".ssh", ".config/gcloud"] as const

type CanonicalListTarget = {
  readonly canonicalRoot: string
  readonly canonicalPath: string
}

const sha256Text = (value: string): string =>
  createHash("sha256").update(value, "utf8").digest("hex")

const assertWithinWorkspaceRoot = (canonicalRoot: string, canonicalPath: string): void => {
  const relativePath = path.relative(canonicalRoot, canonicalPath)
  if (relativePath.startsWith("..") || path.isAbsolute(relativePath)) {
    throw new GuardedAccessDenied("canonicalization_failed")
  }
}

const canonicalizeListTarget = (workspaceRoot: string, cwd: string, userInputPath: string): CanonicalListTarget => {
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
    normalizedPath.includes(`/${directoryName}`),
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
): ToolResultRequest => ({
  request_id: requestId,
  decision_id: decisionId,
  tool_kind: "file",
  status: "blocked",
  started_at: nowIso(),
  finished_at: nowIso(),
  result: {
    error_message: error.message,
  },
})

const createExecutedToolResultPayload = (
  requestId: string,
  decisionId: string,
  decisionToken: string,
  entries: readonly string[],
  startedAt: string,
  finishedAt: string,
): ToolResultRequest => {
  const preview = entries.join("\n").slice(0, 200)
  return {
    request_id: requestId,
    decision_id: decisionId,
    decision_token: decisionToken,
    tool_kind: "file",
    status: "executed",
    started_at: startedAt,
    finished_at: finishedAt,
    result: {
      stdout_hash: sha256Text(entries.join("\n")),
      redacted_preview: preview,
    },
  }
}

const reverifyListTarget = (
  target: CanonicalListTarget,
  cwd: string,
  userInputPath: string,
): string => {
  const absolutePath = path.resolve(cwd, userInputPath)

  let verifiedPath: string
  try {
    verifiedPath = fs.realpathSync(absolutePath)
  } catch {
    throw new GuardedAccessDenied("canonicalization_failed")
  }

  assertWithinWorkspaceRoot(target.canonicalRoot, verifiedPath)
  if (verifiedPath !== target.canonicalPath) {
    throw new GuardedAccessDenied("canonicalization_failed")
  }

  return verifiedPath
}

export const guardedLs = async (
  dependencies: GuardedLsDependencies,
  userInputPath: string,
): Promise<readonly string[]> => {
  const target = canonicalizeListTarget(
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
        name: "guarded_ls",
        operation: "ListFiles",
      },
      resource: {
        id: logicalPath,
        kind: "directory",
        path: logicalPath,
      },
      action: {
        operation: "ListFiles",
        args: {
          path: logicalPath,
        },
      },
      normalized: {
        verb: "list",
        mutation: false,
        destructive: false,
        network: false,
        credential_access: credentialAccess,
        risk_class: credentialAccess ? "critical" : "low",
      },
    },
  )

  switch (interceptDecision.decision) {
    case "allow": {
      if (interceptDecision.decision_token === undefined) {
        throw new Error("allow decision did not include a decision_token")
      }

      const startedAt = nowIso()
      const verifiedPath = reverifyListTarget(
        target,
        dependencies.session.cwd,
        userInputPath,
      )
      const entries = fs.readdirSync(verifiedPath).sort()
      const finishedAt = nowIso()

      await postToolResult(
        dependencies,
        createExecutedToolResultPayload(
          requestId,
          interceptDecision.decision_id,
          interceptDecision.decision_token,
          entries,
          startedAt,
          finishedAt,
        ),
      )
      return entries
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

export const createGuardedLs = (dependencies: GuardedLsDependencies) => {
  return async (userInputPath: string): Promise<readonly string[]> =>
    guardedLs(dependencies, userInputPath)
}
