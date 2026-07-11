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

export type GuardedEditDependencies = InterceptDependencies

const CREDENTIAL_FILE_NAMES = [".env", ".npmrc", ".pypirc", ".git-credentials", "auth.json"] as const
const CREDENTIAL_DIRECTORY_NAMES = [".aws", ".ssh", ".config/gcloud"] as const

type CanonicalEditTarget = {
  readonly canonicalRoot: string
  readonly canonicalPath: string
}

const sha256Text = (value: string): string =>
  createHash("sha256").update(value, "utf8").digest("hex")

const scrubSensitiveText = (value: string): string =>
  value
    .replaceAll(/ghp_[A-Za-z0-9]+/g, "[REDACTED_GITHUB_TOKEN]")
    .replaceAll(/SECRET=[^\s]+/g, "SECRET=[REDACTED]")
    .replaceAll(/AWS_[A-Z_]+=([^\s]+)/g, () => "AWS_[REDACTED]=[REDACTED]")

const assertWithinWorkspaceRoot = (canonicalRoot: string, canonicalPath: string): void => {
  const relativePath = path.relative(canonicalRoot, canonicalPath)
  if (relativePath.startsWith("..") || path.isAbsolute(relativePath)) {
    throw new GuardedAccessDenied("canonicalization_failed")
  }
}

const canonicalizeEditTarget = (workspaceRoot: string, cwd: string, userInputPath: string): CanonicalEditTarget => {
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
    normalizedPath.includes(`/${directoryName}/`),
  )
}

const toWorkspaceLogicalPath = (canonicalRoot: string, canonicalPath: string): string => {
  const relativePath = path.relative(canonicalRoot, canonicalPath)
  return `/workspace/${relativePath.replaceAll("\\", "/")}`
}

const buildDiffPreview = (beforeContent: string, afterContent: string): string =>
  [
    "--- before",
    "+++ after",
    `- ${scrubSensitiveText(beforeContent)}`,
    `+ ${scrubSensitiveText(afterContent)}`,
  ].join("\n").slice(0, 200)

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
  beforeContent: string,
  afterContent: string,
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
    stdout_hash: sha256Text(afterContent),
    stderr_hash: sha256Text(beforeContent),
    redacted_preview: buildDiffPreview(beforeContent, afterContent),
  },
})

const reverifyEditableTarget = (
  target: CanonicalEditTarget,
  cwd: string,
  userInputPath: string,
  expectedBeforeHash: string,
): { readonly verifiedPath: string; readonly currentContent: string } => {
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

  const currentContent = fs.readFileSync(verifiedPath, "utf8")
  if (sha256Text(currentContent) !== expectedBeforeHash) {
    throw new GuardedAccessDenied("concurrent_modification")
  }

  return { verifiedPath, currentContent }
}

export const guardedEdit = async (
  dependencies: GuardedEditDependencies,
  userInputPath: string,
  nextContent: string,
): Promise<void> => {
  const target = canonicalizeEditTarget(
    dependencies.workspaceRoot,
    dependencies.session.cwd,
    userInputPath,
  )
  const beforeContent = fs.readFileSync(target.canonicalPath, "utf8")
  const beforeHash = sha256Text(beforeContent)
  const logicalPath = toWorkspaceLogicalPath(target.canonicalRoot, target.canonicalPath)
  const requestId = createRequestId(dependencies)
  const credentialAccess = isCredentialPath(target.canonicalPath)
  const interceptDecision = await postInterceptDecision(
    dependencies,
    {
      requestId,
      tool: {
        kind: "file",
        name: "guarded_edit",
        operation: "EditFile",
      },
      resource: {
        id: logicalPath,
        kind: "file",
        path: logicalPath,
      },
      action: {
        operation: "EditFile",
        args: {
          path: logicalPath,
          before_bytes: Buffer.byteLength(beforeContent, "utf8"),
          after_bytes: Buffer.byteLength(nextContent, "utf8"),
        },
      },
      normalized: {
        verb: "edit",
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
      const { verifiedPath, currentContent } = reverifyEditableTarget(
        target,
        dependencies.session.cwd,
        userInputPath,
        beforeHash,
      )
      await fs.promises.writeFile(verifiedPath, nextContent, "utf8")
      const finishedAt = nowIso()

      await postToolResult(
        dependencies,
        createExecutedToolResultPayload(
          requestId,
          interceptDecision.decision_id,
          interceptDecision.decision_token,
          currentContent,
          nextContent,
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

export const createGuardedEdit = (dependencies: GuardedEditDependencies) => {
  return async (userInputPath: string, nextContent: string): Promise<void> =>
    guardedEdit(dependencies, userInputPath, nextContent)
}
