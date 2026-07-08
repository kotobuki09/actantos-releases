import * as fs from "node:fs"
import * as path from "node:path"
import * as crypto from "node:crypto"

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

export class GuardedAccessDenied extends Error {
  readonly reason_code: string
  readonly reason: string

  constructor(
    reason_code: string,
    reason: string,
  ) {
    super(`Access denied [${reason_code}]: ${reason}`)
    this.name = "GuardedAccessDenied"
    this.reason_code = reason_code
    this.reason = reason
  }
}

export class ApprovalRequired extends Error {
  readonly approval_id: string
  readonly expires_at: string

  constructor(
    approval_id: string,
    expires_at: string,
  ) {
    super(`Approval required: approval_id=${approval_id}`)
    this.name = "ApprovalRequired"
    this.approval_id = approval_id
    this.expires_at = expires_at
  }
}

// ---------------------------------------------------------------------------
// Credential path patterns (Rule 8: always deny, never approval_required)
// ---------------------------------------------------------------------------

const CREDENTIAL_PATH_PATTERNS = [
  /\.env(\.|$)/i,
  /\/\.ssh\//,
  /auth\.json/i,
  /\/\.aws\//,
  /\/\.npmrc/,
  /\/\.netrc/,
  /\/\.pgpass/,
  /\/\.gnupg\//,
  /\/id_rsa/,
  /\/id_ed25519/,
  /\/id_dsa/,
  /credentials\.json/i,
  /secrets?\.(json|yaml|yml|env)/i,
  /token(s)?\.(json|txt)/i,
]

export const isCredentialPath = (canonicalPath: string): boolean =>
  CREDENTIAL_PATH_PATTERNS.some((pattern) => pattern.test(canonicalPath))

// ---------------------------------------------------------------------------
// Path canonicalization (Rules 1-7 from spec §13)
// ---------------------------------------------------------------------------

export type CanonicalizationResult =
  | { readonly ok: true; readonly path: string }
  | { readonly ok: false; readonly reason: string }

/**
 * Canonicalize a file path for read operations (file must exist).
 * Returns the canonical path or a denial reason.
 */
export const canonicalizeReadPath = (
  userInput: string,
  cwd: string,
  workspaceRoot: string,
): CanonicalizationResult => {
  // Rule 1: Resolve absolute path
  const resolved = path.resolve(cwd, userInput)

  // Rule 2: Resolve all symlinks (file must exist for reads)
  let canonical: string
  try {
    canonical = fs.realpathSync(resolved)
  } catch {
    // Dangling symlink, missing file, or permission error → deny
    return { ok: false, reason: "path does not exist or cannot be resolved" }
  }

  // Rule 3: Separator-safe prefix check
  const rel = path.relative(workspaceRoot, canonical)
  if (rel.startsWith("..") || path.isAbsolute(rel)) {
    return { ok: false, reason: "path is outside workspace root" }
  }

  return { ok: true, path: canonical }
}

// ---------------------------------------------------------------------------
// ActantOS decision client
// ---------------------------------------------------------------------------

export type GuardedReadConfig = {
  readonly actantosUrl: string
  readonly tenantId: string
  readonly agentId: string
  readonly userId: string
  readonly sessionId: string
  readonly workspaceRoot: string
  readonly hmacSecret?: string
}

type InterceptionResponse = {
  readonly decision: "allow" | "deny" | "approval_required"
  readonly decision_mode: string
  readonly reason: string
  readonly reason_code: string
  readonly audit_event_id: string
  readonly decision_token?: string
  readonly approval?: {
    readonly approval_id: string
    readonly status: string
    readonly expires_at: string
  }
}

const callActantOS = async (
  url: string,
  body: unknown,
): Promise<InterceptionResponse> => {
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  })

  if (!response.ok) {
    const text = await response.text()
    throw new Error(`ActantOS returned ${response.status}: ${text}`)
  }

  return response.json() as Promise<InterceptionResponse>
}

// ---------------------------------------------------------------------------
// guarded_read
// ---------------------------------------------------------------------------

export const guardedRead = async (
  userPath: string,
  config: GuardedReadConfig,
  cwd?: string,
): Promise<string> => {
  const workingDir = cwd ?? config.workspaceRoot

  // Step 1: Canonicalize path (before decision)
  const canonResult = canonicalizeReadPath(
    userPath,
    workingDir,
    config.workspaceRoot,
  )

  if (!canonResult.ok) {
    // Still call ActantOS to log the denial, but use the original path in deny
    // We deny locally with canonicalization_failed
    throw new GuardedAccessDenied("canonicalization_failed", canonResult.reason)
  }

  const canonicalPath = canonResult.path

  // Step 2: Check credential_access
  const credentialAccess = isCredentialPath(canonicalPath)

  // Step 3: Build request ID (stable for idempotency per invocation)
  const requestId = `read_${crypto.randomBytes(8).toString("hex")}`

  // Step 4: Call ActantOS
  const interceptBody = {
    request_id: requestId,
    tenant_id: config.tenantId,
    agent: {
      id: config.agentId,
      runtime_type: "pi",
      environment: "dev",
      risk_tier: "low",
    },
    subject: {
      user_id: config.userId,
      role: "developer",
    },
    session: {
      id: config.sessionId,
      cwd: workingDir,
      budget_remaining_cents: 10_000,
    },
    tool: {
      kind: "file",
      name: "guarded_read",
      operation: "ReadFile",
      schema_hash: "",
    },
    resource: {
      id: canonicalPath,
      kind: "file",
      path: canonicalPath,
    },
    action: {
      operation: "ReadFile",
      args: { path: canonicalPath },
    },
    normalized: {
      verb: "read",
      mutation: false,
      destructive: false,
      network: false,
      credential_access: credentialAccess,
      risk_class: credentialAccess ? "critical" : "low",
    },
  }

  const response = await callActantOS(
    `${config.actantosUrl}/v1/intercept/tool-call`,
    interceptBody,
  )

  if (response.decision === "deny") {
    throw new GuardedAccessDenied(
      response.reason_code,
      response.reason,
    )
  }

  if (response.decision === "approval_required") {
    throw new ApprovalRequired(
      response.approval!.approval_id,
      response.approval!.expires_at,
    )
  }

  // Decision is allow — re-verify canonical path before reading (TOCTOU)
  let verifiedPath: string
  try {
    verifiedPath = fs.realpathSync(canonicalPath)
  } catch {
    throw new GuardedAccessDenied("canonicalization_failed", "path no longer accessible at execution time")
  }

  if (verifiedPath !== canonicalPath) {
    throw new GuardedAccessDenied("canonicalization_failed", "path changed between decision and execution (TOCTOU)")
  }

  // Execute: read file
  const content = fs.readFileSync(verifiedPath, "utf8")
  return content
}
