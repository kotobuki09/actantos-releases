import { dirname } from "node:path"

import { canonicalHash } from "./hash.ts"

/**
 * Digest of the concrete command an executor is about to run (invariants S7, S8).
 *
 * The decision token binds *who* asked, *which tool*, and the execution envelope
 * (`constraints_hash`). Until this digest existed it did not bind *what* to run:
 * a token minted for `printf hello` was accepted for `rm -rf /workspace`, because
 * nothing in the token described the command. The server compared the envelope and
 * the identifiers, and the argv passed straight through to `docker run`.
 *
 * Binding the argv is what makes S8 true here. Swapping any element, reordering them,
 * or changing the mounted workspace produces a different digest, so the token no longer
 * describes the action and verification fails closed.
 *
 * The workspace is included because the volume mount decides which host paths the
 * container can reach. A digest over the argv alone would still permit remounting a
 * different host directory under the same command.
 *
 * This is deliberately *not* a new policy language. It is a digest over data the
 * server already has, using the same `canonicalHash` the rest of the control plane uses.
 */
export const canonicalCommandHash = (
  argv: readonly string[],
  workspacePath: string,
): string =>
  canonicalHash({
    // Order is significant: `["rm", "-rf", "x"]` and `["rm", "-x", "-rf"]` are different.
    argv: [...argv],
    workspace_path: workspacePath,
  })

/**
 * Pull the command out of an interception request so the token is minted from the same
 * request the policy engine evaluated, rather than from a value passed alongside it.
 *
 * `host_workspace_path` is declared by the caller because only the caller knows the host
 * directory it will mount. See the limitation noted in `PHASE_REPORT.md`: binding it stops
 * the executed command from diverging from the authorized one, but the policy engine does
 * not evaluate that host path, so this is a consistency control and not a policy input.
 */
export const commandFromRequest = (request: {
  readonly action?: { readonly args?: Record<string, unknown> | undefined } | undefined
  readonly resource?: { readonly path?: string | undefined } | undefined
}): { readonly argv: readonly string[]; readonly workspacePath: string } => {
  const args = request.action?.args
  const rawArgv = args?.["argv"]
  const argv = Array.isArray(rawArgv) && rawArgv.every((entry) => typeof entry === "string")
    ? (rawArgv as readonly string[])
    : []
  const rawWorkspace = args?.["host_workspace_path"]
  const resourcePath = typeof request.resource?.path === "string" ? request.resource.path : ""
  // An undeclared workspace falls back to the directory holding the resource, not the resource
  // path itself. A file is not a directory, so `/workspace/README.md` is not a workspace — and a
  // policy comparing the workspace against an approved root would otherwise refuse every ordinary
  // file request. An empty resource path stays empty rather than becoming `.`.
  const workspacePath = typeof rawWorkspace === "string"
    ? rawWorkspace
    : resourcePath.length > 0
      ? dirname(resourcePath)
      : ""
  return { argv, workspacePath }
}
