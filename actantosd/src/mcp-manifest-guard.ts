import { randomUUID } from "node:crypto"

import type { ToolCallInterceptionRequest } from "./contracts.ts"
import type { Database } from "./database.ts"

export type McpManifestGuardResult =
  | { readonly allowed: true }
  | {
      readonly allowed: false
      readonly reason: string
      readonly reasonCode: "manifest_drift" | "schema_hash_mismatch"
    }

export interface McpManifestGuard {
  evaluate(request: ToolCallInterceptionRequest): Promise<McpManifestGuardResult>
}

type McpServerRow = {
  readonly id: string
  readonly server_identity_hash: string
  readonly status: string
}

type McpToolVersionRow = {
  readonly id: string
  readonly schema_hash: string
  readonly description_hash: string
}

export class AllowAllMcpManifestGuard implements McpManifestGuard {
  async evaluate(): Promise<McpManifestGuardResult> {
    return { allowed: true }
  }
}

const buildManifestJson = (request: ToolCallInterceptionRequest): string =>
  JSON.stringify({
    tool: request.tool,
    action: request.action,
    resource: request.resource,
    normalized: request.normalized,
    mcp: request.mcp,
  })

const isMcpRequest = (
  request: ToolCallInterceptionRequest,
): request is ToolCallInterceptionRequest & {
  readonly tool: ToolCallInterceptionRequest["tool"] & { readonly kind: "mcp" }
  readonly mcp: NonNullable<ToolCallInterceptionRequest["mcp"]>
} => request.tool.kind === "mcp" && request.mcp !== undefined

export class PostgresMcpManifestGuard implements McpManifestGuard {
  readonly #database: Database

  constructor(database: Database) {
    this.#database = database
  }

  async evaluate(
    request: ToolCallInterceptionRequest,
  ): Promise<McpManifestGuardResult> {
    if (!isMcpRequest(request)) {
      return { allowed: true }
    }

    return this.#database.transaction(async (client) => {
      const serverRows = await client.query<McpServerRow>(
        `
          SELECT id, server_identity_hash, status
          FROM mcp_servers
          WHERE tenant_id = $1 AND name = $2
          FOR UPDATE
        `,
        [request.tenant_id, request.mcp.server_id],
      )

      const existingServer = serverRows[0]
      const serverId = existingServer?.id ?? randomUUID()

      if (existingServer === undefined) {
        await client.query(
          `
            INSERT INTO mcp_servers (
              id, tenant_id, name, transport, upstream_url, server_identity_hash, status
            ) VALUES ($1, $2, $3, $4, NULL, $5, 'active')
          `,
          [
            serverId,
            request.tenant_id,
            request.mcp.server_id,
            request.mcp.transport ?? "sse",
            request.mcp.server_identity_hash ?? "",
          ],
        )
      } else {
        if (existingServer.status !== "active") {
          return {
            allowed: false,
            reason: "MCP server is not active",
            reasonCode: "manifest_drift",
          }
        }

        if (
          request.mcp.server_identity_hash !== undefined &&
          existingServer.server_identity_hash !== request.mcp.server_identity_hash
        ) {
          return {
            allowed: false,
            reason: "MCP server identity changed since approval",
            reasonCode: "manifest_drift",
          }
        }
      }

      const approvedVersions = await client.query<McpToolVersionRow>(
        `
          SELECT id, schema_hash, description_hash
          FROM mcp_tool_versions
          WHERE server_id = $1 AND tool_name = $2 AND approved = true
          ORDER BY created_at DESC
          LIMIT 1
        `,
        [serverId, request.mcp.tool_name],
      )

      const approvedVersion = approvedVersions[0]

      if (approvedVersion === undefined) {
        await client.query(
          `
            INSERT INTO mcp_tool_versions (
              id, server_id, tool_name, schema_hash, description_hash, manifest_json, approved
            ) VALUES ($1, $2, $3, $4, $5, $6::jsonb, true)
          `,
          [
            randomUUID(),
            serverId,
            request.mcp.tool_name,
            request.mcp.tool_schema_hash,
            request.mcp.tool_description_hash,
            buildManifestJson(request),
          ],
        )

        return { allowed: true }
      }

      if (
        approvedVersion.schema_hash === request.mcp.tool_schema_hash &&
        approvedVersion.description_hash === request.mcp.tool_description_hash
      ) {
        return { allowed: true }
      }

      const existingDriftRows = await client.query<McpToolVersionRow>(
        `
          SELECT id, schema_hash, description_hash
          FROM mcp_tool_versions
          WHERE server_id = $1
            AND tool_name = $2
            AND schema_hash = $3
            AND description_hash = $4
          LIMIT 1
        `,
        [
          serverId,
          request.mcp.tool_name,
          request.mcp.tool_schema_hash,
          request.mcp.tool_description_hash,
        ],
      )

      if (existingDriftRows[0] === undefined) {
        await client.query(
          `
            INSERT INTO mcp_tool_versions (
              id, server_id, tool_name, schema_hash, description_hash, manifest_json, approved
            ) VALUES ($1, $2, $3, $4, $5, $6::jsonb, false)
          `,
          [
            randomUUID(),
            serverId,
            request.mcp.tool_name,
            request.mcp.tool_schema_hash,
            request.mcp.tool_description_hash,
            buildManifestJson(request),
          ],
        )
      }

      if (approvedVersion.schema_hash !== request.mcp.tool_schema_hash) {
        return {
          allowed: false,
          reason: "MCP tool schema changed since approval",
          reasonCode: "schema_hash_mismatch",
        }
      }

      return {
        allowed: false,
        reason: "MCP tool manifest drift detected",
        reasonCode: "manifest_drift",
      }
    })
  }
}
