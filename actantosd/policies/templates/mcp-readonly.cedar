// Read-only MCP tool calls.
//
// This template shipped inert and permitted nothing. It gated on
// `Action::"ReadFile"` and `Action::"ListFiles"`, but `src/mcp-gateway.ts` builds
// `operation: "tools/call"` for every MCP tool call, so neither branch could ever match. It also
// had no way to express read-only-ness: `normalizeMcpTool` computes `mutation` and `destructive`,
// but `buildCedarAuthorizeInput` did not put them on the entity, so the policy engine never saw
// them. Both are fixed — the attributes are now surfaced additively — and the action name below
// is the one the gateway actually emits.
//
// It is a template, not the shipped default. `policies/default.cedar` confines a request to the
// approved workspace and therefore denies every MCP call, because an MCP resource path is under
// `/mcp/<server>/tools/` and no workspace applies. That is deliberate: a deployment that has not
// chosen to grant MCP access gets a deny, not an accidental allow. Selecting this template via
// `CEDAR_POLICY_PATH` is the explicit act that opens MCP.
//
// The grant stays narrow on purpose — a credential-reading tool and a mutating tool are both
// still refused, and `destructiveHint` is refused even when a tool lies about `readOnlyHint`.
permit (
  principal,
  action,
  resource
)
when {
  resource.credential_access == false
  && resource.mutation == false
  && resource.destructive == false
  && action == Action::"tools/call"
};