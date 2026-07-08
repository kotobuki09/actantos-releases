# MCP Gateway Stable Client Guide

This document freezes the supported client-facing integration pattern for the production MCP gateway.

## Required environment

```bash
ACTANTOS_MCP_UPSTREAM_URL=http://localhost:8080/sse
ACTANTOS_MCP_SERVER_ID=upstream-mcp
```

The gateway exposes:

- `GET /v1/mcp/sse`
- `POST /v1/mcp/message`

## Stable behavior

- `tools/list` is filtered through ActantOS policy evaluation before the client sees tools
- `tools/call` is intercepted before upstream execution
- denied MCP calls are recorded as blocked tool results
- allowed MCP calls record execution results back into the standard audit chain
- manifest drift is surfaced through `/v1/mcp/tool-versions/pending`

## Example: upstream MCP server behind ActantOS

Point the client at ActantOS, not at the upstream server:

```text
Client -> ActantOS /v1/mcp/sse -> upstream MCP SSE endpoint
```

## Example: generic MCP client configuration

```json
{
  "name": "actantos-gateway",
  "transport": {
    "type": "sse",
    "url": "http://localhost:3100/v1/mcp/sse"
  }
}
```

## Operator review loop

When tool metadata drifts:

1. inspect `GET /v1/mcp/tool-versions/pending?tenant_id=...`
2. review the upstream change
3. approve with `POST /v1/mcp/tool-versions/:id/approve`

## Verification commands

```bash
npm test -- --test src/mcp-gateway.test.ts
curl http://localhost:3100/v1/mcp/tool-versions/pending?tenant_id=t_demo
```
