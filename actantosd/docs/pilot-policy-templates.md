# Pilot Policy Templates

Starter set for Design Partner pilots. Load through the policy-bundle surface and pair with risk rules where **Approval** is more appropriate than a hard deny.

Cedar answers **permit / forbid**. ActantOS combines Cedar with risk rules, budgets, kill switch, and Approval state into a **Decision**: `allow` | `deny` | `approval_required`.

## Design Partner postures

| Posture | Role | Cedar starting point | Risk rules |
| --- | --- | --- | --- |
| **Balanced Coding Policy** | **Default** for Pilot #1 (coding / Pi) | `dev-coding-agent.cedar` | Default `policies/risk_rules.json` (push, publish, network, docker, destructive, …) |
| **Strict Coding Policy** | **Opt-in** for high-friction teams | `workspace-readonly-approval-shell.cedar` | Same risk rules; fewer auto-allows because writes are not broadly permitted |

### Balanced Coding Policy (default)

| Action class | Decision intent |
| --- | --- |
| Read workspace source | `allow` |
| Write/edit workspace code | `allow` |
| Read `.env` / keys / credential paths | `deny` (`credential_access` never routes to Approval) |
| Tests / build / local non-push git | `allow` (when not matched by high-risk rules) |
| `git push` / remote side effects | `approval_required` |
| `npm publish` / deploy-class | `approval_required` |
| curl/wget / docker / sudo / destructive delete | `approval_required` or critical risk |
| Mutating MCP tools (if MCP used) | `approval_required` |

### Strict Coding Policy (opt-in)

- Same credential **deny**  
- Workspace **read/list/search** permitted; shell available but expected to pair with Approvals  
- Prefer this when the partner wants friction over speed  

MCP templates remain available; MCP is **optional** for Design Partner Pilot success (**Pi Primary Path** is pilot-gating).

## Included templates

- [`policies/templates/dev-coding-agent.cedar`](../policies/templates/dev-coding-agent.cedar) — Balanced starting Cedar  
- [`policies/templates/workspace-readonly-approval-shell.cedar`](../policies/templates/workspace-readonly-approval-shell.cedar) — Strict starting Cedar  
- [`policies/templates/github-approval-base.cedar`](../policies/templates/github-approval-base.cedar) — GitHub-oriented permit baseline  
- [`policies/templates/mcp-readonly.cedar`](../policies/templates/mcp-readonly.cedar) — MCP Optional Path read-only  
- [`policies/templates/http-readonly.cedar`](../policies/templates/http-readonly.cedar) — HTTP read-only  

## When to use each one

`dev-coding-agent.cedar`

- **default** Balanced coding pilot  
- permits when `credential_access == false`  
- pair with default risk rules for push/publish/network Approvals  

`workspace-readonly-approval-shell.cedar`

- **Strict** opt-in  
- read/list/search + shell action shape; tighten further with risk rules  

`github-approval-base.cedar`

- GitHub or shell release actions in scope  
- credential guard + risk rules for `git push`  

`mcp-readonly.cedar`

- documentation / read-only MCP assistants (optional path)  

`http-readonly.cedar`

- retrieval-only HTTP agents  

## Loading Balanced (recommended first command)

```bash
# 1) Ensure default risk rules are loaded for the tenant (demo seed or PUT /v1/risk-rules)
# 2) Activate Balanced Cedar from the template file contents:

curl -X POST http://localhost:3100/v1/policy-bundles \
  -H "content-type: application/json" \
  -H "x-actantos-api-key: $ACTANTOS_API_KEY" \
  -d @- <<'JSON'
{
  "tenant_id": "t_demo",
  "version": "1.0.0-balanced-coding",
  "engine": "cedar",
  "source_text": "permit (\n  principal,\n  action,\n  resource\n)\nwhen {\n  resource.credential_access == false\n};",
  "active": true
}
JSON
```

For Strict, use the `workspace-readonly-approval-shell.cedar` source and version tag `1.0.0-strict-coding`.

## Risk-rule pairing (Balanced side effects)

Approval flows belong in **risk rules**, not only in Cedar. Default file: [`policies/risk_rules.json`](../policies/risk_rules.json).

| Rule intent | Example rule_id |
| --- | --- |
| git push | `risk.shell.git_push` |
| npm publish | `risk.shell.npm_publish` |
| curl / wget | `risk.shell.curl_wget`, `risk.shell.wget` |
| docker | `risk.shell.docker` |
| sudo | `risk.shell.sudo` |
| destructive recursive delete | `risk.shell.destructive_delete` |
| ambiguous shell | `risk.shell.ambiguous` |
| MCP mutation (optional path) | `risk.mcp.mutation` |

Example shape:

```json
{
  "rule_id": "risk.shell.git_push",
  "description": "Require approval for any git push operation",
  "when": {
    "tool.kind": "shell",
    "normalized.command_family": "git",
    "normalized.subcommand": "push"
  },
  "approval_required": true,
  "risk_class": "high"
}
```

## Verify posture

```bash
npm run policy:regression
npm run demo -- --url http://localhost:3100
```

Expect: safe allow, credential deny, git push `approval_required`. That locks the Balanced Pilot Workflow seam used in Design Partner success.
