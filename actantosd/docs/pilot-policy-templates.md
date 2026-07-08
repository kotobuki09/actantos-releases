# Pilot Policy Templates

These templates are the Milestone 6 starter set for common pilot shapes. They are meant to be loaded through the policy-bundle surface and paired with risk rules where approval is more appropriate than a hard deny.

## Included templates

- [`policies/templates/dev-coding-agent.cedar`](../policies/templates/dev-coding-agent.cedar)
- [`policies/templates/mcp-readonly.cedar`](../policies/templates/mcp-readonly.cedar)
- [`policies/templates/github-approval-base.cedar`](../policies/templates/github-approval-base.cedar)
- [`policies/templates/http-readonly.cedar`](../policies/templates/http-readonly.cedar)
- [`policies/templates/workspace-readonly-approval-shell.cedar`](../policies/templates/workspace-readonly-approval-shell.cedar)

## When to use each one

`dev-coding-agent.cedar`

- good default for internal coding-agent pilots
- allows ordinary reads and non-secret file operations
- still blocks direct credential access

`mcp-readonly.cedar`

- good fit for documentation or read-only knowledge assistants
- permits read/list style actions only
- denies write-style operations through the Cedar layer instead of relying only on downstream normalization

`github-approval-base.cedar`

- good starting point when GitHub or shell-based release actions are in scope
- keeps the default credential guard
- expects risk rules to mark `git push` or equivalent mutations as `approval_required`

`http-readonly.cedar`

- allows read-oriented HTTP fetches without enabling write-oriented network actions
- useful for documentation fetchers or retrieval-only web agents

`workspace-readonly-approval-shell.cedar`

- allows repository reads and discovery commands while leaving shell execution available to pair with approval-driven risk rules
- useful for coding-agent pilots that need fast inspection but human review on command execution

## Loading a template

Example:

```bash
curl -X POST http://localhost:3100/v1/policy-bundles \
  -H "content-type: application/json" \
  -H "x-actantos-api-key: $ACTANTOS_API_KEY" \
  -d @- <<'JSON'
{
  "tenant_id": "t_demo",
  "version": "0.7.0-template-dev-coding",
  "engine": "cedar",
  "source_text": "permit ( principal, action, resource ) when { resource.credential_access == false };",
  "active": false
}
JSON
```

## Pairing with risk rules

Approval flows belong in risk rules, not in Cedar. For a GitHub-style template, pair the Cedar bundle with a rule like:

```json
{
  "rule_id": "risk.shell.git_push.approval",
  "description": "Require approval for git push commands",
  "when": {
    "normalized.command_family": "git",
    "normalized.subcommand": "push"
  },
  "approval_required": true,
  "risk_class": "high"
}
```
