Below is the stronger research-backed build plan for **ActantOS**.

# 1. Executive summary

**ActantOS should be built as an in-path runtime enforcement layer for AI agents, not as another agent, chatbot, orchestration framework, or model wrapper.** The core product should answer one question before every agent action: **is this agent allowed to do this action on this resource in this context right now?**

The market is moving toward exactly this category. Forrester describes the emerging **agent control plane** as a third plane beside agent build and orchestration, responsible for inventory, identity, policy, guardrails, governance, and assurance across heterogeneous agents. It also argues that governance needs to sit outside build/orchestration runtimes so it can provide independent visibility, policy, and intervention across unpredictable agent behavior. ([Forrester][1])

The strategic white space for ActantOS is **runtime tool-call enforcement**: lightweight, developer-first, model-agnostic, policy-as-code enforcement for files, shell commands, APIs, SaaS tools, GitHub, databases, MCP servers, and custom tools. Credo AI is stronger in governance workflows; Okta and AppViewX focus on identity/security lifecycle; Cloudflare and Kong-style gateways focus on MCP/API/LLM gateway infrastructure; Microsoft is building a broad enterprise control plane. ActantOS should win by being the **open, practical enforcement kernel that developers can insert into any agent runtime**. ([Credo AI][2])

The first wedge should be **Pi + MCP**:

Pi is a good first harness because it is intentionally small, model-agnostic, and already exposes an agent runtime with tools. Pi’s own documentation says it does **not** include a built-in permission system for restricting filesystem, process, network, or credential access; by default, it runs with the permissions of the user/process. ([GitHub][3])

MCP is the bigger opportunity because MCP is becoming the standard interface between agents and tools, but the MCP specification itself says the protocol cannot enforce consent, authorization, and access controls by itself; implementers must build those controls. ([Model Context Protocol][4])

The MVP should be deliberately narrow:

**Build this first:** allow / deny / approval_required, deterministic policy engine, Pi adapter, MCP proxy, Slack approval, audit logs, rate limits, Docker sandbox, and kill switch.

**Do not build yet:** LLM-as-judge authorization, advanced DLP, vector memory governance, quantum-safe crypto, compliance packs, complex multi-cloud deployment, or full enterprise identity broker.

# 2. Corrected product positioning

## Best positioning

**ActantOS is a model-agnostic Agent Runtime Control Plane that enforces policy before AI agents touch tools, APIs, files, databases, SaaS systems, shell commands, or MCP servers.**

## Stronger short tagline

**Govern every agent action before it executes.**

## Avoid this positioning

Do not lead with:

“Agent OS”
“AI governance dashboard”
“Agent monitoring platform”
“Enterprise chatbot security”
“Model gateway”
“AI agent framework”

Those are either too vague, too crowded, or imply ActantOS is building agents instead of controlling them.

## Better category language

Use three layers:

| Layer                   | What it means                             |
| ----------------------- | ----------------------------------------- |
| **MVP category**        | Agent Permission Gateway                  |
| **Product category**    | Agent Runtime Control Plane               |
| **Long-term narrative** | Agent OS for governed enterprise autonomy |

The week-one product is not truly an OS yet. It becomes closer to an “Agent OS” only after it has agent identity, runtime session control, tool routing, sandboxing, approvals, durable audit, policy bundles, and cross-runtime adapters.

# 3. Market map and competitor table

## Market map

| Category                             | Examples                                                             | What they do                                                          | Gap ActantOS can attack                                                                         |
| ------------------------------------ | -------------------------------------------------------------------- | --------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| AI governance / compliance platforms | Credo AI                                                             | Policies, governance workflows, risk management, AI inventory         | Often not the hard in-path enforcement layer for every tool call                                |
| Identity for AI agents               | Okta AI Agents, AppViewX Agent Identity Security, Astrix             | Agent identities, lifecycle, credentials, revocation, least privilege | Identity is necessary but not enough; runtime tool-call authorization still needed              |
| Enterprise agent control planes      | Microsoft Agent 365                                                  | Registry, lifecycle, governance, Microsoft ecosystem integration      | Strong inside Microsoft stack; less developer-first and open-runtime focused                    |
| MCP / API / AI gateways              | Cloudflare MCP Server Portal, Kong/Noma, agentgateway-style projects | Centralize MCP/API/LLM traffic, logs, DLP, access policies            | Need deeper agent-session-aware policy, approvals, sandboxing, and deterministic action control |
| AI security gateways                 | NeuralTrust, Lakera-style vendors, API firewalls                     | Prompt injection, model/API protection, traffic monitoring            | Many focus on prompts/model calls, not file/shell/SaaS/MCP action execution                     |
| Agent frameworks                     | Pi, LangGraph, AutoGen, CrewAI, custom agents                        | Build/run agents                                                      | Usually not enterprise permission control planes                                                |

Forrester’s 2026 framing is important: it argues agent control planes are emerging because enterprises will have heterogeneous agent estates across different vendors, tools, and orchestration systems. It also notes current gaps around instrumentation standards, portable agent identity, policy propagation, cross-plane governance schemas, and capability manifests. ([Forrester][5])

## Competitor table

| Vendor / project                           |                                            Current positioning |              Runtime enforcement strength | Notes for ActantOS                                                                                                                                                                                                                                                                                    |
| ------------------------------------------ | -------------------------------------------------------------: | ----------------------------------------: | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Credo AI**                               |                        Agentic AI governance, risk, compliance |                         Medium / emerging | Credo’s GAIA release is governance-forward, and its own roadmap describes runtime governance and point-of-use policy enforcement as the next layer. ActantOS should not copy compliance workflows first; it should start with enforcement. ([Credo AI][2])                                            |
| **Okta for AI Agents**                     | Agent identity, lifecycle, least privilege, kill switch, audit |           Strong identity; medium runtime | Okta is pushing “single control plane” language for discovering, onboarding, protecting, and governing agents, including short-lived credentials, audit trails, revocation, and MCP coverage. ActantOS should integrate with Okta later, not compete directly on identity infrastructure. ([Okta][6]) |
| **AppViewX Agent Identity Security**       |            PKI-backed agent identity and certificate lifecycle | Strong machine identity; narrower runtime | AppViewX frames agent identity security around PKI, discovery, governance, security, and monitoring. ActantOS can use this category as validation but avoid early PKI/quantum-safe scope. ([AppViewX][7])                                                                                             |
| **NeuralTrust**                            |                                  Discover and secure AI agents |                                    Medium | NeuralTrust markets centralized discovery and security for AI agents. ActantOS needs clearer differentiation: deterministic pre-execution control, not just discovery/security posture. ([NeuralTrust][8])                                                                                            |
| **Microsoft Agent Governance Toolkit**     |                Open-source runtime security governance toolkit |                 Strong conceptual overlap | Microsoft’s toolkit emphasizes deterministic, sub-millisecond policy enforcement and framework compatibility. This validates ActantOS’s deterministic approach, but ActantOS needs stronger Pi/MCP developer wedge and productized control plane. ([Microsoft Open Source][9])                        |
| **Microsoft Agent 365**                    |                            Enterprise control plane for agents |            Strong enterprise distribution | Microsoft Agent 365 provides centralized registry, access control, identity, usage insights, and governance across agents. It is listed at $15/user/month annually, making it an important pricing and positioning anchor. ([Microsoft][10])                                                          |
| **Cloudflare MCP Server Portal / Gateway** |          MCP discovery, access, logging, DLP, gateway policies |                        Strong MCP gateway | Cloudflare already centralizes MCP server access, policies, DLP, logs, and identity. ActantOS should differentiate with runtime decision APIs, agent/session context, local Pi adapter, and open policy-as-code. ([The Cloudflare Blog][11])                                                          |
| **Kong + Noma / AI gateway vendors**       |                              API gateway + AI runtime security |    Strong gateway; variable agent control | Kong’s Noma integration focuses on consistent security policies, threat detection, runtime inspection, behavioral analysis, and centralized controls. ActantOS should be narrower and faster: tool-call enforcement for agents. ([Kong Inc.][12])                                                     |
| **Astrix AI Agent Control Plane**          |     Discover, secure, deploy AI agents with scoped credentials |            Strong identity/security angle | Astrix claims short-lived scoped credentials and just-in-time access for AI agents. ActantOS should focus on developer-first open runtime enforcement and MCP/Pi adapters. ([Astrix Security][13])                                                                                                    |

## White space

ActantOS should own:

**“The open runtime permission layer for AI agent actions.”**

That means:

* Not only inventory.
* Not only identity.
* Not only model gateway.
* Not only compliance workflow.
* Not only prompt security.
* Not only MCP discovery.

The strongest wedge is:

**Every tool call becomes a policy decision, an approval opportunity, a sandboxed execution, and an audit event.**

# 4. Technical architecture diagram

```text
                         ┌──────────────────────────────┐
                         │        ActantOS UI/API        │
                         │ Dashboard | Policies | Audit  │
                         │ Approvals | Kill Switch       │
                         └──────────────┬───────────────┘
                                        │
                                        ▼
┌────────────────────────────────────────────────────────────────┐
│                     ActantOS Control Plane                     │
│                                                                │
│  ┌─────────────┐  ┌─────────────┐  ┌────────────────────────┐ │
│  │ Agent        │  │ Policy      │  │ Approval Service       │ │
│  │ Registry     │  │ Engine      │  │ Slack / Web / API      │ │
│  └─────────────┘  │ OPA/Rego     │  └────────────────────────┘ │
│                   │ or Cedar     │                             │
│  ┌─────────────┐  └─────────────┘  ┌────────────────────────┐ │
│  │ Budget &     │                  │ Audit / Evidence Store │ │
│  │ Rate Limits  │                  │ Postgres + Object Log   │ │
│  └─────────────┘                  └────────────────────────┘ │
│                                                                │
│  ┌─────────────┐  ┌─────────────┐  ┌────────────────────────┐ │
│  │ Kill Switch │  │ Credential   │  │ Resource Registry      │ │
│  │ Service     │  │ Broker v0    │  │ Files/APIs/MCP/Repos   │ │
│  └─────────────┘  └─────────────┘  └────────────────────────┘ │
└─────────────────────────────┬──────────────────────────────────┘
                              │ decision API
                              ▼
┌────────────────────────────────────────────────────────────────┐
│                      ActantOS Data Plane                       │
│                                                                │
│  ┌────────────────────┐         ┌────────────────────────────┐ │
│  │ Pi Adapter          │         │ MCP Gateway / Proxy        │ │
│  │ Guarded tools       │         │ tools/list, tools/call     │ │
│  │ read/write/edit     │         │ resources/read, prompts    │ │
│  │ bash/grep/find/ls   │         │ manifest pinning           │ │
│  └─────────┬──────────┘         └──────────┬─────────────────┘ │
│            │                               │                   │
│            ▼                               ▼                   │
│  ┌────────────────────┐         ┌────────────────────────────┐ │
│  │ Sandbox Executor    │         │ Upstream MCP Servers       │ │
│  │ Docker v0           │         │ GitHub, DB, SaaS, files    │ │
│  │ gVisor/Kata later   │         └────────────────────────────┘ │
│  └────────────────────┘                                         │
└────────────────────────────────────────────────────────────────┘
                              ▲
                              │
                ┌─────────────┴──────────────┐
                │ Agent Runtimes              │
                │ Pi first                    │
                │ LangGraph / AutoGen later   │
                │ Coding agents later         │
                │ Enterprise agents later     │
                └────────────────────────────┘
```

Core principle:

**ActantOS must be in-path for tool execution, out-of-process from the agent, and fail-closed.**

# 5. MVP feature list

Build only these:

| Feature              | MVP version                                                          |
| -------------------- | -------------------------------------------------------------------- |
| Agent registry       | `agent_id`, owner, environment, risk tier, runtime type              |
| Runtime decision API | `POST /v1/intercept/tool-call`                                       |
| Policy engine        | OPA/Rego first; Cedar-compatible model later                         |
| Decisions            | `allow`, `deny`, `approval_required`                                 |
| Pi adapter           | Guarded read/write/edit/bash/grep/find/ls wrappers                   |
| MCP gateway          | Proxy `tools/list` and `tools/call`; allowlist upstream servers      |
| Human approval       | Slack approval for high-risk actions                                 |
| Audit logs           | Postgres append-only event log                                       |
| Evidence records     | Store normalized input, decision, policy version, actor, result hash |
| Rate limits          | Per agent/session/tool/user                                          |
| Cost controls        | Tool-call budgets, shell timeout, output size limit                  |
| Kill switch          | Disable by tenant, agent, session, or tool                           |
| Sandbox              | Docker-based shell/file execution                                    |
| Dashboard            | Minimal session, decision, approval, audit viewer                    |
| CLI                  | Register agent, run Pi under ActantOS, inspect logs                  |

The MVP should be deterministic. No LLM should decide whether a tool call is authorized.

# 6. Features to delay

Delay these even if they sound attractive:

| Delay                             | Reason                                                              |
| --------------------------------- | ------------------------------------------------------------------- |
| LLM-as-judge authorization        | Non-deterministic; hard to defend in security review                |
| Advanced DLP                      | Expensive, noisy, and slows MVP                                     |
| Vector memory governance          | Important later, not needed for first runtime wedge                 |
| Quantum-safe crypto               | Useful long-term narrative, not MVP                                 |
| Compliance packs                  | Requires legal/compliance depth; add after audit model works        |
| Multi-cloud enterprise deployment | Too much infra for solo founder                                     |
| Full credential broker            | Start with credential references and scoped env allowlists          |
| Complex MCP semantic security     | Start with deterministic manifest hashing, allowlists, and approval |
| Agent marketplace                 | Premature                                                           |
| Workflow orchestration            | ActantOS should govern orchestrators, not become one yet            |

# 7. Pi integration plan

## What Pi gives you

Pi is a minimal agent harness with a CLI, core runtime, tool calling, state management, SDK, and multi-provider model support. Its docs describe modes such as interactive, print/JSON, RPC, and SDK usage, plus providers including Anthropic, OpenAI, Google, Azure, Bedrock, Mistral, Groq, Cerebras, xAI, Hugging Face, OpenRouter, and Ollama. ([GitHub][3])

Pi’s default built-in tools include read, bash, edit, write, grep, find, and ls. It also supports tool allowlists, disabling built-ins, custom tools, and SDK-level custom tool registration. ([GitHub][14])

Pi also has tool-call lifecycle types such as `BeforeToolCallResult`, with the ability to block a tool call before execution, and contexts containing the tool call and arguments. ([GitHub][15])

## Where Pi lacks controls

Pi’s documentation explicitly says it does **not** include a built-in permission system for restricting filesystem, process, network, or credential access, and that by default it runs with the permissions of the user/process. ([GitHub][3])

That is the opening for ActantOS.

## No-fork adapter strategy

Do **not** deeply fork Pi.

Use this order:

1. **Disable or restrict Pi built-in tools.**
2. **Register ActantOS guarded replacements** for read, write, edit, bash, grep, find, and ls.
3. **Wrap every tool call** with ActantOS’s decision API.
4. **Execute shell/file operations inside a sandbox**, not directly on the host.
5. **Log every decision and result** to ActantOS audit storage.
6. **Use Pi hook APIs where stable**, but do not depend only on hooks if custom guarded tools are more reliable.

Pi’s SDK exposes tool access, custom tools, and extension-registered tools, so the safest first adapter is a wrapper that starts Pi with controlled tools rather than relying on a fragile patch. ([GitHub][16])

## Tool-specific interception

| Tool/action    | MVP control                                                               |
| -------------- | ------------------------------------------------------------------------- |
| `read`         | Normalize path, enforce allowed roots, deny secret paths                  |
| `write`        | Approval required outside workspace; deny secret/config targets           |
| `edit`         | Same as write, plus diff captured in audit                                |
| `bash`         | Parse command with deterministic rules; execute in Docker sandbox         |
| `grep/find/ls` | Allow only approved workspace paths                                       |
| Git commands   | Treat `git push`, credential changes, remote changes as approval_required |
| GitHub CLI     | Treat `gh auth`, `gh repo`, `gh secret`, releases, deploys as high-risk   |
| HTTP via shell | Block by sandbox egress unless host allowlisted                           |
| Credentials    | Do not mount host home; pass only explicit scoped env vars                |

Pi’s bash tool uses child process spawning and exposes pluggable bash operations, making it a natural enforcement point. Its write/edit tools resolve paths and perform filesystem mutations, which makes path normalization and policy checks essential before execution. ([GitHub][17])

## Unverified Pi items to test early

These claims need validation in the current Pi version before you rely on them:

* Whether `beforeToolCall` is publicly easy to inject from the SDK in the exact release you target.
* Whether direct user shell shortcuts such as `!command` can bypass extension-level wrappers.
* Whether any Pi extension can register tools after your adapter and bypass your guarded registry.
* Whether provider HTTP overrides can be safely separated from tool HTTP/network access.
* Whether Pi’s future MCP extension, if added, should be wrapped at the Pi layer or only through ActantOS’s MCP gateway.

# 8. MCP gateway plan

## Why MCP matters

MCP is becoming the standard tool protocol for agents, but its own specification warns that tools may represent arbitrary code execution, tool descriptions should be treated as untrusted unless they come from trusted servers, and hosts should obtain explicit user consent before invoking tools. The spec also states MCP cannot enforce these principles at protocol level by itself. ([Model Context Protocol][4])

That means ActantOS can become:

**The MCP policy gateway for enterprise agents.**

## Concrete MCP proxy architecture

```text
Agent / MCP Client
      │
      ▼
ActantOS MCP Gateway
      │
      ├── Authenticates user / agent / session
      ├── Loads approved MCP server registry
      ├── Filters tools/list
      ├── Pins tool manifests and descriptions
      ├── Intercepts tools/call
      ├── Calls policy engine
      ├── Requests approval when needed
      ├── Issues scoped upstream credential
      ├── Logs evidence
      ▼
Approved Upstream MCP Server
      │
      ▼
Real tool/API/SaaS/database/file system
```

## MCP methods to intercept first

| MCP surface          | Control                                |
| -------------------- | -------------------------------------- |
| `initialize`         | Bind client, user, agent, session      |
| `tools/list`         | Filter hidden/unauthorized tools       |
| `tools/call`         | Main authorization point               |
| `resources/list`     | Filter unauthorized resources          |
| `resources/read`     | Enforce resource policy                |
| `prompts/list`       | Hide risky prompts                     |
| `prompts/get`        | Audit prompt retrieval                 |
| Sampling / callbacks | Deny in MVP unless explicitly approved |

## MCP risks and ActantOS controls

| Risk                  | Control                                                                               |
| --------------------- | ------------------------------------------------------------------------------------- |
| Token passthrough     | Reject raw upstream tokens; use gateway-issued scoped credentials                     |
| Confused deputy       | Bind every request to user + agent + client + session + purpose                       |
| SSRF                  | Block localhost, link-local, metadata IPs, private CIDRs unless explicitly allowed    |
| Malicious MCP servers | Server allowlist, manifest pinning, tool diff review                                  |
| Tool poisoning        | Show full AI-visible tool descriptions to admins; hash and pin descriptions           |
| Rug pulls             | Disable tool if description/schema changes without approval                           |
| Overbroad scopes      | Per-tool scopes and approval-required high-risk operations                            |
| Shadow MCP servers    | Local network egress policy: agents can only connect to ActantOS gateway              |
| Session hijacking     | Random session IDs, auth on every request, bind session to principal                  |
| Audit gaps            | Log tool list changes, tool calls, decisions, approvals, results, and manifest hashes |

The official MCP authorization/security guidance warns against token passthrough, highlights confused deputy and SSRF risks, and recommends binding authorization to proper resource servers and client/user consent. ([Model Context Protocol][18])

Tool poisoning is especially important: Invariant demonstrated attacks where malicious instructions are hidden in MCP tool descriptions, visible to the model but not the user, including rug-pull and shadowing attacks across tools. ([Invariant Labs][19])

NSA’s MCP security guidance also warns that MCP’s flexible architecture can create new attack paths, that the client/server pattern reverses familiar assumptions, and that security posture is implementation-dependent. 

# 9. Data model proposal

Use Postgres first. JSONB is acceptable for tool arguments and evidence payloads.

## Core tables

```text
tenants
- id
- name
- plan
- created_at

users
- id
- tenant_id
- email
- role
- groups[]
- created_at

agents
- id
- tenant_id
- name
- runtime_type          # pi, mcp, langgraph, custom
- owner_user_id
- environment           # dev, staging, prod
- risk_tier             # low, medium, high
- status                # active, disabled
- created_at

agent_versions
- id
- agent_id
- version
- source_ref
- manifest_hash
- created_at

sessions
- id
- tenant_id
- agent_id
- user_id
- purpose
- cwd
- sandbox_id
- status
- started_at
- ended_at

tools
- id
- tenant_id
- name
- kind                  # file, shell, http, github, mcp, db, custom
- server_id
- risk_level
- created_at

mcp_servers
- id
- tenant_id
- name
- transport             # stdio, sse, streamable_http
- upstream_url
- status
- owner_user_id

mcp_tool_versions
- id
- server_id
- tool_name
- schema_hash
- description_hash
- full_manifest_json
- approved
- created_at

policy_bundles
- id
- tenant_id
- name
- version
- engine                # opa, cedar
- source
- hash
- active
- created_at

policy_decisions
- id
- tenant_id
- request_id
- session_id
- agent_id
- tool_id
- policy_bundle_id
- decision              # allow, deny, approval_required
- reason
- constraints_json
- created_at

tool_calls
- id
- tenant_id
- request_id
- session_id
- agent_id
- tool_id
- operation
- normalized_args_json
- resource_json
- decision_id
- status                # pending, approved, denied, executed, failed
- result_hash
- started_at
- finished_at

approvals
- id
- tenant_id
- tool_call_id
- requested_by_agent_id
- approver_user_id
- status                # pending, approved, denied, expired
- reason
- expires_at
- created_at
- decided_at

audit_events
- id
- tenant_id
- event_type
- actor_type            # user, agent, system
- actor_id
- session_id
- tool_call_id
- decision_id
- payload_json
- prev_hash
- event_hash
- created_at

budgets
- id
- tenant_id
- scope_type            # tenant, user, agent, session
- scope_id
- metric                # tool_calls, shell_seconds, model_usd, output_bytes
- limit_value
- window
- current_value

kill_switches
- id
- tenant_id
- scope_type            # tenant, agent, session, tool, mcp_server
- scope_id
- enabled
- reason
- created_by
- created_at

sandboxes
- id
- tenant_id
- session_id
- runtime               # docker, gvisor, kata, firecracker
- image
- network_policy_json
- mounts_json
- status
- created_at
- destroyed_at
```

# 10. Policy model proposal: RBAC + ABAC with OPA/Rego first

Use **OPA/Rego** for the MVP because it is open-source, local, fast, and designed to decouple policy decisions from application logic. OPA describes Rego as a declarative policy language, and OPA can act as a policy decision point with preloaded in-memory data. ([Open Policy Agent][20])

Keep the model Cedar-compatible because Cedar supports RBAC and ABAC patterns and may be attractive later for AWS-heavy enterprise customers. ([AWS Documentation][21])

## Authorization input

```json
{
  "tenant": {
    "id": "org_123"
  },
  "agent": {
    "id": "agent_pi_dev_1",
    "runtime_type": "pi",
    "owner_user_id": "user_1",
    "environment": "dev",
    "risk_tier": "medium",
    "tags": ["coding-agent"]
  },
  "subject": {
    "user_id": "user_1",
    "groups": ["engineering"],
    "role": "developer"
  },
  "session": {
    "id": "sess_123",
    "purpose": "modify website copy",
    "cwd": "/workspace/actantos-site",
    "budget_remaining_usd": 5.00
  },
  "tool": {
    "name": "bash",
    "kind": "shell",
    "risk_level": "high"
  },
  "resource": {
    "kind": "process",
    "path": "/workspace/actantos-site",
    "labels": ["repo", "dev"]
  },
  "action": {
    "operation": "execute",
    "args": {
      "command": "git push origin main"
    },
    "normalized": {
      "command_family": "git",
      "mutation": true,
      "network": true
    }
  },
  "context": {
    "time": "2026-07-05T13:00:00Z",
    "adapter": "pi",
    "sandbox_id": "sbx_123"
  }
}
```

## Authorization output

```json
{
  "decision": "approval_required",
  "reason": "git push requires approval",
  "constraints": {
    "timeout_ms": 30000,
    "network_allowlist": ["github.com"],
    "max_output_bytes": 200000
  },
  "redactions": ["stdout.secrets", "stderr.secrets"],
  "ttl_seconds": 600
}
```

## Example Rego-style policy

```rego
package actantos.authz

default result := {
  "decision": "deny",
  "reason": "no matching allow rule"
}

secret_path if {
  p := lower(input.resource.path)
  contains(p, ".env")
}

secret_path if {
  p := lower(input.resource.path)
  contains(p, "/.ssh/")
}

secret_path if {
  p := lower(input.resource.path)
  contains(p, "auth.json")
}

result := {
  "decision": "deny",
  "reason": "credential-like path is blocked"
} if {
  input.tool.kind == "file"
  secret_path
}

result := {
  "decision": "allow",
  "reason": "read-only workspace access"
} if {
  input.tool.name in {"read", "grep", "find", "ls"}
  startswith(input.resource.path, input.session.cwd)
  input.agent.environment == "dev"
}

result := {
  "decision": "approval_required",
  "reason": "shell mutation or network command requires approval"
} if {
  input.tool.name == "bash"
  re_match("(git push|curl|wget|rm -rf|npm publish|docker|sudo|gh secret)", lower(input.action.args.command))
}

result := {
  "decision": "deny",
  "reason": "production mutation blocked for non-admin"
} if {
  input.agent.environment == "prod"
  input.action.normalized.mutation == true
  not input.subject.role == "security_admin"
}
```

# 11. API schema for tool-call interception

## Main decision endpoint

```http
POST /v1/intercept/tool-call
```

### Request

```json
{
  "request_id": "tc_01JZ...",
  "tenant_id": "org_123",
  "idempotency_key": "tc_01JZ...",
  "agent": {
    "id": "agent_pi_dev_1",
    "runtime_type": "pi",
    "version": "0.1.0",
    "environment": "dev",
    "risk_tier": "medium"
  },
  "subject": {
    "user_id": "user_1",
    "email": "dev@company.com",
    "groups": ["engineering"],
    "role": "developer"
  },
  "session": {
    "id": "sess_123",
    "purpose": "update landing page",
    "cwd": "/workspace/actantos-site"
  },
  "tool": {
    "name": "bash",
    "kind": "shell",
    "server_id": null
  },
  "resource": {
    "kind": "process",
    "path": "/workspace/actantos-site"
  },
  "action": {
    "operation": "execute",
    "args": {
      "command": "git push origin main"
    }
  },
  "runtime": {
    "adapter": "pi",
    "adapter_version": "0.1.0",
    "sandbox_id": "sbx_123"
  }
}
```

### Response: allow

```json
{
  "decision": "allow",
  "decision_id": "dec_123",
  "reason": "read-only command allowed",
  "constraints": {
    "timeout_ms": 10000,
    "max_output_bytes": 100000,
    "network_allowlist": []
  },
  "audit_event_id": "evt_123"
}
```

### Response: deny

```json
{
  "decision": "deny",
  "decision_id": "dec_124",
  "reason": "access to credential-like path is blocked",
  "audit_event_id": "evt_124"
}
```

### Response: approval required

```json
{
  "decision": "approval_required",
  "decision_id": "dec_125",
  "reason": "git push requires human approval",
  "approval": {
    "approval_id": "appr_123",
    "status": "pending",
    "expires_at": "2026-07-05T13:15:00Z"
  },
  "audit_event_id": "evt_125"
}
```

## Result endpoint

```http
POST /v1/tool-result
```

```json
{
  "request_id": "tc_01JZ...",
  "decision_id": "dec_123",
  "status": "executed",
  "started_at": "2026-07-05T13:01:00Z",
  "finished_at": "2026-07-05T13:01:02Z",
  "result": {
    "exit_code": 0,
    "stdout_hash": "sha256:...",
    "stderr_hash": "sha256:...",
    "redacted_preview": "pushed to origin main"
  }
}
```

## Other MVP endpoints

```http
POST /v1/approvals/{approval_id}/approve
POST /v1/approvals/{approval_id}/deny
POST /v1/kill-switches
DELETE /v1/kill-switches/{id}
GET /v1/sessions/{session_id}/events
GET /v1/agents
POST /v1/agents
GET /v1/audit/events
```

All decision endpoints should fail closed.

# 12. Human approval flow

```text
1. Agent attempts high-risk action
   Example: bash "git push origin main"

2. Pi adapter sends decision request to ActantOS

3. Policy engine returns approval_required

4. ActantOS creates approval record

5. Slack message is sent:
   - Agent name
   - User/session
   - Tool
   - Exact command or normalized action
   - Resource
   - Policy reason
   - Approve / Deny buttons
   - Expiration time

6. Approver clicks Approve or Deny

7. ActantOS records approver identity, timestamp, reason, and policy version

8. Adapter polls or receives webhook

9. If approved:
   - Execute with constraints
   - Log result
   - Expire approval after one use or TTL

10. If denied or expired:
   - Block execution
   - Return denial to agent
   - Log evidence
```

Approval should be **one-action scoped**, not broad session approval, for the MVP.

Later you can add temporary grants:

```text
Allow this agent to run git push on repo X for 10 minutes.
```

But week one should keep approvals narrow.

# 13. Audit and evidence model

The audit system should be good enough for security review from day one.

## Audit event types

```text
agent_registered
session_started
tool_call_requested
policy_decision_created
approval_requested
approval_granted
approval_denied
tool_call_executed
tool_call_failed
sandbox_created
sandbox_destroyed
budget_exceeded
kill_switch_enabled
kill_switch_disabled
mcp_server_registered
mcp_tool_manifest_changed
mcp_tool_disabled
```

## Evidence record

Each sensitive action should produce an evidence object:

```json
{
  "event_id": "evt_123",
  "tenant_id": "org_123",
  "timestamp": "2026-07-05T13:01:00Z",
  "actor": {
    "type": "agent",
    "id": "agent_pi_dev_1"
  },
  "subject": {
    "user_id": "user_1"
  },
  "session_id": "sess_123",
  "tool": {
    "name": "bash",
    "kind": "shell"
  },
  "action": {
    "operation": "execute",
    "normalized_args": {
      "command_family": "git",
      "mutation": true,
      "network": true
    }
  },
  "resource": {
    "kind": "repo",
    "path": "/workspace/actantos-site"
  },
  "decision": {
    "effect": "approval_required",
    "policy_bundle_hash": "sha256:...",
    "reason": "git push requires approval"
  },
  "approval": {
    "approval_id": "appr_123",
    "approved_by": "security@company.com",
    "approved_at": "2026-07-05T13:03:00Z"
  },
  "execution": {
    "sandbox_id": "sbx_123",
    "exit_code": 0,
    "stdout_hash": "sha256:...",
    "stderr_hash": "sha256:..."
  },
  "integrity": {
    "prev_hash": "sha256:...",
    "event_hash": "sha256:..."
  }
}
```

## MVP audit storage

Use:

* Postgres for structured events.
* JSONB for raw request/decision payload.
* Hash chain for tamper evidence.
* Redaction before persistence.
* Store full stdout/stderr only when explicitly enabled.
* Store hashes/previews by default.

Enterprise later:

* S3 Object Lock / WORM storage.
* SIEM export.
* Signed policy bundles.
* Evidence export for SOC 2 / ISO 27001.

# 14. Sandboxing and deployment recommendation

## MVP sandbox

Use **Docker** first because it is fast and cheap for a small team.

Recommended default:

```text
- Run Pi host process outside sandbox
- Run shell/file execution inside Docker sandbox
- Mount only the workspace directory
- Do not mount host HOME
- Do not pass all environment variables
- Pass only explicit allowlisted env vars
- Disable privileged containers
- Set CPU/memory/process limits
- Set command timeout
- Set max output bytes
- Default-deny network egress
- Allowlist domains per decision
```

## Important nuance

Do **not** give the sandbox the same credentials as the user’s normal shell. Pi’s documentation says default execution inherits the user/process permissions, so ActantOS must break that default assumption by controlling mounts, environment, network, and process execution. ([GitHub][3])

## Later isolation options

| Isolation            | When to use                                                    |
| -------------------- | -------------------------------------------------------------- |
| Docker               | MVP and local developer demo                                   |
| gVisor               | Stronger container isolation with good developer compatibility |
| Kata Containers      | VM-backed containers for higher-risk workloads                 |
| Firecracker microVMs | Multi-tenant SaaS sandboxes and untrusted code execution       |

Firecracker provides microVM isolation with the speed/resource efficiency associated with containers, and it is used by AWS services such as Lambda and Fargate. gVisor provides a Linux-compatible sandbox layer between applications and the host OS. Kata Containers runs containers inside lightweight VMs for stricter isolation. ([Firecracker][22])

# 15. Cost-control model

Cost control should be treated as a security feature.

## MVP controls

| Scope       | Control                                                  |
| ----------- | -------------------------------------------------------- |
| Tenant      | Max tool calls/day                                       |
| Agent       | Max tool calls/hour                                      |
| Session     | Max shell seconds, max actions, max spend                |
| Tool        | Per-tool rate limits                                     |
| Bash        | Timeout, process limit, output byte limit                |
| MCP server  | Max calls/minute                                         |
| Model spend | Track estimated cost from provider usage where available |
| Approval    | Require approval when budget threshold exceeded          |

## Example rules

```text
- Agent may run max 100 tool calls/hour
- Bash command timeout: 30 seconds
- Max stdout/stderr stored preview: 20 KB
- Max output bytes before truncation: 200 KB
- Network disabled unless policy grants allowlist
- Approval required after $5 session budget
- Kill session after repeated denied high-risk actions
```

This gives ActantOS another buyer message:

**Prevent runaway agents before they create runaway costs.**

# 16. Open-core and enterprise business model

## Recommended model

Use **open-core + hosted control plane + enterprise self-host**.

## Open-source core

Open source:

* Pi adapter.
* MCP gateway basic version.
* Local policy engine integration.
* Basic audit log.
* CLI.
* Docker Compose deployment.
* Starter policy packs.

Goal: developer trust and adoption.

## Paid SaaS

Paid hosted SaaS:

* Hosted dashboard.
* Approval workflows.
* Team management.
* Managed audit storage.
* Policy UI.
* Slack integration.
* Usage analytics.
* Hosted MCP gateway option.

## Enterprise license

Enterprise features:

* SSO/SAML/OIDC.
* SCIM.
* Advanced RBAC.
* Immutable audit storage.
* SIEM export.
* Custom approval workflows.
* Private deployment.
* HA deployment.
* Dedicated support.
* Policy bundle signing.
* Identity integrations with Okta / Entra.
* Credential broker integrations.
* Custom runtime adapters.

## BYOK / token-cost strategy

Do not become a model reseller in the MVP.

Use:

```text
Customer brings model keys.
ActantOS governs actions, not model access.
ActantOS charges by governed agents, seats, and tool decisions.
```

Later, ActantOS can offer optional model gateway integration, but the first business should avoid token-margin complexity.

## Pricing hypothesis

| Plan                   | Price hypothesis                                       |
| ---------------------- | ------------------------------------------------------ |
| OSS developer          | Free                                                   |
| Team SaaS              | $199–$499/month                                        |
| Pro / startup security | $2k–$5k/month                                          |
| Enterprise pilot       | $25k–$75k/year                                         |
| Enterprise scale       | Custom by agents, tool decisions, and deployment model |

Microsoft Agent 365’s public $15/user/month annual pricing is a useful anchor, but ActantOS should avoid pure per-user pricing because its value is tied to governed agents, tool calls, and runtime risk. ([Microsoft][10])

## First 3 pilot customer profiles

| Profile                       | Pain                                                | Why they buy                                               |
| ----------------------------- | --------------------------------------------------- | ---------------------------------------------------------- |
| AI-native devtool startup     | Internal coding agents can run shell/GitHub actions | Need safety without slowing engineering                    |
| Mid-market SaaS security team | Developers use Claude Code/Cursor/MCP/custom agents | Need visibility, approvals, and audit                      |
| Regulated ops automation team | Agents touch SaaS, tickets, APIs, databases         | Need human approval and evidence before production actions |

## Developer adoption strategy

Lead with:

```text
npm install @actantos/pi-adapter
actantos init
actantos run pi
```

Developer-facing promise:

**“Turn Pi into a governed enterprise agent runtime in 10 minutes.”**

Publish:

* Demo repo.
* Pi adapter.
* MCP gateway.
* Starter policies.
* “MCP threat matrix.”
* “Agent permission manifest” spec.
* Examples for coding agents, SaaS agents, and GitHub agents.

## Enterprise buyer messaging

Use:

**“ActantOS lets teams deploy AI agents without giving them unrestricted access to files, tools, APIs, SaaS systems, and MCP servers.”**

Security buyer message:

**“Pre-action enforcement, human approval, kill switch, and audit evidence for every agent action.”**

CIO/platform message:

**“One control plane for heterogeneous agents across Pi, MCP, custom runtimes, and enterprise workflows.”**

Developer message:

**“Keep using your agent framework. Add ActantOS as the permission layer.”**

# 17. 30 / 60 / 90-day build plan

## First 30 days

| Time   | Build                                                                                                     |
| ------ | --------------------------------------------------------------------------------------------------------- |
| Week 1 | Decision API, Postgres audit schema, OPA/Rego integration, first Pi guarded `bash` and `read` wrappers    |
| Week 2 | Guarded `write`, `edit`, `grep`, `find`, `ls`; Docker sandbox; path normalization; secret-path deny rules |
| Week 3 | Slack approval; kill switch; rate limits; audit viewer                                                    |
| Week 4 | MCP proxy POC for `tools/list` and `tools/call`; manifest hashing; demo repo; docs                        |

End of 30 days:

```text
A Pi agent can run under ActantOS.
Safe reads are allowed.
Secret paths are denied.
Risky shell/GitHub actions require Slack approval.
Everything is audited.
MCP tools can be listed, filtered, and called through policy.
```

## First 60 days

Build:

* Better policy templates.
* Dry-run mode.
* CLI.
* Local dashboard.
* Approval expiration.
* One-use approvals.
* Budget counters.
* Redaction.
* MCP upstream registry.
* Tool manifest diff review.
* Tests for path traversal and command risk.
* Docker Compose packaging.
* First 2–3 design partners.

## First 90 days

Build:

* Hosted control plane beta.
* Self-host package.
* Basic org/team management.
* Webhook/SIEM export.
* Agent session timeline.
* MCP gateway hardening.
* Signed policy bundle hash.
* Evidence export.
* Public launch demo.
* Pilot pricing.

# 18. 6-month roadmap

By month 6, ActantOS should support:

| Area                 | Roadmap                                                                                   |
| -------------------- | ----------------------------------------------------------------------------------------- |
| Runtime adapters     | Pi stable, MCP stable, LangGraph adapter, custom Python/TypeScript SDK                    |
| Policy               | OPA/Rego stable, Cedar-style schema compatibility                                         |
| MCP                  | Tool manifest pinning, upstream server registry, per-tool approval, token reference model |
| Sandbox              | Docker stable, gVisor option                                                              |
| Enterprise           | SSO/OIDC, RBAC, audit export, admin roles                                                 |
| Developer experience | CLI, SDK, policy templates, demo apps                                                     |
| Observability        | OpenTelemetry events, webhook export                                                      |
| Evidence             | Hash-chained audit, exportable reports                                                    |
| Commercial           | 3–5 pilots, 1–2 paid design partners                                                      |

# 19. 12-month roadmap

By month 12, ActantOS can become a serious control-plane company if it adds:

| Area                      | Roadmap                                                                       |
| ------------------------- | ----------------------------------------------------------------------------- |
| Agent capability manifest | Standard manifest for tools, permissions, model, owner, risk tier             |
| Credential broker         | Scoped, short-lived credentials for tools and MCP servers                     |
| Enterprise deployment     | HA self-host, private cloud, multi-region SaaS                                |
| Stronger isolation        | Kata / Firecracker for high-risk workloads                                    |
| More adapters             | AutoGen, CrewAI, OpenAI Agents SDK, coding agents, enterprise workflow agents |
| Advanced approvals        | Multi-step approval, break-glass, temporary grants                            |
| Audit                     | Immutable evidence store, SIEM/SOAR integrations                              |
| MCP security              | Shadow MCP detection, server attestation, tool diff workflows                 |
| Memory governance v1      | Basic memory read/write policy, not vector DLP first                          |
| Partnerships              | Okta/Entra identity, Cloudflare/Kong gateway integrations, devtool ecosystems |

# 20. Demo script

## Demo title

**“An AI agent tries to act. ActantOS decides first.”**

## Demo flow

```text
1. Start Pi normally
   Show that Pi can run shell/file actions with the user/process permissions.

2. Start Pi through ActantOS
   Command:
   actantos run pi --policy ./policies/dev.rego

3. Safe action
   User asks:
   “List the files and summarize README.md.”

   Result:
   Allowed.
   Audit log shows read/list actions.

4. Secret access attempt
   User asks:
   “Read ~/.ssh/id_rsa” or “show me .env”

   Result:
   Denied.
   Reason: credential-like path blocked.

5. Risky shell action
   User asks:
   “Push this change to GitHub.”

   Result:
   approval_required.
   Slack approval appears.

6. Approver clicks Approve
   ActantOS executes in Docker sandbox with constrained network.

7. Audit dashboard
   Show:
   - Agent
   - User
   - Tool
   - Command
   - Decision
   - Approver
   - Policy version
   - Result hash

8. MCP attack demo
   Register MCP server.
   Then change tool description/schema.
   ActantOS detects manifest hash change.
   Tool is disabled pending approval.

9. Kill switch
   Disable agent.
   Next tool call is denied immediately.
```

This demo clearly shows the product is not an agent. It is the runtime control layer.

# 21. Landing page copy

## Hero

**Run AI agents in production without giving them the keys to everything.**

ActantOS is a model-agnostic runtime control plane that enforces policy before agents touch files, shells, APIs, SaaS apps, databases, GitHub, or MCP servers.

**CTA:** Govern your first Pi or MCP agent

## Subhero bullets

* Allow, deny, or require approval before every tool call.
* Add policy-as-code to Pi, MCP, and custom agents.
* Route risky actions to Slack approval.
* Sandbox shell and file execution.
* Keep audit evidence for every agent action.
* Kill compromised or runaway agents instantly.

## Section: Not another agent

ActantOS does not build agents, replace your model, or wrap your chatbot.

It sits underneath your agents as the runtime permission layer.

Your agents can still reason, plan, and use tools. ActantOS decides what they are allowed to execute.

## Section: What ActantOS controls

```text
What agents can access
What agents can remember
What agents can decide
What agents can execute
Which actions need approval
Which tools are blocked
Which credentials are exposed
Which sessions must be killed
```

## Section: Built for the MCP era

MCP makes tools easy to connect.

ActantOS makes them safe to use.

Register MCP servers, filter tools, pin manifests, block poisoned or changed tools, require approval for sensitive actions, and audit every call.

## Section: Start with Pi

Pi is a lightweight agent runtime with tool execution.

ActantOS adds the missing enterprise control layer: permissions, approvals, sandboxing, audit, budgets, and kill switch.

## Section: For security teams

See every agent, every tool, every action, every decision, and every approval.

## Section: For developers

Keep your agent framework. Add one runtime gateway.

# 22. Top 10 risks and mitigations

| Risk                                          | Mitigation                                                                                          |
| --------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| Pi APIs change                                | Use wrapper/custom tools first; keep Pi fork avoidance; add integration tests                       |
| Agent bypasses ActantOS through shell/network | Docker sandbox, no host HOME, default-deny egress, no raw credentials                               |
| Direct Pi shortcuts bypass guarded tools      | Test early; disable direct shell shortcuts or route them through guarded bash                       |
| MCP protocol changes                          | Versioned proxy, test against official SDKs, keep gateway small                                     |
| Tool poisoning is hard to detect semantically | Start with manifest pinning, description diffing, allowlists, and approvals                         |
| Market crowded by Microsoft/Okta/Cloudflare   | Position as open developer-first runtime enforcement; integrate with identity/gateway vendors later |
| Approval fatigue                              | Risk tiers, narrow approval triggers, TTL grants later                                              |
| Logs leak secrets                             | Redaction, output hashing, preview limits, opt-in full logs                                         |
| Sandbox escape or weak isolation              | Docker for MVP, gVisor/Kata/Firecracker roadmap for enterprise                                      |
| Scope creep kills speed                       | Build only Pi adapter, MCP proxy, policy engine, audit, Slack approval, sandbox, kill switch first  |

# 23. Final recommendation: what to build this week

Build one thing:

## **ActantOS Guarded Pi MVP**

This week’s target:

```text
A Pi coding agent runs through ActantOS.
Every file and shell tool call is intercepted.
Policy returns allow / deny / approval_required.
Risky commands go to Slack.
Execution happens in Docker.
Every action is audited.
A kill switch stops the agent.
```

## Exact week-one build list

1. Create `actantosd`

   * FastAPI or Node/TypeScript API.
   * Postgres.
   * OPA sidecar or embedded OPA call.
   * `/v1/intercept/tool-call`.
   * `/v1/tool-result`.
   * `/v1/approvals`.

2. Create `@actantos/pi-adapter`

   * Starts Pi with built-ins disabled or replaced.
   * Registers guarded `read`, `write`, `edit`, `bash`, `grep`, `find`, `ls`.
   * Sends every call to ActantOS before execution.

3. Create Docker sandbox executor

   * Workspace-only mount.
   * No host HOME.
   * Env allowlist.
   * Timeout.
   * Output limit.
   * Network disabled by default.

4. Create starter policy pack

   * Allow read/list/grep/find inside workspace.
   * Deny `.env`, `.ssh`, auth files, token files.
   * Require approval for `git push`, `curl`, `wget`, `rm -rf`, `npm publish`, `gh secret`, `docker`, `sudo`.
   * Deny production mutation unless admin.

5. Create Slack approval

   * Approve / Deny buttons.
   * One-use approval.
   * TTL.

6. Create audit viewer

   * Session timeline.
   * Tool call.
   * Decision.
   * Reason.
   * Approver.
   * Result hash.

7. Create one demo

   * “Agent tries to read secrets: denied.”
   * “Agent tries to push code: approval required.”
   * “Agent approved: executes in sandbox.”
   * “Kill switch: next action blocked.”

That is enough to validate the whole ActantOS thesis.

The strongest near-term product is not “Agent OS” yet. It is:

**ActantOS: the runtime permission gateway for AI agents.**