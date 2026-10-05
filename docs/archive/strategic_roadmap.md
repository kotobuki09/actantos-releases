# ActantOS Strategic Roadmap & Architecture Specification

## 1. Executive Summary

ActantOS is built to serve as an in-path, out-of-process, fail-closed runtime control plane for autonomous AI agents. Rather than competing as another agent framework, chatbot builder, or model orchestration layer, ActantOS functions as a policy firewall. It answers a single critical authorization question before any agent action is allowed to execute: **Is this agent allowed to perform this action on this resource in this context right now?**

By decoupling policy evaluation from the agent's build and execution environments, ActantOS addresses the emerging enterprise requirement for independent runtime oversight. 

### Core Strategic Pillars — Dual Wedge Strategy

Two simultaneous wedges run in parallel: **MCP for market reach, Pi for demo speed**.

| Wedge | Purpose | Timeline |
| :--- | :--- | :--- |
| **MCP Policy Gateway** | Strategic market wedge — policy gateway for all MCP clients (Cursor, Claude Desktop, custom enterprise SDKs) | Days 1–45 |
| **Pi Guarded Adapter** | Concrete demo and developer proof — Pi exposes real file/shell/edit tools without built-in permission controls, the exact problem ActantOS solves | **Days 7–30** |

1. **Policy Engine**: AWS Cedar from Day 1, behind a `PolicyDecisionProvider` abstraction. Cedar handles RBAC/ABAC authorization. ActantOS wraps the raw Cedar result into one of three orchestration decisions — `allow`, `deny`, or `approval_required` — by combining Cedar output with kill-switch state, budget checks, risk classification, and approval status. The abstraction allows an `OPAProvider` to be added later without schema rewrites.
2. **Sandbox Stack (phased)**: **Docker** for local MVP and developer workstations (workspace-only mount, no host home dir, env allowlist). **gVisor** for single-tenant hardening (reduces host-kernel attack surface via a user-space application kernel — stronger than plain Docker but not a replacement for microVM isolation). **Firecracker microVMs** for multi-tenant Phase 3 (lightweight KVM-backed isolation; requires bare-metal or nested-virtualization compute with careful host, network, and side-channel hardening).
3. **MCP Gateway**: ActantOS deploys as a **configured** MCP policy gateway. MCP clients connect to ActantOS instead of directly to upstream MCP servers. Not framed as "transparent" — clients require explicit configuration to route through ActantOS.

---

## 2. Product Positioning & Category Definition

ActantOS sits above heterogeneous agent frameworks to secure their interactions with external systems:

* **Core Tagline**: Govern every agent action before it executes.
* **Core Value Statement**: ActantOS is the model-agnostic Agent Runtime Control Plane (ARCP) that enforces deterministic policy before AI agents touch tools, APIs, files, databases, SaaS systems, shell commands, or MCP servers.
* **Product Category Definition**: 
  We define the product category as the **Agent Runtime Control Plane (ARCP)**. It represents the runtime operations layer for governed agentic autonomy. 

### Category Evolution
ActantOS executes a three-stage category transition to scale developer adoption to enterprise infrastructure:

```
  ┌────────────────────────────────┐
  │ Phase 1: Agent Permission      │  <-- Focus: Developer CLI, Pi guarded adapter,
  │ Gateway (MVP)                  │            and configured MCP policy gateway.
  └───────────────┬────────────────┘
                  │
                  ▼
  ┌────────────────────────────────┐
  │ Phase 2: Agent Runtime         │  <-- Focus: Enterprise visibility, approval workflows,
  │ Control Plane (Product)        │            budgets, and federated identity.
  └───────────────┬────────────────┘
                  │
                  ▼
  ┌────────────────────────────────┐
  │ Phase 3: Agent OS for Governed │  <-- Focus: Complete virtualized isolation (Firecracker),
  │ Enterprise Autonomy            │            short-lived credentials, and tamper-proof logs.
  └────────────────────────────────┘
```

---

## 3. Competitive Market Landscape & Map

The AI governance and security market is fragmented. ActantOS establishes a unique space by focusing on **runtime tool-call enforcement** rather than compliance paperwork or prompt-injection filtering.

### Market Landscape Mapping

1. **AI Governance / GRC (e.g., Credo AI)**:
   * *Capabilities*: Credo AI (via platforms like GAIA) provides registry dashboards, model cards, NIST AI RMF/ISO 42001 mapping, and compliance workflows.
   * *ActantOS Differentiation*: GRC platforms are non-blocking, out-of-path systems. ActantOS is a **low-latency in-path runtime gateway** that blocks actions dynamically, generating the tamper-proof evidence that GRC platforms ingest. Local Cedar policy decisions are designed to be low-latency; approval workflows and sandbox execution are asynchronous or bounded by configurable policy constraints.
2. **Identity Governance (e.g., Okta for AI Agents, AppViewX)**:
   * *Capabilities*: Okta secures agent identity lifecycles, OAuth scopes, and revocation. AppViewX focuses on PKI-backed machine identities and certificates.
   * *ActantOS Differentiation*: Okta and AppViewX provide the "who" (identity) and "how" (credentials), but lack the semantic engine to inspect *what* command is executing (e.g., parsing a bash script). ActantOS integrates with these identity providers to map human owners to agent sessions, acting as the inline policy decision engine.
3. **AI Security Gateways / Prompt Firewalls (e.g., NeuralTrust, Lakera)**:
   * *Capabilities*: Secure LLMs against prompt injection, jailbreaks, and sensitive data leakage (DLP) at the text layer.
   * *ActantOS Differentiation*: Prompt firewalls secure the model's inputs and outputs. ActantOS secures the **tool-execution layer** (the system calls, network requests, and database updates generated *by* the agent's tool-use loop), providing deterministic protection where prompt filters fail.
4. **MCP Gateways (e.g., Cloudflare MCP Server Portal, Kong/Noma)**:
   * *Capabilities*: Cloudflare routes MCP requests and applies basic data leakage prevention (DLP) and access controls on standard API networks.
   * *ActantOS Differentiation*: Cloudflare operates at the network edge. ActantOS provides **deep session-aware context evaluation** using deterministic labels, budget state, approval state, and resource metadata — specifically tailored to autonomous agent execution with stateful Slack approvals and isolated sandboxed runtimes.
5. **Agent Governance Toolkits (e.g., Microsoft Agent Governance Toolkit, Agent 365)**:
   * *Capabilities*: Microsoft's Open Source Toolkit enforces policy-as-code inside .NET agent loops. Agent 365 provides Microsoft-centric governance.
   * *ActantOS Differentiation*: ActantOS is a framework-neutral, language-agnostic out-of-process gateway that secures python, typescript, and binary agents alike.

### Competitor Comparison Matrix

| Dimension | AI Governance (Credo AI) | Identity (Okta / AppViewX) | Prompt Firewalls (NeuralTrust) | MCP Gateways (Cloudflare) | ActantOS Gateway |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **In-Path Enforcement** | No (Post-hoc) | No (Access only) | Yes (Input/Output) | Yes (Network) | **Yes (Tool-Call)** |
| **Out-of-Process** | Yes | Yes | Yes | Yes | **Yes** |
| **Policy Language** | Natural / Policy | IAM Roles | Regex / Vector | Basic Rules | **AWS Cedar (Formal)** |
| **Interception Method** | API Polling | OAuth Lifecycle | LLM Wrapper | Network Proxy | **MCP Proxy & Adapter** |
| **Sandbox Execution** | No | No | No | No | **Yes (gVisor/Firecracker)** |
| **Primary Audience** | GRC & Legal | Security & IT | AI Engineers | Network Engineers | **Platform & SecOps** |

---

## 4. Architecture Overview

ActantOS separates the **Control Plane** (policy definition, identity mapping, approval state, and evidence storage) from the **Data Plane** (the proxy gateway and isolated executors).

### System Architecture Diagram (ASCII)

```text
                               ┌─────────────────────────────┐
                               │     ActantOS Admin UI       │
                               │  Policies | Sessions | Logs │
                               └──────────────┬──────────────┘
                                              │
                                              ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                          ActantOS MVP Control Plane                                    │
│                                                                                        │
│  ┌──────────────────────┐    ┌──────────────────────┐    ┌──────────────────────────┐  │
│  │    Agent Registry    │    │   AWS Cedar Engine   │    │   Approval Service       │  │
│  │ (id, environment,    │    │  RBAC / ABAC Policy  │    │   Slack / Webhook API    │  │
│  │  owner, risk_tier)   │    │  Decision Provider   │    │   (one-use, TTL-bounded) │  │
│  └──────────────────────┘    └──────────────────────┘    └──────────────────────────┘  │
│  ┌──────────────────────┐    ┌──────────────────────┐    ┌──────────────────────────┐  │
│  │ Budgets & Rate Limits│    │  Risk Classifier     │    │  Audit & Evidence Store  │  │
│  │ (Runaway loop guard) │    │  (normalizes action, │    │  Postgres hash-chain     │  │
│  └──────────────────────┘    │   calculates class)  │    │  (S3 WORM in Phase 3)    │  │
│                              └──────────────────────┘    └──────────────────────────┘  │
└─────────────────────────────────────────────┬──────────────────────────────────────────┘
                                              │ Decision API (Fail-Closed, HTTPS)
                                              ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                  ActantOS Data Plane                                   │
│                                                                                        │
│   [ Agent / MCP Client ] <───(stdio / SSE)───▶ [ ActantOS MCP Gateway Proxy ]          │
│   (Cursor, Claude Desktop,                     - Intercepts tools/call & resources/read│
│    custom enterprise SDKs)                     - Pins tool manifests & hashes          │
│                                                          │                             │
│                                                          ▼                             │
│                                                [ Verification Check ]                  │
│                                                - Evaluates Cedar Policy                │
│                                                - Resolves Budget & Approvals           │
│                                                          │                             │
│                                            ┌─────────────┴─────────────┐               │
│                                            ▼ (Allow)                   ▼ (Deny / Block)│
│                                   ┌─────────────────┐         ┌─────────────────┐      │
│                                   │ Execute Sandbox │         │ Return Blocked  │      │
│                                   │ (Docker/gVisor) │         │ to Agent Client │      │
│                                   └────────┬────────┘         └─────────────────┘      │
│                                            │                                           │
│                                            ▼                                           │
│                                 ┌─────────────────────┐                                │
│                                 │ Upstream MCP Server │                                │
│                                 │ (GitHub, DB, SaaS)  │                                │
│                                 └─────────────────────┘                                │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

### Design Principles
* **Fail-Closed by Design**: If `actantosd` or the Cedar PDP becomes unreachable, all tool calls are blocked. No tool call executes without an explicit `allow` decision.
  * **Adapter Fail-Closed Contract**: Every integration point (`guarded_*` wrappers, shell hooks, MCP proxy) enforces a short decision timeout (default 200ms local, 2s remote). On timeout, connection error, malformed response, or daemon crash, the adapter raises a fatal error and terminates the tool call (and, for shell hooks, the parent shell session) — it never defaults to execute. `actantosd` runs under a supervisor with a liveness watchdog; OOM/CPU pressure triggers restart while adapters continue to hard-fail closed.
* **Out-of-Process Isolation**: The policy engine runs completely outside the agent's memory space, preventing prompt injections from modifying the runtime security rules.
* **Deterministic Policy**: Authorization uses deterministic labels, budget state, approval state, and resource metadata — not LLM judgment.
* **Immutability of Evidence**: Audit logs are formatted as a hash chain. S3 Object Lock WORM export is added in Phase 3 for compliance evidence.

### Enterprise Architecture (Phase 3)

```text
Hosted Control Plane (Phase 3)
│ OIDC / SCIM       │ SIEM Export        │ WORM Audit Store  │
│ Okta / Entra      │ Splunk / Datadog   │ S3 Object Lock    │
│ Credential Broker │ Policy Marketplace │ Advanced Approvals│
        │
        ▼
Hardened Data Plane
        ├── gVisor (single-tenant hosted runtime)
        └── Firecracker microVMs (multi-tenant SaaS runtime)
```

---

## 5. Technical Specifications

### 5.1. Agent Session Identity Model

ActantOS defines a formal session identity containing five bound entities to prevent confused deputy and session hijacking attacks:

```json
{
  "tenant_id": "org_71aa92f3",
  "agent_id": "agent_code_helper_prod",
  "user_id": "usr_99818ab",
  "session_id": "sess_88291a27e",
  "purpose": "Refactor authentication loops in database.go"
}
```
* **Binding Mechanism**: The session identity is encapsulated in a cryptographically signed JSON Web Token (JWT) issued by the control plane upon session initialization. This token must accompany every decision request.
* **Purpose-as-Context (Deterministic Labels Only)**: The `purpose` string is recorded during session initiation as a user-declared session label. It is used as ABAC context in Cedar policies to restrict tool access only to directories and APIs relevant to the stated task. **Important**: Purpose is a deterministic label supplied by the human operator (e.g., `"repo:auth-service, env:dev"`), not a natural-language string evaluated by an LLM. Avoid using LLM intent classification as a core authorization primitive — that becomes LLM-as-judge with all its reliability and injection risks.

### 5.2. Tool-Call Interception API Schemas

The data plane communicates with the control plane via structured, type-enforced JSON endpoints.

#### 1. Main Interception Point: `POST /v1/intercept/tool-call`

##### Request Schema
```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "ToolCallInterceptionRequest",
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "request_id": { "type": "string", "format": "uuid" },
    "tenant_id": { "type": "string" },
    "agent": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "id": { "type": "string" },
        "runtime_type": { "type": "string", "enum": ["pi", "mcp", "langgraph", "custom"] },
        "environment": { "type": "string", "enum": ["dev", "staging", "prod"] },
        "risk_tier": { "type": "string", "enum": ["low", "medium", "high"] }
      },
      "required": ["id", "runtime_type", "environment", "risk_tier"]
    },
    "subject": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "user_id": { "type": "string" },
        "email": { "type": "string", "format": "email" },
        "role": { "type": "string" }
      },
      "required": ["user_id", "role"]
    },
    "session": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "id": { "type": "string", "minLength": 1 },
        "cwd": { "type": "string", "minLength": 1 },
        "purpose": { "type": "string" },
        "budget_remaining_cents": { "type": "integer", "minimum": 0 }
      },
      "required": ["id", "cwd", "budget_remaining_cents"]
    },
    "tool": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "name": { "type": "string" },
        "kind": { "type": "string", "enum": ["file", "shell", "http", "github", "mcp", "db", "custom"] },
        "schema_hash": { "type": "string" }
      },
      "required": ["name", "kind", "schema_hash"]
    },
    "action": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "operation": { "type": "string" },
        "args": {
          "type": "object",
          "additionalProperties": true,
          "properties": {
            "command": { "type": "string" },
            "subcommand": { "type": "string" },
            "arguments": {
              "type": "array",
              "items": { "type": "string" }
            }
          }
        }
      },
      "required": ["operation", "args"]
    },
    "resource": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "id": { "type": "string" },
        "kind": { "type": "string", "enum": ["file", "shell", "http", "github", "mcp", "db", "custom"] },
        "path": { "type": "string" },
        "url": { "type": "string", "format": "uri" },
        "database": { "type": "string" },
        "table": { "type": "string" }
      },
      "required": ["id", "kind"]
    },
    "authorization": {
      "type": "object",
      "additionalProperties": false,
      "description": "If re-submitting after a prior approval was granted, reference the approval here. ActantOS verifies server-side that the approval belongs to the same tenant/user/agent/session/tool and is unused and unexpired. Adapters must NOT self-assert approval.status.",
      "properties": {
        "prior_decision_id": { "type": "string", "minLength": 8, "maxLength": 128 },
        "approval_token": { "type": "string", "description": "Signed one-use token issued by ActantOS approval service" }
      },
      "required": ["prior_decision_id"]
    },
    "normalized": {
      "type": "object",
      "additionalProperties": false,
      "description": "Pre-computed facts from the gateway's tokenization layer. Cedar evaluates these stable facts, not raw strings.",
      "properties": {
        "verb": { "type": "string", "enum": ["read", "write", "execute", "delete", "list", "create", "network"] },
        "mutation": { "type": "boolean" },
        "destructive": { "type": "boolean" },
        "network": { "type": "boolean" },
        "credential_access": { "type": "boolean" },
        "risk_class": { "type": "string", "enum": ["low", "medium", "high", "critical"] },
        "command_family": { "type": "string" },
        "subcommand": { "type": "string" },
        "target_type": { "type": "string" }
      },
      "required": ["verb", "mutation", "destructive", "network", "credential_access", "risk_class"]
    },
    "mcp": {
      "type": "object",
      "additionalProperties": false,
      "description": "Present when tool.kind == 'mcp'. Carries MCP-native identity for policy and audit.",
      "properties": {
        "server_id": { "type": "string" },
        "server_identity_hash": { "type": "string", "description": "sha256 of server manifest" },
        "tool_name": { "type": "string" },
        "tool_schema_hash": { "type": "string", "description": "sha256 of tool input schema" },
        "tool_description_hash": { "type": "string", "description": "sha256 of tool description (tool poisoning detection)" },
        "transport": { "type": "string", "enum": ["stdio", "sse", "http"] }
      },
      "required": ["server_id", "tool_name", "tool_schema_hash", "tool_description_hash"]
    }
  },
  "required": ["request_id", "tenant_id", "agent", "subject", "session", "tool", "action", "resource"],
  "allOf": [
    {
      "if": {
        "properties": {
          "tool": {
            "properties": {
              "kind": { "const": "file" }
            }
          }
        }
      },
      "then": {
        "properties": {
          "resource": {
            "required": ["path"]
          }
        }
      }
    },
    {
      "if": {
        "properties": {
          "tool": {
            "properties": {
              "kind": { "const": "http" }
            }
          }
        }
      },
      "then": {
        "properties": {
          "resource": {
            "required": ["url"]
          }
        }
      }
    },
    {
      "if": {
        "properties": {
          "tool": {
            "properties": {
              "kind": { "const": "db" }
            }
          }
        }
      },
      "then": {
        "properties": {
          "resource": {
            "required": ["database"]
          }
        }
      }
    },
    {
      "if": {
        "properties": {
          "tool": {
            "properties": {
              "kind": { "const": "shell" }
            }
          }
        }
      },
      "then": {
        "properties": {
          "action": {
            "properties": {
              "args": {
                "type": "object",
                "properties": {
                  "command": { "type": "string" },
                  "binary_name": { "type": "string" },
                  "binary_path": { "type": "string" },
                  "subcommand": { "type": "string" },
                  "arguments": {
                    "type": "array",
                    "items": { "type": "string" }
                  },
                  "stdin": { "type": "string" }
                },
                "required": ["command", "arguments", "binary_name"],
                "additionalProperties": false
              }
            }
          }
        }
      }
    }
  ]
}
```

##### Response Schema
```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "ToolCallInterceptionResponse",
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "decision": { "type": "string", "enum": ["allow", "deny", "approval_required"] },
    "decision_id": { "type": "string", "format": "uuid" },
    "reason": { "type": "string" },
    "approval": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "approval_id": { "type": "string", "format": "uuid" },
        "status": { "type": "string", "enum": ["pending", "approved", "denied"] },
        "expires_at": { "type": "string", "format": "date-time" }
      },
      "required": ["approval_id", "status"]
    },
    "constraints": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "timeout_ms": { "type": "integer" },
        "max_output_bytes": { "type": "integer" },
        "network_allowlist": { "type": "array", "items": { "type": "string" } }
      }
    },
    "audit_event_id": { "type": "string", "format": "uuid" }
  },
  "required": ["decision", "decision_id", "reason", "audit_event_id"],
  "allOf": [
    {
      "if": {
        "properties": {
          "decision": { "const": "approval_required" }
        }
      },
      "then": {
        "required": ["approval"]
      }
    }
  ]
}
```

#### 2. Execution Logging Point: `POST /v1/tool-result`

##### Request Schema
```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "ToolResultRequest",
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "request_id": { "type": "string", "format": "uuid" },
    "decision_id": { "type": "string", "format": "uuid" },
    "tool_kind": { "type": "string", "enum": ["file", "shell", "http", "github", "mcp", "db", "custom"] },
    "status": { "type": "string", "enum": ["executed", "failed", "timeout"] },
    "started_at": { "type": "string", "format": "date-time" },
    "finished_at": { "type": "string", "format": "date-time" },
    "result": {
      "type": "object",
      "additionalProperties": true,
      "properties": {
        "exit_code": { "type": "integer", "minimum": -1 },
        "stdout_hash": { "type": ["string", "null"] },
        "stderr_hash": { "type": ["string", "null"] },
        "redacted_preview": { "type": "string" },
        "error_message": { "type": "string" }
      }
    }
  },
  "required": ["request_id", "decision_id", "tool_kind", "status", "started_at", "finished_at", "result"],
  "allOf": [
    {
      "if": {
        "properties": {
          "status": { "const": "executed" },
          "tool_kind": { "const": "shell" }
        }
      },
      "then": {
        "properties": {
          "result": {
            "type": "object",
            "properties": {
              "exit_code": { "type": "integer", "minimum": -1 },
              "stdout_hash": { "type": ["string", "null"] },
              "stderr_hash": { "type": ["string", "null"] },
              "redacted_preview": { "type": "string" },
              "error_message": { "type": "string" }
            },
            "required": ["exit_code", "stdout_hash"],
            "additionalProperties": false
          }
        }
      }
    },
    {
      "if": { "properties": { "status": { "enum": ["failed", "timeout"] } } },
      "then": { "properties": { "result": { "required": ["error_message"] } } }
    }
  ]
}
```

---

### 5.3. AWS Cedar Policy Examples

AWS Cedar policies provide fine-grained, readable authorization for RBAC and ABAC within ActantOS.

**Approval pipeline model**: Cedar returns `permit` or `forbid`. ActantOS orchestration then combines the Cedar result with risk classification, kill-switch state, budget checks, and approval state to produce the final decision: `allow`, `deny`, or `approval_required`. This keeps Cedar policies focused on authorization logic and keeps workflow state out of policy code.

```text
Cedar evaluates:     permit / forbid
Risk classifier:     approval_required / no_approval_required
ActantOS combines:
  forbid                                          → deny
  permit + approval_required + no valid approval  → approval_required
  permit + approval_required + valid approval      → allow
  permit + no approval required                   → allow
```

**Syntax Note:** Standard AWS Cedar policy syntax strictly requires C-style logical operators `&&` and `||`. Word-based operators like `and` or `or` are syntactically invalid in Cedar and will cause policy compilation errors.

```cedar
// Policy 1: Enterprise Role-Based Access Control (RBAC)
// Restricts production MUTATING commands exclusively to security administrators.
// Read-only actions (ListFiles, ReadFile, GetStatus) are NOT blocked to avoid
// preventing legitimate monitoring and debugging in production.
forbid (
    principal,
    action in [
        Action::"WriteFile",
        Action::"EditFile",
        Action::"DeleteFile",
        Action::"ExecuteShellCommand",
        Action::"CreateResource",
        Action::"UpdateResource",
        Action::"DeleteResource"
    ],
    resource
)
when {
    context.agent.environment == "prod"
}
unless {
    // Note: Cedar strictly requires C-style '&&' (word-based 'and' is invalid)
    principal in Role::"security_admin" &&
    context.agent.risk_tier != "high"
};
```

#### Path Traversal & Symlink Vulnerability & Hardening Design
* **Vulnerability**: Path prefix checks in Cedar (e.g., `resource.path like "/workspace/*"`) can be bypassed using relative traversals (e.g., `/workspace/../etc/passwd`) or symbolic links.
* **Hardening Design**: To mitigate this, the ActantOS Gateway data plane must perform full **Path Canonicalization and Normalization** (resolving symlinks, absolute path resolution, and case normalization) BEFORE passing the path to the Cedar policy engine.
* **TOCTOU Note**: Path canonicalization is **defense-in-depth, not the primary barrier**. A symlink target can be swapped between the canonicalization check and the write (time-of-check/time-of-use). The primary barrier is the sandbox itself: host bind-mounts are limited exclusively to the workspace directory, writable mounts carry `noexec`, and no path outside the workspace mount namespace is reachable — so a post-check symlink swap cannot escape to host paths regardless of policy evaluation timing. Where supported, executors use `openat2(2)` with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS` for file operations.

```cedar
// Policy 2: Attribute-Based Access Control (ABAC) for File Mutations
// Restricts write actions to the designated project workspace and blocks credential paths.
permit (
    principal,
    action in [Action::"WriteFile", Action::"EditFile"],
    resource
)
when {
    // Note: Cedar strictly requires C-style '&&' (word-based 'and' is invalid)
    resource has path &&
    resource.path like "/workspace/*"
}
unless {
    // Note: Cedar strictly requires C-style '&&' and '||' (word-based 'and'/'or' are invalid)
    resource has path && (
        resource.path like "*.env" ||
        resource.path like "*/.ssh/*" ||
        resource.path like "*auth.json"
    )
};
```

```cedar
// Policy 3: Context-Aware Security Guard & Budget Enforcement
// Blocks shell execution if the remaining session budget is insufficient.
forbid (
    principal,
    action == Action::"ExecuteShellCommand",
    resource
)
when {
    context.session.budget_remaining_cents < 100
};
```

#### Shell Command Bypass Vulnerability & Hardening Design

> **MVP shell policy principle**: Avoid shell semantics wherever possible. The goal is not to parse every dangerous shell command perfectly. The goal is to not need to parse shell at all.

**MVP Shell Rules (enforced before Cedar, in the data plane):**
```
- No raw shell string execution by default
- Execute known binaries directly with argv array (not via shell)
- Shell interpreter (bash/sh/python) requires approval_required minimum
- No stdin pipe into interpreter (e.g., echo cmd | bash, bash < script.sh)
- No execution from writable directories (/workspace, /tmp, /home)
- Network disabled by default in sandbox
```

Shell tokenization is **defense-in-depth**, not the primary safety boundary. When shell execution is permitted:
* **Vulnerability**: Substring-based matching on single strings using Cedar's `like` operator (e.g., `context.action.args.command like "*git push*"`) is vulnerable to shell bypasses. Attackers can evade using quotes (`git p''ush`), variables, pipes, or redirection.
* **Hardening Design**: The ActantOS Gateway performs **Pre-execution Command Tokenization** before Cedar evaluation:
  1. Tokenizes the raw command string using a shell-aware lexer (equivalent to Python `shlex.split`).
  2. Resolves the canonical binary path via `execve` lookup, extracting `binary_name` (e.g. `"rm"`) and `binary_path` (e.g. `"/bin/rm"`).
  3. Normalizes all flags to their long-form equivalent (e.g., `rm -r -f`, `rm -fr`, `rm --recursive --force` all normalize to `arguments: ["--recursive", "--force"]`).
  4. Blocks any command that spawns an interactive shell (`bash -i`, `sh`, `python -c`) before Cedar evaluation.
  5. **Rejects unresolved shell expansion**: any command containing unresolved environment variables (`$VAR`, `${VAR}`), command substitution (`$(...)`, backticks), process substitution (`<(...)`), globs that cannot be statically resolved, or chained control operators (`;`, `&&`, `||`, `|`, `>`, `<`) is denied outright unless the gateway fully resolves the expansion to a static argv **before** Cedar evaluation. This prevents evasion patterns such as `git $VAR` where `VAR="push"` or `rm $(echo "-rf")`.
* **Cedar Evaluation**: Cedar Policy 4 evaluates the normalized, structured token output — not the raw string.

```cedar
// Policy 4: State-Aware Human-in-the-Loop Interception
// Requires an explicit manual approval flag for any destructive operations.
forbid (
    principal,
    action == Action::"ExecuteShellCommand",
    resource
)
when {
    // Note: Cedar strictly requires C-style '&&' and '||' (word-based 'and'/'or' are invalid)
    context.action.args has binary_name && (
        (context.action.args.binary_name == "git" && (context.action.args has subcommand && context.action.args.subcommand == "push")) ||
        (context.action.args.binary_name == "rm" && (context.action.args has arguments && context.action.args.arguments.contains("--recursive")) && (context.action.args has arguments && context.action.args.arguments.contains("--force"))) ||
        (context.action.args.binary_name == "npm" && (context.action.args has subcommand && context.action.args.subcommand == "publish"))
    )
}
unless {
    // Note: Cedar strictly requires C-style '&&' (word-based 'and' is invalid)
    context has approval &&
    context.approval.status == "approved"
};
```

---

### 5.4. Sandboxing Execution Isolation Stack

The execution boundary prevents arbitrary LLM-generated shell scripts from compromising the host infrastructure.

```text
┌──────────────────────────────────────────────────────────────┐
│                  Application Layer (LLM CLI)                 │
├──────────────────────────────────────────────────────────────┤
│                   Container Layer (OCI Spec)                 │
├──────────────────────────────────────────────────────────────┤
│                gVisor Sentry (User-Space Kernel)             │
│ - Intercepts all syscalls; runs Go-based virtual kernel      │
│ - Direct syscall translation prevents raw host OS exposure   │
├──────────────────────────────────────────────────────────────┤
│                  gVisor Gofer (File Proxy)                   │
│ - Sandboxed file access; blocks direct host filesystem mounts│
├──────────────────────────────────────────────────────────────┤
│                  Host Linux Kernel (KVM / OCI)               │
└──────────────────────────────────────────────────────────────┘
```

* **Standard Docker (Local MVP & Developer Workstations)**:
  * *Mechanism*: Namespaces and control groups (cgroups).
  * *Day 1 Constraints (guaranteed from first deployment)*:
    ```
    - no host home mount
    - workspace-only bind mount
    - non-root user inside container
    - read-only root filesystem where possible
    - no privileged mode
    - drop all Linux capabilities (cap_drop: ALL, add back only what is needed)
    - pids / memory / cpu limits
    - default-deny network egress
    - explicit env allowlist
    - command execution timeout
    - output byte limit
    ```
  * *Hardening Targets (added during hardening phase, not Day 1)*:
    ```
    - noexec on writable mounts (/workspace, /tmp)
    - dynamic loader restrictions (block /lib/ld-linux* from loading workspace binaries)
    - seccomp profile (deny memfd_create, execveat, mprotect W+X)
    - AppArmor / SELinux profile
    - eBPF execve monitoring → real-time PDP check on every exec
    - gVisor runtime replacement (single-tenant hosted)
    ```
* **gVisor (Single-Tenant Hardening)**:
  * *Mechanism*: Implements a user-space application kernel (Sentry) that interposes between the workload and host OS, intercepting system calls via a Go-based virtual kernel. A file proxy (Gofer) handles sandboxed filesystem access.
  * *Security Posture*: gVisor reduces the host-kernel attack surface compared to plain Docker isolation and is stronger than namespace-only containers. However, **gVisor is not a replacement for microVM isolation** — it still shares the host kernel and hardening gaps exist. Suitable for single-tenant cloud deployments; not recommended for high-risk multi-tenant SaaS.
* **Firecracker MicroVMs (Phase 3 Multi-tenant)**:
  * *Mechanism*: Lightweight KVM-backed microVMs with a minimal device model and attack surface smaller than general-purpose VMs.
  * *Security Posture*: Firecracker provides stronger isolation than gVisor via hardware virtualization boundaries. However, it still requires careful host kernel, networking, and side-channel hardening — it does not eliminate all attack surface. Requires bare-metal compute or nested-virtualization-enabled VMs (KVM support).
  * *Use Case*: Multi-tenant SaaS execution of arbitrary agent code in Phase 3.
* **Sandboxing Execution Constraints**:
  * *Indirect Command Execution Prevention*: The container sandbox blocks execution of any executable file from ALL writable directories, including `/workspace`, `/tmp`, `/var/tmp`, `/dev/shm`, `/run`, and `/home`. Execution is strictly restricted to verified binaries in read-only system directories (`/bin`, `/usr/bin`, `/usr/local/bin`).
  * *Writable Directory Mount Flags*: Writeable directories (specifically `/workspace` and `/tmp`) inside the container sandbox must be mounted with the `noexec` flag (mount option) to enforce process and dynamic library execution blocks.
  * *Direct Dynamic Loader Blocking*: Dynamic loader execution (covering both `ld-linux*` and `ld-musl*`) is restricted to loading libraries strictly from read-only system paths (like `/lib`, `/lib64`, `/usr/lib`), preventing libraries from being loaded from writeable directories like `/workspace` or `/tmp` to prevent bypassing path-based execution filters.
  * *Nested Subprocess Escapes Prevention*: To prevent nested subprocess escapes, the container uses system-level hooks (such as eBPF or ptrace process execution monitoring) to intercept every `execve` system call inside the sandbox and evaluate them against the gateway PDP.
  * *In-Memory Execution Mitigation*: The sandbox restricts `mprotect` write+execute permissions (W^X violations) by default, but allows granular JIT execution exceptions for approved developer runtime engines (like Node.js or JVM) inside the workspace, enforcing seccomp policies that block JIT allocation only for general shell utilities. It also blocks the `memfd_create` and `execveat` system calls.
  * *Stdin Interception & Pipe Blocking*: The ActantOS Gateway intercepts and audits the standard input (stdin) stream of all shell interpreter tool calls, blocking stdin pipe patterns (e.g., `bash < script.sh` or `echo malicious_cmd | bash`) by default.
  * *Interpreter Evaluation*: Any execution of shell interpreters (`bash`, `sh`, `python`, etc.) is treated as high-risk and subject to argument parsing and Cedar policy evaluation before execution.
  * *Network Egress & DNS Controls*: Each sandbox runs in its own network namespace with **default-deny egress enforced via nftables/iptables** (`OUTPUT` policy `DROP`; allow rules only for gateway-approved destinations). Specific rules: (1) DNS resolution is permitted only through a gateway-controlled resolver (port 53/853 to the resolver IP only), with all queries logged and NXDOMAIN-fallback disabled to prevent DNS tunneling and rebinding; (2) link-local `169.254.0.0/16` (including cloud metadata endpoints such as `169.254.169.254`), loopback beyond the sandbox, and RFC-1918 CIDRs are dropped unless explicitly allowlisted; (3) IPv6 receives mirrored rules (`fe80::/10`, ULA `fc00::/7`, metadata `fd00:ec2::254`); (4) allowlisted egress is resolved at the gateway and pinned to IPs at connection time so a post-resolution DNS change cannot redirect traffic.

---

### 5.5. MCP Gateway Security Controls

MCP security goes beyond manifest hashing. The MCP risk surface includes confused deputy attacks, token passthrough to arbitrary servers, SSRF, shadow MCP traffic, and tool poisoning (malicious instructions hidden in tool descriptions visible to models but not to users).

| MCP Risk | ActantOS Control |
| :--- | :--- |
| **Tool poisoning** | Hash and pin tool name, schema, description, and server identity; reject calls if hash drifts |
| **Rug pull (manifest change)** | Disable tool when manifest changes until explicit admin approval |
| **Token passthrough** | Never pass raw user OAuth token to upstream MCP server; inject scoped credentials only |
| **Confused deputy** | Bind token to tenant + user + agent + session + upstream server + audience |
| **SSRF** | Block `localhost`, `169.254.x.x` metadata IPs, and RFC-1918 private CIDRs by default |
| **Shadow MCP server** | Agent network egress only permitted to ActantOS gateway; no direct upstream connections |
| **Overbroad tools** | Filter `tools/list` response based on per-agent Cedar policy before returning to client |
| **Dangerous tool call** | Intercept `tools/call`; apply decision pipeline before forwarding |
| **Audit gap** | Log tool list response hash, manifest hash, call args, decision, approval ref, result hash |
| **Prompt/resource abuse** | Intercept `prompts/get` and `resources/read`; apply policy; sample callbacks deferred to Phase 2 |

---


> **Core principle**: Build the **enforcement kernel first**, then the enterprise platform.
> One agent action cannot execute without an ActantOS decision — prove this first.

---

## 6. Strategic Roadmap

### 6.0. What to Delay (Not MVP)

The following are **intentionally excluded** from MVP to reduce hard dependencies before proving enforcement:

```
gVisor as default hosted runtime      → Docker Day 1, gVisor in hardening phase
Firecracker                           → Phase 3
S3 Object Lock / WORM export          → hash-chain in Postgres first
Credential broker                     → use env allowlist + credential references
Okta / Entra integrations             → OIDC in Month 3-4
Google Drive / DB connectors          → Phase 2
Advanced dashboard                    → tiny approval UI only in MVP
LLM intent / natural language policy  → use deterministic labels only
Formal policy verification claims     → Cedar validates logic, not system security
Multi-tenant SaaS sandbox execution   → Phase 3
```

---

### 6.1. Phase 1: Gateway Kernel & Pi + MCP MVP

#### Week 1: Smallest Possible Proof

**Goal**: One agent action cannot execute without an ActantOS decision.

```
actantosd daemon (decision endpoint only)
one Cedar policy file: deny .env reads
Postgres decisions table (one row per decision, hash-chained)
guarded_bash — calls POST /v1/intercept/tool-call before exec
guarded_read — calls POST /v1/intercept/tool-call before read
approval_required for git push (manual API, not Slack yet)
return allow / deny / approval_required
```

**Success**: `guarded_read .env` is denied. `guarded_bash git push` returns `approval_required`.

#### Weeks 2–4: Demo-Grade MVP

```
Slack approval (one-use, TTL-bounded)
Docker sandbox executor (workspace-only, env allowlist, Day-1 constraints)
guarded_write, guarded_edit, guarded_ls, guarded_grep, guarded_find
Kill switch (disable tenant / agent / session / tool)
Basic audit timeline (web page, not full dashboard)
Pending approvals page
Demo repo:
  read README.md → allowed
  read .env      → denied
  git push       → approval_required
  approved git   → sandboxed execution
  kill switch    → next action denied
```

**Success metric**: One agent action cannot execute without an ActantOS decision.

**Key Deliverables**:
* **`actantosd` Daemon**: Exposes `/v1/intercept/tool-call` and `/v1/tool-result` REST APIs.
* **Cedar `PolicyDecisionProvider`**: Local Cedar evaluator behind abstraction; ActantOS orchestration layer wraps Cedar result into `allow` / `deny` / `approval_required`.
* **Docker Sandbox**: Day-1 constraints applied (see sandboxing section). Workspace-only mount, deny-all network egress, env allowlist.
* **Pi Guarded Adapter (Days 7–30)**: `guarded_*` tools calling `POST /v1/intercept/tool-call` before every execution.
* **Postgres Audit Log**: Hash-chain of decisions, redacted previews.
* **Slack Approval (Week 2–4)**: Single-use callback with TTL.
* **Kill Switch**: Immediately blocks all further actions for tenant/agent/session/tool.

---

### 6.2. Days 31–60: Prove MCP Wedge

**Goal**: A normal MCP client can connect through ActantOS and only see/call policy-approved tools.

```
Build MCP configured gateway for tools/list and tools/call
Add MCP server registry
Add tool manifest hashing and pinning
Add tool diff approval (admin must approve changed manifest)
Add default SSRF blocklist (localhost, metadata IPs, private CIDRs)
Add per-tool Cedar policy
Add minimal web UI:
  terminal-style audit log
  pending approvals page
Add rate limits per agent/session/tool
```

**Success metric**: A normal MCP client can connect through ActantOS and only see/call policy-approved tools.

**Key Deliverables**:
* **MCP Configured Gateway**: Intercepts `tools/list` (filtered by policy) and `tools/call` (blocked or routed to approval). Clients connect to ActantOS, not directly to upstream MCP servers.
* **Tool Manifest Hashing & Pinning**: SHA-256 hash of tool name, schema, description, and server identity. Manifest changes disable the tool until admin approval.
* **SSRF Default Blocklist**: Blocks `localhost`, `169.254.x.x` (metadata IPs), and RFC-1918 private CIDRs unless explicitly allowlisted.
* **Minimal Dashboard**: Terminal-style audit log + pending approvals page. Full 5-screen dashboard (Agents · Sessions · Policies · Decisions · Audit) is added in Month 2–3.

---

### 6.3. Days 61–90: Prove Pilot Readiness

**Goal**: A design partner can govern one real internal agent workflow without custom engineering every time.

```
Add packaged CLI installer
Add policy templates (starter bundle)
Add dry-run mode (log decisions without blocking)
Add SIEM / webhook export
Add basic org / user / team model
Add gVisor optional runtime (single-tenant hosted)
Add self-host Docker Compose bundle
Run 2 design partner pilots
```

**Success metric**: A design partner can run one governed agent workflow end-to-end without custom engineering from the ActantOS team.

---

### 6.4. Month 3–6: Stable Product

```
Stable Pi adapter SDK package
Stable MCP gateway
Custom TypeScript / Python SDK
Policy bundle versioning
Approval TTL grants
gVisor single-tenant runtime (hosted)
OIDC login
Basic RBAC (org / role / policy set)
Audit export (CSV, SIEM webhook)
Tool manifest diff review UI
Hosted private beta
3–5 design partners
1–2 paid pilots
```

---

### 6.5. Month 6–12: Enterprise Platform

```
Firecracker execution tier (multi-tenant SaaS)
Credential broker (short-lived, target-scoped token injection)
Okta / Entra integration + SCIM
S3 Object Lock / WORM audit export (SOC 2, ISO 42001)
SIEM integrations (Splunk, Datadog)
Advanced approval workflows (multi-step, TTL grants, escalation)
MCP shadow traffic detection
Additional adapters: LangGraph, AutoGen, coding agents
Policy marketplace / template library
Enterprise self-host HA bundle
```

---

## 7. Risk Analysis & Mitigations

| # | Risk Event | Impact | Likelihood | Engineering Mitigation Strategy |
| :--- | :--- | :--- | :--- | :--- |
| 1 | **Sandbox Escape / Escape from Container** | Critical | Medium | Run processes as non-root users inside sandbox, strip Linux capabilities, enforce **gVisor** for single-tenant Day 1 deployments, and require **Firecracker** on bare-metal/nested KVM for multi-tenant Phase 3. |
| 2 | **Tool Description Poisoning / Manifest Tampering** | High | High | Compute and pin cryptographic hashes of tool manifests and descriptions. Suspend execution if a modified tool signature is detected. |
| 3 | **Confused Deputy / Token Exfiltration** | High | High | Prevent target credentials from passing through the client. The gateway injects short-lived, target-scoped credentials directly into the sandbox. |
| 4 | **Server-Side Request Forgery (SSRF)** | High | High | Enforce default-deny egress network policies inside the sandbox namespaces. Allow network calls only to allowlisted domains. |
| 5 | **Gateway Latency Overhead** | Medium | Medium | Run the AWS Cedar evaluator locally in-memory. Cache policy decisions and schema hashes. |
| 6 | **Pi / MCP Protocol Schema Drifts** | Medium | Low | Decouple the adapter translation layer from the core decision engine. Parse incoming requests against modular translation schemas. |
| 7 | **Bypass via Spawned Interactive Shells** | High | Medium | Parse command invocations. Block interactive shells (e.g., `bash -i`, `sh`) and restrict TTY allocation within the sandbox. |
| 8 | **Approval Fatigue** | Medium | High | Implement tiered policy budgets: low-risk operations auto-execute, medium-risk trigger warnings, and high-risk route to Slack. |
| 9 | **Shadow MCP Servers** | High | Medium | Enforce network routing rules: agents can only connect to external services through the ActantOS gateway proxy. |
| 10 | **Data Leakage in Audit Trails** | Medium | High | Normalize arguments and scrub sensitive values using regex patterns before writing to the database. Hash large inputs instead of storing them raw. |
| 11 | **Interpreter Execution Bypasses** | High | Medium | Use distroless container images stripped of shell/scripting runtimes in production to prevent execution of unapproved interpreters or scripts. |
| 12 | **Parameter Evasion** | High | High | Use the Gateway pre-execution parser to normalize all flag variations (such as mapping `rm -R` to a canonical `--recursive` token) before policy evaluation. |
| 13 | **Fail-Open Bypass under Daemon Failure** | Critical | Medium | Adapters enforce the Fail-Closed Contract: short decision timeouts (200ms local / 2s remote), fatal termination of the tool call and parent shell session on any daemon unreachability, and supervised `actantosd` with a liveness watchdog. No code path defaults to execute. |
| 14 | **Shell Expansion Evasion** | High | Medium | The pre-execution parser rejects commands containing unresolved variables, command/process substitution, backticks, or chained control operators unless fully resolved to a static argv before Cedar evaluation. |
| 15 | **TOCTOU Symlink Race** | Medium | Low | Sandbox mount namespaces (workspace-only bind mounts, `noexec`, read-only root) are the primary barrier; path canonicalization is defense-in-depth. File executors use `openat2` with `RESOLVE_BENEATH \| RESOLVE_NO_SYMLINKS` where available. |

---

## 8. Justification of Architectural Deviations

### 8.1. Dual Wedge: MCP-First for Market, Pi-First for Demo
1. **Addressable Market**: MCP is supported by Anthropic, Cursor, Claude Desktop, and LangGraph — broad market relevance from Day 1. Building for MCP first gives the largest addressable audience.
2. **Pi for Demo Speed**: Pi already exposes real file/shell/edit tools without built-in permission controls. That is exactly the problem ActantOS solves. A Pi guarded adapter (`guarded_bash`, `guarded_read`, etc.) calling `POST /v1/intercept/tool-call` can be built in Days 7–30 and produces a compelling, immediate demo without waiting for full MCP gateway implementation.
3. **Not Either/Or**: MCP gateway is the strategic wedge; Pi adapter is the fastest demo and developer proof. Both run in parallel.

### 8.2. Choosing AWS Cedar from Day 1 over OPA/Rego
1. **Preventing Technical Debt**: Starting with OPA and migrating later requires rewriting backend databases, decision API schemas, and customer policies. Cedar from Day 1 eliminates this overhead.
2. **Specialized Application Authorization**: OPA/Rego is designed for infrastructure policy. Cedar is built specifically for application-level RBAC/ABAC, structuring policies around principal, action, resource, and context.
3. **Auditability**: Cedar syntax is readable for security administrators; Rego (Datalog-based) is harder to audit.
4. **Analysis Workflows**: Cedar is designed for fast, analyzable authorization and supports policy validation and analysis tooling. Note: Cedar validates policy logic correctness — ActantOS should not claim formal proof of all real-world security behavior in marketing materials.
5. **PolicyDecisionProvider Abstraction**: Cedar is the default `PolicyDecisionProvider` but the abstraction allows adding an `OPAProvider` or custom provider later without database or API rewrites.

### 8.3. Phased Sandboxing Stack
1. **Docker for Local MVP**: Docker is the Day 1 sandbox. Fast to set up, sufficient to prove enforcement. Workspace-only mount and env allowlist provide adequate isolation for developer use cases.
2. **gVisor for Single-Tenant Hardening**: gVisor reduces the host-kernel attack surface via a user-space application kernel (Sentry). It is stronger than plain Docker but **not a replacement for microVM isolation** — it still shares the host kernel. Suitable for single-tenant hosted deployments.
3. **Firecracker for Multi-Tenant SaaS (Phase 3)**: Lightweight KVM-backed microVMs provide hardware virtualization boundaries for multi-tenant isolation. Still requires careful host kernel, networking, and side-channel hardening. Requires bare-metal or nested-virtualization-enabled compute.

---

## 9. Business Model — Open-Core Tiers

| Tier | Features | Price hypothesis |
| :--- | :--- | :--- |
| **Free / Open-Core** | Local `actantosd`, Pi adapter, MCP gateway, starter Cedar policies, local Postgres audit log | Free (self-hosted) |
| **Team SaaS** | Hosted dashboard, Slack approval, team-scoped policies, managed audit storage, usage analytics | $199–$499/month |
| **Startup Pilot** | Hosted gateway, design partner onboarding, policy review | $2k–$5k/month |
| **Enterprise Pilot** | gVisor runtime, OIDC, audit export, SLA | $25k–$75k/year |
| **Enterprise Scale** | Firecracker runtime, SCIM, WORM, SIEM, credential broker, private deployment | Custom |

> **Open-core boundary**: The enforcement kernel (`actantosd`, Cedar PDP, Docker sandbox, audit log hash-chain) is open-source. Hosted infrastructure, dashboard, enterprise integrations, and managed runtime are paid.

> **Pricing model note**: ActantOS value is tied to the number of governed agents, volume of sensitive tool calls, approval/audit volume, and risk level of connected systems — not just seat count.

---

## 10. Ideal Customer Profile (ICP)

### ICP 1: AI-Native DevTool Startups (Early Adopter)
* **Pain**: Developers use coding agents (Cursor, Claude Desktop, custom MCP clients) that can run shell commands, write files, and push to GitHub without any centralized controls.
* **Trigger**: A coding agent deletes a file, pushes broken code, or accesses credentials it shouldn't.
* **Value**: ActantOS blocks dangerous shell/file/GitHub actions, routes risky operations to Slack approval, and provides an audit trail — without requiring developers to change their toolchain.

### ICP 2: Mid-Market SaaS Security Teams
* **Pain**: Developers and operations teams are adopting MCP clients, Cursor, and custom agents without centralized visibility or access controls.
* **Trigger**: Security team is asked "what did that agent do last week?" and has no answer.
* **Value**: ActantOS provides a single control point for all agent tool calls, with session timelines, decision logs, and approval workflows visible to the security team.

### ICP 3: Regulated Operations Automation Teams
* **Pain**: Agents are being used to automate ticket handling, SaaS operations, and API workflows — but need formal approval workflows and audit evidence for compliance (SOC 2, ISO 42001).
* **Trigger**: Compliance audit requires evidence that agent actions were authorized and logged.
* **Value**: ActantOS provides cryptographic audit logs, approval state records, and WORM-ready evidence export without requiring custom engineering.

---

## 11. Go-to-Market Strategy

### Phase 1 GTM: Developer Adoption (Days 1–90)
```
Open-source the enforcement kernel (actantosd + Cedar adapter + Docker sandbox)
Publish the Pi guarded adapter demo repo
Target: AI-native developer communities (HN, Reddit r/LocalLLM, MCP Discord)
Metric: 100 GitHub stars + 5 demo conversations with potential design partners
```

### Phase 2 GTM: Design Partners (Month 2–6)
```
Convert 3–5 demo conversations into paid design partners
Offer white-glove onboarding for first 2 pilots
Target: Mid-market SaaS security teams and devtool startups
Metric: 2 paying pilots generating revenue and case study material
```

### Phase 3 GTM: Enterprise (Month 6–12)
```
Launch SaaS hosted tier with Firecracker runtime
Target regulated ops automation teams through security channel partners
Metric: 5+ paid enterprise contracts, pipeline for Series A narrative
```

### Why ActantOS Wins

Despite Cloudflare, Okta, and Microsoft entering adjacent spaces:

1. **In-path for tool execution** — not just network-edge or post-hoc governance. ActantOS blocks actions *before* they execute, at the tool-call layer.
2. **Framework-neutral** — Pi, MCP, custom agents, LangGraph, AutoGen. No vendor lock-in required from the agent runtime.
3. **Deterministic** — policy, approvals, budgets, and kill switch. Not LLM judgment, not heuristics.
4. **Developer-first** — open-core enforcement kernel, demoable Pi adapter, works locally before any cloud dependency.
5. **Creates enterprise evidence** — every decision, approval, and result is hash-chained and auditable. Cloudflare gives you network logs; ActantOS gives you signed decision records.

---

## 12. References

* **Forrester Category Definition**: Forrester Report (2026) - *Emerging Category: The Agent Control Plane*.
* **MCP Tool Specification**: Anthropic PBC — *Model Context Protocol: Tools, Resources, and Prompts (2025/2026)*.
* **MCP Security Best Practices**: Anthropic PBC — *Security Best Practices: Confused Deputy, Token Passthrough, SSRF in MCP*.
* **Tool Poisoning Attacks**: Invariant Labs — *MCP Security Notification: Tool Poisoning Attacks*.
* **gVisor Security**: Google — *google/gvisor: Application Kernel for Containers*.
* **Firecracker**: AWS — *Firecracker: Lightweight Virtualization for Serverless Applications*.
* **AWS Cedar Language**: Amazon Web Services — *Cedar language specification and validation workflows*.
* **Cedar Paper**: arXiv:2403.04651 — *Cedar: A New Language for Expressive, Fast, Safe, and Analyzable Authorization*.
* **Okta AI Agents**: Okta Inc. — *Okta for AI Agents: Generally Available (2026)*.
* **Microsoft Agent 365**: Microsoft — *The Control Plane for Agents*.
* **Cloudflare MCP Portal**: Cloudflare — *MCP Server Portals: Centralize and Secure MCP Servers*.
* **NIST AI RMF**: NIST — *Artificial Intelligence Risk Management Framework (AI 100-1)*.
* **Credo AI GAIA**: Credo AI — *GAIA Platform for AI Agent Governance*.
* **AppViewX Machine Identity**: AppViewX Governance Report — *PKI-Backed Machine Identity Security in Autonomous Workflows*.
* **Microsoft Agent Governance Toolkit**: Microsoft Developer Open Source Project — *Deterministic policy enforcement for agentic systems*.
