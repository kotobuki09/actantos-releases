I reviewed your pasted ActantOS plan again and checked the current market/tooling landscape. The main correction is this:

**ActantOS should not be framed as “AI agent governance on top of Pi.”**
Better: **ActantOS is a model-agnostic agent control plane / runtime governance OS. Pi is only the first execution harness. MCP is the bigger market entry.**

Your original direction already says “build framework and OS instead of just another AI,” and that is the right strategic move. 

## 1. Deep research conclusion

The market is validating your idea. Forrester formally described the **agent control plane** as a third enterprise plane, separate from the build plane and orchestration plane. Its role is to inventory, govern, orchestrate, and assure heterogeneous AI agents across vendors and domains. Forrester specifically says governance needs to sit **outside** the build/orchestration layer so it can provide independent oversight and intervention. ([Forrester][1])

That means ActantOS should position itself as:

> **The runtime control plane for AI agents: identity, policy, approvals, audit, kill switch, and safe tool execution across any model, framework, or MCP server.**

This is stronger than saying “we secure Pi agents.”

## 2. What was right in the old plan

The old plan had several good instincts:

| Original idea                        |        Keep / Change | Reason                                                                        |
| ------------------------------------ | -------------------: | ----------------------------------------------------------------------------- |
| Build framework + OS, not another AI |             **Keep** | Models become commodities; control layer becomes infrastructure.              |
| Start with Pi                        | **Keep, but narrow** | Pi is a good first integration because it lacks built-in permission controls. |
| Gateway/interceptor architecture     |             **Keep** | Runtime enforcement is the real product.                                      |
| Human approval workflow              |             **Keep** | Enterprises want control, reversibility, and accountability.                  |
| Audit log                            |             **Keep** | This becomes compliance evidence and buyer trust.                             |
| Quantum-safe roadmap                 |            **Delay** | Good future story, bad MVP priority.                                          |
| Advanced vector memory governance    |            **Delay** | Too much complexity before proving the core gateway.                          |

Pi is a valid first wedge because its GitHub documentation says it has **no built-in permission system** for filesystem, process, network, or credential access, and by default it runs with the permissions of the user/process that launched it. ([GitHub][2])

## 3. What needs to be corrected

Some claims in the previous pasted plan should be treated carefully. The Forrester “agent control plane” claim is real and sourceable. The MCP security gap is real and sourceable. The Pi permission gap is real and sourceable. But claims like exact NeuralTrust funding, exact intervention percentages, and some competitor-specific architecture details need stronger sources before using them in a pitch deck.

Do **not** build investor/business messaging on weak claims. Build it on these verified points instead:

1. **Agent control plane is becoming a recognized category.** ([Forrester][1])
2. **Pi lacks built-in permission isolation.** ([GitHub][2])
3. **MCP standardizes tool access but does not fully define governance before execution.** Microsoft explicitly says MCP standardizes the execution surface but does not define how that surface should be governed or where policy should be evaluated before tool calls. ([Microsoft Developer][3])
4. **MCP security guidance already warns about token passthrough, audit gaps, trust-boundary failures, and SSRF.** ([Model Context Protocol][4])
5. **Regulators are starting to care about agentic AI kill switches and circuit breakers.** Reuters reported on June 30, 2026 that the Bank of England is considering guardrails, circuit breakers, and kill switches for agentic AI in finance. ([Reuters][5])

## 4. Improved ActantOS positioning

### Bad positioning

“ActantOS is a governance layer for Pi agents.”

Too small. Too tied to one framework.

### Better positioning

“ActantOS is the runtime control plane for enterprise AI agents.”

Good, but a little generic.

### Best positioning

**ActantOS is the policy firewall and operating layer for AI agents before they touch real tools, data, APIs, or enterprise systems.**

This makes the value immediately clear.

## 5. Improved product thesis

**The future enterprise will not use one agent framework.** It will have Copilot agents, LangGraph agents, internal Python agents, MCP servers, coding agents, workflow agents, and SaaS-native agents. Forrester’s control-plane framing supports this: enterprises need governance outside individual agent platforms because agents will be heterogeneous across vendors and domains. ([Forrester][1])

So ActantOS should not compete with LangGraph, AutoGen, Pi, CrewAI, or MCP. It should sit **above and around them**.

The product should answer six questions:

1. **Who is this agent?**
2. **Who owns it?**
3. **What can it access?**
4. **What can it execute?**
5. **What requires human approval?**
6. **What exactly happened, and can we prove it later?**

Okta’s AI agent product messaging validates this identity-first angle: discover agents, onboard them, control connections, enforce least privilege, use short-lived credentials, maintain audit trails, and revoke access when needed. ([Okta][6])

## 6. Competitor review

| Category                     | Examples                                | What they do                                                                                                                                                                                                                | ActantOS opportunity                                                               |
| ---------------------------- | --------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| AI governance / GRC          | Credo AI                                | Registry, agent cards, policy packs, regulatory mapping, evidence, monitoring. Credo says it supports agents, models, applications, workflows, EU AI Act, NIST AI RMF, ISO 42001, Slack, GitHub, Jira, etc. ([Credo AI][7]) | Do not fight them on compliance paperwork first. Win on runtime enforcement.       |
| Identity governance          | Okta, AppViewX                          | Treat agents as first-class identities, short-lived credentials, secret vaulting, access revocation, lifecycle governance. ([Okta][6])                                                                                      | Integrate with them later. For MVP, build your own lightweight agent identity.     |
| AI security gateway          | NeuralTrust, Lakera-style products      | Prompt security, data leakage prevention, gateway controls, rate limits, red teaming, observability. ([NeuralTrust][8])                                                                                                     | Differentiate by governing **tool execution**, not only prompts/responses.         |
| MCP governance               | Microsoft AGT, MCP security gateways    | Microsoft AGT adds governance to MCP servers: policy enforcement, startup scanning, runtime tool-call governance, response sanitization. ([Microsoft for Developers][9])                                                    | ActantOS should be framework-neutral and usable outside Microsoft/.NET ecosystems. |
| Sandboxing/runtime isolation | Docker Sandboxes, Firecracker, microVMs | Docker Sandboxes run AI coding agents in isolated microVMs with separate filesystem, network, and Docker daemon. ([Docker Documentation][10])                                                                               | Use this instead of building your own sandbox early.                               |

## 7. The real MVP

Your MVP should not be a full OS yet. It should be a **runtime decision point**.

### MVP name

**ActantOS Gateway**

### Core promise

> “No AI agent action reaches tools, APIs, files, shell, or SaaS systems until ActantOS evaluates policy.”

### MVP features

| Feature                | MVP requirement                                                                            |
| ---------------------- | ------------------------------------------------------------------------------------------ |
| Agent identity         | Each agent session gets `agent_id`, `owner_id`, `org_id`, `session_id`.                    |
| Tool-call interception | Agent calls ActantOS before file, shell, HTTP, GitHub, database, Drive, Slack, email, etc. |
| Policy engine          | Deterministic allow / deny / approval_required.                                            |
| Audit log              | Store request, decision, reason, timestamp, actor, resource, result hash.                  |
| Rate limit             | Max tool calls, max runtime, max cost estimate.                                            |
| Human approval         | Slack approval first. Teams later.                                                         |
| Kill switch            | Disable agent/session/org instantly.                                                       |
| Dashboard              | Only enough to show agents, blocked actions, approvals, audit logs.                        |

Do **not** use LLM-as-judge for authorization. Use deterministic policy. Open Policy Agent is relevant because it separates policy decision-making from enforcement and supports policy-as-code across APIs, microservices, Kubernetes, CI/CD, and gateways. ([Open Policy Agent][11]) Cedar is also relevant because it supports RBAC and ABAC-style authorization and returns allow/deny decisions with determining policies. ([AWS Documentation][12])

## 8. Improved architecture

```text
                     ┌──────────────────────────────┐
                     │        Admin Dashboard        │
                     │ agents / policies / audit     │
                     └──────────────┬───────────────┘
                                    │
                     ┌──────────────▼───────────────┐
                     │        ActantOS Control       │
                     │ registry / owners / policy UI │
                     └──────────────┬───────────────┘
                                    │
┌──────────────┐       ┌────────────▼──────────────┐       ┌──────────────┐
│ Pi Agent     │──────▶│      ActantOS Gateway      │──────▶│ Tools / APIs  │
│ MCP Client   │       │ policy / approval / audit  │       │ MCP / SaaS    │
│ LangGraph    │◀──────│ rate limit / kill switch   │◀──────│ Files / Shell │
└──────────────┘       └────────────┬──────────────┘       └──────────────┘
                                    │
                     ┌──────────────▼───────────────┐
                     │       Evidence Store          │
                     │ audit logs / hashes / traces  │
                     └──────────────────────────────┘
```

Important design principle:

**The agent is untrusted. The gateway is trusted. The policy engine must run outside the agent’s process.**

This aligns with Forrester’s point that governance must sit outside build and orchestration environments to preserve independent visibility and intervention. ([Forrester][1])

## 9. Pi integration plan

Use Pi only as your first proof case.

### Step 1: Wrap risky Pi tools

Start with:

* file read
* file write
* shell command
* HTTP request
* GitHub operation
* environment variable / secret access

Every risky tool becomes:

```json
{
  "agent_id": "agent_123",
  "session_id": "sess_456",
  "tool": "shell.exec",
  "action": "run",
  "resource": "local_workspace",
  "arguments": {
    "cmd": "rm -rf ./prod-data"
  },
  "risk": "high"
}
```

ActantOS returns:

```json
{
  "decision": "deny",
  "reason": "Shell destructive command blocked by policy",
  "audit_id": "audit_789"
}
```

### Step 2: Use Docker Sandboxes for local safety

For early developer demos, Docker Sandboxes are attractive because they run AI coding agents in isolated microVMs with their own filesystem and network, while still allowing the agent to build containers and modify files without touching the host. ([Docker Documentation][10])

### Step 3: Do not fork Pi deeply

Do not become dependent on maintaining a Pi fork. Build an adapter. The long-term value is the ActantOS policy/gateway layer, not a modified Pi runtime.

## 10. MCP gateway plan

This is more important than Pi long-term.

MCP has become the standard way for agents to discover and use tools, but Microsoft notes that MCP does not define how the execution surface should be governed or where policy should be evaluated before a tool call. ([Microsoft Developer][3])

So ActantOS should become:

> **An MCP security and policy gateway that sits between MCP clients and MCP servers.**

### MCP risks ActantOS should handle

| Risk               | ActantOS control                                                                                                                                                         |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Token passthrough  | Reject tokens not issued for the MCP server; enforce audience validation. MCP guidance explicitly calls token passthrough an anti-pattern. ([Model Context Protocol][4]) |
| Confused deputy    | Bind agent identity, user identity, resource, and purpose.                                                                                                               |
| SSRF               | Block internal IPs, metadata endpoints, private network ranges unless explicitly allowed.                                                                                |
| Tool poisoning     | Scan MCP tool descriptions and manifests before exposing them to agents.                                                                                                 |
| Overbroad scopes   | Require least-privilege scopes and short-lived credentials.                                                                                                              |
| Shadow MCP servers | Registry + approval before use.                                                                                                                                          |
| Audit gaps         | Log every call, decision, resource, and response hash.                                                                                                                   |

## 11. Compliance angle

Do not sell “we make you compliant” too early. Sell:

> **ActantOS produces runtime evidence for AI governance.**

NIST AI RMF is voluntary and focused on improving trustworthy AI risk management across design, development, use, and evaluation. NIST also released a 2026 concept note for trustworthy AI in critical infrastructure, which supports your critical-infrastructure messaging later. ([NIST][13])

ISO/IEC 42001 applies to organizations that develop, integrate, use, or manage AI systems, and includes AI policy, risk management, data governance, lifecycle controls, monitoring, and continual improvement. ([ISO][14])

ActantOS should map product features to these frameworks, but the MVP should remain runtime-first:

| Framework need        | ActantOS evidence                |
| --------------------- | -------------------------------- |
| Inventory             | Agent registry                   |
| Risk management       | Policy classification            |
| Monitoring            | Runtime logs                     |
| Human accountability  | Owner + approval workflow        |
| Control effectiveness | Blocked/approved action evidence |
| Continual improvement | Policy changes + incident review |

## 12. 90-day improved build plan

### Days 1–10: Category + PRD

Output:

* Product one-liner
* Architecture diagram
* Threat model
* Competitor table
* MVP spec
* Demo script

Decision:

**ActantOS = Agent Runtime Control Plane. Pi adapter = first integration. MCP gateway = strategic expansion.**

### Days 11–25: Gateway kernel

Build:

* `POST /v1/decision`
* `POST /v1/audit`
* `POST /v1/approval/request`
* `POST /v1/session/kill`
* PostgreSQL schema
* basic policy engine

Policy decision format:

```json
{
  "decision": "allow | deny | approval_required",
  "reason": "string",
  "policy_id": "string",
  "audit_id": "string"
}
```

### Days 26–40: Pi adapter

Build:

* wrapper for file read/write
* wrapper for shell command
* wrapper for HTTP request
* local sandbox demo
* blocked action demo

Demo:

> “Pi tries to read a sensitive file and send it externally. ActantOS blocks it, logs it, and explains why.”

### Days 41–55: Approval flow

Build:

* Slack approval
* pending approval queue
* approve/deny webhook
* resume/abort execution state
* audit trail for human decision

### Days 56–70: Dashboard

Build only five screens:

1. Agents
2. Sessions
3. Policies
4. Pending approvals
5. Audit logs

No fancy analytics yet.

### Days 71–90: MCP gateway prototype

Build:

* register MCP server
* proxy MCP tool list
* hide risky tools from agent
* evaluate tool call before forwarding
* log response hash
* block SSRF/test malicious request

This makes the product much bigger than Pi.

## 13. 6-month roadmap

| Month | Build                                            |
| ----- | ------------------------------------------------ |
| 1     | Gateway kernel + policy decision API             |
| 2     | Pi adapter + demo                                |
| 3     | Slack approval + audit dashboard                 |
| 4     | MCP gateway prototype                            |
| 5     | GitHub, Google Drive, Slack, Postgres connectors |
| 6     | VPC/local deployment package + first pilots      |

## 14. 12-month roadmap

| Quarter | Focus                                                                              |
| ------- | ---------------------------------------------------------------------------------- |
| Q1      | Runtime enforcement MVP                                                            |
| Q2      | MCP governance + enterprise connectors                                             |
| Q3      | Identity integrations: Okta, Entra, short-lived credentials                        |
| Q4      | Advanced enterprise: tamper-evident logs, policy packs, SOC2 evidence, VPC/on-prem |

Delay quantum-safe identity until you already have enterprise pull. AppViewX is already pushing AI agent identity with PKI and quantum-era messaging, so you can use that as future validation, but it should not be your first build. ([AppViewX][15])

## 15. Business model recommendation

Best early model:

**Open-core developer framework + paid enterprise control plane.**

Free/open:

* SDK
* Pi adapter
* local policy engine
* basic audit logs
* local demo

Paid:

* dashboard
* organization management
* Slack/Teams approvals
* hosted gateway
* MCP gateway
* enterprise connectors
* VPC deployment
* audit export
* SSO
* policy templates
* kill switch
* long-term log retention

Avoid absorbing LLM costs. Use **BYOK / customer-paid model APIs**. Your product should monetize governance, not tokens.

## 16. Landing page message

Use sharper pain:

**Headline:**
Govern AI agents before they touch real tools, data, or production systems.

**Subheadline:**
ActantOS is the runtime control plane for enterprise AI agents — enforcing identity, policy, approval workflows, audit logs, rate limits, and kill switches across Pi, MCP, and custom agents.

**Core sections:**

1. Agents are moving from chat to action.
2. Existing IAM was built for humans and services, not autonomous agents.
3. ActantOS intercepts every high-risk action before execution.
4. Policy decides: allow, deny, or require approval.
5. Every action becomes auditable evidence.
6. Works across models, frameworks, and MCP tools.

## 17. Improved `/goal` command

/goal Conduct deep research and produce a stronger build plan for ActantOS, a model-agnostic Agent Runtime Control Plane / Agent OS.

Context:
ActantOS should not be another AI agent, chatbot, or model wrapper. It should be the runtime governance layer that controls what AI agents can access, remember, decide, and execute before they touch enterprise tools, APIs, files, databases, SaaS systems, shell commands, or MCP servers.

The first integration target is earendil-works/pi because Pi has an agent runtime and tool execution model but does not provide built-in enterprise permission controls. However, Pi must be treated only as the first harness. The bigger long-term strategy is to support MCP-compatible agents, custom agents, LangGraph/AutoGen-style agents, coding agents, and enterprise workflow agents.

Research objectives:

1. Review the current agent control plane market.

   * Study Forrester’s agent control plane framing.
   * Compare Credo AI, Okta for AI Agents, AppViewX Agent Identity Security, NeuralTrust, Microsoft Agent Governance Toolkit, MCP gateways, and AI security gateway vendors.
   * Separate compliance/governance platforms from true runtime enforcement platforms.
   * Identify white space for ActantOS.

2. Review Pi deeply.

   * Identify where Pi lacks permission controls.
   * Identify how to intercept file, shell, HTTP, GitHub, credential, and process actions.
   * Recommend adapter/wrapper strategy without deeply forking Pi.
   * Recommend sandbox approach using Docker Sandboxes, microVMs, or other isolation layers.

3. Review MCP deeply.

   * Explain how ActantOS can become an MCP policy gateway.
   * Cover risks including token passthrough, confused deputy, SSRF, malicious MCP servers, tool poisoning, overbroad scopes, shadow MCP servers, session hijacking, and audit gaps.
   * Propose a concrete MCP proxy architecture.

4. Design ActantOS architecture.

   * Agent identity and registry.
   * Runtime gateway.
   * Deterministic policy engine.
   * Human approval workflow.
   * Audit/evidence store.
   * Rate limits and cost controls.
   * Kill switch.
   * Dashboard.
   * Pi adapter.
   * MCP gateway.

5. Produce a realistic MVP plan.

   * Keep the MVP cheap, deterministic, and fast to build.
   * Do not use LLM-as-judge for core authorization.
   * Do not build advanced DLP, vector memory governance, quantum-safe crypto, complex compliance packs, or multi-cloud enterprise deployment in the MVP.
   * Focus first on allow / deny / approval_required, audit logs, Slack approval, rate limits, and kill switch.

6. Produce business strategy.

   * Recommend open-core vs SaaS vs enterprise license.
   * Recommend BYOK/token-cost strategy.
   * Define first 3 pilot customer profiles.
   * Define pricing hypothesis.
   * Define developer adoption strategy.
   * Define enterprise buyer messaging.

Required output:

1. Executive summary.
2. Corrected product positioning.
3. Market map and competitor table.
4. Technical architecture diagram in text form.
5. MVP feature list.
6. Features to delay.
7. Pi integration plan.
8. MCP gateway plan.
9. Data model proposal.
10. Policy model proposal using RBAC/ABAC and OPA/Rego or Cedar-style policy.
11. API schema for tool-call interception.
12. Human approval flow.
13. Audit and evidence model.
14. Sandboxing/deployment recommendation.
15. Cost-control model.
16. Open-core and enterprise business model.
17. 30/60/90-day build plan.
18. 6-month roadmap.
19. 12-month roadmap.
20. Demo script.
21. Landing page copy.
22. Top 10 risks and mitigations.
23. Final recommendation for what to build this week.

Quality requirements:

* Use current sources and cite them.
* Flag unverified claims.
* Be practical for a solo founder or very small team.
* Prefer runtime enforcement over dashboards.
* Prefer deterministic security controls over AI-based judgment.
* Make the final plan strong enough for engineering, investor discussion, and landing page strategy.

## Final recommendation

Build this first:

**ActantOS Gateway v0.1 + Pi adapter + one killer demo.**

The killer demo should show:

1. Pi agent receives a task.
2. It attempts a risky action.
3. ActantOS intercepts the action.
4. Policy returns deny or approval_required.
5. Slack approval appears.
6. Human approves/denies.
7. Audit log records the full event.
8. Dashboard shows blocked risk, policy reason, and evidence.

That demo proves the whole company. Everything else is expansion.