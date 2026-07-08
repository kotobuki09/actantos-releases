export interface TenantsTable {
  readonly id: string
  readonly name: string
  readonly status: string
  readonly created_at: Date | string
}

export interface UsersTable {
  readonly tenant_id: string
  readonly id: string
  readonly name: string
  readonly role: string
  readonly status: string
  readonly created_at: Date | string
}

export interface AgentsTable {
  readonly id: string
  readonly external_id: string
  readonly tenant_id: string
  readonly name: string
  readonly runtime_type: string
  readonly owner_user_id: string
  readonly environment: string
  readonly risk_tier: string
  readonly status: string
  readonly created_at: Date | string
}

export interface SessionsTable {
  readonly id: string
  readonly external_id: string
  readonly tenant_id: string
  readonly agent_id: string
  readonly user_id: string
  readonly purpose: string | null
  readonly cwd: string | null
  readonly status: string
  readonly started_at: Date | string
  readonly ended_at: Date | string | null
}

export interface PolicyBundlesTable {
  readonly id: string
  readonly tenant_id: string
  readonly version: string
  readonly engine: string
  readonly source_hash: string
  readonly source_text: string
  readonly active: boolean
  readonly created_at: Date | string
}

export interface RiskRuleSetsTable {
  readonly tenant_id: string
  readonly rules_json: unknown
  readonly updated_at: Date | string
}

export interface ToolCallsTable {
  readonly id: string
  readonly request_id: string
  readonly tenant_id: string
  readonly session_id: string
  readonly agent_id: string
  readonly tool_kind: string
  readonly tool_name: string
  readonly operation: string
  readonly resource_json: unknown
  readonly action_json: unknown
  readonly normalized_json: unknown
  readonly mcp_json: unknown
  readonly scope_hash: string
  readonly status: string
  readonly result_hash: string | null
  readonly started_at: Date | string | null
  readonly finished_at: Date | string | null
  readonly error_code: string | null
  readonly created_at: Date | string
}

export interface PolicyDecisionsTable {
  readonly id: string
  readonly request_id: string
  readonly tenant_id: string
  readonly tool_call_id: string
  readonly policy_bundle_id: string | null
  readonly cedar_result: string
  readonly risk_class: string
  readonly approval_req: boolean
  readonly final_decision: string
  readonly decision_mode: string
  readonly reason: string
  readonly reason_code: string
  readonly constraints_json: unknown
  readonly created_at: Date | string
}

export interface ApprovalsTable {
  readonly id: string
  readonly tenant_id: string
  readonly decision_id: string
  readonly tool_call_id: string
  readonly status: string
  readonly approver_user_id: string | null
  readonly decided_by: string | null
  readonly one_use_token_hash: string | null
  readonly scope_hash: string
  readonly expires_at: Date | string
  readonly decided_at: Date | string | null
  readonly used_at: Date | string | null
  readonly used_by_request_id: string | null
  readonly created_at: Date | string
}

export interface AuditEventsTable {
  readonly id: string
  readonly tenant_id: string
  readonly event_type: string
  readonly actor_type: string
  readonly actor_id: string
  readonly session_id: string | null
  readonly tool_call_id: string | null
  readonly decision_id: string | null
  readonly seq: string | number | bigint
  readonly payload_json: unknown
  readonly prev_hash: string
  readonly event_hash: string
  readonly created_at: Date | string
}

export interface AuditChainStateTable {
  readonly tenant_id: string
  readonly last_hash: string
  readonly seq: string | number | bigint
  readonly updated_at: Date | string
}

export interface BudgetsTable {
  readonly id: string
  readonly tenant_id: string
  readonly scope_type: string
  readonly scope_id: string
  readonly metric: string
  readonly limit_value: string | number
  readonly window_seconds: number
  readonly current_value: string | number
  readonly window_start: Date | string
}

export interface RateLimitsTable {
  readonly id: string
  readonly tenant_id: string
  readonly scope_type: string
  readonly scope_id: string
  readonly action_key: string
  readonly limit_value: string | number
  readonly window_seconds: number
  readonly current_value: string | number
  readonly window_start: Date | string
}

export interface KillSwitchesTable {
  readonly id: string
  readonly tenant_id: string
  readonly scope_type: string
  readonly scope_id: string
  readonly reason: string
  readonly enabled: boolean
  readonly created_at: Date | string
}

export interface ActantDatabaseSchema {
  readonly agents: AgentsTable
  readonly approvals: ApprovalsTable
  readonly audit_chain_state: AuditChainStateTable
  readonly audit_events: AuditEventsTable
  readonly budgets: BudgetsTable
  readonly kill_switches: KillSwitchesTable
  readonly policy_bundles: PolicyBundlesTable
  readonly policy_decisions: PolicyDecisionsTable
  readonly rate_limits: RateLimitsTable
  readonly risk_rule_sets: RiskRuleSetsTable
  readonly sessions: SessionsTable
  readonly tenants: TenantsTable
  readonly tool_calls: ToolCallsTable
  readonly users: UsersTable
}
