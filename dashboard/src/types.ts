// TypeScript shapes of every API response the dashboard uses.

export type Decision = "ALLOW" | "DENY" | "ERROR";

export interface AuditRow {
  id: number;
  timestamp: string;
  request_id: string;
  agent_did: string | null;
  role: string | null;
  action: string;
  resource: string | null;
  decision: Decision;
  reason: string;
  http_status: number;
  latency_ms: number;
  token_verify_ms: number | null;
  opa_ms: number | null;
  token_jti: string | null;
  prev_hash: string;
  row_hash: string;
}

export interface AgentCounts {
  total: number;
  ALLOW: number;
  DENY: number;
  ERROR: number;
}

export interface Stats {
  total: number;
  allowed: number;
  denied: number;
  errors: number;
  average_latency_ms: number;
  per_agent: Record<string, AgentCounts>;
}

export interface ChainResult {
  valid: boolean;
  rows_checked: number;
  first_broken_id: number | null;
  reason: string | null;
}

export interface AgentInfo {
  did: string;
  role: string;
  status: string;
  credential_status: string;
  last_action: {
    timestamp: string;
    action: string;
    resource: string | null;
    decision: Decision;
  } | null;
}

export interface DemoStep {
  step: number;
  title: string;
  request: string;
  status: number;
  decision: Decision;
  detail: string;
  expected: string;
  decision_ms: string | null;
}

export interface DemoResult {
  scenario: string;
  summary: string;
  steps: DemoStep[];
}

export interface PolicyResponse {
  policy: string;
}
