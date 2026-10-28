// All calls to the Supervisor API live here.
import type { AgentInfo, AuditRow, ChainResult, DemoResult, PolicyResponse, Stats } from "./types";

const API_URL: string = import.meta.env.VITE_API_URL ?? "http://localhost:8000";
// DEV ONLY: this key is visible in the browser. Fine for a local demo, never for production.
const ADMIN_KEY: string = import.meta.env.VITE_ADMIN_KEY ?? "";

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const response = await fetch(`${API_URL}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", "x-admin-key": ADMIN_KEY },
  });
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}: ${await response.text()}`);
  }
  return (await response.json()) as T;
}

export function getStats(): Promise<Stats> {
  return request<Stats>("/api/v1/audit/stats");
}

export function getAudit(decision: string, agent: string, limit = 100): Promise<AuditRow[]> {
  const params = new URLSearchParams({ limit: String(limit) });
  if (decision) params.set("decision", decision);
  if (agent) params.set("agent", agent);
  return request<AuditRow[]>(`/api/v1/audit?${params.toString()}`);
}

export function verifyChain(): Promise<ChainResult> {
  return request<ChainResult>("/api/v1/audit/verify-chain");
}

export function getAgents(): Promise<AgentInfo[]> {
  return request<AgentInfo[]>("/api/v1/agents");
}

export function getPolicy(): Promise<PolicyResponse> {
  return request<PolicyResponse>("/api/v1/policy");
}

export function runScenario(name: string): Promise<DemoResult> {
  return request<DemoResult>(`/api/v1/demo/run/${name}`, { method: "POST" });
}
