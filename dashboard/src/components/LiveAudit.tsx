import { useState } from "react";
import { getAudit, verifyChain } from "../api";
import type { AuditRow, ChainResult } from "../types";
import { usePolling } from "../usePolling";
import DecisionBadge from "./DecisionBadge";

const CSV_COLUMNS: (keyof AuditRow)[] = [
  "id", "timestamp", "agent_did", "role", "action", "resource", "decision", "reason",
  "http_status", "latency_ms", "token_verify_ms", "opa_ms",
];

function toCsv(rows: AuditRow[]): string {
  const escape = (value: unknown) => `"${String(value ?? "").replace(/"/g, '""')}"`;
  const lines = rows.map((row) => CSV_COLUMNS.map((c) => escape(row[c])).join(","));
  return [CSV_COLUMNS.join(","), ...lines].join("\n");
}

function downloadCsv(rows: AuditRow[]) {
  const blob = new Blob([toCsv(rows)], { type: "text/csv" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = "audit_log.csv";
  link.click();
  URL.revokeObjectURL(link.href);
}

export default function LiveAudit() {
  const [decision, setDecision] = useState("");
  const [agent, setAgent] = useState("");
  const [chain, setChain] = useState<ChainResult | null>(null);
  const [chainError, setChainError] = useState<string | null>(null);

  // refreshes every 2 seconds
  const { data: rows, error } = usePolling(() => getAudit(decision, agent, 100), 2000, [decision, agent]);

  async function onVerify() {
    try {
      setChainError(null);
      setChain(await verifyChain());
    } catch (e) {
      setChainError(e instanceof Error ? e.message : String(e));
    }
  }

  return (
    <div>
      <div className="toolbar">
        <label>
          Decision{" "}
          <select value={decision} onChange={(e) => setDecision(e.target.value)}>
            <option value="">all</option>
            <option value="ALLOW">ALLOW</option>
            <option value="DENY">DENY</option>
            <option value="ERROR">ERROR</option>
          </select>
        </label>
        <label>
          Agent DID{" "}
          <input value={agent} placeholder="did:example:agent-a" onChange={(e) => setAgent(e.target.value.trim())} />
        </label>
        <button onClick={() => rows && downloadCsv(rows)} disabled={!rows}>
          Export CSV
        </button>
        <button onClick={() => void onVerify()}>Verify chain</button>
        {chain && (
          <span className={chain.valid ? "ok" : "error"}>
            {chain.valid
              ? `Chain valid (${chain.rows_checked} rows)`
              : `Chain BROKEN at row ${chain.first_broken_id}: ${chain.reason}`}
          </span>
        )}
        {chainError && <span className="error">{chainError}</span>}
      </div>

      {error && <p className="error">Cannot load audit log: {error}</p>}
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Agent</th>
            <th>Role</th>
            <th>Action</th>
            <th>Resource</th>
            <th>Decision</th>
            <th>Reason</th>
            <th>ms</th>
          </tr>
        </thead>
        <tbody>
          {(rows ?? []).map((row) => (
            <tr key={row.id}>
              <td>{row.timestamp.slice(11, 23)}</td>
              <td>{row.agent_did ?? "-"}</td>
              <td>{row.role ?? "-"}</td>
              <td>{row.action}</td>
              <td>{row.resource ?? "-"}</td>
              <td>
                <DecisionBadge decision={row.decision} />
              </td>
              <td>{row.reason}</td>
              <td>{row.latency_ms.toFixed(2)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
