import { useState } from "react";
import { runScenario } from "../api";
import type { DemoResult } from "../types";
import DecisionBadge from "./DecisionBadge";

const SCENARIOS = [
  { id: "normal_flow", label: "Normal flow (A \u2192 B \u2192 C)" },
  { id: "analyst_blocks_ip", label: "Log Analyst tries to block an IP" },
  { id: "expired_token", label: "Expired token" },
  { id: "forged_token", label: "Forged token" },
  { id: "revoked_token", label: "Revoked token" },
  { id: "protected_ip", label: "Block the protected gateway IP" },
];

export default function Simulator() {
  const [result, setResult] = useState<DemoResult | null>(null);
  const [running, setRunning] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function run(id: string) {
    setRunning(id);
    setError(null);
    try {
      setResult(await runScenario(id));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setRunning(null);
    }
  }

  return (
    <div>
      <p>Each button runs the REAL flow against the API (dev only). Watch the Live Audit tab.</p>
      <div className="toolbar">
        {SCENARIOS.map((s) => (
          <button key={s.id} disabled={running !== null} onClick={() => void run(s.id)}>
            {running === s.id ? "Running..." : s.label}
          </button>
        ))}
      </div>

      {error && <p className="error">{error}</p>}
      {result && (
        <div>
          <h3>{result.scenario}</h3>
          <p>{result.summary}</p>
          <table>
            <thead>
              <tr>
                <th>#</th>
                <th>Step</th>
                <th>Request</th>
                <th>HTTP</th>
                <th>Decision</th>
                <th>Expected</th>
                <th>Detail</th>
              </tr>
            </thead>
            <tbody>
              {result.steps.map((s) => (
                <tr key={s.step}>
                  <td>{s.step}</td>
                  <td>{s.title}</td>
                  <td className="mono">{s.request}</td>
                  <td>{s.status}</td>
                  <td>
                    <DecisionBadge decision={s.decision} />
                  </td>
                  <td>{s.expected}</td>
                  <td>{s.detail}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
