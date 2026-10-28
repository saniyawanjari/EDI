import { getAgents } from "../api";
import { usePolling } from "../usePolling";
import DecisionBadge from "./DecisionBadge";

export default function Agents() {
  const { data: agents, error } = usePolling(getAgents, 5000);
  if (error) return <p className="error">Cannot load agents: {error}</p>;
  if (!agents) return <p>Loading...</p>;
  if (agents.length === 0) return <p>No agents yet. Run: python scripts/create_agents.py</p>;

  return (
    <div className="cards">
      {agents.map((agent) => (
        <div className="card wide" key={agent.did}>
          <div className="card-label">{agent.role}</div>
          <div className="mono">{agent.did}</div>
          <p>
            Status: <b>{agent.status}</b>
          </p>
          <p>
            Credential:{" "}
            <b className={agent.credential_status === "valid" ? "ok" : "error"}>{agent.credential_status}</b>
          </p>
          <p>
            Last action:{" "}
            {agent.last_action ? (
              <>
                {agent.last_action.action} on {agent.last_action.resource ?? "-"}{" "}
                <DecisionBadge decision={agent.last_action.decision} />
              </>
            ) : (
              "none yet"
            )}
          </p>
        </div>
      ))}
    </div>
  );
}
