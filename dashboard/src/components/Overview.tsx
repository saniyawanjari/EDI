import { getStats } from "../api";
import { usePolling } from "../usePolling";

function Card({ label, value, color }: { label: string; value: string | number; color?: string }) {
  return (
    <div className="card">
      <div className="card-label">{label}</div>
      <div className="card-value" style={{ color }}>
        {value}
      </div>
    </div>
  );
}

export default function Overview() {
  const { data: stats, error } = usePolling(getStats, 3000);
  if (error) return <p className="error">Cannot load stats: {error}</p>;
  if (!stats) return <p>Loading...</p>;

  const bars = [
    { label: "Allowed", value: stats.allowed, color: "#1a7f37" },
    { label: "Denied", value: stats.denied, color: "#cf222e" },
    { label: "Errors", value: stats.errors, color: "#bf8700" },
  ];
  const max = Math.max(1, ...bars.map((b) => b.value));

  return (
    <div>
      <div className="cards">
        <Card label="Total decisions" value={stats.total} />
        <Card label="Allowed" value={stats.allowed} color="#1a7f37" />
        <Card label="Denied" value={stats.denied} color="#cf222e" />
        <Card label="Average latency" value={`${stats.average_latency_ms} ms`} />
      </div>

      <h3>Allowed vs denied</h3>
      <svg width="100%" height={bars.length * 40 + 10} role="img" aria-label="allowed versus denied">
        {bars.map((bar, i) => (
          <g key={bar.label} transform={`translate(0, ${i * 40 + 5})`}>
            <text x="0" y="20" fontSize="14">
              {bar.label}
            </text>
            <rect x="80" y="4" height="24" rx="3" fill={bar.color} width={`${(bar.value / max) * 70}%`} />
            <text x="82" y="21" fontSize="13" fill="#fff">
              {bar.value > 0 ? bar.value : ""}
            </text>
          </g>
        ))}
      </svg>

      <h3>Per agent</h3>
      <table>
        <thead>
          <tr>
            <th>Agent</th>
            <th>Total</th>
            <th>Allowed</th>
            <th>Denied</th>
            <th>Errors</th>
          </tr>
        </thead>
        <tbody>
          {Object.entries(stats.per_agent).map(([did, c]) => (
            <tr key={did}>
              <td>{did}</td>
              <td>{c.total}</td>
              <td>{c.ALLOW}</td>
              <td>{c.DENY}</td>
              <td>{c.ERROR}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
