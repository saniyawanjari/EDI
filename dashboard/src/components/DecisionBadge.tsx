import type { Decision } from "../types";

// green = ALLOW, red = DENY, amber = ERROR
const COLORS: Record<Decision, string> = {
  ALLOW: "#1a7f37",
  DENY: "#cf222e",
  ERROR: "#bf8700",
};

export default function DecisionBadge({ decision }: { decision: Decision }) {
  return (
    <span className="badge" style={{ background: COLORS[decision] }}>
      {decision}
    </span>
  );
}
