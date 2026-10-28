import { useState } from "react";
import Agents from "./components/Agents";
import LiveAudit from "./components/LiveAudit";
import Overview from "./components/Overview";
import Policy from "./components/Policy";
import Simulator from "./components/Simulator";

const TABS = ["Overview", "Live Audit", "Agents", "Simulator", "Policy"] as const;
type Tab = (typeof TABS)[number];

export default function App() {
  const [tab, setTab] = useState<Tab>("Overview");
  return (
    <div className="app">
      <header>
        <h1>SOC Agent Supervisor</h1>
        <nav>
          {TABS.map((t) => (
            <button key={t} className={t === tab ? "tab active" : "tab"} onClick={() => setTab(t)}>
              {t}
            </button>
          ))}
        </nav>
      </header>
      <main>
        {tab === "Overview" && <Overview />}
        {tab === "Live Audit" && <LiveAudit />}
        {tab === "Agents" && <Agents />}
        {tab === "Simulator" && <Simulator />}
        {tab === "Policy" && <Policy />}
      </main>
    </div>
  );
}
