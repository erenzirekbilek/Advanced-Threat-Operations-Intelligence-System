import React from "react";
import Dashboard from "./components/Dashboard";
import ThreatList from "./components/ThreatList";
import ComplianceStatus from "./components/ComplianceStatus";
import AttackSimulator from "./components/AttackSimulator";

function App() {
  return (
    <div style={{ padding: "20px", fontFamily: "Arial" }}>
      <h1>🛡️ ESIP - Enterprise Security & Intelligence Platform</h1>
      <Dashboard />
      <hr />
      <ThreatList />
      <hr />
      <ComplianceStatus />
      <hr />
      <AttackSimulator />
    </div>
  );
}

export default App;
