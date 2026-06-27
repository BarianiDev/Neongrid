import { useState, useEffect} from "react";

const SEVERITY_COLORS = {
  CRITICAL: "#e74c3c",
  HIGH: "#e67e22",
  MEDIUM: "#f1c40f",
  LOW: "#3498db",
};

const API = "http://localhost:8000";

function App() {
  const [alerts, setAlerts] = useState([]);
  const [scans, setScans] = useState([]);

  useEffect(() => {
    const load = () => {
      fetch(`${API}/api/alerts`).then((r) => r.json()).then(setAlerts);
      fetch(`${API}/api/scans`).then((r) => r.json()).then(setScans);
    };

    load();
    const id = setInterval(load, 5000);
    return () => clearInterval(id);
  }, []);

  const countBySeverity = (severity) =>
    alerts.filter((a) => a.severity === severity).length;



  return (
    <div style={{padding: "2rem", fontFamily: "sans-serif", background: "#0f1117", color: "#e6e6e6", minHeight: "100vh" }}>
      <h1>NeonGrid - Security Dashboard</h1>

      <div style={{ display: "flex", gap: "1rem", marginBottom: "2rem" }}>
        {["CRITICAL", "HIGH", "MEDIUM"].map((sev) => (
          <div key={sev} style={{background: "#1a1d27", padding: "1rem 1.5rem", borderRadius: "6px", borderTop: `3px solid ${SEVERITY_COLORS[sev]}` }}>
            <div style={{ fontSize: "1.8rem", fontWeight: "bold", color: SEVERITY_COLORS[sev] }}>{countBySeverity(sev)}</div>
            <div style={{ fontSize: "0.8rem", color: "#9aa" }}>{sev}</div>
            </div>
        ))}
       <div style={{ background: "#1a1d27", padding: "1rem 1.5rem", borderRadius: "6px", borderTop: "3px solid #888" }}>
          <div style={{ fontSize: "1.8rem", fontWeight: "bold" }}>{scans.length}</div>
          <div style={{ fontSize: "0.8rem", color: "#9aa" }}>OPEN PORTS</div>
        </div>
      </div>

      <h2>Alerts ({alerts.length})</h2>
      {alerts.map((alert, index) => (
        <div key={index} style={{ background: "#1a1d27", borderLeft: `5px solid ${SEVERITY_COLORS[alert.severity] || "#888"}`, padding: "0.8rem 1rem", marginBottom: "0.6rem", borderRadius: "4px" }}>
          <span style={{ color: SEVERITY_COLORS[alert.severity] || "#888", fontWeight: "bold" }}>[{alert.severity}]</span>{" "}
          <strong>{alert.rule}</strong> — {alert.detail}
          {alert.mitre_id && (
            <span style={{ marginLeft: "0.5rem", fontSize: "0.75rem", background: "#2a2e3a", padding: "0.15rem 0.5rem", borderRadius: "10px", color: "#9ab" }}>
              {alert.mitre_id} {alert.mitre_technique}
            </span>
          )}
        </div>
      ))}

      <h2 style={{ marginTop: "2rem" }}>Open Ports ({scans.length})</h2>
      {scans.map((scan, index) => (
        <div key={index} style={{ background: "#1a1d27", padding: "0.6rem 1rem", marginBottom: "0.4rem", borderRadius: "4px" }}>
          Port {scan.port} ({scan.service}) on {scan.target_ip} — risk:{" "}
          <span style={{ color: SEVERITY_COLORS[scan.risk] || "#888", fontWeight: "bold" }}>{scan.risk}</span>
        </div>
      ))}
    </div>
  );
}

export default App;