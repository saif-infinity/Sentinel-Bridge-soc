import { useState } from "react";
import { Radar } from "lucide-react";
import { useAuth } from "../contexts/AuthContext";
import { useData } from "../contexts/DataContext";
import { useTranslation } from "../i18n";

export default function RadarPage() {
  const { fetchWithAuth, headers } = useAuth();
  const { trackTask } = useData();
  const { lang } = useTranslation();
  const [scanResults, setScanResults] = useState([]);
  const [isScanning, setIsScanning] = useState(false);
  const [subnet, setSubnet] = useState("");
  const [scanType, setScanType] = useState("fast");

  const startNetworkScan = async (subnet, type) => {
    if (isScanning) return;
    setIsScanning(true);
    setScanResults([]);

    try {
      const r = await fetchWithAuth("/api/tasks/nmap-scan", {
        method: "POST",
        headers,
        body: JSON.stringify({ target: subnet || "auto", scan_type: type }),
      });
      if (r.ok) {
        const { task_id } = await r.json();
        trackTask(task_id, "Nmap Scan", subnet || "auto");
        const interval = setInterval(async () => {
          try {
            const res = await fetchWithAuth(`/api/tasks/status/${task_id}`, { headers });
            if (res.ok) {
              const data = await res.json();
              if (data.status === "SUCCESS") {
                clearInterval(interval);
                setScanResults(
                  data.result.results.map((r) => ({ ip: r.ip, mac: r.mac, status: [r.os, ...r.ports] }))
                );
                setIsScanning(false);
              } else if (data.status === "FAILURE") {
                clearInterval(interval);
                setIsScanning(false);
              }
            }
          } catch {
            clearInterval(interval);
            setIsScanning(false);
          }
        }, 3000);
      } else {
        setIsScanning(false);
      }
    } catch {
      setIsScanning(false);
    }
  };

  return (
    <div className="tab-pane animate-fade-in">
      <div className="section-card">
        <div className="section-header">
          <h2><Radar size={18} /> Network Reconnaissance</h2>
          <div style={{ display: "flex", gap: "10px" }}>
            <input
              type="text"
              placeholder="Target Subnet (Auto if empty)"
              value={subnet}
              onChange={(e) => setSubnet(e.target.value)}
              style={{ width: "100%", maxWidth: "200px" }}
            />
            <select
              value={scanType}
              onChange={(e) => setScanType(e.target.value)}
              style={{
                background: "rgba(255,255,255,0.05)", border: "1px solid var(--border)",
                color: "white", borderRadius: "12px", padding: "0 15px", fontSize: "13px", cursor: "pointer",
              }}
            >
              <option value="fast" style={{ background: "#0a0c12" }}>
                {lang === "fr" ? "Decouverte Rapide" : "Fast Discovery"}
              </option>
              <option value="ports" style={{ background: "#0a0c12" }}>
                {lang === "fr" ? "Scan de Ports" : "Port Scan"}
              </option>
              <option value="services" style={{ background: "#0a0c12" }}>
                {lang === "fr" ? "Detection Services" : "Service Detection"}
              </option>
              <option value="os" style={{ background: "#0a0c12" }}>
                {lang === "fr" ? "Detection OS" : "OS Detection"}
              </option>
              <option value="vuln" style={{ background: "#0a0c12" }}>
                {lang === "fr" ? "Audit Vulnerabilite" : "Vulnerability Audit"}
              </option>
            </select>
            <button className="btn-primary" onClick={() => startNetworkScan(subnet, scanType)} disabled={isScanning}>
              {isScanning ? "Analyzing..." : "Run Scan"}
            </button>
          </div>
        </div>
        <div className="table-wrapper">
          <table className="custom-table">
            <thead>
              <tr><th>IP</th><th>MAC Address</th><th>State</th></tr>
            </thead>
            <tbody>
              {scanResults.map((r, i) => (
                <tr key={i}>
                  <td>{r.ip}</td>
                  <td>{r.mac}</td>
                  <td>
                    <div style={{ display: "flex", flexDirection: "column", gap: "4px" }}>
                      {Array.isArray(r.status) ? (
                        r.status.map((item, idx) => (
                          <div key={idx} style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                            <div style={{ width: "4px", height: "4px", borderRadius: "50%", background: "var(--accent-cyan)" }} />
                            <span style={{ fontSize: "12px" }}>{item}</span>
                          </div>
                        ))
                      ) : (
                        <span style={{ fontSize: "12px" }}>{r.status}</span>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
