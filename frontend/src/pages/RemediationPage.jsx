import { useState, useEffect } from "react";
import { Shield } from "lucide-react";
import { useAuth } from "../contexts/AuthContext";

export default function RemediationPage() {
  const { fetchWithAuth, headers } = useAuth();
  const [activeResponses, setActiveResponses] = useState([]);

  const fetchActiveResponses = async () => {
    if (!headers || Object.keys(headers).length === 0) return;
    try {
      const res = await fetchWithAuth("/api/wazuh/active-responses", { headers });
      if (res.ok) {
        const data = await res.json();
        setActiveResponses(Array.isArray(data) ? data : (data.responses || []));
      }
    } catch {}
  };

  useEffect(() => {
    fetchActiveResponses();
    const interval = setInterval(fetchActiveResponses, 30000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="tab-content fadeIn">
      <div className="section-header">
        <h2>Active Response History</h2>
      </div>

      <div className="ar-timeline">
        {activeResponses.length === 0 ? (
          <div className="empty-state card">
            <span className="icon" style={{ fontSize: "3rem", opacity: 0.3 }}>&#128737;</span>
            <p>Aucune action de defense detectee pour le moment.</p>
          </div>
        ) : (
          <div className="section-card border-glow" style={{ padding: "0", overflow: "hidden", width: "100%", maxWidth: "100%" }}>
            <div className="section-header" style={{ borderLeft: "4px solid var(--primary)" }}>
              <h2 style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                <Shield size={20} color="var(--primary)" />
                Active Defense Timeline
              </h2>
              <span className="status-pill status-success">{activeResponses.length} Actions</span>
            </div>
            <div className="table-wrapper" style={{ maxHeight: "500px", overflowY: "auto", width: "100%" }}>
              <table className="custom-table" style={{ tableLayout: "fixed", width: "100%" }}>
                <thead>
                  <tr>
                    <th style={{ width: "160px" }}>Timestamp</th>
                    <th style={{ width: "180px" }}>Action</th>
                    <th style={{ width: "150px" }}>Target Agent</th>
                    <th style={{ width: "100px" }}>Level</th>
                    <th>Technical Log Preview</th>
                  </tr>
                </thead>
                <tbody>
                  {activeResponses
                    .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
                    .map((ar, idx) => {
                      const isUnblock = (ar.action || "").toLowerCase().includes("unblock");
                      const severityLevel = parseInt(ar.level || 0);
                      const isCritical = severityLevel >= 10;
                      return (
                        <tr key={idx} className={`${isUnblock ? "suricata-row-low" : severityLevel >= 7 ? "suricata-row-critical" : "suricata-row-medium"} ${isCritical ? "critical-row-pulse" : ""}`}>
                          <td style={{ color: "var(--text-muted)", fontSize: "11px", whiteSpace: "nowrap" }}>
                            {new Date(ar.timestamp).toLocaleString()}
                          </td>
                          <td>
                            <span className={`suricata-sev-${isUnblock ? "low" : severityLevel >= 7 ? "critical" : "medium"}`} style={{ textTransform: "uppercase", fontWeight: "bold" }}>
                              {ar.action}
                            </span>
                          </td>
                          <td style={{ fontFamily: "monospace", fontSize: "12px", color: "#7dd3fc" }}>{ar.agent_id || "N/A"}</td>
                          <td>
                            <span className={`suricata-sev-${isCritical ? "critical" : severityLevel >= 4 ? "high" : "medium"}`}>
                              Level {severityLevel}
                            </span>
                          </td>
                          <td style={{ fontSize: "11px", color: "var(--text-muted)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", maxWidth: "300px" }}>
                            {ar.full_log || ar.output || ar.message || "No log output available"}
                          </td>
                        </tr>
                      );
                    })}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
