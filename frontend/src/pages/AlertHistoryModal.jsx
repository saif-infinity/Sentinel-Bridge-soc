import { Database, X } from "lucide-react";

export default function AlertHistoryModal({ lang, isFetching, alerts, historySort, setHistorySort, onClose }) {
  return (
    <div
      className="modal-overlay"
      style={{
        position: "fixed", inset: 0, background: "rgba(5, 8, 15, 0.85)", backdropFilter: "blur(15px)",
        zIndex: 2000, display: "flex", alignItems: "center", justifyContent: "center", padding: "20px",
      }}
      onClick={onClose}
    >
      <div
        className="modal-content"
        style={{
          background: "#0a0c12", border: "1px solid var(--border)", borderRadius: "24px",
          width: "90%", maxWidth: "1200px", maxHeight: "90vh", overflow: "hidden",
          display: "flex", flexDirection: "column",
          boxShadow: "0 25px 50px -12px rgba(0, 0, 0, 0.5), 0 0 0 1px rgba(255,255,255,0.05)",
        }}
        onClick={(e) => e.stopPropagation()}
      >
        <div style={{ padding: "20px 30px", borderBottom: "1px solid var(--border)", display: "flex", justifyContent: "space-between", alignItems: "center", background: "linear-gradient(to right, rgba(14, 165, 233, 0.05), transparent)" }}>
          <h2 style={{ margin: 0, display: "flex", alignItems: "center", gap: "15px", color: "#fff" }}>
            <Database size={24} color="var(--accent-blue)" /> {lang === "fr" ? "Historique Complet des Alertes" : "Full Alert History"}
          </h2>
          <button onClick={onClose} style={{ background: "transparent", border: "none", color: "var(--text-muted)", cursor: "pointer" }}>
            <X size={24} />
          </button>
        </div>
        <div style={{ padding: "30px", overflowY: "auto", flex: 1 }}>
          {isFetching ? (
            <div style={{ textAlign: "center", padding: "50px", color: "var(--text-muted)" }}>
              <div className="discovery-pulse" style={{ margin: "0 auto 20px auto", width: "40px", height: "40px", background: "var(--accent-blue)" }}></div>
              {lang === "fr" ? "Chargement des donnees..." : "Loading database records..."}
            </div>
          ) : alerts.length === 0 ? (
            <div style={{ textAlign: "center", padding: "50px", color: "var(--text-muted)" }}>
              {lang === "fr" ? "Aucune alerte trouvee dans la base de donnees." : "No alerts found in the database."}
            </div>
          ) : (
            <div className="table-wrapper">
              <table className="custom-table">
                <thead>
                  <tr>
                    <th style={{ cursor: "pointer", userSelect: "none" }} onClick={() => setHistorySort((s) => ({ key: "timestamp", dir: s.key === "timestamp" && s.dir === "desc" ? "asc" : "desc" }))}>
                      {lang === "fr" ? "Horodatage" : "Timestamp"}
                      {historySort.key === "timestamp" && (historySort.dir === "desc" ? " \u25BC" : " \u25B2")}
                    </th>
                    <th>Description</th>
                    <th style={{ cursor: "pointer", userSelect: "none" }} onClick={() => setHistorySort((s) => ({ key: "severity", dir: s.key === "severity" && s.dir === "desc" ? "asc" : "desc" }))}>
                      {lang === "fr" ? "Severite" : "Severity"}
                      {historySort.key === "severity" && (historySort.dir === "desc" ? " \u25BC" : " \u25B2")}
                    </th>
                    <th>Source IP</th>
                    <th>MAC Address</th>
                    <th>Agent ID</th>
                  </tr>
                </thead>
                <tbody>
                  {alerts.slice().sort((a, b) => {
                    if (historySort.key === "timestamp") {
                      return historySort.dir === "desc"
                        ? new Date(b.Timestamp) - new Date(a.Timestamp)
                        : new Date(a.Timestamp) - new Date(b.Timestamp);
                    }
                    if (historySort.key === "severity") {
                      const sevA = parseInt(a.Severity || 0);
                      const sevB = parseInt(b.Severity || 0);
                      return historySort.dir === "desc" ? sevB - sevA : sevA - sevB;
                    }
                    return 0;
                  }).map((alert, index) => (
                    <tr key={index}>
                      <td style={{ color: "var(--text-muted)", fontSize: "12px" }}>{new Date(alert.Timestamp).toLocaleString()}</td>
                      <td style={{ fontWeight: 500 }}>{alert.Description}</td>
                      <td>
                        <span className={parseInt(alert.Severity) >= 10 ? "suricata-sev-critical" : parseInt(alert.Severity) >= 7 ? "suricata-sev-high" : "suricata-sev-medium"}>
                          Level {alert.Severity}
                        </span>
                      </td>
                      <td style={{ fontFamily: "monospace", color: "#7dd3fc" }}>{alert["Source IP"] || "-"}</td>
                      <td style={{ fontFamily: "monospace", color: "#94a3b8" }}>{alert["MAC Address"] || "-"}</td>
                      <td>{alert["Agent ID"] || "Unknown"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
