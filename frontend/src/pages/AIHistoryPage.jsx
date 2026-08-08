import { useState, useEffect } from "react";
import { FileText, ShieldAlert, Network, Activity, Globe } from "lucide-react";
import { useAuth } from "../contexts/AuthContext";
import { formatReport } from "../lib/formatters";

export default function AIHistoryPage() {
  const { fetchWithAuth, headers } = useAuth();
  const [aiHistory, setAiHistory] = useState([]);
  const [isFetchingHistory, setIsFetchingHistory] = useState(false);
  const [historyError, setHistoryError] = useState("");
  const [selectedReport, setSelectedReport] = useState(null);

  const fetchAiHistory = async () => {
    setIsFetchingHistory(true);
    setHistoryError("");
    try {
      const res = await fetchWithAuth("/api/analyse/history", { headers });
      if (res.ok) {
        setAiHistory(await res.json());
      } else {
        const errText = await res.text().catch(() => "");
        setHistoryError(errText || `Erreur lors du chargement de l'historique (${res.status})`);
      }
    } catch {
      setHistoryError("Impossible de contacter le serveur pour charger l'historique IA.");
    }
    setIsFetchingHistory(false);
  };

  useEffect(() => {
    fetchAiHistory();
  }, []);

  const threatReports = aiHistory.filter((r) => r.report_type === "threat_analysis");
  const networkReports = aiHistory.filter((r) => r.report_type === "global_network");
  const behavioralReports = aiHistory.filter((r) => r.report_type === "behavioral");
  const globalReports = aiHistory.filter((r) => r.report_type === "global");

  const tableStyle = { width: "100%", borderCollapse: "collapse", fontSize: "13px" };
  const thStyle = { textAlign: "left", padding: "12px 16px", borderBottom: "1px solid var(--border)", color: "var(--text-muted)", fontWeight: "600", fontSize: "11px", textTransform: "uppercase", letterSpacing: "0.5px" };
  const tdStyle = { padding: "12px 16px", borderBottom: "1px solid rgba(255,255,255,0.04)", cursor: "pointer" };

  const renderReportTable = (reports, icon, color, bgColor, label) => (
    <div className="section-card" style={{ padding: "0", overflow: "hidden" }}>
      <div className="section-header" style={{ padding: "18px 20px", background: bgColor, borderBottom: "1px solid var(--border)" }}>
        <h3 style={{ margin: 0, fontSize: "15px", display: "flex", alignItems: "center", gap: "10px" }}>
          {icon} {label}
          <span style={{ fontSize: "11px", color: "var(--text-muted)", fontWeight: "normal" }}>({reports.length} rapport{reports.length > 1 ? "s" : ""})</span>
        </h3>
      </div>
      <div style={{ overflowX: "auto" }}>
        <table style={tableStyle}>
          <thead><tr><th style={thStyle}>Date de creation</th><th style={thStyle}>ID Rapport</th></tr></thead>
          <tbody>
            {reports.map((report) => (
              <tr key={report.id} onClick={() => setSelectedReport(report)} style={{ transition: "background 0.2s", cursor: "pointer" }}
                onMouseEnter={(e) => (e.currentTarget.style.background = "rgba(255,255,255,0.03)")}
                onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}>
                <td style={tdStyle}>{new Date(report.timestamp).toLocaleString()}</td>
                <td style={{ ...tdStyle, fontFamily: "monospace", color: "var(--accent-cyan)", fontSize: "12px" }}>{report.id}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );

  return (
    <div className="tab-pane active" style={{ display: "flex", flexDirection: "column", gap: "20px", height: "100%", overflowY: "auto", paddingRight: "10px" }}>
      <div className="section-card" style={{ flex: "0 0 auto", padding: "25px", background: "linear-gradient(90deg, rgba(56, 189, 248, 0.05) 0%, transparent 100%)" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <div>
            <h2 style={{ display: "flex", alignItems: "center", gap: "12px", fontSize: "24px" }}>
              <FileText size={28} color="var(--accent-cyan)" /> Historique des Rapports IA
            </h2>
            <p style={{ color: "var(--text-muted)", margin: "5px 0 0 0" }}>Consultez tous les rapports generes par l'Intelligence Artificielle.</p>
          </div>
          <button className="btn-primary" onClick={fetchAiHistory} disabled={isFetchingHistory} style={{ padding: "8px 16px", background: "rgba(56, 189, 248, 0.2)", color: "var(--accent-cyan)" }}>
            {isFetchingHistory ? "Chargement..." : "Actualiser"}
          </button>
        </div>
      </div>

      {historyError && (
        <div className="section-card" style={{ padding: "16px 20px", border: "1px solid rgba(239,68,68,0.4)", background: "rgba(239,68,68,0.08)" }}>
          <p style={{ margin: 0, color: "#f87171", fontSize: "13px" }}>
            <ShieldAlert size={16} style={{ verticalAlign: "middle", marginRight: "8px" }} />
            {historyError}
          </p>
        </div>
      )}

      {selectedReport ? (
        <div className="section-card" style={{ position: "relative", padding: "25px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "20px" }}>
            <div>
              <span style={{
                padding: "4px 8px", borderRadius: "4px", fontSize: "12px", fontWeight: "bold",
                background: selectedReport.report_type === "threat_analysis" ? "rgba(255,165,0,0.2)" : selectedReport.report_type === "global_network" ? "rgba(99,102,241,0.2)" : selectedReport.report_type === "behavioral" ? "rgba(16,185,129,0.2)" : "rgba(139,92,246,0.2)",
                color: selectedReport.report_type === "threat_analysis" ? "#ffb020" : selectedReport.report_type === "global_network" ? "#818cf8" : selectedReport.report_type === "behavioral" ? "#10b981" : "#a78bfa",
              }}>
                {selectedReport.report_type === "threat_analysis" ? "Analyse Wazuh (Alertes Critiques)" : selectedReport.report_type === "global_network" ? "Audit Reseau Global (Suricata)" : selectedReport.report_type === "behavioral" ? "Analyse Comportementale" : "Rapport Global"}
              </span>
              <span style={{ fontSize: "13px", color: "var(--text-muted)", marginLeft: "15px" }}>{new Date(selectedReport.timestamp).toLocaleString()}</span>
            </div>
            <button className="btn-primary" onClick={() => setSelectedReport(null)} style={{ padding: "6px 14px", fontSize: "11px", background: "rgba(255,255,255,0.05)", color: "var(--text-muted)" }}>Retour</button>
          </div>
          <div style={{ overflowY: "auto", maxHeight: "70vh", padding: "20px", background: "rgba(0,0,0,0.1)", borderRadius: "12px" }}>
            <div className="markdown-body" style={{ fontSize: "13px", lineHeight: "1.6" }}>{formatReport(selectedReport.content)}</div>
          </div>
        </div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: "25px" }}>
          {aiHistory.length === 0 && !isFetchingHistory && !historyError ? (
            <div className="section-card" style={{ textAlign: "center", padding: "60px" }}>
              <FileText size={48} color="var(--text-muted)" style={{ opacity: 0.5, marginBottom: "20px", display: "inline-block" }} />
              <h4 style={{ margin: 0 }}>Aucun rapport trouve</h4>
              <p style={{ color: "var(--text-muted)", marginTop: "10px" }}>Lancez une analyse IA pour generer des rapports dans cette section.</p>
            </div>
          ) : (
            <>
              {threatReports.length > 0 && renderReportTable(threatReports, <ShieldAlert size={18} color="#ffb020" />, "#ffb020", "rgba(255,165,0,0.05)", "Analyse Wazuh (Alertes Critiques)")}
              {networkReports.length > 0 && renderReportTable(networkReports, <Network size={18} color="#818cf8" />, "#818cf8", "rgba(99,102,241,0.05)", "Audit Reseau Global (Suricata)")}
              {behavioralReports.length > 0 && renderReportTable(behavioralReports, <Activity size={18} color="#10b981" />, "#10b981", "rgba(16,185,129,0.05)", "Analyse Comportementale")}
              {globalReports.length > 0 && renderReportTable(globalReports, <Globe size={18} color="#a78bfa" />, "#a78bfa", "rgba(139,92,246,0.05)", "Rapport Global")}
            </>
          )}
        </div>
      )}
    </div>
  );
}
