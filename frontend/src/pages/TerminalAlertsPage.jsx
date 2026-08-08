import { useState } from "react";
import { ShieldAlert, Database } from "lucide-react";
import { useAuth } from "../contexts/AuthContext";
import { useData } from "../contexts/DataContext";
import { useTranslation } from "../i18n";
import AlertRow from "../components/AlertRow";
import InvestigationModal from "./InvestigationModal";
import AlertHistoryModal from "./AlertHistoryModal";

export default function TerminalAlertsPage() {
  const { fetchWithAuth, headers } = useAuth();
  const { wazuhAlerts, devices } = useData();
  const { t, lang } = useTranslation();
  const [alertFilterSeverity, setAlertFilterSeverity] = useState("");
  const [alertFilterIP, setAlertFilterIP] = useState("");
  const [alertFilterMAC, setAlertFilterMAC] = useState("");
  const [alertFilterTime, setAlertFilterTime] = useState("");
  const [showAlertHistory, setShowAlertHistory] = useState(false);
  const [isFetchingFullHistory, setIsFetchingFullHistory] = useState(false);
  const [fullAlertHistory, setFullAlertHistory] = useState([]);
  const [historySort, setHistorySort] = useState({ key: "timestamp", dir: "desc" });

  const [isInvestigating, setIsInvestigating] = useState(false);
  const [investigationTarget, setInvestigationTarget] = useState(null);
  const [deepForensics, setDeepForensics] = useState(null);
  const [aiBehaviorReport, setAiBehaviorReport] = useState(null);
  const [isAnalyzingBehavior, setIsAnalyzingBehavior] = useState(false);

  const fetchFullAlertHistory = async () => {
    setIsFetchingFullHistory(true);
    try {
      const res = await fetchWithAuth("/api/alerts/history", { headers });
      if (res.ok) setFullAlertHistory(await res.json());
    } catch {}
    setIsFetchingFullHistory(false);
  };

  const filterAlert = (a) => {
    const sev = parseInt(a.Severity || a.severity || 0);
    const ip = (a["Source IP"] || a.src_ip || a.srcip || "").toLowerCase();
    const mac = (a["MAC Address"] || a.mac || "").toLowerCase();
    const alertTime = new Date(a.Timestamp || a.timestamp || 0).getTime();
    const now = new Date().getTime();

    let passSeverity = true;
    if (alertFilterSeverity === "12") passSeverity = sev >= 12;
    else if (alertFilterSeverity === "8") passSeverity = sev >= 8 && sev < 12;
    else if (alertFilterSeverity === "4") passSeverity = sev >= 4 && sev < 8;
    else if (alertFilterSeverity === "0") passSeverity = sev >= 0 && sev < 4;

    let passTime = true;
    if (alertFilterTime === "5m") passTime = now - alertTime <= 5 * 60 * 1000;
    else if (alertFilterTime === "1h") passTime = now - alertTime <= 60 * 60 * 1000;
    else if (alertFilterTime === "24h") passTime = now - alertTime <= 24 * 60 * 60 * 1000;

    const passIP = alertFilterIP === "" || ip.includes(alertFilterIP.toLowerCase());
    const passMAC = alertFilterMAC === "" || mac.includes(alertFilterMAC.toLowerCase());
    return passSeverity && passIP && passMAC && passTime;
  };

  const filteredAlerts = wazuhAlerts.filter(filterAlert).sort((a, b) => parseInt(b.Severity || b.severity || 0) - parseInt(a.Severity || a.severity || 0));

  const handleInvestigate = async (target) => {
    const mac = target["MAC Address"] || target.mac;
    const ip = target["Source IP"] || target.srcip;
    const agentId = target["Agent ID"];
    const dev = devices.find((d) => d.mac === mac || d.ip === ip);
    setInvestigationTarget({ ...target, device: dev });
    setIsInvestigating(true);
    setDeepForensics(null);

    if (agentId && agentId !== "Unknown") {
      try {
        const res = await fetchWithAuth(`/api/wazuh/investigate/${agentId}`, { headers });
        if (res.ok) setDeepForensics(await res.json());
      } catch {}
    }
  };

  const inputStyle = {
    background: "rgba(255,255,255,0.03)", border: "1px solid var(--border)",
    color: "var(--text-primary)", padding: "8px 12px", borderRadius: "8px",
    outline: "none", fontSize: "13px", transition: "all 0.3s ease",
  };

  return (
    <div className="tab-pane">
      <div className="section-card">
        <div className="section-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "15px", padding: "15px 20px" }}>
          <h2 style={{ margin: 0, display: "flex", alignItems: "center", gap: "10px" }}>
            <ShieldAlert size={20} color="var(--danger)" /> Orchestrated SOC Alerts
          </h2>
          <div style={{ display: "flex", alignItems: "center", gap: "12px", flexWrap: "wrap" }}>
            <button
              onClick={() => { setShowAlertHistory(true); fetchFullAlertHistory(); }}
              disabled={isFetchingFullHistory}
              style={{
                background: "rgba(14, 165, 233, 0.1)", border: "1px solid rgba(14, 165, 233, 0.3)",
                color: "var(--accent-blue)", padding: "8px 14px", borderRadius: "8px", fontSize: "12px",
                fontWeight: 600, cursor: isFetchingFullHistory ? "not-allowed" : "pointer",
                display: "flex", alignItems: "center", gap: "6px", opacity: isFetchingFullHistory ? 0.6 : 1,
              }}
            >
              <Database size={14} /> {isFetchingFullHistory ? "Loading..." : "Full History"}
            </button>
            <div style={{ display: "flex", gap: "12px", flexWrap: "wrap" }}>
              <select style={inputStyle} value={alertFilterTime} onChange={(e) => setAlertFilterTime(e.target.value)}>
                <option value="" style={{ background: "#0a0c12" }}>Time: All</option>
                <option value="5m" style={{ background: "#0a0c12" }}>Last 5 Minutes</option>
                <option value="1h" style={{ background: "#0a0c12" }}>Last 1 Hour</option>
                <option value="24h" style={{ background: "#0a0c12" }}>Last 24 Hours</option>
              </select>
              <select style={inputStyle} value={alertFilterSeverity} onChange={(e) => setAlertFilterSeverity(e.target.value)}>
                <option value="" style={{ background: "#0a0c12" }}>Severity: All</option>
                <option value="12" style={{ background: "#0a0c12" }}>Critical (12+)</option>
                <option value="8" style={{ background: "#0a0c12" }}>High (8-11)</option>
                <option value="4" style={{ background: "#0a0c12" }}>Medium (4-7)</option>
                <option value="0" style={{ background: "#0a0c12" }}>Low (0-3)</option>
              </select>
              <input type="text" style={{ ...inputStyle, width: "180px" }} placeholder="Search IP..." value={alertFilterIP} onChange={(e) => setAlertFilterIP(e.target.value)} />
              <input type="text" style={{ ...inputStyle, width: "180px" }} placeholder="Search MAC..." value={alertFilterMAC} onChange={(e) => setAlertFilterMAC(e.target.value)} />
            </div>
          </div>
        </div>
        <div className="table-wrapper">
          <table className="custom-table">
            <thead>
              <tr><th>Time</th><th>Description</th><th>Severity</th><th>IP</th><th>MAC Address</th><th>Employee</th><th>Action</th></tr>
            </thead>
            <tbody>
              {filteredAlerts.length > 0 ? (
                filteredAlerts.map((a, idx) => (
                  <AlertRow key={(a.Timestamp || a.timestamp || "") + (a.Description || a.description || "") + idx} alert={a} t={t} onInvestigate={handleInvestigate} />
                ))
              ) : (
                <tr><td colSpan="7" style={{ textAlign: "center", padding: "40px", color: "var(--text-muted)" }}>No Active Threats Found</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {isInvestigating && investigationTarget && (
        <InvestigationModal
          target={investigationTarget}
          deepForensics={deepForensics}
          aiBehaviorReport={aiBehaviorReport}
          isAnalyzingBehavior={isAnalyzingBehavior}
          onClose={() => { setIsInvestigating(false); setAiBehaviorReport(null); }}
          onRunAI={(agentId) => {
            setIsAnalyzingBehavior(true);
            setAiBehaviorReport(null);
            fetchWithAuth(`/api/wazuh/ai-report/${agentId}`, { headers })
              .then(async (res) => {
                if (!res.ok || !res.body) return;
                const reader = res.body.getReader();
                const decoder = new TextDecoder();
                let text = "";
                while (true) {
                  const { done, value } = await reader.read();
                  if (done) break;
                  text += decoder.decode(value, { stream: true });
                  setAiBehaviorReport(text);
                }
              })
              .finally(() => setIsAnalyzingBehavior(false));
          }}
        />
      )}

      {showAlertHistory && (
        <AlertHistoryModal
          lang={lang}
          isFetching={isFetchingFullHistory}
          alerts={fullAlertHistory}
          historySort={historySort}
          setHistorySort={setHistorySort}
          onClose={() => setShowAlertHistory(false)}
        />
      )}
    </div>
  );
}
