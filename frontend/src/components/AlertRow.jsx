import { memo } from "react";
import { ShieldAlert, Shield, Search, FileSearch } from "lucide-react";
import IntelBadge from "./IntelBadge";
import { useData } from "../contexts/DataContext";
import { SEVERITY_CRITICAL, SEVERITY_HIGH } from "../lib/formatters";

const RISK_PILL = {
  critical: "bg-red-500/10 text-red-400 border border-red-500/20",
  high: "bg-orange-500/10 text-orange-400 border border-orange-500/20",
  medium: "bg-yellow-500/10 text-yellow-400 border border-yellow-500/20",
  low: "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20",
};
const VISIBLE_INV_STATUSES = ["running", "scoring", "summarizing", "awaiting_response", "complete"];

const AlertRow = memo(({ alert, onInvestigate, t }) => {
  const { investigations } = useData();
  const alertId = alert.id ?? alert.alert_id ?? alert.ID ?? null;
  const inv = (() => {
    if (alertId == null || !investigations?.length) return null;
    const sid = String(alertId);
    return investigations.find((it) => String(it.trigger_alert_id) === sid && (it.trigger_alert_type === "alert" || !it.trigger_alert_type) && VISIBLE_INV_STATUSES.includes(it.status)) || null;
  })();
  const sev = parseInt(alert.Severity || alert.severity || 0);
  // Seuils partagés (lib/formatters) : « critique » ne veut plus dire >=12 ici
  // et >=10 ailleurs. isHigh passait de >=7 à >=8 pour s'aligner sur le reste.
  const isCritical = sev >= SEVERITY_CRITICAL;
  const isHigh = sev >= SEVERITY_HIGH && sev < SEVERITY_CRITICAL;

  const formatTime = (ts) => {
    if (!ts) return "--:--";
    const date = new Date(ts);
    const now = new Date();
    const isToday = date.toDateString() === now.toDateString();
    return isToday
      ? date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })
      : date.toLocaleDateString([], { day: "2-digit", month: "short" }) +
          " " +
          date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  };

  const rawDesc = alert.Description || alert.description || "Unknown security event";
  const cleanDesc = rawDesc.replace(/^Wazuh Alert: /i, "").replace(/^Suricata: /i, "");
  const timestamp = formatTime(alert.Timestamp || alert.timestamp);

  return (
    <tr className={isCritical ? "critical-row" : ""}>
      <td style={{ fontSize: "11px", color: "var(--text-muted)", whiteSpace: "nowrap" }}>
        {timestamp}
      </td>
      <td className={isCritical ? "critical-text" : ""} style={{ fontWeight: "600", maxWidth: "400px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
          {isCritical ? <ShieldAlert size={16} className="critical-icon" /> : <Shield size={16} />}
          <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
            {cleanDesc}
          </span>
        </div>
      </td>
      <td>
        <span className={`severity-tag ${isCritical ? "level-critical" : isHigh ? "level-high" : "level-medium"}`}>
          Level {sev}
        </span>
      </td>
      <td>
        <strong>{alert["Source IP"] || alert.srcip || "0.0.0.0"}</strong>
      </td>
      <td>
        <div style={{ display: "flex", alignItems: "center", gap: "6px", flexWrap: "wrap" }}>
          <IntelBadge alert={alert} />
          {inv && (
            <span
              className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold whitespace-nowrap ${inv.risk_level ? (RISK_PILL[inv.risk_level] || "bg-gray-500/10 text-gray-400 border border-gray-500/20") : "bg-cyan-500/10 text-cyan-400 border border-cyan-500/20"} ${inv.status === "awaiting_response" ? "ring-1 ring-amber-400/40" : ""}`}
              title={`Enquête #${inv.id} — ${inv.status}${inv.risk_level ? ` · ${inv.risk_level} ${inv.risk_score ?? ""}/100` : ""}`}
            >
              <FileSearch size={11} />
              Enquête
              {inv.risk_level && <span className="opacity-80">· {inv.risk_level}</span>}
            </span>
          )}
        </div>
      </td>
      <td style={{ fontFamily: "monospace", color: "var(--accent-cyan)", fontSize: "12px" }}>
        {alert["MAC Address"] || alert.mac || "N/A"}
      </td>
      <td>
        <div style={{ display: "flex", flexDirection: "column" }}>
          <span style={{ fontSize: "13px", fontWeight: 700 }}>
            {alert["Employee Name"] || alert.employee || "Unknown"}
          </span>
          <span style={{ fontSize: "10px", color: "var(--text-muted)" }}>
            {alert.Department || alert.department || "N/A"}
          </span>
        </div>
      </td>
      <td>
        <button
          className="btn-primary"
          style={{ padding: "6px 14px", fontSize: "11px", borderRadius: "8px" }}
          onClick={() => onInvestigate(alert)}
        >
          <Search size={14} /> {t("investigate")}
        </button>
      </td>
    </tr>
  );
});

export default AlertRow;
