import { memo } from "react";
import { ShieldAlert, Shield, Search } from "lucide-react";
import IntelBadge from "./IntelBadge";

const AlertRow = memo(({ alert, onInvestigate, t }) => {
  const sev = parseInt(alert.Severity || alert.severity || 0);
  const isCritical = sev >= 12;
  const isHigh = sev >= 7 && sev < 12;

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
        <IntelBadge alert={alert} />
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
