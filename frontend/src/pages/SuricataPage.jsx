import { useState } from "react";
import { Activity, ShieldAlert } from "lucide-react";
import { useData } from "../contexts/DataContext";
import { formatSuricataDetails } from "../lib/formatters";

export default function SuricataPage() {
  const { suricataAlerts } = useData();
  const [srcFilter, setSrcFilter] = useState("");
  const [destFilter, setDestFilter] = useState("");
  const [sort, setSort] = useState({ key: "timestamp", dir: "desc" });

  const eventTypes = ["alert", "flow", "http", "dns", "tls", "ssh", "fileinfo", "unknown"];

  return (
    <div className="tab-pane" style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
      {/* Filter bar */}
      <div className="section-card border-glow" style={{ padding: "15px 20px", display: "flex", flexWrap: "wrap", gap: "15px", alignItems: "center", background: "rgba(255,255,255,0.02)" }}>
        <Activity size={20} color="var(--primary)" />
        <h3 style={{ fontSize: "14px", margin: 0, marginRight: "auto", whiteSpace: "nowrap" }}>Filtrage Global du Trafic</h3>
        <div style={{ display: "flex", gap: "10px", flex: "1 1 280px" }}>
          <input
            type="text" placeholder="Rechercher IP Source..." value={srcFilter}
            onChange={(e) => setSrcFilter(e.target.value.replace(/\s/g, ""))}
            style={{ padding: "6px 12px", background: "rgba(255,255,255,0.05)", border: "1px solid var(--border)", borderRadius: "6px", color: "white", fontSize: "12px", width: "100%", maxWidth: "200px", minWidth: "140px" }}
          />
          <input
            type="text" placeholder="Rechercher IP Destination..." value={destFilter}
            onChange={(e) => setDestFilter(e.target.value.replace(/\s/g, ""))}
            style={{ padding: "6px 12px", background: "rgba(255,255,255,0.05)", border: "1px solid var(--border)", borderRadius: "6px", color: "white", fontSize: "12px", width: "100%", maxWidth: "200px", minWidth: "140px" }}
          />
        </div>
      </div>

      {eventTypes.map((eType) => {
        const typeAlerts = suricataAlerts
          .filter((a) => (a.event_type || "unknown").toLowerCase() === eType)
          .filter((a) => (a.src_ip || "").includes(srcFilter) && (a.dest_ip || "").includes(destFilter))
          .sort((a, b) => {
            let aVal, bVal;
            if (sort.key === "timestamp") { aVal = new Date(a.timestamp).getTime(); bVal = new Date(b.timestamp).getTime(); }
            else if (sort.key === "severity") { aVal = parseInt(a.severity || 0); bVal = parseInt(b.severity || 0); }
            else { aVal = new Date(a.timestamp).getTime(); bVal = new Date(b.timestamp).getTime(); }
            const diff = aVal - bVal;
            return sort.dir === "asc" ? diff : -diff;
          });
        if (eType === "stats") return null;
        const shouldAlwaysShow = ["alert", "http", "flow", "dns"].includes(eType);
        if (typeAlerts.length === 0 && !shouldAlwaysShow) return null;
        const isAlert = eType === "alert";

        return (
          <div className="section-card" key={eType}>
            <div className="section-header" style={{ borderLeft: `4px solid ${isAlert ? "#ef4444" : "#38bdf8"}` }}>
              <h2 style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                {isAlert ? <ShieldAlert size={20} color="#ef4444" /> : <Activity size={20} color="#38bdf8" />}
                Suricata {eType.toUpperCase()}
              </h2>
              <span className={`status-pill ${isAlert ? "status-danger" : "status-success"}`}>{typeAlerts.length} Events</span>
            </div>
            <div className="table-wrapper" style={eType !== "alert" ? { maxHeight: "350px", overflowY: "auto" } : {}}>
              <table className="custom-table">
                <thead>
                  <tr>
                    <th style={{ cursor: "pointer", userSelect: "none" }} onClick={() => setSort((prev) => ({ key: "timestamp", dir: prev.key === "timestamp" && prev.dir === "desc" ? "asc" : "desc" }))}>
                      Time {sort.key === "timestamp" && <span style={{ marginLeft: "4px" }}>{sort.dir === "asc" ? "\u25B2" : "\u25BC"}</span>}
                    </th>
                    <th>Message / Type</th>
                    <th>Protocol</th>
                    <th>Source IP</th>
                    <th>Dest IP</th>
                    {isAlert ? (
                      <th style={{ cursor: "pointer", userSelect: "none" }} onClick={() => setSort((prev) => ({ key: "severity", dir: prev.key === "severity" && prev.dir === "desc" ? "asc" : "desc" }))}>
                        Severity {sort.key === "severity" && <span style={{ marginLeft: "4px" }}>{sort.dir === "asc" ? "\u25B2" : "\u25BC"}</span>}
                      </th>
                    ) : (
                      <th>Details</th>
                    )}
                  </tr>
                </thead>
                <tbody>
                  {typeAlerts.length > 0 ? (
                    typeAlerts.map((a, i) => {
                      const sev = parseInt(a.severity || 0);
                      const isCritical = isAlert && sev >= 12;
                      const isHigh = isAlert && sev >= 7 && sev < 12;
                      const isMedium = isAlert && sev >= 3 && sev < 7;
                      const isLow = isAlert && sev > 0 && sev < 3;
                      const rowClass = isCritical ? "suricata-row-critical" : isHigh ? "suricata-row-high" : isMedium ? "suricata-row-medium" : isLow ? "suricata-row-low" : "suricata-row";
                      const sevClass = isCritical ? "suricata-sev-critical" : isHigh ? "suricata-sev-high" : isMedium ? "suricata-sev-medium" : isLow ? "suricata-sev-low" : "suricata-sev-info";
                      const protoTagClass = isAlert ? "" : `suricata-event-${eType}`;

                      return (
                        <tr key={i} className={rowClass}>
                          <td style={{ color: "var(--text-muted)", fontSize: "11px" }}>{new Date(a.timestamp).toLocaleString()}</td>
                          <td style={{ fontWeight: 600, color: isCritical ? "#ff6b6b" : isHigh ? "#fb923c" : isMedium ? "#fbbf24" : "#cbd5e1" }}>
                            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                              {isCritical && <ShieldAlert size={14} className="critical-icon" />}
                              {a.alert_msg}
                            </div>
                          </td>
                          <td>
                            <span className={protoTagClass || undefined} style={{ fontSize: "10px", padding: "3px 8px", borderRadius: "4px", ...(protoTagClass ? {} : { background: "rgba(255,255,255,0.08)", color: "#94a3b8" }) }}>
                              {a.proto || (isAlert ? "TCP" : eType)}
                            </span>
                          </td>
                          <td style={{ fontFamily: "monospace", fontSize: "12px", color: "#7dd3fc" }}>{a.src_ip || "-"}</td>
                          <td style={{ fontFamily: "monospace", fontSize: "12px", color: "#94a3b8" }}>{a.dest_ip || "-"}</td>
                          <td>
                            {isAlert ? (
                              <span className={sevClass}>Level {sev}</span>
                            ) : (
                              <span style={{ fontSize: "11px", color: "var(--text-muted)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", maxWidth: "350px", display: "inline-block" }} title={a.payload || ""}>
                                {formatSuricataDetails(a.payload, eType)}
                              </span>
                            )}
                          </td>
                        </tr>
                      );
                    })
                  ) : (
                    <tr><td colSpan="6" style={{ textAlign: "center", padding: "40px", color: "var(--text-muted)" }}>No {eType} events detected by Suricata.</td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        );
      })}
    </div>
  );
}
