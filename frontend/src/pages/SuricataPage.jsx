import { useState, useEffect, useCallback } from "react";
import { Activity, ShieldAlert, Settings, Lock } from "lucide-react";
import { useData } from "../contexts/DataContext";
import { useAuth } from "../contexts/AuthContext";
import { SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, formatSuricataDetails, suricataSeverityOf } from "../lib/formatters";
import SourceConfigWizard from "../components/SourceConfigWizard";

export default function SuricataPage() {
  const { suricataAlerts } = useData();
  const { fetchWithAuth, headers, hasRole } = useAuth();
  const canEdit = hasRole ? hasRole("analyst") : false;
  const [srcFilter, setSrcFilter] = useState("");
  const [destFilter, setDestFilter] = useState("");
  const [sort, setSort] = useState({ key: "timestamp", dir: "desc" });
  const [gate, setGate] = useState({ enabled: null, configured: null, loading: true });
  const [wizard, setWizard] = useState({ open: false });

  const fetchGate = useCallback(async () => {
    try {
      const res1 = await fetchWithAuth("/api/settings/sources", { headers, silent: true });
      let enabled = null;
      if (res1.ok) {
        const d1 = await res1.json();
        enabled = typeof d1.suricata === "boolean" ? d1.suricata : false;
      } else if (res1.status === 404) {
        enabled = true; // dégradé: backend pas à jour -> ne pas bloquer
      }
      const res2 = await fetchWithAuth("/api/settings/sources/config", { headers, silent: true });
      let configured = null;
      if (res2.ok) {
        const d2 = await res2.json();
        configured = d2.suricata?.configured === true;
      } else if (res2.status === 404) {
        configured = true; // dégradé
      } else if (res2.status === 403) {
        configured = false;
      }
      // si 404 dégradé on considère non-bloquant
      if (enabled === null && configured === null) {
        setGate({ enabled: true, configured: true, loading: false });
      } else {
        setGate({ enabled: enabled ?? true, configured: configured ?? true, loading: false });
      }
    } catch {
      setGate({ enabled: true, configured: true, loading: false });
    }
  }, [fetchWithAuth, headers]);

  useEffect(() => {
    fetchGate();
  }, [fetchGate]);

  const blocked = !gate.loading && (!gate.enabled || !gate.configured);

  if (blocked) {
    return (
      <div className="tab-pane animate-fade-in" style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
        <div className="section-card" style={{ padding: "40px 24px", textAlign: "center", maxWidth: "560px", margin: "40px auto", width: "100%" }}>
          <div style={{ width: "48px", height: "48px", borderRadius: "12px", background: "rgba(56,189,248,0.12)", border: "1px solid rgba(56,189,248,0.2)", display: "flex", alignItems: "center", justifyContent: "center", margin: "0 auto 16px" }}>
            <Settings size={22} color="var(--accent-cyan)" />
          </div>
          <h3 style={{ margin: 0, fontSize: "16px", color: "var(--text-main)" }}>Source Suricata non configurée</h3>
          <p style={{ fontSize: "13px", color: "var(--text-muted)", margin: "8px 0 0 0", lineHeight: 1.5 }}>
            {!gate.enabled ? "La source Suricata est désactivée." : "La source Suricata n'est pas configurée (méthode et identifiants manquants)."}
            <br /> Configurez la source pour afficher les événements Suricata.
          </p>
          <div style={{ display: "flex", gap: "10px", justifyContent: "center", marginTop: "18px", flexWrap: "wrap" }}>
            <button
              onClick={() => canEdit && setWizard({ open: true })}
              disabled={!canEdit}
              title={canEdit ? "Ouvrir le paramétrage" : "Nécessite un compte analyste"}
              style={{
                padding: "8px 16px",
                background: canEdit ? "rgba(56,189,248,0.9)" : "rgba(255,255,255,0.08)",
                color: canEdit ? "#fff" : "var(--text-muted)",
                border: "1px solid var(--border)",
                borderRadius: "8px",
                cursor: canEdit ? "pointer" : "not-allowed",
                fontSize: "13px",
                fontWeight: 600,
                display: "flex",
                alignItems: "center",
                gap: "6px",
              }}
            >
              {!canEdit && <Lock size={12} />} Configurer Suricata
            </button>
            {!gate.enabled && (
              <span style={{ fontSize: "12px", color: "var(--text-muted)", alignSelf: "center" }}>ou activez-la depuis le dashboard</span>
            )}
          </div>
          {!canEdit && (
            <div style={{ marginTop: "12px", fontSize: "12px", color: "var(--text-muted)", display: "flex", alignItems: "center", justifyContent: "center", gap: "6px" }}>
              <Lock size={12} /> Lecture seule — compte analyste requis pour configurer.
            </div>
          )}
        </div>
        <SourceConfigWizard open={wizard.open} source="suricata" onClose={() => setWizard({ open: false })} onSuccess={() => { setWizard({ open: false }); fetchGate(); }} />
      </div>
    );
  }

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
            else if (sort.key === "severity") { aVal = suricataSeverityOf(a); bVal = suricataSeverityOf(b); }
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
                      // suricataSeverityOf() : passe par normalized_severity quand le
                      // backend la fournit, sinon remappe l'échelle inversée de Suricata
                      // (1 = critique). Un `parseInt(a.severity)` nu comparait un « 1 »
                      // Suricata à SEVERITY_CRITICAL = 12 : tout s'affichait en Low.
                      const sev = suricataSeverityOf(a);
                      const rawSev = parseInt(a.severity || 0);
                      // Seuils partagés ; isMedium remontait de >=3 à >=4
                      // (SEVERITY_MEDIUM) pour coller au reste de l'app.
                      const isCritical = isAlert && sev >= SEVERITY_CRITICAL;
                      const isHigh = isAlert && sev >= SEVERITY_HIGH && sev < SEVERITY_CRITICAL;
                      const isMedium = isAlert && sev >= SEVERITY_MEDIUM && sev < SEVERITY_HIGH;
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
                              <span className={sevClass} title={`Sévérité Suricata brute : ${rawSev} (échelle inversée) — normalisée : ${sev}/15`}>Level {rawSev} · {sev}/15</span>
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
