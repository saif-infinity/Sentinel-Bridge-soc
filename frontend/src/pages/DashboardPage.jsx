import { ShieldAlert, Activity, Zap, FileSearch, BrainCircuit, RefreshCw, AlertCircle, Sparkles } from "lucide-react";
import { AreaChart, Area, BarChart, Bar, CartesianGrid, XAxis, YAxis, Tooltip, Legend, ResponsiveContainer } from "recharts";
import { useData } from "../contexts/DataContext";
import { useTranslation } from "../i18n";
import { SEVERITY_HIGH, getHourlyAlertsData, severityOf } from "../lib/formatters";
import { useAuth } from "../contexts/AuthContext";
import { useState, useEffect, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import SourceToggles from "../components/SourceToggles";

export default function DashboardPage() {
  const { wazuhAlerts, onlineHistory, throughputHistory, suricataHistory, investigations } = useData();
  const { t } = useTranslation();
  const { fetchWithAuth, headers, hasRole } = useAuth();
  const navigate = useNavigate();
  const canViewAI = hasRole ? hasRole("analyst") : false;
  const hourlyData = getHourlyAlertsData(wazuhAlerts);
  const awaitingCount = (investigations || []).filter((inv) => inv.status === "awaiting_response").length;

  const tooltipStyle = { background: "var(--bg-card)", border: "1px solid var(--border)", borderRadius: "8px" };

  const [aiEnabled, setAiEnabled] = useState(null);
  const [analyses, setAnalyses] = useState([]);
  const [aiLoading, setAiLoading] = useState(false);
  const [expanded, setExpanded] = useState({});

  const fetchAI = useCallback(async () => {
    if (!canViewAI) return;
    setAiLoading(true);
    try {
      const r1 = await fetchWithAuth("/api/settings/ai-auto", { headers, silent: true });
      if (r1.ok) {
        const d1 = await r1.json();
        setAiEnabled(!!d1.enabled);
      } else if (r1.status === 404 || r1.status === 403) {
        setAiEnabled(false);
      }
      const r2 = await fetchWithAuth("/api/ai-auto/analyses?limit=10", { headers, silent: true });
      if (r2.ok) {
        const d2 = await r2.json();
        setAnalyses(d2.analyses || []);
      } else {
        setAnalyses([]);
      }
    } catch {
      setAnalyses([]);
    } finally {
      setAiLoading(false);
    }
  }, [fetchWithAuth, headers, canViewAI]);

  useEffect(() => {
    fetchAI();
  }, [fetchAI]);
  useEffect(() => {
    const h = () => fetchAI();
    window.addEventListener("sources-changed", h);
    return () => window.removeEventListener("sources-changed", h);
  }, [fetchAI]);

  return (
    <div className="tab-pane animate-fade-in">
      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-icon" style={{ background: "rgba(244, 63, 94, 0.1)", color: "var(--danger)" }}>
            <ShieldAlert size={20} />
          </div>
          <div className="stat-info">
            <span className="stat-value">{wazuhAlerts.length}</span>
            <span className="stat-label">{t("active_threats")}</span>
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-icon" style={{ background: "rgba(56, 189, 248, 0.1)", color: "var(--accent-primary)" }}>
            <Activity size={20} />
          </div>
          <div className="stat-info">
            <span className="stat-value">{wazuhAlerts.filter((a) => severityOf(a) >= SEVERITY_HIGH).length}</span>
            <span className="stat-label">{t("critical_alerts")}</span>
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-icon" style={{ background: "rgba(56, 189, 248, 0.1)", color: "#38bdf8" }}>
            <Activity size={20} />
          </div>
          <div className="stat-info">
            <span className="stat-value">
              {suricataHistory[suricataHistory.length - 1]?.packets.toLocaleString() || "0"}
            </span>
            <span className="stat-label">IPS Packets</span>
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-icon" style={{ background: "rgba(239, 68, 68, 0.1)", color: "#ef4444" }}>
            <ShieldAlert size={20} />
          </div>
          <div className="stat-info">
            <span className="stat-value" style={{ color: "#ef4444" }}>
              {suricataHistory[suricataHistory.length - 1]?.drops || "0"}
            </span>
            <span className="stat-label">IPS Drops</span>
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-icon" style={{ background: "rgba(234, 179, 8, 0.1)", color: "#eab308" }}>
            <FileSearch size={20} />
          </div>
          <div className="stat-info">
            <span className="stat-value" style={{ color: awaitingCount > 0 ? "#eab308" : undefined }}>{awaitingCount}</span>
            <span className="stat-label">En attente de réponse</span>
          </div>
        </div>
      </div>

      <div className="dashboard-grid">
        {/* Chart 1: Presence Analytics */}
        <div className="section-card" style={{ height: "350px" }}>
          <div className="section-header">
            <h2 style={{ display: "flex", alignItems: "center", gap: "10px" }}>
              <Activity size={18} color="var(--accent-cyan)" /> Network Presence Analytics
            </h2>
          </div>
          <div style={{ width: "100%", height: "280px", marginTop: "10px" }}>
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={onlineHistory}>
                <defs>
                  <linearGradient id="colorCount" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="var(--accent-cyan)" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="var(--accent-cyan)" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                <XAxis dataKey="time" stroke="var(--text-muted)" fontSize={10} tickLine={false} />
                <YAxis stroke="var(--text-muted)" fontSize={10} tickLine={false} axisLine={false} />
                <Tooltip contentStyle={tooltipStyle} />
                <Area type="monotone" dataKey="count" stroke="var(--accent-cyan)" fill="url(#colorCount)" strokeWidth={3} animationDuration={1000} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Chart 2: Bandwidth */}
        <div className="section-card" style={{ height: "350px" }}>
          <div className="section-header">
            <h2><Zap size={18} /> Real-time Bandwidth (MB/s)</h2>
          </div>
          <div style={{ width: "100%", height: "280px", marginTop: "10px" }}>
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={throughputHistory}>
                <defs>
                  <linearGradient id="colorValue" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="var(--accent-blue)" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="var(--accent-blue)" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                <XAxis dataKey="time" stroke="var(--text-muted)" fontSize={10} tickLine={false} />
                <YAxis stroke="var(--text-muted)" fontSize={10} tickLine={false} axisLine={false} />
                <Tooltip contentStyle={tooltipStyle} />
                <Area type="monotone" dataKey="value" stroke="var(--accent-blue)" fillOpacity={1} fill="url(#colorValue)" strokeWidth={3} animationDuration={1500} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Chart 3: IDS Protection Activity */}
        <div className="section-card" style={{ height: "350px" }}>
          <div className="section-header">
            <h2 style={{ display: "flex", alignItems: "center", gap: "10px" }}>
              <Activity size={18} color="#38bdf8" /> Activite de Protection Reseau (IPS)
            </h2>
          </div>
          <div style={{ width: "100%", height: "220px", marginTop: "20px" }}>
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={suricataHistory}>
                <defs>
                  <linearGradient id="colorIDS" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#38bdf8" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#38bdf8" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="time" stroke="var(--text-muted)" fontSize={10} hide />
                <YAxis stroke="var(--text-muted)" fontSize={10} axisLine={false} tickLine={false} />
                <Tooltip contentStyle={tooltipStyle} />
                <Area type="monotone" dataKey="packets" stroke="#38bdf8" fillOpacity={1} fill="url(#colorIDS)" strokeWidth={2} name="Flux Inspecte" />
                <Area type="monotone" dataKey="drops" stroke="#ef4444" fillOpacity={0} strokeWidth={2} name="Anomalies" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
          <div style={{ display: "flex", gap: "15px", marginTop: "15px", padding: "10px", background: "rgba(255,255,255,0.02)", borderRadius: "8px" }}>
            <div style={{ flex: 1 }}>
              <span style={{ fontSize: "9px", color: "var(--text-muted)", textTransform: "uppercase" }}>Inspection en cours</span>
              <div style={{ fontSize: "16px", fontWeight: 700, color: "#38bdf8" }}>
                {suricataHistory[suricataHistory.length - 1]?.packets.toLocaleString() || "0"} pkt
              </div>
            </div>
            <div style={{ flex: 1 }}>
              <span style={{ fontSize: "9px", color: "var(--text-muted)", textTransform: "uppercase" }}>Anomalies bloquees</span>
              <div style={{ fontSize: "16px", fontWeight: 700, color: "#ef4444" }}>
                {suricataHistory[suricataHistory.length - 1]?.drops || "0"}
              </div>
            </div>
          </div>
        </div>

        {/* Chart 4: Threat Distribution */}
        <div className="section-card" style={{ height: "350px" }}>
          <div className="section-header">
            <h2 style={{ display: "flex", alignItems: "center", gap: "10px" }}>
              <ShieldAlert size={18} color="var(--danger)" /> {t("threat_intensity_distribution")} (24h)
            </h2>
          </div>
          <div style={{ width: "100%", height: "240px", marginTop: "15px" }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={hourlyData}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
                <XAxis dataKey="time" stroke="var(--text-muted)" fontSize={10} tickLine={false} />
                <YAxis stroke="var(--text-muted)" fontSize={10} tickLine={false} axisLine={false} />
                <Tooltip cursor={{ fill: "rgba(255,255,255,0.05)" }} contentStyle={tooltipStyle} />
                <Legend iconType="circle" wrapperStyle={{ fontSize: "10px", paddingTop: "10px" }} />
                <Bar dataKey="Critical" stackId="a" fill="#f43f5e" radius={[0, 0, 0, 0]} />
                <Bar dataKey="High" stackId="a" fill="#fb923c" radius={[0, 0, 0, 0]} />
                <Bar dataKey="Medium" stackId="a" fill="#38bdf8" radius={[0, 0, 0, 0]} />
                <Bar dataKey="Low" stackId="a" fill="#4ade80" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <SourceToggles variant="dashboard" />
      </div>

      {canViewAI && (
        <div className="section-card" style={{ padding: "20px 24px" }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "16px" }}>
            <h2 style={{ display: "flex", alignItems: "center", gap: "10px", fontSize: "15px", margin: 0 }}>
              <BrainCircuit size={18} color="var(--accent-cyan)" /> Analyses IA automatiques
              {aiEnabled === false && <span style={{ fontSize: "10px", color: "var(--text-muted)", background: "rgba(255,255,255,0.06)", border: "1px solid var(--border)", padding: "2px 6px", borderRadius: "999px" }}>désactivée</span>}
              {aiEnabled === true && <span style={{ fontSize: "10px", color: "var(--accent-cyan)", background: "rgba(56,189,248,0.12)", border: "1px solid rgba(56,189,248,0.2)", padding: "2px 6px", borderRadius: "999px" }}>activée</span>}
            </h2>
            <button onClick={fetchAI} disabled={aiLoading} title="Rafraîchir" style={{ background: "rgba(255,255,255,0.04)", border: "1px solid var(--border)", borderRadius: "8px", padding: "6px 8px", color: "var(--text-muted)", cursor: aiLoading ? "not-allowed" : "pointer", display: "flex", alignItems: "center" }}>
              <RefreshCw size={14} style={{ animation: aiLoading ? "spin 0.8s linear infinite" : undefined }} />
            </button>
          </div>

          {aiLoading && analyses.length === 0 ? (
            <div style={{ textAlign: "center", padding: "20px", color: "var(--text-muted)", fontSize: "13px" }}>Chargement…</div>
          ) : aiEnabled === false ? (
            <div style={{ textAlign: "center", padding: "20px" }}>
              <div style={{ fontSize: "13px", color: "var(--text-muted)" }}>Auto-analyse IA désactivée — activez-la dans Settings.</div>
              <button onClick={() => navigate("/settings")} style={{ marginTop: "10px", padding: "6px 12px", background: "rgba(56,189,248,0.12)", border: "1px solid rgba(56,189,248,0.2)", borderRadius: "8px", color: "var(--accent-cyan)", cursor: "pointer", fontSize: "12px" }}>
                Aller aux paramètres
              </button>
            </div>
          ) : analyses.length === 0 ? (
            <div style={{ textAlign: "center", padding: "20px", color: "var(--text-muted)", fontSize: "13px" }}>Aucun burst critique à analyser.</div>
          ) : (
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: "12px" }}>
              {analyses.map((a) => {
                const isExpanded = !!expanded[a.id];
                const long = a.response && a.response.length > 400;
                const text = !a.response ? "" : isExpanded || !long ? a.response : a.response.slice(0, 400) + "…";
                return (
                  <div key={a.id} style={{ background: "rgba(255,255,255,0.03)", border: "1px solid var(--border)", borderRadius: "12px", padding: "14px", display: "flex", flexDirection: "column", gap: "8px" }}>
                    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: "8px" }}>
                      <span style={{ fontSize: "13px", fontWeight: 700, color: "var(--text-main)" }}>{a.hostname || a.agent_id}</span>
                      <span style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                        <span style={{ fontSize: "10px", fontWeight: 700, background: "rgba(56,189,248,0.12)", border: "1px solid rgba(56,189,248,0.2)", color: "var(--accent-cyan)", padding: "2px 6px", borderRadius: "999px" }}>{a.severity_count} alertes critiques</span>
                        {a.status === "running" && <span style={{ fontSize: "10px", color: "var(--text-muted)", display: "flex", alignItems: "center", gap: "4px" }}><RefreshCw size={10} style={{ animation: "spin 0.8s linear infinite" }} /> en cours</span>}
                        {a.status === "error" && <span style={{ fontSize: "10px", color: "#ef4444", background: "rgba(239,68,68,0.12)", border: "1px solid rgba(239,68,68,0.2)", padding: "2px 6px", borderRadius: "999px", display: "flex", alignItems: "center", gap: "4px" }}><AlertCircle size={10} /> erreur</span>}
                        {a.status === "done" && <span style={{ fontSize: "10px", color: "#10b981", background: "rgba(16,185,129,0.12)", border: "1px solid rgba(16,185,129,0.2)", padding: "2px 6px", borderRadius: "999px" }}>terminée</span>}
                      </span>
                    </div>
                    <div style={{ fontSize: "11px", color: "var(--text-muted)" }}>{a.analyzed_at ? new Date(a.analyzed_at).toLocaleString("fr-FR") : a.created_at ? new Date(a.created_at).toLocaleString("fr-FR") : ""} · {a.model}</div>
                    {a.status === "error" && a.error && <div style={{ fontSize: "12px", color: "#ef4444", background: "rgba(239,68,68,0.06)", border: "1px solid rgba(239,68,68,0.15)", padding: "8px", borderRadius: "8px" }}>{a.error}</div>}
                    {a.status !== "error" && (
                      <div style={{ fontSize: "12px", color: "var(--text-main)", background: "rgba(255,255,255,0.02)", border: "1px solid var(--border)", borderRadius: "8px", padding: "10px", whiteSpace: "pre-wrap", maxHeight: isExpanded ? "400px" : "180px", overflowY: "auto", lineHeight: 1.5 }}>
                        {text || <span style={{ color: "var(--text-muted)" }}>—</span>}
                      </div>
                    )}
                    {long && (
                      <button onClick={() => setExpanded((p) => ({ ...p, [a.id]: !p[a.id] }))} style={{ alignSelf: "flex-start", background: "none", border: "none", color: "var(--accent-cyan)", cursor: "pointer", fontSize: "11px", display: "flex", alignItems: "center", gap: "4px" }}>
                        <Sparkles size={12} /> {isExpanded ? "Voir moins" : "Voir plus"}
                      </button>
                    )}
                    <div style={{ fontSize: "10px", color: "var(--text-muted)" }}>alert_ids: {a.alert_ids?.join(", ") || "—"}</div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
