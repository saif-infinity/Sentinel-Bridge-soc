import { ShieldAlert, Activity, Zap } from "lucide-react";
import { AreaChart, Area, BarChart, Bar, CartesianGrid, XAxis, YAxis, Tooltip, Legend, ResponsiveContainer } from "recharts";
import { useData } from "../contexts/DataContext";
import { useTranslation } from "../i18n";
import { getHourlyAlertsData } from "../lib/formatters";

export default function DashboardPage() {
  const { wazuhAlerts, onlineHistory, throughputHistory, suricataHistory } = useData();
  const { t } = useTranslation();
  const hourlyData = getHourlyAlertsData(wazuhAlerts);

  const tooltipStyle = { background: "var(--bg-card)", border: "1px solid var(--border)", borderRadius: "8px" };

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
            <span className="stat-value">{wazuhAlerts.filter((a) => a.Severity >= 8).length}</span>
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
      </div>
    </div>
  );
}
