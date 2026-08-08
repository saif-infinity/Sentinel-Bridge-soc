// src/views/SensorsView.jsx
// Capteurs — system health, gauges, services, alerts, suricata.
import { useCallback, useEffect, useState } from "react";
import {
  ActivitySquare,
  Cpu,
  HardDrive,
  Database,
  Wifi,
  Radio,
  Users,
  LogIn,
  Activity,
  AlertTriangle,
  Shield,
  ShieldCheck,
  FileText,
  BarChart3,
  AlertCircle,
  Zap,
  Loader2,
} from "lucide-react";
import { apiFetch, getToken } from "../api";

/* GaugeMeter: SVG tachometer-style gauge */
function GaugeMeter({ value, max, label, unit, icon: Icon, color, size = 170 }) {
  const ratio = max > 0 ? Math.min(Math.max(value / max, 0), 1) : 0;
  const startAngle = -210;
  const endAngle = 30;
  const sweep = endAngle - startAngle;
  const needleAngle = startAngle + ratio * sweep;

  const cx = size / 2;
  const cy = size / 2;
  const r = size * 0.38;

  const getColor = (rat) => {
    if (color) return color;
    if (rat < 0.5) return "#00ffc8";
    if (rat < 0.75) return "#fbbf24";
    return "#ff4060";
  };

  function polarToCartesian(angle) {
    const rad = (angle * Math.PI) / 180;
    return { x: cx + r * Math.cos(rad), y: cy + r * Math.sin(rad) };
  }
  function describeArc(startA, endA) {
    const start = polarToCartesian(endA);
    const end = polarToCartesian(startA);
    const large = endA - startA <= 180 ? "0" : "1";
    return `M ${start.x} ${start.y} A ${r} ${r} 0 ${large} 0 ${end.x} ${end.y}`;
  }

  const tickCount = 10;
  const ticks = [];
  for (let i = 0; i <= tickCount; i++) {
    const a = startAngle + (i / tickCount) * sweep;
    const rad = (a * Math.PI) / 180;
    ticks.push({
      x1: cx + (r - 8) * Math.cos(rad), y1: cy + (r - 8) * Math.sin(rad),
      x2: cx + (r + 2) * Math.cos(rad), y2: cy + (r + 2) * Math.sin(rad),
      major: i % 5 === 0 || i === tickCount,
    });
  }

  const needleLen = r - 12;
  const nRad = (needleAngle * Math.PI) / 180;
  const nx = cx + needleLen * Math.cos(nRad);
  const ny = cy + needleLen * Math.sin(nRad);
  const activeColor = getColor(ratio);

  return (
    <div className="admin-gauge-card">
      <div className="admin-gauge-card-header">
        {Icon && <Icon size={14} color={activeColor} />}
        <span>{label}</span>
      </div>
      <svg width={size} height={size * 0.82} viewBox={`0 0 ${size} ${size}`}>
        <path d={describeArc(startAngle, endAngle)} fill="none" stroke="rgba(0,255,200,0.08)" strokeWidth="12" strokeLinecap="round" />
        {ratio > 0.005 && (
          <path d={describeArc(startAngle, startAngle + ratio * sweep)} fill="none" stroke={activeColor} strokeWidth="12" strokeLinecap="round"
            style={{ filter: `drop-shadow(0 0 6px ${activeColor}60)`, transition: "all 0.8s ease" }} />
        )}
        {ticks.map((t, i) => (
          <line key={i} x1={t.x1} y1={t.y1} x2={t.x2} y2={t.y2}
            stroke={t.major ? "rgba(255,255,255,0.3)" : "rgba(255,255,255,0.1)"} strokeWidth={t.major ? 2 : 1} />
        ))}
        <line x1={cx} y1={cy} x2={nx} y2={ny} stroke={activeColor} strokeWidth="2.5" strokeLinecap="round"
          style={{ filter: `drop-shadow(0 0 4px ${activeColor})`, transition: "all 0.8s ease" }} />
        <circle cx={cx} cy={cy} r="5" fill={activeColor} style={{ filter: `drop-shadow(0 0 4px ${activeColor})` }} />
        <text x={cx} y={cy + r * 0.5} textAnchor="middle" fill={activeColor} fontFamily="'Orbitron', monospace" fontSize={size * 0.14} fontWeight="700">
          {typeof value === "number" ? (value >= 100 ? Math.round(value) : value.toFixed(1)) : value}
        </text>
        <text x={cx} y={cy + r * 0.5 + size * 0.09} textAnchor="middle" fill="rgba(255,255,255,0.3)" fontFamily="'JetBrains Mono', monospace" fontSize={size * 0.065}>
          {unit || ""}
        </text>
      </svg>
    </div>
  );
}

/* ServiceStatus: pill showing service up/down */
function ServiceStatus({ name, running }) {
  return (
    <div className={`admin-service-pill ${running ? "up" : "down"}`}>
      <span className={`admin-service-dot ${running ? "up" : "down"}`} />
      <span className="admin-service-name">{name}</span>
      <span className="admin-service-status">{running ? "UP" : "DOWN"}</span>
    </div>
  );
}

export default function SensorsView({ sensorData }) {
  const [health, setHealth] = useState(null);
  const [loading, setLoading] = useState(true);

  const fetchHealth = useCallback(async () => {
    if (!getToken()) return;
    try {
      const res = await apiFetch(`/api/sensors/health`);
      if (res.ok) setHealth(await res.json());
    } catch (e) { /* ignore */ }
    setLoading(false);
  }, []);

  useEffect(() => {
    fetchHealth();
    const interval = setInterval(fetchHealth, 8000);
    return () => clearInterval(interval);
  }, [fetchHealth]);

  const r = health?.resources;
  const s = health?.services;
  const st = health?.stats;

  function formatUptime(seconds) {
    if (!seconds) return "--";
    const d = Math.floor(seconds / 86400);
    const h = Math.floor((seconds % 86400) / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    if (d > 0) return `${d}j ${h}h`;
    if (h > 0) return `${h}h ${m}m`;
    return `${m}m`;
  }

  return (
    <div className="admin-tab">
      <div className="admin-page-header">
        <h2><ActivitySquare size={20} /> Santé du Système</h2>
        {health && <span className="admin-realtime">MAJ: {new Date(health.timestamp).toLocaleTimeString("fr-FR")}</span>}
        {loading && <Loader2 size={14} className="admin-spin" />}
      </div>

      {loading && !health ? (
        <div className="admin-section-card"><div className="admin-empty">Chargement des capteurs...</div></div>
      ) : !health ? (
        <div className="admin-section-card"><div className="admin-empty">Impossible de charger les données système</div></div>
      ) : (
        <>
          {/* ── Resource Gauges ── */}
          <div className="admin-gauge-grid">
            <GaugeMeter value={r.cpu_percent} max={100} label="CPU" unit={`${r.cpu_count} cores`} icon={Cpu} />
            <GaugeMeter value={r.memory_percent} max={100} label="RAM" unit={`${r.memory_used_gb} / ${r.memory_total_gb} GB`} icon={HardDrive} />
            <GaugeMeter value={r.disk_percent} max={100} label="Disque" unit={`${r.disk_used_gb} / ${r.disk_total_gb} GB`} icon={Database} />
            <GaugeMeter value={r.net_mbps} max={Math.max(r.net_mbps * 2, 1)} label="Réseau" unit={`${r.net_sent_gb}↑ / ${r.net_recv_gb}↓ GB`} icon={Wifi} color="#a855f7" />
          </div>

          {/* ── Services + Stats ── */}
          <div className="admin-health-row">
            <div className="admin-section-card admin-health-services">
              <h3><Zap size={16} /> Services</h3>
              <div className="admin-services-grid">
                <ServiceStatus name="PostgreSQL" running={s.postgresql} />
                <ServiceStatus name="Redis" running={s.redis} />
                <ServiceStatus name="Celery" running={s.celery} />
                <ServiceStatus name="Ollama" running={s.ollama} />
              </div>
              <div className="admin-health-extra">
                <div className="admin-health-extra-item">
                  <span className="admin-health-extra-label">Uptime</span>
                  <span className="admin-health-extra-value">{formatUptime(r.uptime_seconds)}</span>
                </div>
                <div className="admin-health-extra-item">
                  <span className="admin-health-extra-label">Processes</span>
                  <span className="admin-health-extra-value">{r.process_count}</span>
                </div>
                <div className="admin-health-extra-item">
                  <span className="admin-health-extra-label">Load Avg</span>
                  <span className="admin-health-extra-value">{r.load_avg_1m} / {r.load_avg_5m} / {r.load_avg_15m}</span>
                </div>
                <div className="admin-health-extra-item">
                  <span className="admin-health-extra-label">Swap</span>
                  <span className="admin-health-extra-value">{r.swap_percent}%</span>
                </div>
              </div>
            </div>

            <div className="admin-section-card admin-health-stats">
              <h3><BarChart3 size={16} /> Statistiques</h3>
              <div className="admin-health-stat-grid">
                <div className="admin-health-stat-pill"><Users size={14} color="#60a5fa" /><span>{st.online_users}</span><label>En ligne</label></div>
                <div className="admin-health-stat-pill"><LogIn size={14} color="#34d399" /><span>{st.today_logins}</span><label>Connexions/jour</label></div>
                <div className="admin-health-stat-pill"><Activity size={14} color="#fbbf24" /><span>{st.today_actions}</span><label>Actions/jour</label></div>
                <div className="admin-health-stat-pill"><AlertTriangle size={14} color="#f87171" /><span>{st.today_alerts}</span><label>Alertes/jour</label></div>
                <div className="admin-health-stat-pill"><AlertCircle size={14} color="#f87171" /><span>{st.critical_alerts}</span><label>Critiques</label></div>
                <div className="admin-health-stat-pill"><Shield size={14} color="#a855f7" /><span>{st.today_suricata}</span><label>Suricata/jour</label></div>
                <div className="admin-health-stat-pill"><FileText size={14} color="#60a5fa" /><span>{st.total_alerts}</span><label>Total alertes</label></div>
                <div className="admin-health-stat-pill"><ShieldCheck size={14} color="#f87171" /><span>{st.critical_suricata}</span><label>Suri. critique</label></div>
              </div>
            </div>
          </div>

          {/* ── Bandwidth Gauges ── */}
          {sensorData && sensorData.length > 0 && (
            <>
              <div className="admin-section-card admin-section-mt">
                <h3><Radio size={16} /> Débit par station</h3>
              </div>
              <div className="admin-gauge-grid">
                {sensorData.map((sd) => (
                  <GaugeMeter
                    key={sd.username}
                    value={sd.latest_bandwidth_mbps || 0}
                    max={Math.max(...sensorData.map(x => x.latest_bandwidth_mbps || 0), 1) * 1.3}
                    label={sd.username}
                    unit={sd.ip_address || "—"}
                    icon={Radio}
                  />
                ))}
              </div>
            </>
          )}

          {/* ── Alerts + Suricata tables ── */}
          <div className="admin-health-row">
            <div className="admin-section-card">
              <h3><AlertTriangle size={16} /> Alertes récentes</h3>
              {health.recent_alerts.length === 0 ? (
                <div className="admin-empty-sm">Aucune alerte</div>
              ) : (
                <div className="admin-health-table-wrap">
                  <table className="admin-table admin-table-sm">
                    <thead><tr><th>Sev</th><th>Description</th><th>Source</th><th>Heure</th></tr></thead>
                    <tbody>
                      {health.recent_alerts.map((a, i) => (
                        <tr key={i}>
                          <td><span className={`admin-badge-sm ${a.severity >= 7 ? "danger" : a.severity >= 4 ? "warning" : "success"}`}>{a.severity}</span></td>
                          <td className="admin-cell-mono">{a.description?.substring(0, 60)}</td>
                          <td className="admin-cell-mono">{a.src_ip || "--"}</td>
                          <td className="admin-cell-mono">{new Date(a.timestamp).toLocaleTimeString("fr-FR")}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            <div className="admin-section-card">
              <h3><Shield size={16} /> Suricata</h3>
              {health.recent_suricata.length === 0 ? (
                <div className="admin-empty-sm">Aucune alerte Suricata</div>
              ) : (
                <div className="admin-health-table-wrap">
                  <table className="admin-table admin-table-sm">
                    <thead><tr><th>Type</th><th>Message</th><th>Src → Dst</th><th>Heure</th></tr></thead>
                    <tbody>
                      {health.recent_suricata.map((sv, i) => (
                        <tr key={i}>
                          <td><span className="admin-badge-sm muted">{sv.event_type}</span></td>
                          <td className="admin-cell-mono">{sv.alert_msg?.substring(0, 50) || "--"}</td>
                          <td className="admin-cell-mono">{sv.src_ip || "?"} → {sv.dest_ip || "?"}</td>
                          <td className="admin-cell-mono">{new Date(sv.timestamp).toLocaleTimeString("fr-FR")}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>

          {/* ── Actions + Errors ── */}
          <div className="admin-health-row">
            <div className="admin-section-card">
              <h3><Activity size={16} /> Actions récentes</h3>
              {health.recent_actions.length === 0 ? (
                <div className="admin-empty-sm">Aucune action</div>
              ) : (
                <div className="admin-health-table-wrap">
                  <table className="admin-table admin-table-sm">
                    <thead><tr><th>User</th><th>Action</th><th>Ressource</th><th>Heure</th></tr></thead>
                    <tbody>
                      {health.recent_actions.map((a, i) => (
                        <tr key={i}>
                          <td><span className="admin-cell-user">{a.username}</span></td>
                          <td className="admin-cell-mono">{a.action}</td>
                          <td className="admin-cell-mono">{a.resource || "--"}</td>
                          <td className="admin-cell-mono">{new Date(a.timestamp).toLocaleTimeString("fr-FR")}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            <div className="admin-section-card">
              <h3><AlertCircle size={16} /> Erreurs récentes</h3>
              {health.recent_errors.length === 0 ? (
                <div className="admin-empty-sm">Aucune erreur récente</div>
              ) : (
                <div className="admin-health-table-wrap">
                  <table className="admin-table admin-table-sm">
                    <thead><tr><th>User</th><th>Action</th><th>Détails</th><th>Heure</th></tr></thead>
                    <tbody>
                      {health.recent_errors.map((e, i) => (
                        <tr key={i}>
                          <td><span className="admin-cell-user">{e.username}</span></td>
                          <td className="admin-cell-mono">{e.action}</td>
                          <td className="admin-cell-mono">{e.details?.substring(0, 50) || "--"}</td>
                          <td className="admin-cell-mono">{new Date(e.timestamp).toLocaleTimeString("fr-FR")}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}