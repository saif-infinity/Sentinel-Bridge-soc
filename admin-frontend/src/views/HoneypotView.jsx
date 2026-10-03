// src/views/HoneypotView.jsx
// Honeypot — statut, événements et statistiques.
import { useState, useEffect, useCallback } from "react";
import { Bug, Server, Clock, Globe, Activity, Loader2, Shield } from "lucide-react";
import { apiFetch } from "../api";

const API = "/api/admin";

function formatTimestamp(iso) {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleString("fr-FR", {
      day: "2-digit", month: "2-digit", year: "numeric",
      hour: "2-digit", minute: "2-digit", second: "2-digit",
    });
  } catch {
    return iso;
  }
}

export default function HoneypotView() {
  const [status, setStatus] = useState({ running: false, ports: [], total_events: 0 });
  const [events, setEvents] = useState([]);
  const [stats, setStats] = useState({ total_events: 0, events_per_port: [], top_ips: [] });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchData = useCallback(async () => {
    try {
      const [statusRes, eventsRes, statsRes] = await Promise.all([
        apiFetch(`${API}/honeypot/status`),
        apiFetch(`${API}/honeypot/events?limit=20`),
        apiFetch(`${API}/honeypot/stats`),
      ]);
      if (statusRes.ok) setStatus(await statusRes.json());
      if (eventsRes.ok) setEvents(await eventsRes.json());
      if (statsRes.ok) setStats(await statsRes.json());
      setError(null);
    } catch (err) {
      setError("Erreur réseau. Réessayez.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    const id = setInterval(fetchData, 10000);
    return () => clearInterval(id);
  }, [fetchData]);

  if (loading) {
    return (
      <div className="flr-card">
        <div className="flr-loading">
          <Loader2 size={18} className="admin-spin" /> Chargement du honeypot...
        </div>
      </div>
    );
  }

  return (
    <div className="flr-card">
      <div className="flr-header">
        <Bug size={18} />
        <h3>Honeypot</h3>
        <span className={`admin-badge ${status.running ? "success" : "alert"}`}>
          {status.running ? "Running" : "Stopped"}
        </span>
        <span className="admin-total-badge" style={{ marginLeft: 8 }}>
          <Server size={12} /> {status.ports.length} port(s) · {status.total_events} événements
        </span>
      </div>

      {/* ── Status summary ── */}
      <div style={{ display: "flex", gap: 12, padding: "12px 16px", flexWrap: "wrap" }}>
        <div className="flr-stat">
          <Activity size={14} color="var(--accent-purple)" />
          <span>{status.total_events} total events</span>
        </div>
        <div className="flr-stat">
          <Server size={14} color="var(--success)" />
          <span>{status.ports.join(", ") || "Aucun"}</span>
        </div>
      </div>

      {/* ── Stats ── */}
      <div className="os-tabs" style={{ justifyContent: "space-between" }}>
        <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
          <span className="os-tab" style={{ cursor: "default" }}>
            <Globe size={12} /> Top IPs
          </span>
          {stats.top_ips.map((ip) => (
            <span key={ip.ip} className="os-tab-count" style={{ background: "rgba(168,85,247,0.12)", color: "var(--text-muted)" }}>
              {ip.ip}: {ip.count}
            </span>
          ))}
        </div>
      </div>
      <div style={{ padding: "8px 16px" }}>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          {stats.events_per_port.map((p) => (
            <span key={p.port} className="admin-badge-sm" style={{ background: "rgba(168,85,247,0.10)", color: "var(--accent-purple)" }}>
              Port {p.port}: {p.count}
            </span>
          ))}
        </div>
      </div>

      {/* ── Events table ── */}
      <div className="os-tabs" style={{ justifyContent: "space-between" }}>
        <span style={{ fontFamily: "'JetBrains Mono'", fontSize: 11, color: "var(--text-muted)" }}>
          <Clock size={12} /> Derniers événements
        </span>
        <span className="admin-total-badge" style={{ fontSize: 9 }}>
          {stats.total_events} au total
        </span>
      </div>

      {error && (
        <div className="admin-error-msg" style={{ margin: "12px 16px 0" }}>
          <Shield size={14} /> {error}
        </div>
      )}

      {events.length === 0 ? (
        <div className="flr-empty">
          <Bug size={36} />
          <p>Aucun événement honeypot enregistré</p>
          <span className="os-empty-hint">Les connexions suspectes apparaîtront ici.</span>
        </div>
      ) : (
        <div style={{ overflowX: "auto", padding: "0 16px 16px" }}>
          <table className="flr-table os-table" style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr>
                <th className="os-table th">Port</th>
                <th className="os-table th">Src IP</th>
                <th className="os-table th">Src Port</th>
                <th className="os-table th">Timestamp</th>
                <th className="os-table th">Preview</th>
              </tr>
            </thead>
            <tbody>
              {events.map((ev) => (
                <tr key={ev.id}>
                  <td className="os-table td">
                    <span className="admin-badge-sm" style={{ background: "rgba(244,63,94,0.10)", color: "var(--danger)" }}>
                      {ev.port}
                    </span>
                  </td>
                  <td className="os-table td" style={{ fontFamily: "'JetBrains Mono'", fontSize: 11 }}>
                    {ev.src_ip}
                  </td>
                  <td className="os-table td">{ev.src_port ?? "—"}</td>
                  <td className="os-table td" style={{ fontSize: 11 }}>
                    {formatTimestamp(ev.timestamp)}
                  </td>
                  <td className="os-table td" style={{ maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis", fontSize: 11 }}>
                    {ev.payload_preview ?? "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
