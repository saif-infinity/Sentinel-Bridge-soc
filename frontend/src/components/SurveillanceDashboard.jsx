import { useState, useEffect, useCallback } from "react";
import {
  Users,
  Clock,
  Fingerprint,
  LogIn,
  LogOut,
  ShieldCheck,
  AlertCircle,
  UserCheck,
  History,
  BarChart3,
} from "lucide-react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from "recharts";

const API_BASE = "/api/surveillance";

function formatDuration(seconds) {
  if (!seconds && seconds !== 0) return "--";
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

function timeAgo(dateStr) {
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "à l'instant";
  if (mins < 60) return `il y a ${mins} min`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `il y a ${hours}h`;
  return `il y a ${Math.floor(hours / 24)}j`;
}

export default function SurveillanceDashboard({ token }) {
  const [onlineUsers, setOnlineUsers] = useState([]);
  const [logs, setLogs] = useState([]);
  const [totalLogs, setTotalLogs] = useState(0);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activeSection, setActiveSection] = useState("overview");
  const [now, setNow] = useState(Date.now());

  const headers = {
    Authorization: `Bearer ${token}`,
    "Content-Type": "application/json",
  };

  useEffect(() => {
    const interval = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(interval);
  }, []);

  const fetchData = useCallback(async () => {
    try {
      const [onlineRes, logsRes, statsRes] = await Promise.all([
        fetch(`${API_BASE}/online`, { headers }),
        fetch(`${API_BASE}/logs?limit=50`, { headers }),
        fetch(`${API_BASE}/stats`, { headers }),
      ]);
      if (onlineRes.ok) setOnlineUsers(await onlineRes.json());
      if (logsRes.ok) {
        const logsData = await logsRes.json();
        setLogs(logsData.items || []);
        setTotalLogs(logsData.total || 0);
      }
      if (statsRes.ok) setStats(await statsRes.json());
    } catch (err) {
      console.error("Surveillance fetch error:", err);
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 10000);
    return () => clearInterval(interval);
  }, [fetchData]);

  if (loading) {
    return (
      <div className="tab-pane animate-fade-in">
        <div className="surveillance-loading">
          <div className="spinner" />
          <span>Chargement du tableau de bord...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="tab-pane animate-fade-in">
      <div className="surveillance-header">
        <div className="surveillance-title">
          <Users size={22} />
          <h2>Plateforme de Surveillance</h2>
        </div>
        <div className="surveillance-tabs">
          <button
            className={`surv-tab ${activeSection === "overview" ? "active" : ""}`}
            onClick={() => setActiveSection("overview")}
          >
            <BarChart3 size={14} /> Vue d'ensemble
          </button>
          <button
            className={`surv-tab ${activeSection === "online" ? "active" : ""}`}
            onClick={() => setActiveSection("online")}
          >
            <UserCheck size={14} /> En ligne ({onlineUsers.length})
          </button>
          <button
            className={`surv-tab ${activeSection === "history" ? "active" : ""}`}
            onClick={() => setActiveSection("history")}
          >
            <History size={14} /> Historique
          </button>
        </div>
      </div>

      <div className="surveillance-stats-row">
        <div className="surv-stat-card">
          <div className="surv-stat-icon online">
            <UserCheck size={20} />
          </div>
          <div className="surv-stat-info">
            <span className="surv-stat-value">{stats?.users_online || 0}</span>
            <span className="surv-stat-label">Utilisateurs en ligne</span>
          </div>
        </div>
        <div className="surv-stat-card">
          <div className="surv-stat-icon logins">
            <LogIn size={20} />
          </div>
          <div className="surv-stat-info">
            <span className="surv-stat-value">{stats?.total_logins_today || 0}</span>
            <span className="surv-stat-label">Connexions aujourd'hui</span>
          </div>
        </div>
        <div className="surv-stat-card">
          <div className="surv-stat-icon duration">
            <Clock size={20} />
          </div>
          <div className="surv-stat-info">
            <span className="surv-stat-value">
              {stats?.avg_session_minutes ? `${stats.avg_session_minutes} min` : "--"}
            </span>
            <span className="surv-stat-label">Session moyenne</span>
          </div>
        </div>
        <div className="surv-stat-card">
          <div className="surv-stat-icon face">
            <Fingerprint size={20} />
          </div>
          <div className="surv-stat-info">
            <span className="surv-stat-value">{stats?.face_auth_percentage || 0}%</span>
            <span className="surv-stat-label">Auth faciale</span>
          </div>
        </div>
        <div className="surv-stat-card">
          <div className="surv-stat-icon users">
            <Users size={20} />
          </div>
          <div className="surv-stat-info">
            <span className="surv-stat-value">{stats?.total_users_registered || 0}</span>
            <span className="surv-stat-label">Utilisateurs uniques</span>
          </div>
        </div>
      </div>

      {activeSection === "overview" && (
        <div className="surveillance-overview">
          <div className="surv-chart-card">
            <h3>
              <BarChart3 size={16} /> Connexions par heure (aujourd'hui)
            </h3>
            <div className="surv-chart">
              <ResponsiveContainer width="100%" height={250}>
                <BarChart data={stats?.hourly_logins || []}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                  <XAxis
                    dataKey="hour"
                    stroke="rgba(255,255,255,0.3)"
                    tickFormatter={(h) => `${h}h`}
                    fontSize={12}
                  />
                  <YAxis stroke="rgba(255,255,255,0.3)" fontSize={12} allowDecimals={false} />
                  <Tooltip
                    contentStyle={{
                      background: "rgba(15,23,42,0.95)",
                      border: "1px solid rgba(255,255,255,0.1)",
                      borderRadius: 8,
                      fontSize: 12,
                    }}
                    formatter={(value) => [value, "Connexions"]}
                    labelFormatter={(h) => `${h}:00`}
                  />
                  <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                    {(stats?.hourly_logins || []).map((entry, idx) => (
                      <Cell
                        key={idx}
                        fill={entry.count > 0 ? "#0ea5e9" : "rgba(255,255,255,0.05)"}
                      />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div className="surv-online-card">
            <h3>
              <UserCheck size={16} /> Utilisateurs en ligne
            </h3>
            {onlineUsers.length === 0 ? (
              <div className="surv-empty">Aucun utilisateur en ligne</div>
            ) : (
              <div className="surv-online-list">
                {onlineUsers.map((user) => {
                  const onlineSecs = Math.floor(
                    (now - new Date(user.login_time).getTime()) / 1000
                  );
                  return (
                    <div key={user.id} className="surv-online-item">
                      <div className="surv-online-avatar">
                        {user.face_image ? (
                          <img
                            src={`data:image/jpeg;base64,${user.face_image}`}
                            alt={user.username}
                          />
                        ) : (
                          <div className="surv-avatar-placeholder">
                            {user.username.charAt(0).toUpperCase()}
                          </div>
                        )}
                        <span className="surv-online-dot" />
                      </div>
                      <div className="surv-online-info">
                        <span className="surv-online-name">{user.username}</span>
                        <span className="surv-online-time">
                          <Clock size={11} /> En ligne depuis {formatDuration(onlineSecs)}
                        </span>
                      </div>
                      {user.face_verified && (
                        <span className="surv-badge-face">
                          <ShieldCheck size={12} /> Face
                        </span>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      )}

      {activeSection === "online" && (
        <div className="surv-online-grid">
          {onlineUsers.length === 0 ? (
            <div className="surv-empty">Aucun utilisateur connecté actuellement</div>
          ) : (
            onlineUsers.map((user) => {
              const onlineSecs = Math.floor(
                (now - new Date(user.login_time).getTime()) / 1000
              );
              return (
                <div key={user.id} className="surv-user-card">
                  <div className="surv-user-card-header">
                    {user.face_image ? (
                      <img
                        src={`data:image/jpeg;base64,${user.face_image}`}
                        alt={user.username}
                        className="surv-user-face"
                      />
                    ) : (
                      <div className="surv-user-face-placeholder">
                        {user.username.charAt(0).toUpperCase()}
                      </div>
                    )}
                    <div className="surv-user-status">
                      <span className="surv-online-dot large" />
                      <span>En ligne</span>
                    </div>
                  </div>
                  <div className="surv-user-card-body">
                    <h4>{user.username}</h4>
                    <div className="surv-user-detail">
                      <Clock size={13} />
                      <span>Connecté depuis {formatDuration(onlineSecs)}</span>
                    </div>
                    <div className="surv-user-detail">
                      <LogIn size={13} />
                      <span>{timeAgo(user.login_time)}</span>
                    </div>
                    {user.face_verified && (
                      <div className="surv-user-detail verified">
                        <ShieldCheck size={13} />
                        <span>Visage vérifié</span>
                      </div>
                    )}
                  </div>
                </div>
              );
            })
          )}
        </div>
      )}

      {activeSection === "history" && (
        <div className="surv-history">
          <div className="surv-history-header">
            <span className="surv-history-count">{totalLogs} événements</span>
          </div>
          <div className="surv-table-wrapper">
            <table className="surv-table">
              <thead>
                <tr>
                  <th>Utilisateur</th>
                  <th>Visage</th>
                  <th>Connexion</th>
                  <th>Déconnexion</th>
                  <th>Durée</th>
                  <th>Méthode</th>
                  <th>Statut</th>
                </tr>
              </thead>
              <tbody>
                {logs.map((log) => (
                  <tr key={log.id}>
                    <td>
                      <div className="surv-table-user">
                        {log.face_image ? (
                          <img
                            src={`data:image/jpeg;base64,${log.face_image}`}
                            alt={log.username}
                            className="surv-table-face"
                          />
                        ) : (
                          <div className="surv-table-face-placeholder">
                            {log.username.charAt(0).toUpperCase()}
                          </div>
                        )}
                        <span>{log.username}</span>
                      </div>
                    </td>
                    <td>
                      {log.face_verified ? (
                        <span className="surv-badge-success">
                          <ShieldCheck size={12} /> Vérifié
                        </span>
                      ) : (
                        <span className="surv-badge-muted">
                          <AlertCircle size={12} /> Non
                        </span>
                      )}
                    </td>
                    <td className="surv-cell-time">{new Date(log.login_time).toLocaleString("fr-FR")}</td>
                    <td className="surv-cell-time">
                      {log.logout_time ? new Date(log.logout_time).toLocaleString("fr-FR") : "--"}
                    </td>
                    <td>{log.session_duration ? formatDuration(log.session_duration) : "--"}</td>
                    <td>
                      <span className={`surv-badge-method ${log.login_method}`}>
                        {log.login_method === "password+face" ? "Mot passe + Face" : "Mot de passe"}
                      </span>
                    </td>
                    <td>
                      {log.is_online ? (
                        <span className="surv-status-online">
                          <span className="surv-online-dot small" /> En ligne
                        </span>
                      ) : (
                        <span className="surv-status-offline">
                          <span className="surv-offline-dot" /> Hors ligne
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
