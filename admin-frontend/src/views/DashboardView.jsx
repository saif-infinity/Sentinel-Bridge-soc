// src/views/DashboardView.jsx
// Dashboard — main overview + analyst detail panel.
import { useMemo, useState } from "react";
import {
  Users,
  Activity,
  Clock,
  Fingerprint,
  LogOut,
  X,
  AlertTriangle,
  BarChart3,
  Server,
  Eye,
  AlertCircle,
  FileText,
} from "lucide-react";

const ACTION_ICONS = {
  view: Eye,
  create: AlertCircle,
  update: FileText,
  delete: X,
};

const ACTION_LABELS = {
  "view:/api/devices": "Consultation des appareils",
  "view:/api/alerts": "Consultation des alertes",
  "view:/api/scan": "Consultation des scans",
  "view:/api/analyse": "Analyse des menaces",
  "create:/api/scan": "Lancement d'un scan",
  "view:/api/tasks": "Consultation des tâches",
  "view:/api/suricata": "Consultation Suricata",
  "view:/api/terminal": "Accès terminal",
  "view:/api/wazuh": "Consultation Wazuh",
  "view:/api/ai": "Requête IA",
};

function getActionLabel(action) {
  return ACTION_LABELS[action] || action;
}

function getActionIcon(action) {
  const prefix = action.split(":")[0];
  const Icon = ACTION_ICONS[prefix];
  return Icon || Activity;
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

// Analyst face avatar. Falls back to the initial-letter placeholder
// when the image route returns 404 or errors (no stored face image).
function FaceImage({ username, fallbackClass }) {
  const [failed, setFailed] = useState(false);
  if (failed) {
    return <div className={fallbackClass}>{username[0].toUpperCase()}</div>;
  }
  return (
    <img
      src={`/api/faces/image/${username}`}
      alt={username}
      onError={() => setFailed(true)}
    />
  );
}

export default function DashboardView({
  stats,
  analysts,
  actions,
  totalActions,
  onSelectAnalyst,
  selectedAnalyst,
  setSelectedAnalyst,
  analystActions,
  analystSessions,
  forceLogout,
}) {
  const onlineCount = analysts.filter((a) => a.is_online).length;

  // Group actions by hour for the chart
  const hourlyData = useMemo(() => {
    const hours = Array.from({ length: 24 }, (_, i) => ({ hour: i, count: 0 }));
    actions.forEach((a) => {
      const h = new Date(a.timestamp).getHours();
      if (hours[h]) hours[h].count++;
    });
    const maxCount = Math.max(...hours.map((h) => h.count), 1);
    return { hours, maxCount };
  }, [actions]);

  if (selectedAnalyst) {
    return (
      <div className="admin-tab">
        <div className="admin-page-header">
          <h2><Users size={20} /> {selectedAnalyst.username}</h2>
          <span className="admin-total-badge">{selectedAnalyst.is_online ? "En ligne" : "Hors ligne"}</span>
        </div>
        <div className="admin-analysts-layout">
          <div className="admin-section-card">
            <h3><Activity size={16} /> Actions récentes</h3>
            {analystActions.length === 0 ? (
              <div className="admin-empty">Aucune action</div>
            ) : (
              <div className="admin-table-wrapper">
                <table className="admin-table">
                  <thead><tr><th>Action</th><th>Détails</th><th>Heure</th></tr></thead>
                  <tbody>
                    {analystActions.map((a, i) => (
                      <tr key={i}>
                        <td>
                          <span className="admin-table-action-cell">
                            {(() => { const I = getActionIcon(a.action); return <I size={13} />; })()}
                            <span className="admin-table-action">{getActionLabel(a.action)}</span>
                          </span>
                        </td>
                        <td className="admin-cell-mono">{a.details || a.resource || "--"}</td>
                        <td className="admin-cell-mono">{timeAgo(a.timestamp)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
          <div className="admin-analyst-detail-panel">
            <div className="admin-detail-header">
              <h4>Détails</h4>
              <button className="admin-btn-close" onClick={() => setSelectedAnalyst(null)}>
                <X size={14} />
              </button>
            </div>
            <div className="admin-detail-face">
              {selectedAnalyst.has_face ? (
                <FaceImage username={selectedAnalyst.username} fallbackClass="admin-analyst-avatar-lg" />
              ) : (
                <div className="admin-analyst-avatar-lg">{selectedAnalyst.username[0].toUpperCase()}</div>
              )}
            </div>
            <div className="admin-analyst-status">
              <span className={`admin-online-dot ${selectedAnalyst.is_online ? "large" : ""} ${!selectedAnalyst.is_online ? "offline" : ""}`} />
              {selectedAnalyst.is_online ? "En ligne" : "Hors ligne"}
            </div>
            <div className="admin-detail-section">
              <h5><Clock size={12} /> Sessions ({analystSessions.length})</h5>
              {analystSessions.length === 0 ? (
                <div className="admin-empty-sm">Aucune session</div>
              ) : (
                <div className="admin-detail-action-list">
                  {analystSessions.slice(0, 5).map((s, i) => (
                    <div key={i} className="admin-detail-action-item">
                      <Clock size={11} />
                      <span className="admin-detail-action-text">{s.method || "?"} {s.endpoint || s.path || ""}</span>
                      <span className="admin-detail-action-time">{timeAgo(s.timestamp)}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
            <button className="admin-btn-danger-sm" onClick={() => forceLogout(selectedAnalyst.username)}>
              <LogOut size={12} /> Forcer déconnexion
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="admin-tab">
      <div className="admin-page-header">
        <h2><BarChart3 size={20} /> Tableau de bord</h2>
        {stats && <span className="admin-realtime">En direct</span>}
      </div>

      {/* ── Stats Cards ── */}
      {stats && (
        <div className="admin-stats-grid">
          <div className="admin-stat-card">
            <div className="admin-stat-icon blue"><Users size={20} /></div>
            <div>
              <div className="admin-stat-value">{onlineCount}</div>
              <div className="admin-stat-label">Analystes en ligne</div>
            </div>
          </div>
          <div className="admin-stat-card">
            <div className="admin-stat-icon green"><Activity size={20} /></div>
            <div>
              <div className="admin-stat-value">{totalActions}</div>
              <div className="admin-stat-label">Actions totales</div>
            </div>
          </div>
          <div className="admin-stat-card">
            <div className="admin-stat-icon orange"><AlertTriangle size={20} /></div>
            <div>
              <div className="admin-stat-value">{stats.total_alerts ?? "--"}</div>
              <div className="admin-stat-label">Alertes totales</div>
            </div>
          </div>
          <div className="admin-stat-card">
            <div className="admin-stat-icon purple"><Server size={20} /></div>
            <div>
              <div className="admin-stat-value">{analysts.length}</div>
              <div className="admin-stat-label">Analystes inscrits</div>
            </div>
          </div>
        </div>
      )}

      {/* ── Dashboard Grid ── */}
      <div className="admin-dashboard-grid">
        {/* Online Analysts */}
        <div className="admin-section-card">
          <h3><Users size={16} /> Analystes</h3>
          {analysts.length === 0 ? (
            <div className="admin-empty">Aucun analyste</div>
          ) : (
            <div className="admin-online-list">
              {analysts.map((a) => (
                <div key={a.username} className="admin-online-item" onClick={() => onSelectAnalyst(a)}>
                  <div className="admin-online-avatar">
                    {a.has_face ? (
                      <FaceImage username={a.username} fallbackClass="admin-avatar-placeholder" />
                    ) : (
                      <div className="admin-avatar-placeholder">{a.username[0].toUpperCase()}</div>
                    )}
                    {a.is_online && <div className="admin-online-dot" />}
                  </div>
                  <div className="admin-online-info">
                    <div className="admin-online-name">{a.username}</div>
                    <div className="admin-online-meta">
                      {a.is_online ? (
                        <><span className="admin-online-dot large" /> En ligne · {a.session_duration || "actif"}</>
                      ) : (
                        <span>Dernière vue {timeAgo(a.last_seen)}</span>
                      )}
                    </div>
                  </div>
                  {a.has_face && (
                    <div className="admin-online-tags">
                      <span className="admin-tag-face"><Fingerprint size={9} /> FACE</span>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Activity Feed */}
        <div className="admin-section-card">
          <h3><Activity size={16} /> Activité récente</h3>
          {actions.length === 0 ? (
            <div className="admin-empty">Aucune activité</div>
          ) : (
            <div className="admin-activity-feed">
              {actions.slice(0, 15).map((a, i) => {
                const I = getActionIcon(a.action);
                return (
                  <div key={i} className="admin-feed-item">
                    <div className="admin-feed-icon"><I size={13} /></div>
                    <div className="admin-feed-content">
                      <span className="admin-feed-user">{a.username}</span>
                      <div className="admin-feed-action">{getActionLabel(a.action)}</div>
                    </div>
                    <span className="admin-feed-time">{timeAgo(a.timestamp)}</span>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>

      {/* ── Hourly Chart ── */}
      <div className="admin-section-card">
        <h3><BarChart3 size={16} /> Activité par heure (24h)</h3>
        <div className="admin-hourly-chart">
          {hourlyData.hours.map(({ hour, count }) => (
            <div key={hour} className="admin-hour-bar-wrapper">
              <div className="admin-hour-bar" style={{ height: `${(count / hourlyData.maxCount) * 100}%` }}>
                {count > 0 && <span className="admin-hour-count">{count}</span>}
              </div>
              <span className="admin-hour-label">{String(hour).padStart(2, "0")}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}