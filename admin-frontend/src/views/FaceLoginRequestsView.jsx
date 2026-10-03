// src/views/FaceLoginRequestsView.jsx
// Sessions ouvertes + demandes de connexion faciale via GET /api/admin/analysts et /face-login-requests
import { useState, useEffect, useCallback } from "react";
import { Shield, Check, X, Clock, ScanFace, Loader2, Users, Radio, MonitorSmartphone } from "lucide-react";
import { apiFetch } from "../api";

const API = "/api/admin";

function timeAgo(dateStr) {
  if (!dateStr) return "—";
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "à l'instant";
  if (mins < 60) return `il y a ${mins} min`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `il y a ${hours}h`;
  return `il y a ${Math.floor(hours / 24)}j`;
}

function formatLoginTime(iso) {
  if (!iso) return "—";
  try {
    const d = new Date(iso);
    return d.toLocaleString("fr-FR", {
      day: "2-digit",
      month: "2-digit",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  } catch {
    return iso;
  }
}

export default function FaceLoginRequestsView({ onCountChange }) {
  const [activeView, setActiveView] = useState("sessions"); // 'sessions' | 'requests'
  const [sessions, setSessions] = useState([]);
  const [requests, setRequests] = useState([]);
  const [loadingSessions, setLoadingSessions] = useState(true);
  const [loadingRequests, setLoadingRequests] = useState(true);
  const [acting, setActing] = useState(null);

  const fetchSessions = useCallback(async () => {
    try {
      const res = await apiFetch(`${API}/analysts`);
      if (res.ok) {
        const data = await res.json();
        const items = Array.isArray(data) ? data : data.items || data.analysts || [];
        const online = items.filter((u) => u.is_online === undefined || u.is_online === true);
        const list = items.length === online.length ? items : online;
        setSessions(list);
      }
    } catch (err) {
      console.error("Failed to fetch sessions:", err);
    } finally {
      setLoadingSessions(false);
    }
  }, []);

  const fetchRequests = useCallback(async () => {
    try {
      const res = await apiFetch(`${API}/face-login-requests?status=pending`);
      if (res.ok) {
        const data = await res.json();
        const items = data.items || [];
        setRequests(items);
        if (onCountChange) onCountChange(items.length);
      }
    } catch (err) {
      console.error("Failed to fetch face login requests:", err);
    } finally {
      setLoadingRequests(false);
    }
  }, [onCountChange]);

  useEffect(() => {
    fetchSessions();
    fetchRequests();
    const interval = setInterval(() => {
      fetchSessions();
      fetchRequests();
    }, 10000);
    return () => clearInterval(interval);
  }, [fetchSessions, fetchRequests]);

  const handleApprove = async (id) => {
    setActing(id);
    try {
      await apiFetch(`${API}/face-login-requests/${id}/approve`, { method: "POST" });
      fetchRequests();
    } catch (err) {
      console.error("Approve failed:", err);
    } finally {
      setActing(null);
    }
  };

  const handleRefuse = async (id) => {
    setActing(id);
    try {
      await apiFetch(`${API}/face-login-requests/${id}/refuse`, { method: "POST" });
      fetchRequests();
    } catch (err) {
      console.error("Refuse failed:", err);
    } finally {
      setActing(null);
    }
  };

  if (loadingSessions && activeView === "sessions" && sessions.length === 0 && loadingRequests) {
    return (
      <div className="flr-card">
        <div className="flr-loading">
          <Loader2 size={20} className="admin-spin" /> Chargement des sessions...
        </div>
      </div>
    );
  }

  return (
    <div className="flr-card">
      <div className="flr-header">
        {activeView === "sessions" ? <Users size={18} /> : <ScanFace size={18} />}
        <h3>{activeView === "sessions" ? "Sessions ouvertes" : "Demandes de connexion faciale"}</h3>
        {activeView === "sessions" ? (
          sessions.length > 0 && <span className="flr-count flr-count--success">{sessions.length}</span>
        ) : (
          requests.length > 0 && <span className="flr-count">{requests.length}</span>
        )}
        <span className="admin-total-badge" style={{ marginLeft: 8 }}>
          {activeView === "sessions" ? "Utilisateurs connectés" : "En attente"}
        </span>
      </div>

      <div className="os-tabs">
        <button
          className={`os-tab ${activeView === "sessions" ? "active" : ""}`}
          onClick={() => setActiveView("sessions")}
        >
          <Radio size={13} /> Sessions ouvertes
          {sessions.length > 0 && <span className="os-tab-count os-tab-count--online">{sessions.length}</span>}
        </button>
        <button
          className={`os-tab ${activeView === "requests" ? "active" : ""}`}
          onClick={() => setActiveView("requests")}
        >
          <ScanFace size={13} /> Demandes en attente
          {requests.length > 0 && <span className="os-tab-count os-tab-count--alert">{requests.length}</span>}
        </button>
      </div>

      {activeView === "sessions" && (
        <>
          {loadingSessions && sessions.length === 0 ? (
            <div className="flr-loading">
              <Loader2 size={20} className="admin-spin" /> Chargement...
            </div>
          ) : sessions.length === 0 ? (
            <div className="flr-empty">
              <Shield size={36} />
              <p>Aucune session ouverte</p>
              <span className="os-empty-hint">Aucun utilisateur connecté pour le moment.</span>
            </div>
          ) : (
            <div className="flr-table-wrap">
              <table className="flr-table os-table">
                <thead>
                  <tr>
                    <th style={{ width: 64 }}>ID</th>
                    <th>Utilisateur</th>
                    <th>Début de session</th>
                    <th>Méthode</th>
                    <th>IP</th>
                    <th>Statut</th>
                  </tr>
                </thead>
                <tbody>
                  {sessions.map((item) => (
                    <tr key={item.id ?? item.username} className="flr-row">
                      <td className="os-id">#{item.id ?? "—"}</td>
                      <td>
                        <div className="flr-user">
                          {item.face_image ? (
                            <img
                              src={`data:image/jpeg;base64,${item.face_image}`}
                              alt={item.username}
                              className="flr-avatar os-avatar"
                              onError={(e) => {
                                e.currentTarget.style.display = "none";
                              }}
                            />
                          ) : (
                            <div className="os-avatar-placeholder">
                              {item.username ? item.username[0].toUpperCase() : "?"}
                            </div>
                          )}
                          <div className="os-user-meta">
                            <span className="flr-username">{item.username}</span>
                            {item.face_verified !== undefined && (
                              <span className={`os-face-badge ${item.face_verified ? "ok" : "muted"}`}>
                                {item.face_verified ? "Face OK" : "Face —"}
                              </span>
                            )}
                          </div>
                        </div>
                      </td>
                      <td className="flr-time os-time">
                        <Clock size={12} />
                        <span title={item.login_time}>{formatLoginTime(item.login_time)}</span>
                        <span className="os-time-ago">· {timeAgo(item.login_time)}</span>
                      </td>
                      <td>
                        <span className="admin-badge-sm muted os-method">
                          {item.login_method || "—"}
                        </span>
                      </td>
                      <td className="flr-time">
                        <MonitorSmartphone size={11} style={{ marginRight: 4, verticalAlign: "middle" }} />
                        {item.ip_address || "—"}
                      </td>
                      <td>
                        <span className="admin-badge-sm success os-status">
                          <span className="os-dot" /> En ligne
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}

      {activeView === "requests" && (
        <>
          {loadingRequests ? (
            <div className="flr-loading">
              <Loader2 size={20} className="admin-spin" /> Chargement...
            </div>
          ) : requests.length === 0 ? (
            <div className="flr-empty">
              <Shield size={36} />
              <p>Aucune demande en attente</p>
            </div>
          ) : (
            <div className="flr-table-wrap">
              <table className="flr-table">
                <thead>
                  <tr>
                    <th>Utilisateur</th>
                    <th>Demandé</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {requests.map((req) => (
                    <tr key={req.id} className="flr-row">
                      <td>
                        <div className="flr-user">
                          <img
                            src={`/api/faces/image/${req.username}`}
                            alt={req.username}
                            className="flr-avatar"
                            onError={(e) => {
                              e.target.style.display = "none";
                            }}
                          />
                          <span className="flr-username">{req.username}</span>
                        </div>
                      </td>
                      <td className="flr-time">
                        <Clock size={12} /> {timeAgo(req.created_at)}
                      </td>
                      <td>
                        <div className="flr-actions">
                          <button
                            className="flr-btn-approve"
                            onClick={() => handleApprove(req.id)}
                            disabled={acting === req.id}
                          >
                            {acting === req.id ? <Loader2 size={14} className="admin-spin" /> : <Check size={14} />}
                            Approuver
                          </button>
                          <button
                            className="flr-btn-refuse"
                            onClick={() => handleRefuse(req.id)}
                            disabled={acting === req.id}
                          >
                            {acting === req.id ? <Loader2 size={14} className="admin-spin" /> : <X size={14} />}
                            Refuser
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </div>
  );
}
