// src/views/RegistrationRequestsView.jsx
// Demandes d'inscription en attente avec actions Approuver/Refuser
import { useState, useEffect, useCallback } from "react";
import { Shield, Check, X, Clock, UserPlus, Loader2 } from "lucide-react";
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

export default function RegistrationRequestsView({ onCountChange }) {
  const [requests, setRequests] = useState([]);
  const [loading, setLoading] = useState(true);
  const [acting, setActing] = useState(null);

  const fetchRequests = useCallback(async () => {
    try {
      const res = await apiFetch(`${API}/registration-requests?status=pending`);
      if (res.ok) {
        const data = await res.json();
        const items = data.items || [];
        setRequests(items);
        if (onCountChange) onCountChange(items.length);
      }
    } catch (err) {
      console.error("Failed to fetch registration requests:", err);
    } finally {
      setLoading(false);
    }
  }, [onCountChange]);

  useEffect(() => {
    fetchRequests();
    const interval = setInterval(fetchRequests, 10000);
    return () => clearInterval(interval);
  }, [fetchRequests]);

  const handleApprove = async (id) => {
    setActing(id);
    try {
      await apiFetch(`${API}/registration-requests/${id}/approve`, { method: "POST" });
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
      await apiFetch(`${API}/registration-requests/${id}/refuse`, { method: "POST" });
      fetchRequests();
    } catch (err) {
      console.error("Refuse failed:", err);
    } finally {
      setActing(null);
    }
  };

  if (loading) {
    return (
      <div className="flr-card">
        <div className="flr-loading">
          <Loader2 size={20} className="admin-spin" /> Chargement...
        </div>
      </div>
    );
  }

  return (
    <div className="flr-card">
      <div className="flr-header">
        <UserPlus size={18} />
        <h3>Demandes d'inscription</h3>
        {requests.length > 0 && <span className="flr-count">{requests.length}</span>}
      </div>

      {requests.length === 0 ? (
        <div className="flr-empty">
          <Shield size={36} />
          <p>Aucune demande d'inscription en attente</p>
        </div>
      ) : (
        <div className="flr-table-wrap">
          <table className="flr-table">
            <thead>
              <tr>
                <th>Utilisateur</th>
                <th>Rôle</th>
                <th>Demandé</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {requests.map((req) => (
                <tr key={req.id} className="flr-row">
                  <td>
                    <div className="flr-user">
                      {req.face_image ? (
                        <img
                          src={req.face_image.startsWith("data:") ? req.face_image : `data:image/jpeg;base64,${req.face_image}`}
                          alt={req.username}
                          className="flr-avatar"
                          onError={(e) => { e.currentTarget.style.display = "none"; }}
                        />
                      ) : (
                        <img
                          src={`/api/faces/image/${req.username}`}
                          alt={req.username}
                          className="flr-avatar"
                          onError={(e) => { e.target.style.display = "none"; }}
                        />
                      )}
                      <span className="flr-username">{req.username}</span>
                    </div>
                  </td>
                  <td className="flr-time">{req.role}</td>
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
    </div>
  );
}
