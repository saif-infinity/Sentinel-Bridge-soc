// src/views/IntrusionAttemptsView.jsx
// Tentatives d'intrusion — captures de visages non reconnus via GET /api/admin/attempts
import { useState, useEffect, useCallback } from "react";
import { ShieldAlert, Clock, User, CheckCircle2, XCircle, Loader2, Shield, Filter } from "lucide-react";
import { apiFetch } from "../api";

const API = "/api/admin";

function formatCaptureTime(iso) {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleString("fr-FR", {
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

function AttemptPhoto({ faceImage, username }) {
  const [failed, setFailed] = useState(false);
  const src = faceImage ? (faceImage.startsWith("data:") ? faceImage : `data:image/jpeg;base64,${faceImage}`) : null;
  const initial = (username || "?")[0]?.toUpperCase() || "?";

  if (!src || failed) {
    return <div className="ia-photo-placeholder">{initial}</div>;
  }

  return (
    <img
      src={src}
      alt={username || "Inconnu"}
      className="ia-photo"
      onError={() => setFailed(true)}
    />
  );
}

export default function IntrusionAttemptsView({ onCountChange }) {
  const [attempts, setAttempts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [filter, setFilter] = useState("all"); // all | unresolved | resolved
  const [, setNowTick] = useState(Date.now());

  useEffect(() => {
    const t = setInterval(() => setNowTick(Date.now()), 60000);
    return () => clearInterval(t);
  }, []);

  const fetchAttempts = useCallback(async () => {
    try {
      const res = await apiFetch(`${API}/attempts`, { method: "GET" });
      if (res.ok) {
        const data = await res.json();
        const items = Array.isArray(data) ? data : data.items || data.attempts || [];
        setAttempts(items);
        setError(null);
        if (onCountChange) {
          const unresolved = items.filter((a) => !(a.resolved || a.status === "resolved" || a.resolved_at)).length;
          onCountChange(unresolved);
        }
      } else if (res.status === 404 || res.status === 501) {
        setAttempts([]);
        setError(null);
        if (onCountChange) onCountChange(0);
      } else {
        if (attempts.length === 0) setError("Impossible de charger les tentatives.");
      }
    } catch {
      if (attempts.length === 0) setError("Erreur réseau. Réessayez.");
    } finally {
      setLoading(false);
    }
  }, [onCountChange]);

  useEffect(() => {
    fetchAttempts();
    const id = setInterval(fetchAttempts, 10000);
    return () => clearInterval(id);
  }, [fetchAttempts]);

  const filtered = attempts.filter((a) => {
    const resolved = !!(a.resolved || a.status === "resolved" || a.resolved_at);
    if (filter === "unresolved") return !resolved;
    if (filter === "resolved") return resolved;
    return true;
  });

  const unresolvedCount = attempts.filter((a) => !(a.resolved || a.status === "resolved" || a.resolved_at)).length;

  if (loading) {
    return (
      <div className="flr-card">
        <div className="flr-loading">
          <Loader2 size={18} className="admin-spin" /> Chargement des tentatives d'intrusion...
        </div>
      </div>
    );
  }

  return (
    <div className="flr-card">
      <div className="flr-header">
        <ShieldAlert size={18} />
        <h3>Tentatives d'intrusion</h3>
        {attempts.length > 0 && (
          <span className={`flr-count ${unresolvedCount === 0 ? "flr-count--success" : ""}`}>
            {attempts.length}
          </span>
        )}
        <span className="admin-total-badge" style={{ marginLeft: 8 }}>
          {filter === "all" ? "Toutes" : filter === "unresolved" ? "Non résolues" : "Résolues"}
          {" · "}
          {formatCaptureTime(new Date().toISOString()).slice(0, 10)}
        </span>
      </div>

      <div className="os-tabs" style={{ justifyContent: "space-between", flexWrap: "wrap" }}>
        <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
          <button className={`os-tab ${filter === "all" ? "active" : ""}`} onClick={() => setFilter("all")}>
            <Filter size={12} /> Toutes
            <span className="os-tab-count" style={{ background: "rgba(168,85,247,0.12)", color: "var(--text-muted)" }}>
              {attempts.length}
            </span>
          </button>
          <button className={`os-tab ${filter === "unresolved" ? "active" : ""}`} onClick={() => setFilter("unresolved")}>
            <XCircle size={12} /> Non résolues
            {unresolvedCount > 0 && <span className="os-tab-count os-tab-count--alert">{unresolvedCount}</span>}
          </button>
          <button className={`os-tab ${filter === "resolved" ? "active" : ""}`} onClick={() => setFilter("resolved")}>
            <CheckCircle2 size={12} /> Résolues
          </button>
        </div>
        <span className="admin-total-badge" style={{ fontSize: 9 }}>
          Rafraîchissement auto · 10 s
        </span>
      </div>

      {error && (
        <div className="admin-error-msg" style={{ margin: "12px 16px 0" }}>
          <ShieldAlert size={14} /> {error}
        </div>
      )}

      {filtered.length === 0 ? (
        <div className="flr-empty">
          <Shield size={36} />
          <p>{attempts.length === 0 ? "Aucune tentative d'intrusion enregistrée" : "Aucun résultat pour ce filtre"}</p>
          <span className="os-empty-hint">
            {attempts.length === 0
              ? "Les captures de visages non reconnus apparaîtront ici."
              : "Modifiez le filtre pour voir d'autres tentatives."}
          </span>
        </div>
      ) : (
        <div className="ia-grid">
          {filtered.map((item) => {
            const resolved = !!(item.resolved || item.status === "resolved" || item.resolved_at);
            const captureTime = item.capture_time || item.captured_at || item.timestamp || item.created_at;
            const username = item.username || item.attempted_username || "Inconnu";
            return (
              <div key={item.id ?? `${username}-${captureTime}`} className={`ia-card ${resolved ? "resolved" : "unresolved"}`}>
                <div className="ia-photo-wrap">
                  <AttemptPhoto faceImage={item.face_image || item.capture_image || item.image} username={username} />
                  <span className={`ia-status-dot ${resolved ? "resolved" : "unresolved"}`} title={resolved ? "Résolu" : "Non résolu"} />
                </div>
                <div className="ia-body">
                  <div className="ia-top">
                    <span className="ia-username" title={username}>
                      <User size={12} /> {username}
                    </span>
                    <span className={`admin-badge-sm ${resolved ? "success" : "danger"}`}>
                      {resolved ? <><CheckCircle2 size={10} /> Résolu</> : <><XCircle size={10} /> Non résolu</>}
                    </span>
                  </div>
                  <div className="ia-time">
                    <Clock size={11} />
                    <span title={captureTime}>{formatCaptureTime(captureTime)}</span>
                    <span className="os-time-ago">· {timeAgo(captureTime)}</span>
                  </div>
                  {(item.resolved_by || item.resolved_at) && (
                    <div className="ia-resolved-meta">
                      {item.resolved_by && <span>Par {item.resolved_by}</span>}
                      {item.resolved_at && <span>{formatCaptureTime(item.resolved_at)}</span>}
                    </div>
                  )}
                  {item.reason && <div className="ia-reason">{item.reason}</div>}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
