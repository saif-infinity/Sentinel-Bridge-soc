// src/views/SettingsView.jsx
// Paramètres — password change + face registration.
import { useEffect, useRef, useState } from "react";
import {
  Settings,
  Lock,
  KeyRound,
  AlertTriangle,
  CheckCircle2,
  Loader2,
  ScanFace,
  Camera,
} from "lucide-react";
import { changePassword, getFaceStatus, registerFace, getToken } from "../auth";

/* Admin Face Registration (for Settings) */
function AdminFaceRegistration({ username }) {
  const [registered, setRegistered] = useState(null);
  const [cameraStarted, setCameraStarted] = useState(false);
  const [stream, setStream] = useState(null);
  const [loading, setLoading] = useState(false);
  const [msg, setMsg] = useState("");
  const [error, setError] = useState("");
  const videoRef = useRef(null);
  const canvasRef = useRef(null);

  useEffect(() => {
    getFaceStatus(getToken())
      .then((d) => { if (d) setRegistered(d.registered); })
      .catch(() => {});
  }, []);

  useEffect(() => {
    return () => { if (stream) stream.getTracks().forEach((t) => t.stop()); };
  }, [stream]);

  useEffect(() => {
    if (videoRef.current && stream) videoRef.current.srcObject = stream;
  }, [stream, cameraStarted]);

  const startCamera = async () => {
    try {
      setError("");
      const s = await navigator.mediaDevices.getUserMedia({ video: { width: 320, height: 240, facingMode: "user" } });
      setStream(s);
      setCameraStarted(true);
      if (videoRef.current) videoRef.current.srcObject = s;
    } catch {
      setError("Impossible d'accéder à la caméra");
    }
  };

  const stopCamera = () => {
    if (stream) stream.getTracks().forEach((t) => t.stop());
    setStream(null);
    setCameraStarted(false);
  };

  const capture = () => {
    if (!videoRef.current || !canvasRef.current) return null;
    const canvas = canvasRef.current;
    const video = videoRef.current;
    canvas.width = video.videoWidth || 320;
    canvas.height = video.videoHeight || 240;
    canvas.getContext("2d").drawImage(video, 0, 0, canvas.width, canvas.height);
    return canvas.toDataURL("image/jpeg", 0.8).split(",")[1];
  };

  const handleRegister = async () => {
    const image = capture();
    if (!image) { setError("Impossible de capturer l'image"); return; }
    setError("");
    setMsg("");
    setLoading(true);
    try {
      await registerFace(getToken(), username, image);
      setMsg("Visage enregistré avec succès");
      setRegistered(true);
      stopCamera();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      {registered !== null && (
        <div className="admin-face-status-text" style={{ color: registered ? "var(--success)" : "var(--text-muted)" }}>
          {registered ? "Visage enregistré" : "Aucun visage enregistré"}
        </div>
      )}
      {cameraStarted ? (
        <div style={{ marginBottom: 10 }}>
          <video ref={videoRef} autoPlay playsInline muted className="admin-face-video admin-face-settings-video" />
          <canvas ref={canvasRef} style={{ display: "none" }} />
        </div>
      ) : null}
      {error && <div className="admin-error-msg admin-msg-spacing"><AlertTriangle size={14} /> {error}</div>}
      {msg && <div className="admin-success-msg admin-msg-spacing"><CheckCircle2 size={14} /> {msg}</div>}
      <div className="admin-face-btn-row">
        {!cameraStarted ? (
          <button type="button" className="admin-login-btn" onClick={startCamera} style={{ flex: 1 }}>
            <Camera size={14} /> Démarrer la caméra
          </button>
        ) : (
          <>
            <button type="button" className="admin-login-btn" onClick={handleRegister} disabled={loading} style={{ flex: 1 }}>
              {loading ? <><Loader2 size={14} className="admin-spin" /> ...</> : <><CheckCircle2 size={14} /> Enregistrer</>}
            </button>
            <button type="button" className="admin-skip-btn" onClick={stopCamera}>Arrêter</button>
          </>
        )}
      </div>
    </div>
  );
}

export default function SettingsView({
  username,
  currentPw, setCurrentPw,
  newPw, setNewPw,
  confirmPw, setConfirmPw,
  pwLoading, setPwLoading,
  pwError, setPwError,
  pwSuccess, setPwSuccess,
}) {
  const handleChangePassword = async (e) => {
    e.preventDefault();
    setPwError("");
    setPwSuccess("");
    if (newPw !== confirmPw) {
      setPwError("Les mots de passe ne correspondent pas");
      return;
    }
    if (newPw.length < 4) {
      setPwError("Le mot de passe doit contenir au moins 4 caractères");
      return;
    }
    setPwLoading(true);
    try {
      await changePassword(currentPw, newPw);
      setPwSuccess("Mot de passe modifié avec succès");
      setCurrentPw("");
      setNewPw("");
      setConfirmPw("");
    } catch (err) {
      setPwError(err.message);
    } finally {
      setPwLoading(false);
    }
  };

  return (
    <div className="admin-tab">
      <div className="admin-page-header">
        <h2><Settings size={20} /> Paramètres</h2>
      </div>
      <div className="admin-dashboard-grid">
        {/* Password Change */}
        <div className="admin-section-card">
          <h3><Lock size={16} /> Changer le mot de passe</h3>
          <form onSubmit={handleChangePassword}>
            <div className="admin-field">
              <label><KeyRound size={14} /> Mot de passe actuel</label>
              <input type="password" value={currentPw} onChange={(e) => setCurrentPw(e.target.value)} placeholder="Mot de passe actuel" />
            </div>
            <div className="admin-field">
              <label><KeyRound size={14} /> Nouveau mot de passe</label>
              <input type="password" value={newPw} onChange={(e) => setNewPw(e.target.value)} placeholder="Nouveau mot de passe" />
            </div>
            <div className="admin-field">
              <label><KeyRound size={14} /> Confirmer</label>
              <input type="password" value={confirmPw} onChange={(e) => setConfirmPw(e.target.value)} placeholder="Confirmer le mot de passe" />
            </div>
            {pwError && <div className="admin-error-msg"><AlertTriangle size={14} /> {pwError}</div>}
            {pwSuccess && <div className="admin-success-msg"><CheckCircle2 size={14} /> {pwSuccess}</div>}
            <button type="submit" className="admin-login-btn admin-btn-submit" disabled={pwLoading}>
              {pwLoading ? <><Loader2 size={14} className="admin-spin" /> Modification...</> : "Modifier le mot de passe"}
            </button>
          </form>
        </div>

        {/* Face Registration */}
        <div className="admin-section-card">
          <h3><ScanFace size={16} /> Enregistrement facial</h3>
          <p className="admin-text-muted-sm">
            L'enregistrement facial est utilisé pour l'authentification biométrique.
          </p>
          <AdminFaceRegistration username={username} />
        </div>
      </div>
    </div>
  );
}