import { useState, useEffect, useCallback, useRef } from "react";
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  BarChart3,
  Radio,
  Settings,
  Database,
  List,
  LogOut,
  ScanFace,
  Camera,
  CameraOff,
  CheckCircle2,
  Loader2,
  AlertTriangle,
  UserPlus,
  Users,
  Bug,
} from "lucide-react";
import { apiFetch, onUnauthorized, getToken, setToken, clearToken } from "./api";
import {
  login,
  getFaceStatus,
  verifyFace,
  registerFace,
  forceLogout as apiForceLogout,
} from "./auth";
import DashboardView from "./views/DashboardView";
import SensorsView from "./views/SensorsView";
import SettingsView from "./views/SettingsView";
import DatabaseView from "./views/DatabaseView";
import FaceLoginRequestsView from "./views/FaceLoginRequestsView";
import RegistrationRequestsView from "./views/RegistrationRequestsView";
import IntrusionAttemptsView from "./views/IntrusionAttemptsView";
import HoneypotView from "./views/HoneypotView";
import SurveillanceView from "./views/SurveillanceView";
import MatrixRain from "./MatrixRain";

const API = "/api/admin";

export default function App() {
  const [token, setTokenState] = useState(() => getToken());
  const [isAuthenticated, setIsAuthenticated] = useState(!!token);
  const [username, setUsername] = useState("");
  const [adminUsername, setAdminUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  // 2-step login: 1=credentials, 2=face scan
  const [loginStep, setLoginStep] = useState(1);
  const [interimToken, setInterimToken] = useState(null);
  const [faceRegistered, setFaceRegistered] = useState(null);
  const [faceLoading, setFaceLoading] = useState(false);
  const [faceError, setFaceError] = useState("");
  const [faceStream, setFaceStream] = useState(null);
  const [cameraStarted, setCameraStarted] = useState(false);
  const videoRef = useRef(null);
  const canvasRef = useRef(null);

  const [activeTab, setActiveTab] = useState("dashboard");
  const [analysts, setAnalysts] = useState([]);
  const [actions, setActions] = useState([]);
  const [totalActions, setTotalActions] = useState(0);
  const [stats, setStats] = useState(null);
  const [selectedAnalyst, setSelectedAnalyst] = useState(null);
  const [analystActions, setAnalystActions] = useState([]);
  const [analystSessions, setAnalystSessions] = useState([]);
  const [actionFilter, setActionFilter] = useState("");
  const [sensorData, setSensorData] = useState([]);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [pendingRequestCount, setPendingRequestCount] = useState(0);
  const [pendingRegistrationCount, setPendingRegistrationCount] = useState(0);
  const [pendingIntrusionCount, setPendingIntrusionCount] = useState(0);
  const [honeypotTotal, setHoneypotTotal] = useState(0);

  // Settings tab state
  const [currentPw, setCurrentPw] = useState("");
  const [newPw, setNewPw] = useState("");
  const [confirmPw, setConfirmPw] = useState("");
  const [pwLoading, setPwLoading] = useState(false);
  const [pwError, setPwError] = useState("");
  const [pwSuccess, setPwSuccess] = useState("");

  const stopCamera = useCallback(() => {
    if (faceStream) {
      faceStream.getTracks().forEach((t) => t.stop());
      setFaceStream(null);
    }
    setCameraStarted(false);
  }, [faceStream]);

  const startCamera = async () => {
    try {
      setFaceError("");
      const stream = await navigator.mediaDevices.getUserMedia({
        video: { width: 320, height: 240, facingMode: "user" },
      });
      setFaceStream(stream);
      setCameraStarted(true);
      if (videoRef.current) {
        videoRef.current.srcObject = stream;
      }
    } catch {
      setFaceError("Impossible d'accéder à la caméra. Vous pouvez passer cette étape.");
    }
  };

  const captureFrame = () => {
    if (!videoRef.current || !canvasRef.current) return null;
    const canvas = canvasRef.current;
    const video = videoRef.current;
    canvas.width = video.videoWidth || 320;
    canvas.height = video.videoHeight || 240;
    const ctx = canvas.getContext("2d");
    ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
    return canvas.toDataURL("image/jpeg", 0.8).split(",")[1];
  };

  const handleCredentialsLogin = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const data = await login(username, password);
      setInterimToken(data.access_token);
      setAdminUsername(username);
      // Check face status
      const faceData = await getFaceStatus(data.access_token);
      setFaceRegistered(faceData ? faceData.registered : false);
      setLoginStep(2);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleFaceVerify = async () => {
    const image = captureFrame();
    if (!image) {
      setFaceError("Impossible de capturer l'image. Vérifiez que la caméra est active.");
      return;
    }
    setFaceError("");
    setFaceLoading(true);
    try {
      await verifyFace(interimToken, adminUsername, image);
      completeLogin(interimToken);
    } catch (err) {
      setFaceError(err.message);
    } finally {
      setFaceLoading(false);
    }
  };

  const handleFaceRegister = async () => {
    const image = captureFrame();
    if (!image) {
      setFaceError("Impossible de capturer l'image. Vérifiez que la caméra est active.");
      return;
    }
    setFaceError("");
    setFaceLoading(true);
    try {
      await registerFace(interimToken, adminUsername, image);
      // Now verify
      await verifyFace(interimToken, adminUsername, image);
      completeLogin(interimToken);
    } catch (err) {
      setFaceError(err.message);
    } finally {
      setFaceLoading(false);
    }
  };

  const skipFace = () => {
    completeLogin(interimToken);
  };

  const completeLogin = (tok) => {
    stopCamera();
    setToken(tok);
    setTokenState(tok);
    setIsAuthenticated(true);
    setLoginStep(1);
    setInterimToken(null);
    setFaceRegistered(null);
    setFaceError("");
  };

  const resetAuthState = useCallback(() => {
    stopCamera();
    clearToken();
    setTokenState(null);
    setIsAuthenticated(false);
    setLoginStep(1);
    setInterimToken(null);
    setFaceRegistered(null);
    setFaceError("");
    setUsername("");
    setPassword("");
    setAdminUsername("");
  }, [stopCamera]);

  const handleLogout = () => {
    resetAuthState();
  };

  // Expired/invalid token (401) → clear token and return to login.
  const handleSessionExpired = useCallback(() => {
    resetAuthState();
    setError("Session expirée. Veuillez vous reconnecter.");
  }, [resetAuthState]);

  useEffect(() => {
    return onUnauthorized(handleSessionExpired);
  }, [handleSessionExpired]);

  const fetchData = useCallback(async () => {
    if (!token) return;
    try {
      const [statsRes, analystsRes, actionsRes, sensorsRes] = await Promise.all([
        apiFetch(`${API}/stats`),
        apiFetch(`${API}/analysts`),
        apiFetch(`${API}/actions?limit=100`),
        apiFetch(`/api/sensors/analysts?hours=24`),
      ]);
      if (statsRes.ok) setStats(await statsRes.json());
      if (analystsRes.ok) setAnalysts(await analystsRes.json());
      if (actionsRes.ok) {
        const d = await actionsRes.json();
        setActions(d.items || []);
        setTotalActions(d.total || 0);
      }
      if (sensorsRes.ok) setSensorData(await sensorsRes.json());
    } catch (err) {
      console.error("Admin fetch error:", err);
    }
  }, [token]);

  useEffect(() => {
    if (isAuthenticated) {
      fetchData();
      const interval = setInterval(fetchData, 15000);
      return () => clearInterval(interval);
    }
  }, [isAuthenticated, fetchData]);

  // Badges — polling 10s des 3 compteurs (intrusions non résolues, connexions faciales, inscriptions)
  const fetchBadgeCounts = useCallback(async () => {
    if (!isAuthenticated) return;
    try {
      const [attemptsRes, faceRes, regRes] = await Promise.all([
        apiFetch(`${API}/attempts`),
        apiFetch(`${API}/face-login-requests?status=pending`),
        apiFetch(`${API}/registration-requests?status=pending`),
      ]);
      if (attemptsRes.ok) {
        const data = await attemptsRes.json();
        const items = Array.isArray(data) ? data : data.items || data.attempts || [];
        const unresolved = items.filter((a) => !(a.resolved || a.status === "resolved" || a.resolved_at)).length;
        setPendingIntrusionCount(unresolved);
      } else if (attemptsRes.status === 404 || attemptsRes.status === 501) {
        setPendingIntrusionCount(0);
      }
      if (faceRes.ok) {
        const d = await faceRes.json();
        setPendingRequestCount((d.items || []).length);
      }
      if (regRes.ok) {
        const d = await regRes.json();
        setPendingRegistrationCount((d.items || []).length);
      }
    } catch {
      // silencieux — garde la dernière valeur
    }
  }, [isAuthenticated]);

  useEffect(() => {
    if (isAuthenticated) {
      fetchBadgeCounts();
      const id = setInterval(fetchBadgeCounts, 10000);
      return () => clearInterval(id);
    } else {
      setPendingIntrusionCount(0);
      setPendingRequestCount(0);
      setPendingRegistrationCount(0);
    }
  }, [isAuthenticated, fetchBadgeCounts]);

  const selectAnalyst = async (user) => {
    setSelectedAnalyst(user);
    try {
      const [actionsRes, sessionsRes] = await Promise.all([
        apiFetch(`${API}/analysts/${user.username}/actions`),
        apiFetch(`${API}/analysts/${user.username}/sessions`),
      ]);
      if (actionsRes.ok) setAnalystActions(await actionsRes.json());
      if (sessionsRes.ok) setAnalystSessions(await sessionsRes.json());
    } catch (err) {
      console.error("Analyst detail error:", err);
    }
  };

  const forceLogout = async (targetUsername) => {
    if (!confirm(`Forcer la déconnexion de ${targetUsername} ?`)) return;
    try {
      await apiForceLogout(targetUsername);
      fetchData();
      if (selectedAnalyst?.username === targetUsername) setSelectedAnalyst(null);
    } catch (err) {
      console.error("Force logout error:", err);
    }
  };

  const filteredActions = actions.filter((a) =>
    !actionFilter || a.username.toLowerCase().includes(actionFilter.toLowerCase()) ||
    a.action.toLowerCase().includes(actionFilter.toLowerCase())
  );

  // Cleanup camera on unmount
  useEffect(() => {
    return () => {
      if (faceStream) faceStream.getTracks().forEach((t) => t.stop());
    };
  }, [faceStream]);

  // Sync video element with stream
  useEffect(() => {
    if (videoRef.current && faceStream) {
      videoRef.current.srcObject = faceStream;
    }
  }, [faceStream, cameraStarted]);

  // Auto-dismiss password success
  useEffect(() => {
    if (pwSuccess) {
      const t = setTimeout(() => setPwSuccess(""), 3000);
      return () => clearTimeout(t);
    }
  }, [pwSuccess]);

  const bgContent = (
    <div className="admin-login-bg">
      <div className="admin-bg-gradient" />
      <MatrixRain />
      <div className="admin-login-scanlines" />
      <div className="admin-login-radar" />
    </div>
  );

  if (!isAuthenticated) {
    return (
      <div className="admin-login-page">
        {bgContent}
        <div className="admin-login-container">
          <div className="admin-hud-corner-tr" />
          <div className="admin-hud-corner-bl" />
          <div className="admin-card-scan-overlay" />
          <div className="admin-card-glow" />

          {/* Step 1: Credentials */}
          {loginStep === 1 && (
            <>
              <div className="admin-login-header">
                <div className="admin-login-logo">
                  <ShieldCheck size={28} color="#a855f7" />
                </div>
                <h1>SUPERVISION ADMIN</h1>
                <p>Sentinel Bridge - Plateforme d'administration</p>
                <p className="admin-login-sys-text">ADMIN CONSOLE // RESTRICTED ACCESS</p>
              </div>
              <form className="admin-login-form" onSubmit={handleCredentialsLogin}>
                <div className="admin-field">
                  <label><Shield size={14} /> Nom d'utilisateur</label>
                  <input
                    type="text"
                    placeholder="admin"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    autoFocus
                  />
                </div>
                <div className="admin-field">
                  <label><Shield size={14} /> Mot de passe</label>
                  <input
                    type="password"
                    placeholder="Entrez votre mot de passe"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                  />
                </div>
                {error && (
                  <div className="admin-error-msg">
                    <AlertTriangle size={14} /> {error}
                  </div>
                )}
                <button type="submit" className="admin-login-btn" disabled={loading}>
                  {loading ? "Authentification..." : "Se connecter"}
                </button>
              </form>
            </>
          )}

          {/* Step 2: Face scan */}
          {loginStep === 2 && (
            <>
              <div className="admin-login-header">
                <div className="admin-login-logo">
                  <ScanFace size={28} color="#a855f7" />
                </div>
                <h1>BIOMÉTRIE</h1>
                <p className="admin-login-sys-text">
                  {faceRegistered
                    ? "VERIFICATION FACIALE REQUISE"
                    : "ENREGISTREMENT FACIAL REQUIS"}
                </p>
              </div>

              <div className="admin-face-scan-box">
                {cameraStarted ? (
                  <video
                    ref={videoRef}
                    autoPlay
                    playsInline
                    muted
                    className="admin-face-video"
                  />
                ) : (
                  <div className="admin-face-placeholder">
                    <CameraOff size={32} />
                    <span>Caméra inactive</span>
                  </div>
                )}
                <canvas ref={canvasRef} style={{ display: "none" }} />
              </div>

              {faceError && (
                <div className="admin-error-msg">
                  <AlertTriangle size={14} /> {faceError}
                </div>
              )}

              <div className="admin-face-actions">
                {!cameraStarted ? (
                  <button
                    type="button"
                    className="admin-login-btn"
                    onClick={startCamera}
                  >
                    <Camera size={14} /> Démarrer la caméra
                  </button>
                ) : (
                  <button
                    type="button"
                    className="admin-login-btn"
                    onClick={faceRegistered ? handleFaceVerify : handleFaceRegister}
                    disabled={faceLoading}
                  >
                    {faceLoading ? (
                      <><Loader2 size={14} className="admin-spin" /> Analyse...</>
                    ) : (
                      <><CheckCircle2 size={14} /> Capturer et {faceRegistered ? "vérifier" : "enregistrer"}</>
                    )}
                  </button>
                )}
                <button
                  type="button"
                  className="admin-skip-btn"
                  onClick={skipFace}
                >
                  Passer cette étape
                </button>
              </div>
            </>
          )}
      </div>
    </div>
  );
  }

  /* ═══════════════════════════════════════════
     AUTHENTICATED DASHBOARD
     ═══════════════════════════════════════════ */
  const onlineCount = analysts.filter((a) => a.is_online).length;

  return (
    <div className="admin-app">
      {/* ── Sidebar ── */}
      <aside className={`admin-sidebar ${sidebarOpen ? 'mobile-visible' : ''}`}>
        <div className="admin-logo">
          <ShieldCheck size={20} />
          <span>SOC ADMIN</span>
        </div>
        <nav className="admin-nav">
          <button className={`admin-nav-item ${activeTab === "dashboard" ? "active" : ""}`}
            onClick={() => { setActiveTab("dashboard"); setSelectedAnalyst(null); setSidebarOpen(false); }}>
            <BarChart3 size={16} /> Tableau de bord
          </button>
          <button className={`admin-nav-item ${activeTab === "capteurs" ? "active" : ""}`}
            onClick={() => { setActiveTab("capteurs"); setSelectedAnalyst(null); setSidebarOpen(false); }}>
            <Radio size={16} /> Capteurs
            <span className="admin-badge">{onlineCount}</span>
          </button>
          <button className={`admin-nav-item ${activeTab === "surveillance" ? "active" : ""}`}
            onClick={() => { setActiveTab("surveillance"); setSelectedAnalyst(null); setSidebarOpen(false); }}>
            <Camera size={16} /> Surveillance
          </button>
          <button className={`admin-nav-item ${activeTab === "intrusions" ? "active" : ""}`}
            onClick={() => { setActiveTab("intrusions"); setSelectedAnalyst(null); setSidebarOpen(false); }}>
            <ShieldAlert size={16} /> Tentatives d'intrusion
            {isAuthenticated && pendingIntrusionCount > 0 && <span className="admin-badge alert">{pendingIntrusionCount}</span>}
          </button>
          <button className={`admin-nav-item ${activeTab === "connexions" ? "active" : ""}`}
            onClick={() => { setActiveTab("connexions"); setSelectedAnalyst(null); setSidebarOpen(false); }}>
            <ScanFace size={16} /> Connexions faciales
            {isAuthenticated && pendingRequestCount > 0 && <span className="admin-badge success">{pendingRequestCount}</span>}
          </button>
          <button className={`admin-nav-item ${activeTab === "inscriptions" ? "active" : ""}`}
            onClick={() => { setActiveTab("inscriptions"); setSelectedAnalyst(null); setSidebarOpen(false); }}>
            <UserPlus size={16} /> Demandes d'inscription
            {isAuthenticated && pendingRegistrationCount > 0 && <span className="admin-badge alert">{pendingRegistrationCount}</span>}
          </button>
          <button className={`admin-nav-item ${activeTab === "settings" ? "active" : ""}`}
            onClick={() => { setActiveTab("settings"); setSelectedAnalyst(null); setSidebarOpen(false); }}>
            <Settings size={16} /> Paramètres
          </button>
          <button className={`admin-nav-item ${activeTab === "honeypot" ? "active" : ""}`}
            onClick={() => { setActiveTab("honeypot"); setSelectedAnalyst(null); setSidebarOpen(false); }}>
            <Bug size={16} /> Honeypot
            {isAuthenticated && honeypotTotal > 0 && <span className="admin-badge alert">{honeypotTotal}</span>}
          </button>
          <button className={`admin-nav-item ${activeTab === "database" ? "active" : ""}`}
            onClick={() => { setActiveTab("database"); setSelectedAnalyst(null); setSidebarOpen(false); }}>
            <Database size={16} /> Base de données
          </button>
        </nav>
        <div className="admin-sidebar-footer">
          <div className="admin-user-info">
            <Shield size={14} /> admin
          </div>
          <button className="admin-logout-btn" onClick={handleLogout}>
            <LogOut size={14} /> Déconnexion
          </button>
        </div>
      </aside>
      {sidebarOpen && <div className="admin-sidebar-overlay visible" onClick={() => setSidebarOpen(false)} />}

      {/* ── Main ── */}
      <main className="admin-main">
        <button className="admin-sidebar-toggle" onClick={() => setSidebarOpen(!sidebarOpen)}>
          <List size={20} />
        </button>
        {activeTab === "dashboard" && (
          <DashboardView
            stats={stats}
            analysts={analysts}
            actions={filteredActions}
            totalActions={totalActions}
            onSelectAnalyst={selectAnalyst}
            selectedAnalyst={selectedAnalyst}
            setSelectedAnalyst={setSelectedAnalyst}
            analystActions={analystActions}
            analystSessions={analystSessions}
            forceLogout={forceLogout}
          />
        )}
        {activeTab === "capteurs" && (
          <SensorsView sensorData={sensorData} />
        )}
        {activeTab === "surveillance" && (
          <SurveillanceView token={token} />
        )}
        {activeTab === "intrusions" && (
          <IntrusionAttemptsView onCountChange={setPendingIntrusionCount} />
        )}
        {activeTab === "connexions" && (
          <FaceLoginRequestsView onCountChange={setPendingRequestCount} />
        )}
        {activeTab === "inscriptions" && (
          <RegistrationRequestsView onCountChange={setPendingRegistrationCount} />
        )}
        {activeTab === "settings" && (
          <SettingsView
            username={adminUsername}
            currentPw={currentPw} setCurrentPw={setCurrentPw}
            newPw={newPw} setNewPw={setNewPw}
            confirmPw={confirmPw} setConfirmPw={setConfirmPw}
            pwLoading={pwLoading} setPwLoading={setPwLoading}
            pwError={pwError} setPwError={setPwError}
            pwSuccess={pwSuccess} setPwSuccess={setPwSuccess}
          />
        )}
        {activeTab === "database" && (
          <DatabaseView />
        )}
        {activeTab === "honeypot" && (
          <HoneypotView />
        )}
      </main>
    </div>
  );
}