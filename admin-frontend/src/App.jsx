import { useState, useEffect, useCallback, useMemo, useRef } from "react";
import {
  Shield,
  ShieldCheck,
  Users,
  Activity,
  Clock,
  Fingerprint,
  LogOut,
  LogIn,
  Eye,
  Search,
  X,
  AlertTriangle,
  UserCheck,
  BarChart3,
  List,
  Grid,
  ChevronDown,
  Terminal,
  Server,
  Radio,
  FileText,
  AlertCircle,
  Camera,
  CameraOff,
  CheckCircle2,
  Loader2,
  ScanFace,
  Settings,
  Lock,
  KeyRound,
  Cpu,
  HardDrive,
  Wifi,
  Database,
  Zap,
  ActivitySquare,
  Table,
  Trash2,
} from "lucide-react";
import "./App.css";

const API = "/api/admin";
const FACES_API = "/api/faces";

function timeAgo(dateStr) {
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "à l'instant";
  if (mins < 60) return `il y a ${mins} min`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `il y a ${hours}h`;
  return `il y a ${Math.floor(hours / 24)}j`;
}

function formatDuration(seconds) {
  if (!seconds && seconds !== 0) return "--";
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

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

export default function App() {
  const [token, setToken] = useState(() => localStorage.getItem("admin_token"));
  const [isAuthenticated, setIsAuthenticated] = useState(!!token);
  const [username, setUsername] = useState("");
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
  const [viewMode, setViewMode] = useState("cards");
  const [sensorData, setSensorData] = useState([]);
  const [sidebarOpen, setSidebarOpen] = useState(false);

  // Settings tab state
  const [currentPw, setCurrentPw] = useState("");
  const [newPw, setNewPw] = useState("");
  const [confirmPw, setConfirmPw] = useState("");
  const [pwLoading, setPwLoading] = useState(false);
  const [pwError, setPwError] = useState("");
  const [pwSuccess, setPwSuccess] = useState("");

  const headers = token ? { Authorization: `Bearer ${token}`, "Content-Type": "application/json" } : {};

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
      const res = await fetch(`${API}/token`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ username, password }),
      });
      if (!res.ok) throw new Error("Identifiants admin incorrects");
      const data = await res.json();
      setInterimToken(data.access_token);
      // Check face status
      const faceRes = await fetch(`${API}/face/status`, {
        headers: { Authorization: `Bearer ${data.access_token}` },
      });
      if (faceRes.ok) {
        const faceData = await faceRes.json();
        setFaceRegistered(faceData.registered);
      } else {
        setFaceRegistered(false);
      }
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
      const res = await fetch(`${FACES_API}/verify`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${interimToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ username: "admin", image }),
      });
      if (!res.ok) {
        const d = await res.json().catch(() => ({}));
        throw new Error(d.detail || "Vérification échouée");
      }
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
      const regRes = await fetch(`${FACES_API}/register`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${interimToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ username: "admin", image }),
      });
      if (!regRes.ok) {
        const d = await regRes.json().catch(() => ({}));
        throw new Error(d.detail || "Enregistrement échoué");
      }
      // Now verify
      const verRes = await fetch(`${FACES_API}/verify`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${interimToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ username: "admin", image }),
      });
      if (!verRes.ok) {
        const d = await verRes.json().catch(() => ({}));
        throw new Error(d.detail || "Vérification échouée après enregistrement");
      }
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
    localStorage.setItem("admin_token", tok);
    setToken(tok);
    setIsAuthenticated(true);
    setLoginStep(1);
    setInterimToken(null);
    setFaceRegistered(null);
    setFaceError("");
  };

  const handleLogout = () => {
    stopCamera();
    localStorage.removeItem("admin_token");
    setToken(null);
    setIsAuthenticated(false);
    setLoginStep(1);
    setInterimToken(null);
    setFaceRegistered(null);
    setUsername("");
    setPassword("");
  };

  const fetchData = useCallback(async () => {
    if (!token) return;
    try {
      const [statsRes, analystsRes, actionsRes, sensorsRes] = await Promise.all([
        fetch(`${API}/stats`, { headers }),
        fetch(`${API}/analysts`, { headers }),
        fetch(`${API}/actions?limit=100`, { headers }),
        fetch(`/api/sensors/analysts?hours=24`, { headers }),
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

  const selectAnalyst = async (user) => {
    setSelectedAnalyst(user);
    try {
      const [actionsRes, sessionsRes] = await Promise.all([
        fetch(`${API}/analysts/${user.username}/actions`, { headers }),
        fetch(`${API}/analysts/${user.username}/sessions`, { headers }),
      ]);
      if (actionsRes.ok) setAnalystActions(await actionsRes.json());
      if (sessionsRes.ok) setAnalystSessions(await sessionsRes.json());
    } catch (err) {
      console.error("Analyst detail error:", err);
    }
  };

  const forceLogout = async (username) => {
    if (!confirm(`Forcer la déconnexion de ${username} ?`)) return;
    try {
      await fetch(`${API}/analysts/${username}/force-logout`, {
        method: "POST",
        headers,
      });
      fetchData();
      if (selectedAnalyst?.username === username) setSelectedAnalyst(null);
    } catch (err) {
      console.error("Force logout error:", err);
    }
  };

  const filteredActions = actions.filter((a) =>
    !actionFilter || a.username.toLowerCase().includes(actionFilter.toLowerCase()) ||
    a.action.toLowerCase().includes(actionFilter.toLowerCase())
  );

  const rainColumns = useMemo(() => {
    const charSets = [
      "01",
      "0123456789ABCDEF",
      "01アイウエオカキクケコ",
      "ALERT BREACH THREAT INTRUSION MALWARE",
      "01001101 10110010 01110010 11010011",
      "█▓▒░╔╗╚╝║═",
      "RSA AES SSL VPN IDS IPS",
      "255.255.255.0 192.168.1.1 ::1",
      "λ=∑∫∂√π∞≠≈≤≥",
      "FATAL CRIT WARN ERROR FAIL DENY",
      "SHA256 MD5 ECDSA HMAC JWT",
      "TCP UDP ICMP HTTP DNS SSH",
      "root admin sys kern daemon",
      "0xDEAD 0xBEEF 0xCAFE 0xF00D",
      "chmod 755 exec fork kill sudo su",
      "SYN ACK FIN RST PSH URG",
      "\\\\x1b[31m \\\\x1b[32m \\\\x1b[0m",
      "XSS SSRF RCE LFI IDOR CSRF OWASP",
    ];
    return charSets.map((chars, i) => (
      <div
        key={i}
        className="admin-matrix-column"
        style={{
          left: `${(i / charSets.length) * 100}%`,
          animationDuration: `${10 + Math.random() * 14}s`,
          animationDelay: `${Math.random() * -20}s`,
          fontSize: `${11 + Math.floor(Math.random() * 4)}px`,
          opacity: 0.3 + Math.random() * 0.7,
          transition: "all 0.3s ease",
        }}
      >
        {chars}
      </div>
    ));
  }, []);

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
      <div className="admin-matrix-rain">{rainColumns}</div>
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
          <button className={`admin-nav-item ${activeTab === "settings" ? "active" : ""}`}
            onClick={() => { setActiveTab("settings"); setSelectedAnalyst(null); setSidebarOpen(false); }}>
            <Settings size={16} /> Paramètres
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
          <Dashboard
            stats={stats}
            analysts={analysts}
            actions={filteredActions}
            totalActions={totalActions}
            sensorData={sensorData}
            onSelectAnalyst={selectAnalyst}
            selectedAnalyst={selectedAnalyst}
            setSelectedAnalyst={setSelectedAnalyst}
            analystActions={analystActions}
            analystSessions={analystSessions}
            forceLogout={forceLogout}
            headers={headers}
          />
        )}
        {activeTab === "capteurs" && (
          <SensorsView sensorData={sensorData} headers={headers} />
        )}
        {activeTab === "settings" && (
          <SettingsView
            headers={headers}
            currentPw={currentPw} setCurrentPw={setCurrentPw}
            newPw={newPw} setNewPw={setNewPw}
            confirmPw={confirmPw} setConfirmPw={setConfirmPw}
            pwLoading={pwLoading} setPwLoading={setPwLoading}
            pwError={pwError} setPwError={setPwError}
            pwSuccess={pwSuccess} setPwSuccess={setPwSuccess}
            token={token}
          />
        )}
        {activeTab === "database" && (
          <DatabaseView headers={headers} />
        )}
      </main>
    </div>
  );
}

/* ═══════════════════════════════════════════
   Dashboard — main overview
   ═══════════════════════════════════════════ */
function Dashboard({ stats, analysts, actions, totalActions, sensorData, onSelectAnalyst, selectedAnalyst, setSelectedAnalyst, analystActions, analystSessions, forceLogout, headers }) {
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
                <img src={`/api/faces/image/${selectedAnalyst.username}`} alt={selectedAnalyst.username} />
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
                      <img src={`/api/faces/image/${a.username}`} alt={a.username} />
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

/* ═══════════════════════════════════════════
   Settings View
   ═══════════════════════════════════════════ */
function SettingsView({ headers, currentPw, setCurrentPw, newPw, setNewPw, confirmPw, setConfirmPw, pwLoading, setPwLoading, pwError, setPwError, pwSuccess, setPwSuccess, token }) {
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
      const res = await fetch(`${API}/change-password`, {
        method: "POST",
        headers,
        body: JSON.stringify({ current_password: currentPw, new_password: newPw }),
      });
      if (!res.ok) {
        const d = await res.json().catch(() => ({}));
        throw new Error(d.detail || "Erreur lors du changement de mot de passe");
      }
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
          <AdminFaceRegistration token={token} headers={headers} />
        </div>
      </div>
    </div>
  );
}

/* ═══════════════════════════════════════════
   Admin Face Registration (for Settings)
   ═══════════════════════════════════════════ */
function AdminFaceRegistration({ token, headers }) {
  const [registered, setRegistered] = useState(null);
  const [cameraStarted, setCameraStarted] = useState(false);
  const [stream, setStream] = useState(null);
  const [loading, setLoading] = useState(false);
  const [msg, setMsg] = useState("");
  const [error, setError] = useState("");
  const videoRef = useRef(null);
  const canvasRef = useRef(null);

  useEffect(() => {
    fetch(`${API}/face/status`, { headers })
      .then((r) => r.ok ? r.json() : null)
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
      const res = await fetch(`${FACES_API}/register`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ username: "admin", image }),
      });
      if (!res.ok) {
        const d = await res.json().catch(() => ({}));
        throw new Error(d.detail || "Échec de l'enregistrement");
      }
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

/* ═══════════════════════════════════════════
   Database View — table browser with stats + CRUD
   ═══════════════════════════════════════════ */
function DatabaseView({ headers }) {
  const [stats, setStats] = useState(null);
  const [tables, setTables] = useState([]);
  const [selectedTable, setSelectedTable] = useState(null);
  const [columns, setColumns] = useState([]);
  const [rows, setRows] = useState([]);
  const [total, setTotal] = useState(0);
  const [totalPages, setTotalPages] = useState(1);
  const [page, setPage] = useState(1);
  const [pageSize] = useState(50);
  const [search, setSearch] = useState("");
  const [sortBy, setSortBy] = useState(null);
  const [sortDir, setSortDir] = useState("desc");
  const [loading, setLoading] = useState(false);
  const [tablesLoading, setTablesLoading] = useState(true);

  // Edit state
  const [editingCell, setEditingCell] = useState(null); // { rowIndex, colName }
  const [editValue, setEditValue] = useState("");
  const [saveStatus, setSaveStatus] = useState(null); // { type: 'success'|'error', msg: '' }

  // Insert state
  const [showInsert, setShowInsert] = useState(false);
  const [insertData, setInsertData] = useState({});

  // Delete confirmation
  const [deletingRow, setDeletingRow] = useState(null);

  // View toggle: tables | stats
  const [viewMode, setViewMode] = useState("tables");

  // ── Create table state ──
  const [showCreateTable, setShowCreateTable] = useState(false);
  const [createTableName, setCreateTableName] = useState("");
  const [createColumns, setCreateColumns] = useState([
    { name: "", type: "text", nullable: true, primary_key: false, default: "" },
  ]);
  const [createLoading, setCreateLoading] = useState(false);

  // ── Drop table state ──
  const [droppingTable, setDroppingTable] = useState(null);

  // Fetch global stats
  useEffect(() => {
    if (!headers?.Authorization) return;
    fetch("/api/admin/database/stats", { headers })
      .then((r) => r.json())
      .then((d) => { setStats(d); setTables(d.tables || []); })
      .catch(() => {})
      .finally(() => setTablesLoading(false));
  }, [headers]);

  // Auto-dismiss save status
  useEffect(() => {
    if (saveStatus) {
      const t = setTimeout(() => setSaveStatus(null), 3000);
      return () => clearTimeout(t);
    }
  }, [saveStatus]);

  // Fetch columns + rows when table changes
  const loadTable = useCallback(async (tableName, p, s, sb, sd) => {
    if (!headers?.Authorization) return;
    setLoading(true);
    try {
      const [colsRes, rowsRes] = await Promise.all([
        fetch(`/api/admin/database/tables/${tableName}/columns`, { headers }),
        fetch(`/api/admin/database/tables/${tableName}/rows?page=${p}&page_size=${pageSize}${s ? `&search=${encodeURIComponent(s)}` : ""}${sb ? `&sort_by=${encodeURIComponent(sb)}&sort_dir=${sd}` : ""}`, { headers }),
      ]);
      if (colsRes.ok) setColumns(await colsRes.json());
      if (rowsRes.ok) {
        const data = await rowsRes.json();
        setRows(data.rows || []);
        setTotal(data.total || 0);
        setTotalPages(data.total_pages || 1);
      }
    } catch (e) { /* ignore */ }
    setLoading(false);
  }, [headers, pageSize]);

  useEffect(() => {
    if (selectedTable) loadTable(selectedTable, page, search, sortBy, sortDir);
  }, [selectedTable, page, search, sortBy, sortDir, loadTable]);

  const handleSearch = (e) => {
    e.preventDefault();
    setPage(1);
    if (selectedTable) loadTable(selectedTable, 1, search, sortBy, sortDir);
  };

  const handleSort = (col) => {
    if (sortBy === col) {
      setSortDir((d) => d === "asc" ? "desc" : "asc");
    } else {
      setSortBy(col);
      setSortDir("desc");
    }
    setPage(1);
  };

  // ── Inline cell editing ──
  const startEdit = (rowIndex, colName, currentValue) => {
    setEditingCell({ rowIndex, colName });
    setEditValue(currentValue === null ? "" : String(currentValue));
  };

  const cancelEdit = () => {
    setEditingCell(null);
    setEditValue("");
  };

  const saveEdit = async (rowIndex, colName) => {
    const pkCol = columns.find((c) => c.primary_key);
    if (!pkCol) { cancelEdit(); return; }
    const rowId = rows[rowIndex][pkCol.name];
    if (rowId === undefined) { cancelEdit(); return; }

    // Convert value back to proper type
    let newVal = editValue;
    const colMeta = columns.find((c) => c.name === colName);
    if (colMeta) {
      const t = colMeta.type.toUpperCase();
      if (t === "INTEGER" || t === "BIGINT" || t === "SMALLINT") {
        newVal = editValue === "" ? null : parseInt(editValue, 10);
      } else if (t === "FLOAT" || t === "DOUBLE PRECISION" || t === "NUMERIC" || t === "REAL") {
        newVal = editValue === "" ? null : parseFloat(editValue);
      } else if (t === "BOOLEAN") {
        newVal = editValue === "true";
      } else if (editValue === "") {
        newVal = null;
      }
    }

    try {
      const res = await fetch(`/api/admin/database/tables/${selectedTable}/rows/${rowId}`, {
        method: "PUT",
        headers,
        body: JSON.stringify({ data: { [colName]: newVal } }),
      });
      if (!res.ok) {
        const d = await res.json().catch(() => ({}));
        throw new Error(d.detail || "Update failed");
      }
      // Update local row
      setRows((prev) => {
        const next = [...prev];
        next[rowIndex] = { ...next[rowIndex], [colName]: newVal };
        return next;
      });
      setSaveStatus({ type: "success", msg: `${colName} mis à jour` });
    } catch (err) {
      setSaveStatus({ type: "error", msg: err.message });
    }
    cancelEdit();
  };

  // ── Delete row ──
  const handleDelete = async (rowIndex) => {
    const pkCol = columns.find((c) => c.primary_key);
    if (!pkCol) return;
    const rowId = rows[rowIndex][pkCol.name];
    try {
      const res = await fetch(`/api/admin/database/tables/${selectedTable}/rows/${rowId}`, {
        method: "DELETE",
        headers,
      });
      if (!res.ok) {
        const d = await res.json().catch(() => ({}));
        throw new Error(d.detail || "Delete failed");
      }
      setSaveStatus({ type: "success", msg: `Ligne #${rowId} supprimée` });
      setDeletingRow(null);
      loadTable(selectedTable, page, search, sortBy, sortDir);
      // Refresh stats
      fetch("/api/admin/database/stats", { headers }).then((r) => r.json()).then(setStats).catch(() => {});
    } catch (err) {
      setSaveStatus({ type: "error", msg: err.message });
    }
  };

  // ── Insert row ──
  const handleInsert = async (e) => {
    e.preventDefault();
    try {
      const res = await fetch(`/api/admin/database/tables/${selectedTable}/rows`, {
        method: "POST",
        headers,
        body: JSON.stringify({ data: insertData }),
      });
      if (!res.ok) {
        const d = await res.json().catch(() => ({}));
        throw new Error(d.detail || "Insert failed");
      }
      setSaveStatus({ type: "success", msg: "Ligne insérée" });
      setShowInsert(false);
      setInsertData({});
      setPage(1);
      loadTable(selectedTable, 1, search, sortBy, sortDir);
      fetch("/api/admin/database/stats", { headers }).then((r) => r.json()).then(setStats).catch(() => {});
    } catch (err) {
      setSaveStatus({ type: "error", msg: err.message });
    }
  };

  // ── Create table ──
  const addCreateColumn = () => {
    setCreateColumns((prev) => [...prev, { name: "", type: "text", nullable: true, primary_key: false, default: "" }]);
  };
  const removeCreateColumn = (idx) => {
    setCreateColumns((prev) => prev.filter((_, i) => i !== idx));
  };
  const updateCreateColumn = (idx, field, value) => {
    setCreateColumns((prev) => prev.map((c, i) => i === idx ? { ...c, [field]: value } : c));
  };

  const handleCreateTable = async (e) => {
    e.preventDefault();
    setCreateLoading(true);
    try {
      const validCols = createColumns.filter((c) => c.name.trim());
      if (!createTableName.trim()) throw new Error("Nom de table requis");
      if (validCols.length === 0) throw new Error("Au moins une colonne requise");

      const res = await fetch("/api/admin/database/tables", {
        method: "POST",
        headers,
        body: JSON.stringify({
          table_name: createTableName.trim(),
          columns: validCols.map((c) => ({
            name: c.name.trim(),
            type: c.type.trim(),
            nullable: c.nullable,
            primary_key: c.primary_key,
            default: c.default.trim() || null,
          })),
        }),
      });
      if (!res.ok) {
        const d = await res.json().catch(() => ({}));
        throw new Error(d.detail || "Création échouée");
      }
      setSaveStatus({ type: "success", msg: `Table "${createTableName}" créée` });
      setShowCreateTable(false);
      setCreateTableName("");
      setCreateColumns([{ name: "", type: "text", nullable: true, primary_key: false, default: "" }]);
      // Refresh table list + stats
      fetch("/api/admin/database/stats", { headers })
        .then((r) => r.json())
        .then((d) => { setStats(d); setTables(d.tables || []); })
        .catch(() => {});
    } catch (err) {
      setSaveStatus({ type: "error", msg: err.message });
    }
    setCreateLoading(false);
  };

  // ── Drop table ──
  const handleDropTable = async (tableName) => {
    try {
      const res = await fetch(`/api/admin/database/tables/${tableName}`, {
        method: "DELETE",
        headers,
      });
      if (!res.ok) {
        const d = await res.json().catch(() => ({}));
        throw new Error(d.detail || "Suppression échouée");
      }
      setSaveStatus({ type: "success", msg: `Table "${tableName}" supprimée` });
      setDroppingTable(null);
      if (selectedTable === tableName) {
        setSelectedTable(null);
        setColumns([]);
        setRows([]);
      }
      fetch("/api/admin/database/stats", { headers })
        .then((r) => r.json())
        .then((d) => { setStats(d); setTables(d.tables || []); })
        .catch(() => {});
    } catch (err) {
      setSaveStatus({ type: "error", msg: err.message });
      setDroppingTable(null);
    }
  };

  const formatValue = (val) => {
    if (val === null || val === undefined) return <span className="db-cell-null">NULL</span>;
    if (typeof val === "boolean") return val ? <span className="db-cell-bool-true">true</span> : <span className="db-cell-bool-false">false</span>;
    const s = String(val);
    if (s.length > 80) return s.substring(0, 80) + "…";
    return s;
  };

  const pkCol = columns.find((c) => c.primary_key);

  return (
    <div className="admin-tab">
      <div className="admin-page-header">
        <h2><Database size={20} /> Base de données</h2>
        <div className="admin-page-header-actions">
          {saveStatus && (
            <span className={`db-save-status ${saveStatus.type}`}>
              {saveStatus.type === "success" ? <CheckCircle2 size={12} /> : <AlertTriangle size={12} />}
              {saveStatus.msg}
            </span>
          )}
          <button className="db-action-btn db-insert-btn" onClick={() => setShowCreateTable(!showCreateTable)}>
            <Database size={13} /> {showCreateTable ? "Fermer" : "Créer table"}
          </button>
          <div className="db-view-toggle">
            <button className={`admin-toggle-btn ${viewMode === "tables" ? "active" : ""}`} onClick={() => setViewMode("tables")}>
              <Database size={13} /> Tables
            </button>
            <button className={`admin-toggle-btn ${viewMode === "stats" ? "active" : ""}`} onClick={() => setViewMode("stats")}>
              <BarChart3 size={13} /> Statistiques
            </button>
          </div>
        </div>
      </div>

      {/* ═══ Global Stats Banner ═══ */}
      {stats && (
        <div className="db-stats-banner">
          <div className="db-stat-pill"><Server size={13} color="#60a5fa" /><span>{stats.database_name}</span><label>Nom</label></div>
          <div className="db-stat-pill"><Database size={13} color="#a855f7" /><span>{stats.database_size_human}</span><label>Taille</label></div>
          <div className="db-stat-pill"><Activity size={13} color="#34d399" /><span>{stats.connections.active}</span><label>Actives</label></div>
          <div className="db-stat-pill"><Clock size={13} color="#fbbf24" /><span>{stats.connections.idle}</span><label>Idle</label></div>
          <div className="db-stat-pill"><Users size={13} color="#60a5fa" /><span>{stats.connections.total}/{stats.max_connections}</span><label>Connexions</label></div>
          <div className="db-stat-pill"><BarChart3 size={13} color="#f87171" /><span>{stats.total_rows.toLocaleString()}</span><label>Total lignes</label></div>
          <div className="db-stat-pill"><Table size={13} color="#a855f7" /><span>{stats.total_tables}</span><label>Tables</label></div>
        </div>
      )}

      {/* ═══ Create Table Form ═══ */}
      {showCreateTable && (
        <div className="db-create-table-form">
          <h4><Database size={14} /> Nouvelle table</h4>
          <form onSubmit={handleCreateTable}>
            <div className="db-create-table-name">
              <label>Nom de la table</label>
              <input
                type="text"
                value={createTableName}
                onChange={(e) => setCreateTableName(e.target.value)}
                placeholder="ma_nouvelle_table"
                autoFocus
              />
            </div>

            <div className="db-create-columns">
              <label>Colonnes</label>
              {createColumns.map((col, idx) => (
                <div key={idx} className="db-create-col-row">
                  <input
                    type="text"
                    value={col.name}
                    onChange={(e) => updateCreateColumn(idx, "name", e.target.value)}
                    placeholder="nom_colonne"
                    className="db-create-col-name"
                  />
                  <select
                    value={col.type}
                    onChange={(e) => updateCreateColumn(idx, "type", e.target.value)}
                    className="db-create-col-type"
                  >
                    <option value="integer">INTEGER</option>
                    <option value="bigint">BIGINT</option>
                    <option value="smallint">SMALLINT</option>
                    <option value="real">REAL</option>
                    <option value="double precision">DOUBLE PRECISION</option>
                    <option value="numeric">NUMERIC</option>
                    <option value="boolean">BOOLEAN</option>
                    <option value="character varying(255)">VARCHAR(255)</option>
                    <option value="text">TEXT</option>
                    <option value="timestamp with time zone">TIMESTAMPTZ</option>
                    <option value="timestamp without time zone">TIMESTAMP</option>
                    <option value="date">DATE</option>
                    <option value="jsonb">JSONB</option>
                    <option value="json">JSON</option>
                    <option value="uuid">UUID</option>
                  </select>
                  <label className="db-create-col-check" title="Nullable">
                    <input
                      type="checkbox"
                      checked={col.nullable}
                      onChange={(e) => updateCreateColumn(idx, "nullable", e.target.checked)}
                    />
                    Nul
                  </label>
                  <label className="db-create-col-check" title="Primary Key">
                    <input
                      type="checkbox"
                      checked={col.primary_key}
                      onChange={(e) => updateCreateColumn(idx, "primary_key", e.target.checked)}
                    />
                    PK
                  </label>
                  <input
                    type="text"
                    value={col.default}
                    onChange={(e) => updateCreateColumn(idx, "default", e.target.value)}
                    placeholder="défaut (opt.)"
                    className="db-create-col-default"
                  />
                  {createColumns.length > 1 && (
                    <button type="button" className="db-row-delete" onClick={() => removeCreateColumn(idx)}>
                      <Trash2 size={11} />
                    </button>
                  )}
                </div>
              ))}
              <button type="button" className="db-action-btn admin-btn-mt-sm" onClick={addCreateColumn}>
                + Ajouter colonne
              </button>
            </div>

            <div className="db-create-actions">
              <button type="submit" className="admin-login-btn admin-btn-compact" disabled={createLoading}>
                {createLoading ? <><Loader2 size={13} className="admin-spin" /> Création...</> : <><Database size={13} /> Créer</>}
              </button>
              <button type="button" className="db-action-btn" onClick={() => setShowCreateTable(false)}>Annuler</button>
            </div>
          </form>
        </div>
      )}

      {/* ═══ View: Tables ═══ */}
      {viewMode === "tables" && (
        <>
          {/* ── Table cards ── */}
          {tablesLoading ? (
            <div className="admin-section-card"><div className="admin-empty"><Loader2 size={18} className="admin-spin" /> Chargement...</div></div>
          ) : (
            <div className="db-tables-grid">
              {tables.map((t) => (
                <div
                  key={t.name}
                  className={`db-table-card ${selectedTable === t.name ? "selected" : ""}`}
                  onClick={() => { setSelectedTable(t.name); setPage(1); setSearch(""); setSortBy(null); setShowInsert(false); }}
                >
                  <div className="db-table-card-icon"><Database size={16} /></div>
                  <div className="db-table-card-info">
                    <span className="db-table-card-name">{t.name}</span>
                    <span className="db-table-card-meta">{t.row_count.toLocaleString()} lignes · {t.column_count} cols · {t.total_size_human}</span>
                  </div>
                  <div className="db-table-card-actions" onClick={(e) => e.stopPropagation()}>
                    {droppingTable === t.name ? (
                      <div className="db-delete-confirm">
                        <span>Supprimer "{t.name}" ?</span>
                        <button className="db-edit-save" onClick={() => handleDropTable(t.name)}><CheckCircle2 size={11} /></button>
                        <button className="db-edit-cancel" onClick={() => setDroppingTable(null)}><X size={11} /></button>
                      </div>
                    ) : (
                      <button className="db-row-delete" onClick={() => setDroppingTable(t.name)} title="Supprimer cette table">
                        <Trash2 size={12} />
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* ── Data viewer ── */}
          {selectedTable && (
            <div className="db-viewer">
              <div className="db-viewer-header">
                <h3><Database size={14} /> {selectedTable}</h3>
                <div className="db-viewer-controls">
                  <span className="db-total-badge">{total.toLocaleString()} résultats</span>
                  <button className="db-action-btn db-insert-btn" onClick={() => { setShowInsert(!showInsert); setInsertData({}); }}>
                    <CheckCircle2 size={13} /> Insérer
                  </button>
                  <form className="db-search-form" onSubmit={handleSearch}>
                    <input type="text" value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Rechercher..." className="db-search-input" />
                    <button type="submit" className="db-search-btn"><Search size={14} /></button>
                    {search && <button type="button" className="db-search-clear" onClick={() => { setSearch(""); setPage(1); }}><X size={14} /></button>}
                  </form>
                </div>
              </div>

              {/* Column labels */}
              <div className="db-column-chips">
                {columns.map((c) => (
                  <span key={c.name} className={`db-col-chip ${c.primary_key ? "pk" : ""}`}>
                    {c.primary_key && <KeyRound size={10} />}
                    {c.name}
                    <span className="db-col-type">{c.type}</span>
                  </span>
                ))}
              </div>

              {/* Insert form */}
              {showInsert && (
                <form className="db-insert-form" onSubmit={handleInsert}>
                  <h4><CheckCircle2 size={14} /> Nouvelle ligne</h4>
                  <div className="db-insert-fields">
                    {columns.map((c) => (
                      <div key={c.name} className="db-insert-field">
                        <label>{c.name} {c.primary_key && <span className="db-col-type">(auto)</span>}</label>
                        <input
                          type="text"
                          disabled={c.primary_key}
                          value={insertData[c.name] ?? ""}
                          onChange={(e) => setInsertData((prev) => ({ ...prev, [c.name]: e.target.value }))}
                          placeholder={c.type}
                        />
                      </div>
                    ))}
                  </div>
                  <div className="db-insert-actions">
                    <button type="submit" className="admin-login-btn admin-btn-compact">Enregistrer</button>
                    <button type="button" className="db-action-btn" onClick={() => setShowInsert(false)}>Annuler</button>
                  </div>
                </form>
              )}

              {/* Data table */}
              <div className="db-table-wrap">
                {loading ? (
                  <div className="admin-empty"><Loader2 size={18} className="admin-spin" /> Chargement...</div>
                ) : rows.length === 0 ? (
                  <div className="admin-empty">Aucune donnée</div>
                ) : (
                  <table className="admin-table db-data-table">
                    <thead>
                      <tr>
                        {columns.map((c) => (
                          <th key={c.name} onClick={() => handleSort(c.name)} className={sortBy === c.name ? "sorted" : ""}>
                            {c.name}
                            {sortBy === c.name && <span className="db-sort-arrow">{sortDir === "asc" ? " ▲" : " ▼"}</span>}
                          </th>
                        ))}
                        <th className="db-actions-col">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {rows.map((row, ri) => (
                        <tr key={ri}>
                          {columns.map((c) => {
                            const isEditing = editingCell?.rowIndex === ri && editingCell?.colName === c.name;
                            return (
                              <td key={c.name} className={`db-cell ${isEditing ? "editing" : ""}`}
                                onDoubleClick={() => !c.primary_key && startEdit(ri, c.name, row[c.name])}
                                title={String(row[c.name] ?? "")}>
                                {isEditing ? (
                                  <div className="db-edit-box">
                                    <input
                                      autoFocus
                                      value={editValue}
                                      onChange={(e) => setEditValue(e.target.value)}
                                      onKeyDown={(e) => {
                                        if (e.key === "Enter") saveEdit(ri, c.name);
                                        if (e.key === "Escape") cancelEdit();
                                      }}
                                    />
                                    <div className="db-edit-actions">
                                      <button className="db-edit-save" onClick={() => saveEdit(ri, c.name)}><CheckCircle2 size={11} /></button>
                                      <button className="db-edit-cancel" onClick={cancelEdit}><X size={11} /></button>
                                    </div>
                                  </div>
                                ) : (
                                  formatValue(row[c.name])
                                )}
                              </td>
                            );
                          })}
                          <td className="db-actions-cell">
                            {deletingRow === ri ? (
                              <div className="db-delete-confirm">
                                <span>Supprimer?</span>
                                <button className="db-edit-save" onClick={() => handleDelete(ri)}><CheckCircle2 size={11} /></button>
                                <button className="db-edit-cancel" onClick={() => setDeletingRow(null)}><X size={11} /></button>
                              </div>
                            ) : (
                              <button className="db-row-delete" onClick={() => setDeletingRow(ri)} title="Supprimer cette ligne">
                                <Trash2 size={12} />
                              </button>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>

              {/* Pagination */}
              {totalPages > 1 && (
                <div className="db-pagination">
                  <button disabled={page <= 1} onClick={() => setPage((p) => Math.max(1, p - 1))}>← Préc</button>
                  <span className="db-page-info">Page {page} / {totalPages}</span>
                  <button disabled={page >= totalPages} onClick={() => setPage((p) => Math.min(totalPages, p + 1))}>Suiv →</button>
                </div>
              )}
            </div>
          )}
        </>
      )}

      {/* ═══ View: Stats ═══ */}
      {viewMode === "stats" && stats && (
        <div className="db-stats-view">
          <div className="admin-section-card">
            <h3><Server size={16} /> Informations</h3>
            <div className="db-info-grid">
              <div className="db-info-item"><span className="db-info-label">Base de données</span><span className="db-info-value">{stats.database_name}</span></div>
              <div className="db-info-item"><span className="db-info-label">PostgreSQL</span><span className="db-info-value">{stats.postgres_version?.split(",")[0]}</span></div>
              <div className="db-info-item"><span className="db-info-label">Taille totale</span><span className="db-info-value">{stats.database_size_human}</span></div>
              <div className="db-info-item"><span className="db-info-label">Tables</span><span className="db-info-value">{stats.total_tables}</span></div>
              <div className="db-info-item"><span className="db-info-label">Lignes totales</span><span className="db-info-value">{stats.total_rows.toLocaleString()}</span></div>
              <div className="db-info-item"><span className="db-info-label">Requêtes lentes</span><span className="db-info-value">{stats.slow_queries}</span></div>
              <div className="db-info-item"><span className="db-info-label">Connexions</span><span className="db-info-value">{stats.connections.total} / {stats.max_connections}</span></div>
              <div className="db-info-item"><span className="db-info-label">Actives / Idle</span><span className="db-info-value">{stats.connections.active} / {stats.connections.idle}</span></div>
            </div>
          </div>

          <div className="admin-section-card admin-section-mt">
            <h3><BarChart3 size={16} /> Détails par table</h3>
            <div className="db-table-wrap db-table-wrap-tall">
              <table className="admin-table db-stats-table">
                <thead>
                  <tr>
                    <th>Table</th>
                    <th>Lignes</th>
                    <th>Taille totale</th>
                    <th>Données</th>
                    <th>Index</th>
                    <th>Seq Scans</th>
                    <th>Idx Scans</th>
                    <th>Ins</th>
                    <th>Upd</th>
                    <th>Del</th>
                    <th>Mortes</th>
                    <th>Dernier vacuum</th>
                  </tr>
                </thead>
                <tbody>
                  {stats.tables.map((t) => (
                    <tr key={t.name}>
                      <td className="db-cell-name">{t.name}</td>
                      <td>{t.row_count.toLocaleString()}</td>
                      <td>{t.total_size_human}</td>
                      <td>{t.data_size_human}</td>
                      <td>{t.index_size_human}</td>
                      <td>{t.seq_scans.toLocaleString()}</td>
                      <td>{t.idx_scans.toLocaleString()}</td>
                      <td>{t.inserts.toLocaleString()}</td>
                      <td>{t.updates.toLocaleString()}</td>
                      <td>{t.deletes.toLocaleString()}</td>
                      <td>{t.dead_tuples > 0 ? <span className="db-cell-bool-false">{t.dead_tuples.toLocaleString()}</span> : "0"}</td>
                      <td className="db-cell-mono">{t.last_autovacuum || t.last_vacuum || "jamais"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

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

function SensorsView({ sensorData, headers }) {
  const [health, setHealth] = useState(null);
  const [loading, setLoading] = useState(true);

  const fetchHealth = useCallback(async () => {
    if (!headers?.Authorization) return;
    try {
      const res = await fetch(`/api/sensors/health`, { headers });
      if (res.ok) setHealth(await res.json());
    } catch (e) { /* ignore */ }
    setLoading(false);
  }, [headers]);

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
