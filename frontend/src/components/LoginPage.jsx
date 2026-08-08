import { useState, useRef, useCallback, useEffect, useMemo } from "react";
import { Shield, User, Lock, ScanFace, Camera, CameraOff, LogIn, AlertCircle, CheckCircle2, Fingerprint, Loader2, UserPlus } from "lucide-react";

const FACES_API_BASE = "/api/faces";
const DETECT_INTERVAL = 100;
const REQUIRED_HITS = 8;
const DETECT_TIMEOUT = 30000;

export default function LoginPage({ onLogin }) {
  const [mode, setMode] = useState("signin");
  const [step, setStep] = useState("credentials");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState("");
  const [successMessage, setSuccessMessage] = useState("");
  const [isLoading, setIsLoading] = useState(false);

  const [isCameraOpen, setIsCameraOpen] = useState(false);
  const [faceImage, setFaceImage] = useState(null);
  const [faceScanned, setFaceScanned] = useState(false);
  const faceScannedRef = useRef(false);
  const [faceStatus, setFaceStatus] = useState(null);
  const [faceVerifyResult, setFaceVerifyResult] = useState(null);
  const [faceRegisterMode, setFaceRegisterMode] = useState(false);
  const [detectState, setDetectState] = useState("idle");
  const [detectProgress, setDetectProgress] = useState(0);
  const [slideDir, setSlideDir] = useState("forward");
  const [faceVerifying, setFaceVerifying] = useState(false);

  const videoRef = useRef(null);
  const canvasRef = useRef(null);
  const detectCanvasRef = useRef(null);
  const streamRef = useRef(null);
  const detectIntervalRef = useRef(null);
  const detectCountRef = useRef(0);
  const detectTimeoutRef = useRef(null);
  const mountedRef = useRef(true);
  const pendingTokenRef = useRef(null);
  const pendingRoleRef = useRef(null);
  const autoVerifyRef = useRef(false);
  const detectExpiredRef = useRef(false);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      if (streamRef.current) streamRef.current.getTracks().forEach(t => t.stop());
      if (detectIntervalRef.current) clearInterval(detectIntervalRef.current);
      if (detectTimeoutRef.current) clearTimeout(detectTimeoutRef.current);
    };
  }, []);

  useEffect(() => {
    setError(""); setFaceVerifyResult(null); setFaceImage(null); setFaceScanned(false); setFaceStatus(null); setFaceRegisterMode(false);
    setDetectState("idle"); setDetectProgress(0); setStep("credentials"); setSlideDir("forward"); setFaceVerifying(false);
    if (streamRef.current) { streamRef.current.getTracks().forEach(t => t.stop()); streamRef.current = null; }
    setIsCameraOpen(false);
    pendingTokenRef.current = null;
    pendingRoleRef.current = null;
    autoVerifyRef.current = false;
    faceScannedRef.current = false;
  }, [mode]);

  useEffect(() => {
    if (!videoRef.current || !streamRef.current) return;
    if (videoRef.current.srcObject === streamRef.current) return;
    videoRef.current.srcObject = streamRef.current;
    videoRef.current.play().catch(() => {});
  });

  useEffect(() => {
    if (!videoRef.current || !streamRef.current || detectState !== "idle") return;
    if (videoRef.current.readyState >= 2) {
      setTimeout(() => { if (mountedRef.current) startAutoDetect(); }, 800);
    }
  });

  const analyzeFrame = useCallback(() => {
    const video = videoRef.current;
    const cvs = detectCanvasRef.current;
    if (!video || video.readyState < 2 || !cvs) return false;

    const vw = video.videoWidth || 640;
    const vh = video.videoHeight || 480;
    cvs.width = vw;
    cvs.height = vh;
    const ctx = cvs.getContext("2d");
    ctx.drawImage(video, 0, 0);

    // More zones covering a wider area
    const zones = [
      { x: 0.2,  y: 0.15, w: 0.6, h: 0.25 },
      { x: 0.25, y: 0.35, w: 0.5, h: 0.25 },
      { x: 0.2,  y: 0.55, w: 0.6, h: 0.2  },
      { x: 0.35, y: 0.1,  w: 0.3, h: 0.15 },
      { x: 0.35, y: 0.65, w: 0.3, h: 0.15 },
    ];

    let highFreqPx = 0;
    let zonesPassed = 0;
    let totalBrightness = 0;
    let totalSkin = 0;
    let totalContrast = 0;
    let zoneCount = 0;

    for (const z of zones) {
      const zx = Math.floor(vw * z.x);
      const zy = Math.floor(vh * z.y);
      const zw = Math.floor(vw * z.w);
      const zh = Math.floor(vh * z.h);
      if (zw < 10 || zh < 10) continue;

      const imgData = ctx.getImageData(zx, zy, zw, zh);
      const px = imgData.data;
      let sum = 0, sumSq = 0, skinPx = 0, brightSum = 0, cnt = 0;

      for (let i = 0; i < px.length; i += 4) {
        const r = px[i], g = px[i + 1], b = px[i + 2];
        const gray = 0.299 * r + 0.587 * g + 0.114 * b;
        sum += gray;
        sumSq += gray * gray;

        // Broader skin colour model (works for more skin tones)
        const isSkin = r > 50 && g > 30 && b > 15
          && r > g && r > b
          && (r - g) > 8
          && Math.abs(g - b) < 40;
        if (isSkin) skinPx++;

        brightSum += gray;
        cnt++;
      }

      if (cnt === 0) continue;
      const mean = sum / cnt;
      const variance = sumSq / cnt - mean * mean;
      const stdDev = Math.sqrt(variance);
      const avgBright = brightSum / cnt;
      const skinRatio = skinPx / cnt;

      totalBrightness += avgBright;
      totalSkin += skinRatio;
      totalContrast += stdDev;
      zoneCount++;

      if (stdDev > 12 && avgBright > 35 && avgBright < 240) zonesPassed++;
    }

    if (zoneCount === 0) return false;

    const avgBright = totalBrightness / zoneCount;
    const avgSkin = totalSkin / zoneCount;
    const avgContrast = totalContrast / zoneCount;

    // Edge detection: look for high-frequency content (face features)
    if (avgContrast > 8 && vw > 0) {
      const midY = Math.floor(vh * 0.4);
      const rowData = ctx.getImageData(0, midY, vw, 1).data;
      for (let i = 8; i < rowData.length - 8; i += 4) {
        const g0 = 0.299 * rowData[i] + 0.587 * rowData[i + 1] + 0.114 * rowData[i + 2];
        const g1 = 0.299 * rowData[i + 8] + 0.587 * rowData[i + 9] + 0.114 * rowData[i + 10];
        if (Math.abs(g0 - g1) > 15) highFreqPx++;
      }
    }

    // Primary: 3+ zones pass (strict for high confidence)
    if (zonesPassed >= 3) return true;

    // Secondary: 2 zones + skin + good brightness
    if (zonesPassed >= 2 && avgSkin > 0.02 && avgBright > 50 && avgBright < 220) return true;

    // Fallback: edge density + skin + brightness (for faces with less contrast)
    const edgeDensity = highFreqPx / vw;
    if (edgeDensity > 0.15 && avgSkin > 0.015 && avgBright > 45 && avgBright < 220) return true;

    return false;
  }, []);

  const stopDetect = useCallback(() => {
    if (detectIntervalRef.current) { clearInterval(detectIntervalRef.current); detectIntervalRef.current = null; }
    if (detectTimeoutRef.current) { clearTimeout(detectTimeoutRef.current); detectTimeoutRef.current = null; }
    detectCountRef.current = 0;
    if (mountedRef.current) { setDetectState("idle"); setDetectProgress(0); }
  }, []);

  const closeCamera = useCallback(() => {
    stopDetect();
    if (streamRef.current) {
      streamRef.current.getTracks().forEach(t => t.stop());
      streamRef.current = null;
    }
    if (videoRef.current) videoRef.current.srcObject = null;
    setIsCameraOpen(false);
    setDetectState("idle"); setDetectProgress(0);
    detectExpiredRef.current = false;
    if (!faceScannedRef.current) setFaceImage(null);
  }, [stopDetect]);

  const verifyFaceAndLogin = useCallback(async (image, user, token) => {
    setFaceVerifying(true);
    try {
      const verifyRes = await fetch(`${FACES_API_BASE}/verify`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ image, username: user }),
      });
      if (verifyRes.ok) {
        closeCamera();
        if (mountedRef.current) {
          setSuccessMessage("✅ Visage vérifié ! Connexion...");
          setTimeout(() => {
            try { fetch("/api/surveillance/login", { method: "POST", headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" }, body: JSON.stringify({ username: user, face_image: image, face_verified: true, login_method: "password+face" }) }); } catch {}
            onLogin(token, user, undefined, pendingRoleRef.current);
          }, 600);
        }
      } else {
        const err = await verifyRes.json().catch(() => ({}));
        closeCamera();
        if (mountedRef.current) {
          setError(err.detail || "❌ Visage non reconnu");
          autoVerifyRef.current = false;
          pendingTokenRef.current = token;
        }
      }
    } catch {
      closeCamera();
      if (mountedRef.current) {
        setError("Erreur de vérification faciale");
        autoVerifyRef.current = false;
        pendingTokenRef.current = token;
      }
    }
    if (mountedRef.current) setFaceVerifying(false);
  }, [closeCamera, onLogin]);

  const captureFace = useCallback(() => {
    stopDetect();
    const video = videoRef.current;
    const canvas = canvasRef.current;
    if (!video || !canvas) return;
    canvas.width = video.videoWidth;
    canvas.height = video.videoHeight;
    const ctx = canvas.getContext("2d");
    ctx.drawImage(video, 0, 0);
    const imageData = canvas.toDataURL("image/jpeg", 0.9);
    setFaceImage(imageData);
    setFaceScanned(true);
    faceScannedRef.current = true;
    closeCamera();
    setSuccessMessage("Visage capturé !");
    setTimeout(() => { if (mountedRef.current) setSuccessMessage(""); }, 3000);
  }, [closeCamera, stopDetect]);

  const retakeFace = useCallback(() => {
    setFaceImage(null); setFaceScanned(false); faceScannedRef.current = false; setFaceVerifyResult(null); setError("");
  }, []);

  const doCapture = useCallback(() => {
    const video = videoRef.current;
    const canvas = canvasRef.current;
    if (!video || !canvas || !mountedRef.current) return;
    canvas.width = video.videoWidth;
    canvas.height = video.videoHeight;
    const ctx = canvas.getContext("2d");
    ctx.drawImage(video, 0, 0);
    const dataUrl = canvas.toDataURL("image/jpeg", 0.92);
    setFaceImage(dataUrl);
    setFaceScanned(true);
    faceScannedRef.current = true;
    setDetectState("done");

    const token = pendingTokenRef.current;
    if (token) {
      verifyFaceAndLogin(dataUrl, username.trim(), token);
    } else {
      setTimeout(() => {
        if (mountedRef.current) {
          closeCamera();
          setSuccessMessage("Visage capturé !");
          setTimeout(() => { if (mountedRef.current) setSuccessMessage(""); }, 3000);
        }
      }, 1200);
    }
  }, [closeCamera, verifyFaceAndLogin, username, onLogin]);

  const startAutoDetect = useCallback(() => {
    stopDetect();
    detectCountRef.current = 0;
    detectExpiredRef.current = false;
    if (mountedRef.current) { setDetectState("detecting"); setDetectProgress(0); }

    detectTimeoutRef.current = setTimeout(() => {
      if (mountedRef.current) {
        setDetectState("idle");
        setDetectProgress(0);
        detectExpiredRef.current = true;
      }
    }, DETECT_TIMEOUT);

    detectIntervalRef.current = setInterval(() => {
      if (!mountedRef.current) { stopDetect(); return; }

      const hasFace = analyzeFrame();
      if (hasFace) {
        detectCountRef.current = Math.min(detectCountRef.current + 1, REQUIRED_HITS + 1);
        if (mountedRef.current) setDetectProgress(Math.min(detectCountRef.current / REQUIRED_HITS, 1));

        if (detectCountRef.current >= REQUIRED_HITS) {
          stopDetect();
          setDetectState("capturing");
          setTimeout(doCapture, 200);
        }
      } else {
        if (detectCountRef.current > 2) {
          detectCountRef.current = Math.max(0, detectCountRef.current - 2);
        } else {
          detectCountRef.current = 0;
        }
        if (mountedRef.current) setDetectProgress(Math.max(detectCountRef.current / REQUIRED_HITS, 0));
      }
    }, DETECT_INTERVAL);
  }, [analyzeFrame, stopDetect, doCapture]);

  const openCamera = useCallback(async () => {
    setError(""); setFaceVerifyResult(null);
    if (isCameraOpen || streamRef.current) return;
    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: "user", width: { ideal: 1280 }, height: { ideal: 720 } }
      });
      streamRef.current = stream;
      setIsCameraOpen(true);
    } catch {
      setError("Impossible d'accéder à la caméra. Vérifiez les permissions.");
    }
  }, [isCameraOpen]);

  const checkFaceStatus = useCallback(async (user) => {
    if (!user) return;
    setFaceStatus("checking");
    try {
      const res = await fetch(`${FACES_API_BASE}/status/${encodeURIComponent(user)}`);
      if (res.ok) { const data = await res.json(); setFaceStatus(data.registered ? "registered" : "unregistered"); return data.registered; }
    } catch {}
    setFaceStatus("unregistered");
    return false;
  }, []);

  const handleUsernameBlur = useCallback(() => {
    if (username.trim() && mode === "signin") checkFaceStatus(username.trim());
  }, [username, checkFaceStatus, mode]);

  const goToFace = useCallback(() => {
    if (!username.trim()) { setError("Veuillez entrer un nom d'utilisateur."); return; }
    if (!password.trim()) { setError("Veuillez entrer un mot de passe."); return; }
    if (mode === "signup" && password !== confirmPassword) { setError("Les mots de passe ne correspondent pas."); return; }
    if (mode === "signup" && password.length < 4) { setError("Minimum 4 caractères."); return; }
    setError("");
    setSlideDir("forward");
    setStep("face");
    setTimeout(() => openCamera(), 400);
  }, [username, password, confirmPassword, mode, openCamera]);

  const goToCredentials = useCallback(() => {
    closeCamera();
    setSlideDir("back");
    setStep("credentials");
  }, [closeCamera]);

  const handleRegisterFace = async () => {
    if (!faceImage) return;
    setError(""); setFaceVerifyResult(null);
    try {
      const res = await fetch(`${FACES_API_BASE}/register`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ image: faceImage, username: username.trim() }),
      });
      if (res.ok) { setFaceVerifyResult({ ok: true, message: "Visage enregistré !" }); setFaceStatus("registered"); setFaceRegisterMode(false); }
      else { const err = await res.json(); setFaceVerifyResult({ ok: false, message: err.detail || "Erreur" }); }
    } catch { setFaceVerifyResult({ ok: false, message: "Erreur de connexion" }); }
  };

  const handleSignUp = async (e) => {
    e.preventDefault(); setError(""); setFaceVerifyResult(null);
    if (!username.trim() || !password.trim()) { setError("Veuillez remplir tous les champs."); return; }
    if (password !== confirmPassword) { setError("Les mots de passe ne correspondent pas."); return; }
    if (password.length < 4) { setError("Minimum 4 caractères."); return; }
    setIsLoading(true);
    try {
      const res = await fetch("/auth/register", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ username: username.trim(), password }) });
      if (!res.ok) { const errData = await res.json().catch(() => ({})); throw new Error(errData.detail || "Erreur d'inscription"); }
      const data = await res.json();
      if (faceImage) { try { await fetch(`${FACES_API_BASE}/register`, { method: "POST", headers: { Authorization: `Bearer ${data.access_token}`, "Content-Type": "application/json" }, body: JSON.stringify({ image: faceImage, username: username.trim() }) }); } catch {} }
      onLogin(data.access_token, username.trim(), undefined, data.role);
    } catch (err) { setError(err.message); }
    finally { setIsLoading(false); }
  };

  const handleSignIn = async (e) => {
    e.preventDefault(); setError(""); setFaceVerifyResult(null);
    if (!username.trim() || !password.trim()) { setError("Veuillez entrer un nom d'utilisateur et un mot de passe."); return; }
    setIsLoading(true);
    try {
      const loginRes = await fetch("/auth/token", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ username: username.trim(), password }) });
      if (!loginRes.ok) { const errData = await loginRes.json().catch(() => ({})); throw new Error(errData.detail || "Identifiants incorrects"); }
      const data = await loginRes.json();
      const token = data.access_token;
      pendingRoleRef.current = data.role || null;

      const hasFace = await checkFaceStatus(username.trim());
      pendingTokenRef.current = token;
      autoVerifyRef.current = hasFace;
      setSlideDir("forward");
      setStep("face");
      setTimeout(() => openCamera(), 400);
    } catch (err) { setError(err.message || "Erreur de connexion au serveur."); }
    finally { setIsLoading(false); }
  };

  const handleFaceSubmit = useCallback(async () => {
    const token = pendingTokenRef.current;
    if (!token) { setError("Session expirée, veuillez vous reconnecter."); return; }
    if (!faceImage) { setError("Veuillez capturer votre visage d'abord."); return; }
    setError(""); setFaceVerifying(true);
    try {
      const verifyRes = await fetch(`${FACES_API_BASE}/verify`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ image: faceImage, username: username.trim() }),
      });
      if (verifyRes.ok) {
        setSuccessMessage("✅ Visage vérifié ! Connexion...");
        setTimeout(() => {
          try { fetch("/api/surveillance/login", { method: "POST", headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" }, body: JSON.stringify({ username: username.trim(), face_image: faceImage, face_verified: true, login_method: "password+face" }) }); } catch {}
          onLogin(token, username.trim(), undefined, pendingRoleRef.current);
        }, 600);
      } else {
        const err = await verifyRes.json().catch(() => ({}));
        setError(err.detail || "❌ Visage non reconnu");
      }
    } catch { setError("Erreur de vérification faciale"); }
    finally { setFaceVerifying(false); }
  }, [faceImage, username, onLogin]);

  const renderCameraPreview = () => (
    <div className="camera-preview">
      <div className="camera-frame">
        <video ref={videoRef} autoPlay playsInline muted />
        <div className="camera-overlay"><div className="face-guide" /></div>

        {detectState === "detecting" && (
          <>
            <div className="detect-progress-bottom">
              <div className="detect-progress-track">
                <div className="detect-progress-fill" style={{ width: `${detectProgress * 100}%` }} />
              </div>
              <span className="detect-progress-label">{Math.round(detectProgress * 100)}%</span>
            </div>
            <div className="detect-status-dots">
              {Array.from({ length: 5 }).map((_, i) => (
                <div key={i} className={`detect-dot ${i <= Math.floor(detectProgress * 5) ? "active" : ""}`} />
              ))}
            </div>
          </>
        )}

        {detectState === "capturing" && (
          <div className="capture-flash" />
        )}

        {detectState === "done" && faceImage && (
          <div className="capture-preview-overlay">
            <img src={faceImage} alt="capture" className="capture-preview-img" />
            <div className="capture-preview-check">
              <CheckCircle2 size={28} />
            </div>
          </div>
        )}

        {detectState === "idle" && detectExpiredRef.current && !faceScanned && (
          <div className="detect-retry-overlay">
            <p>Détection interrompue</p>
            <button type="button" className="face-capture-btn" onClick={startAutoDetect}><Camera size={18} /> Réessayer</button>
          </div>
        )}
      </div>
      <canvas ref={canvasRef} style={{ display: "none" }} />
      <canvas ref={detectCanvasRef} style={{ display: "none" }} />
      <div className="camera-actions">
        <button type="button" className="face-capture-btn" onClick={captureFace} disabled={detectState === "done"}><Camera size={18} /> Capturer</button>
        <button type="button" className="face-cancel-btn" onClick={closeCamera} disabled={detectState === "done"}><CameraOff size={18} /> Annuler</button>
      </div>
    </div>
  );

  const renderFaceResult = () => (
    <div className="face-result">
      <div className="face-result-image"><img src={faceImage} alt="Face" /></div>
      <div className="face-result-actions">
        <span className="face-success"><CheckCircle2 size={16} /> Visage capturé</span>
        <button type="button" className="retake-btn" onClick={retakeFace}>Re-capturer</button>
      </div>
    </div>
  );

  // Matrix rain columns — stable across renders
  const rainColumns = useMemo(() => {
    const charSets = [
      "01",                                      // binary
      "0123456789ABCDEF",                        // hex
      "01アイウエオカキクケコ",                    // katakana
      "ALERT BREACH THREAT INTRUSION MALWARE",   // security words
      "01001101 10110010 01110010 11010011",     // binary blocks
      "█▓▒░╔╗╚╝║═",                             // block chars
      "RSA AES SSL VPN IDS IPS",                // crypto/net terms
      "255.255.255.0 192.168.1.1 ::1",          // IP fragments
      "λ=∑∫∂√π∞≠≈≤≥",                          // math symbols
      "FATAL CRIT WARN ERROR FAIL DENY",        // log levels
      "SHA256 MD5 ECDSA HMAC JWT",              // hashing/algo
      "TCP UDP ICMP HTTP DNS SSH",              // protocols
      "root admin sys kern daemon",             // system users
      "0xDEAD 0xBEEF 0xCAFE 0xF00D",           // hex words
      "chmod 755 exec fork kill sudo su",       // shell commands
      "SYN ACK FIN RST PSH URG",               // TCP flags
      "\\\\x1b[31m \\\\x1b[32m \\\\x1b[0m",     // ANSI escapes
      "XSS SSRF RCE LFI IDOR CSRF OWASP",      // vuln types
    ];
    return charSets.map((chars, i) => (
      <div
        key={i}
        className="matrix-column"
        style={{
          left: `${(i / charSets.length) * 100}%`,
          animationDuration: `${8 + Math.random() * 12}s`,
          animationDelay: `${Math.random() * -20}s`,
          fontSize: `${11 + Math.floor(Math.random() * 5)}px`,
          opacity: 0.3 + Math.random() * 0.7,
        }}
      >
        {chars}
      </div>
    ));
  }, []);

  return (
    <div className="login-page">
      <div className="login-background">
        <div className="login-bg-gradient" />
        <div className="matrix-rain">{rainColumns}</div>
        <div className="login-scanlines" />
        <div className="login-radar" />
      </div>
      <div className="login-container">
        <div className="hud-corner-tr" />
        <div className="hud-corner-bl" />
        <div className="login-scan-overlay" />
        <div className="login-glow-border" />
        <div className="login-header">
          <div className="login-logo"><Shield size={32} color="#00ff88" /></div>
          <h1>SENTINEL BRIDGE</h1>
          <p className="login-subtitle">SOC Dashboard - Analyse Réseau</p>
          <p className="login-system-text">SYS v2.0 // ENCRYPTED CHANNEL // SECURE</p>
        </div>

        <div className="auth-mode-toggle">
          <button className={`auth-mode-btn ${mode === "signin" ? "active" : ""}`} onClick={() => setMode("signin")} disabled={step === "face"}><LogIn size={14} /> Connexion</button>
          <button className={`auth-mode-btn ${mode === "signup" ? "active" : ""}`} onClick={() => setMode("signup")} disabled={step === "face"}><UserPlus size={14} /> Inscription</button>
        </div>

        <div className="login-step-container">
          {/* ───── STEP 1 : Identifiants ───── */}
          <div className={`login-step-panel ${step === "credentials" ? "active" : "hidden"}`}>
            {mode === "signin" ? (
              <form className="login-form" onSubmit={handleSignIn}>
                <div className="step-indicator">Étape 1 sur 2 — Identifiants</div>
                <div className="login-field">
                  <label><User size={16} /> <span>Nom d'utilisateur</span></label>
                  <input type="text" placeholder="Entrez votre identifiant" value={username} onChange={(e) => setUsername(e.target.value)} onBlur={handleUsernameBlur} disabled={isLoading} autoFocus />
                  {faceStatus === "checking" && <span className="field-hint"><Loader2 size={12} className="spin" /> Vérification...</span>}
                  {faceStatus === "registered" && <span className="field-hint hint-success"><CheckCircle2 size={12} /> Visage enregistré</span>}
                  {faceStatus === "unregistered" && <span className="field-hint hint-warn"><AlertCircle size={12} /> Aucun visage enregistré</span>}
                </div>
                <div className="login-field">
                  <label><Lock size={16} /> <span>Mot de passe</span></label>
                  <input type="password" placeholder="Entrez votre mot de passe" value={password} onChange={(e) => setPassword(e.target.value)} disabled={isLoading} />
                </div>
                {error && <div className="login-error-msg"><AlertCircle size={16} /> {error}</div>}
                <button type="submit" className="login-submit-btn" disabled={isLoading}>
                  {isLoading ? <><Loader2 size={18} className="spin" /> Vérification...</> : <><LogIn size={18} /> Se connecter</>}
                </button>
              </form>
            ) : (
              <div className="login-form">
                <div className="step-indicator">Étape 1 sur 2 — Identifiants</div>
                <div className="login-field">
                  <label><User size={16} /> <span>Nom d'utilisateur</span></label>
                  <input type="text" placeholder="Choisissez un identifiant" value={username} onChange={(e) => setUsername(e.target.value)} disabled={isLoading} autoFocus />
                </div>
                <div className="login-field">
                  <label><Lock size={16} /> <span>Mot de passe</span></label>
                  <input type="password" placeholder="Créez un mot de passe" value={password} onChange={(e) => setPassword(e.target.value)} disabled={isLoading} />
                </div>
                <div className="login-field">
                  <label><Lock size={16} /> <span>Confirmer le mot de passe</span></label>
                  <input type="password" placeholder="Confirmez le mot de passe" value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} disabled={isLoading} />
                </div>
                {error && <div className="login-error-msg"><AlertCircle size={16} /> {error}</div>}
                <button type="button" className="login-submit-btn" onClick={goToFace} disabled={isLoading}>
                  Suivant <ScanFace size={18} />
                </button>
              </div>
            )}
          </div>

          {/* ───── STEP 2 : Scan Facial ───── */}
          <div className={`login-step-panel ${step === "face" ? "active" : "hidden"}`}>
            <div className="login-form">
              <div className="step-indicator">Étape 2 sur 2 — {mode === "signin" ? "Vérification" : "Enregistrement"} facial</div>
              {faceVerifying && (
                <div className="face-verifying-banner">
                  <Loader2 size={20} className="spin" /> Vérification du visage en cours...
                </div>
              )}
              <div className="login-field face-scan-field">
                {!faceImage && !isCameraOpen && !faceVerifying && (
                  <p className="face-auto-hint">La caméra va s'ouvrir automatiquement pour {mode === "signin" ? "vérifier" : "enregistrer"} votre visage.</p>
                )}
                <label><ScanFace size={16} /> <span>Scan Facial</span>
                  {mode === "signin" && faceStatus === "registered" && <span className="badge-optional">Enregistré</span>}
                </label>
                {!faceImage && !isCameraOpen && !faceVerifying && (
                  <button type="button" className="face-scan-btn" onClick={openCamera} disabled={isLoading}><Camera size={20} /> <span>Ouvrir la caméra</span></button>
                )}
                {isCameraOpen && renderCameraPreview()}
                {faceImage && !faceVerifying && renderFaceResult()}
              </div>
              {error && <div className="login-error-msg"><AlertCircle size={16} /> {error}</div>}
              {successMessage && <div className="login-success-msg"><CheckCircle2 size={16} /> {successMessage}</div>}
              <div className="step-actions">
                <button type="button" className="face-cancel-btn" onClick={goToCredentials} disabled={faceVerifying}><Lock size={16} /> Identifiants</button>
                {mode === "signin" ? (
                  <button type="button" className="login-submit-btn" onClick={handleFaceSubmit} disabled={isLoading || faceVerifying || !faceImage}>
                    {faceVerifying ? <><Loader2 size={18} className="spin" /> Vérification...</> : <><Fingerprint size={18} /> Vérifier & Connexion</>}
                  </button>
                ) : (
                  <button type="button" className="login-submit-btn" onClick={handleSignUp} disabled={isLoading}>
                    {isLoading ? <><Loader2 size={18} className="spin" /> Inscription...</> : <><UserPlus size={18} /> Créer mon compte</>}
                  </button>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}