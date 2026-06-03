import { useEffect, useState, memo, useRef, useCallback } from "react";
import { ToastContainer, toast } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, AreaChart, Area,
  BarChart, Bar, Legend, Cell
} from 'recharts';
import {
  Shield,
  Server,
  Radar,
  Activity,
  Plus,
  Search,
  ShieldAlert,
  ShieldCheck,
  Cpu,
  Clock,
  Zap,
  Lock,
  Network,
  Database,
  Globe,
  AlertTriangle,
  Volume2,
  VolumeX,
  Printer,
  LayoutDashboard,
  Monitor,
  Laptop,
  HardDrive,
  Terminal,
  Radio
} from 'lucide-react';
import "./App.css";
import TopologyView from "./components/TopologyView";

// API key should be handled via environment variables or backend proxy in production
// const API_KEY = import.meta.env.VITE_API_KEY || ""; 
// For development only - REMOVE IN PRODUCTION
const API_KEY = "sDr6ANE9JVhPTBxjLJpKq5SHLXHNSt3_LAfz4c6yj3U";
const HEADERS = {
  "X-API-Key": API_KEY,
  "Content-Type": "application/json"
};

// Separate component for the clock to prevent App-wide re-renders
const SystemClock = memo(() => {
  const [time, setTime] = useState(new Date().toLocaleTimeString());
  useEffect(() => {
    const timer = setInterval(() => setTime(new Date().toLocaleTimeString()), 1000);
    return () => clearInterval(timer);
  }, []);
  return <div className="clock-system"><Clock size={14} /> {time}</div>;
});

// Memoized AlertRow to stop flickering in table
const AlertRow = memo(({ alert, onInvestigate, t }) => {
  const sev = parseInt(alert.Severity || alert.severity || 0);
  const isCritical = sev >= 12;
  const isHigh = sev >= 7 && sev < 12;

  // Human readable time
  const formatTime = (ts) => {
    if (!ts) return "--:--";
    const date = new Date(ts);
    const now = new Date();
    const isToday = date.toDateString() === now.toDateString();
    return isToday
      ? date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
      : date.toLocaleDateString([], { day: '2-digit', month: 'short' }) + " " + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  };

  const rawDesc = alert.Description || alert.description || "Unknown security event";
  const cleanDesc = rawDesc.replace(/^Wazuh Alert: /i, "").replace(/^Suricata: /i, "");
  const timestamp = formatTime(alert.Timestamp || alert.timestamp);

  return (
    <tr className={isCritical ? "critical-row" : ""}>
      <td style={{ fontSize: '11px', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>{timestamp}</td>
      <td className={isCritical ? "critical-text" : ""} style={{ fontWeight: '600', maxWidth: '400px' }}>
        <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
          {isCritical ? <ShieldAlert size={16} className="critical-icon" /> : <Shield size={16} />}
          <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{cleanDesc}</span>
        </div>
      </td>
      <td>
        <span className={`severity-tag ${isCritical ? 'level-critical' : isHigh ? 'level-high' : 'level-medium'}`}>
          Level {sev}
        </span>
      </td>
      <td><strong>{alert["Source IP"] || alert.srcip || "0.0.0.0"}</strong></td>
      <td style={{ fontFamily: 'monospace', color: 'var(--accent-cyan)', fontSize: '12px' }}>{alert["MAC Address"] || alert.mac || "N/A"}</td>
      <td>
        <div style={{ display: 'flex', flexDirection: 'column' }}>
          <span style={{ fontSize: '13px', fontWeight: 700 }}>{alert["Employee Name"] || alert.employee || "Unknown"}</span>
          <span style={{ fontSize: '10px', color: 'var(--text-muted)' }}>{alert.Department || alert.department || "N/A"}</span>
        </div>
      </td>
      <td>
        <button
          className="btn-primary"
          style={{ padding: '6px 14px', fontSize: '11px', borderRadius: '8px' }}
          onClick={() => onInvestigate(alert)}
        >
          <Search size={14} /> {t("investigate")}
        </button>
      </td>
    </tr>
  );
});

const formatSuricataDetails = (payloadStr, eventType) => {
  if (!payloadStr) return "-";
  try {
    const data = typeof payloadStr === 'string' ? JSON.parse(payloadStr) : payloadStr;
    const type = (eventType || "").toLowerCase();

    if (type === "flow" && data.flow) {
      return `State: ${data.flow.state || '?'} | To Client: ${data.flow.bytes_toclient || 0}B | To Server: ${data.flow.bytes_toserver || 0}B`;
    }
    if (type === "http" && data.http) {
      return `${data.http.http_method || 'HTTP'} ${data.http.url || '/'} ${data.http.status ? `(${data.http.status})` : ''}`;
    }
    if (type === "fileinfo" && data.fileinfo) {
      return `File: ${data.fileinfo.filename || '?'} | Size: ${data.fileinfo.size || 0}B | Magic: ${data.fileinfo.magic ? data.fileinfo.magic.substring(0, 25) + '...' : '?'}`;
    }
    if (type === "stats" && data.stats) {
      return `Uptime: ${data.stats.uptime || 0}s | Packets: ${data.stats.capture?.kernel_packets || 0} | Drops: ${data.stats.capture?.kernel_drops || 0}`;
    }
    if (type === "dns" && data.dns) {
      return `DNS Query: ${data.dns.rrname || '?'} (${data.dns.rrtype || '?'})`;
    }
    if (type === "tls" && data.tls) {
      return `TLS Subject: ${data.tls.subject || '?'} | Issuer: ${data.tls.issuerdn || '?'}`;
    }

    // Fallback
    const str = typeof payloadStr === 'string' ? payloadStr : JSON.stringify(payloadStr);
    return str.length > 70 ? str.substring(0, 70) + "..." : str;
  } catch (e) {
    return payloadStr.length > 70 ? payloadStr.substring(0, 70) + "..." : payloadStr;
  }
};

export default function App() {
  const [activeTab, setActiveTab] = useState("dashboard");
  const terminalInputRef = useRef(null);
  const terminalBodyRef = useRef(null);
  const [terminalHistory, setTerminalHistory] = useState(() => {
    const saved = localStorage.getItem("terminalHistory");
    return saved ? JSON.parse(saved) : [{ type: 'system', content: 'Welcome to Sentinel SIEM Control. Connection established with Wazuh Manager.' }];
  });
  const [suricataTerminalHistory, setSuricataTerminalHistory] = useState(() => {
    const saved = localStorage.getItem("suricataTerminalHistory");
    return saved ? JSON.parse(saved) : [{ type: 'system', content: 'Welcome to Sentinel Network Control. Connected to Suricata IPS (192.168.133.136)' }];
  });
  const [currentCmd, setCurrentCmd] = useState("");
  const [suricataCmd, setSuricataCmd] = useState("");
  const [isExecutingCmd, setIsExecutingCmd] = useState(false);
  const suricataInputRef = useRef(null);
  const suricataBodyRef = useRef(null);
  const [activeResponses, setActiveResponses] = useState([]);
  const [isFetchingAR, setIsFetchingAR] = useState(false);
  const [isInvestigating, setIsInvestigating] = useState(false);
  const [investigationTarget, setInvestigationTarget] = useState(null);
  const [deepForensics, setDeepForensics] = useState(null);
  const [devices, setDevices] = useState([]);
  const [wazuhAlerts, setWazuhAlerts] = useState([]);
  const [suricataAlerts, setSuricataAlerts] = useState([]);
  const [scanResults, setScanResults] = useState([]);
  const [isScanning, setIsScanning] = useState(false);
  const [aiAnalysis, setAiAnalysis] = useState(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [aiBehaviorReport, setAiBehaviorReport] = useState(null);
  const [isAnalyzingBehavior, setIsAnalyzingBehavior] = useState(false);
  const [analysisController, setAnalysisController] = useState(null);
  const [globalAiReport, setGlobalAiReport] = useState(null);
  const [isAnalyzingGlobal, setIsAnalyzingGlobal] = useState(false);
  const [onlineHistory, setOnlineHistory] = useState([]);
  const [throughputHistory, setThroughputHistory] = useState([]);
  const [suricataHistory, setSuricataHistory] = useState([]);
  const [suricataSrcFilter, setSuricataSrcFilter] = useState("");
  const [suricataDestFilter, setSuricataDestFilter] = useState("");
  const [lang, setLang] = useState("fr");
  const [alertFilterSeverity, setAlertFilterSeverity] = useState("");
  const [alertFilterIP, setAlertFilterIP] = useState("");
  const [alertFilterMAC, setAlertFilterMAC] = useState("");
  const [alertFilterTime, setAlertFilterTime] = useState("");
  const [pendingTasks, setPendingTasks] = useState([]);
  const [isMuted, setIsMuted] = useState(false);
  const alarmRef = useRef(null);

  // Helper to add a task to tracking
  const trackTask = (taskId, type, target) => {
    setPendingTasks(prev => [...prev, { id: taskId, type, target, status: "PENDING", startTime: new Date() }]);
  };

  // Helper to update task status
  const updateTaskStatus = (taskId, status, result = null) => {
    setPendingTasks(prev => prev.map(t => t.id === taskId ? { ...t, status, result } : t));
    if (status === "SUCCESS") {
      toast.success(`Tâche terminée: ${taskId.substring(0, 8)}...`);
    }
  };

  const translations = {
    en: {
      dashboard: "Dashboard",
      inventory: "Inventory",
      radar: "Radar (Scan)",
      topology: "Topology Map",
      alerts: "Wazuh Alerts",
      ai: "AI Intelligence",
      ai_copilot: "AI Copilot",
      suricata: "Suricata IDS",
      active_threats: "Active Threats",
      critical_alerts: "Critical Alerts",
      monitored_assets: "Monitored Assets",
      online_assets: "Online Assets",
      total_assets: "Total Assets",
      online: "Online",
      offline: "Offline",
      presence: "Presence",
      investigate: "Investigate",
      threat_intensity_distribution: "Threat Intensity Distribution"
    },
    fr: {
      dashboard: "Tableau de Bord",
      inventory: "Inventaire",
      radar: "Radar (Scan)",
      topology: "Carte Topologie",
      alerts: "Alertes Wazuh",
      ai: "Intelligence IA",
      ai_copilot: "AI Copilot",
      suricata: "Suricata IDS",
      active_threats: "Menaces Actives",
      critical_alerts: "Alertes Critiques",
      monitored_assets: "Actifs Surveillés",
      online_assets: "Actifs en Ligne",
      total_assets: "Actifs Totaux",
      online: "En Ligne",
      offline: "Hors Ligne",
      presence: "Présence",
      investigate: "Enquêter",
      threat_intensity_distribution: "Distribution de l'Intensité des Menaces"
    }
  };

  const t = (key) => translations[lang][key] || key;

  const playAlarm = () => {
    console.log("🔔 Triggering Alarm... Muted:", isMuted);
    if (isMuted) return;

    try {
      const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
      const oscillator = audioCtx.createOscillator();
      const gainNode = audioCtx.createGain();

      oscillator.type = "sine";
      oscillator.frequency.setValueAtTime(880, audioCtx.currentTime); // A5 note
      gainNode.gain.setValueAtTime(0.5, audioCtx.currentTime);
      gainNode.gain.exponentialRampToValueAtTime(0.01, audioCtx.currentTime + 0.5);

      oscillator.connect(gainNode);
      gainNode.connect(audioCtx.destination);

      oscillator.start();
      oscillator.stop(audioCtx.currentTime + 0.5);

      console.log("🔊 Web Audio Beep generated!");
    } catch (e) {
      console.error("❌ Web Audio failed:", e);
    }
  };

  const checkCriticalAlerts = (alerts) => {
    // Already handled by useEffect monitoring the state
  };

  useEffect(() => {
    const hasCriticalWazuh = wazuhAlerts.some(a => parseInt(a.Severity || a.severity || 0) >= 15);
    const hasCriticalSuricata = suricataAlerts.some(a => parseInt(a.severity || 0) >= 15);
    const needsAlarm = hasCriticalWazuh || hasCriticalSuricata;
    const isViewing = activeTab === "alerts" || activeTab === "suricata";

    if (needsAlarm && !isViewing && !isMuted) {
      if (!alarmRef.current) {
        alarmRef.current = setInterval(playAlarm, 2000);
      }
    } else {
      if (alarmRef.current) {
        clearInterval(alarmRef.current);
        alarmRef.current = null;
      }
    }
  }, [wazuhAlerts, suricataAlerts, activeTab, isMuted]);

  // Persistence Effects
  useEffect(() => {
    localStorage.setItem("terminalHistory", JSON.stringify(terminalHistory));
  }, [terminalHistory]);

  useEffect(() => {
    localStorage.setItem("suricataTerminalHistory", JSON.stringify(suricataTerminalHistory));
  }, [suricataTerminalHistory]);

  // Terminal Auto-scroll & Auto-focus
  useEffect(() => {
    if (activeTab === "terminal") {
      terminalInputRef.current?.focus();
    } else if (activeTab === "network_control") {
      suricataInputRef.current?.focus();
    }

    const handleGlobalType = (e) => {
      if (document.activeElement?.tagName !== 'INPUT' && document.activeElement?.tagName !== 'TEXTAREA') {
        if (activeTab === "terminal") terminalInputRef.current?.focus();
        if (activeTab === "network_control") suricataInputRef.current?.focus();
      }
    };
    window.addEventListener('keydown', handleGlobalType);
    return () => window.removeEventListener('keydown', handleGlobalType);
  }, [activeTab]);

  useEffect(() => {
    if (terminalBodyRef.current) terminalBodyRef.current.scrollTop = terminalBodyRef.current.scrollHeight;
    if (suricataBodyRef.current) suricataBodyRef.current.scrollTop = suricataBodyRef.current.scrollHeight;
  }, [terminalHistory, suricataTerminalHistory, isExecutingCmd]);

  const executeCommand = async (e, target = 'wazuh') => {
    if (e) e.preventDefault();
    const cmd = target === 'wazuh' ? currentCmd : suricataCmd;
    if (!cmd.trim()) return;

    if (target === 'wazuh') {
      setCurrentCmd("");
      setTerminalHistory(prev => [...prev, { type: 'input', content: cmd }]);
    } else {
      setSuricataCmd("");
      setSuricataTerminalHistory(prev => [...prev, { type: 'input', content: cmd }]);
    }

    setIsExecutingCmd(true);

    try {
      const res = await fetch("http://localhost:8000/api/terminal/exec", {
        method: 'POST',
        headers: HEADERS,
        body: JSON.stringify({ command: cmd, target: target })
      });
      const data = await res.json();
      if (target === 'wazuh') {
        setTerminalHistory(prev => [...prev, { type: 'output', content: data.output, status: data.status }]);
      } else {
        setSuricataTerminalHistory(prev => [...prev, { type: 'output', content: data.output, status: data.status }]);
      }
    } catch (err) {
      const errMsg = { type: 'output', content: "Failed to connect to backend", status: 'error' };
      target === 'wazuh' ? setTerminalHistory(prev => [...prev, errMsg]) : setSuricataTerminalHistory(prev => [...prev, errMsg]);
    } finally {
      setIsExecutingCmd(false);
    }
  };

  const fetchActiveResponses = async () => {
    setIsFetchingAR(true);
    try {
      const res = await fetch("http://localhost:8000/api/wazuh/active-responses", { headers: HEADERS });
      if (res.ok) {
        const data = await res.json();
        setActiveResponses(data);
      }
    } catch (err) {
      console.error("AR fetch error:", err);
    } finally {
      setIsFetchingAR(false);
    }
  };

  useEffect(() => {
    if (activeTab === "remediation") {
      fetchActiveResponses();
      const arInterval = setInterval(fetchActiveResponses, 30000);
      return () => clearInterval(arInterval);
    }
  }, [activeTab]);

  const fetchCritical = useCallback(async () => {
    try {
      const [devRes, alertsRes] = await Promise.all([
        fetch("/devices", { headers: HEADERS }),
        fetch("/api/real-alerts", { headers: HEADERS }),
      ]);

      if (devRes.ok) {
        const devData = await devRes.json();
        setDevices(prev => {
          const prevIds = prev.map(d => d.id + (d.is_online ? '1' : '0')).join();
          const nextIds = devData.map(d => d.id + (d.is_online ? '1' : '0')).join();
          return prevIds === nextIds ? prev : devData;
        });
      }
      if (alertsRes.ok) {
        const alertData = await alertsRes.json();
        setWazuhAlerts(alertData); // Replace — already sorted by backend
      }
    } catch (err) {
      console.error("[fetchCritical] error:", err);
    }
  }, []);

  // Medium poll: suricata alerts every 20s
  const fetchSuricata = useCallback(async () => {
    try {
      const res = await fetch("/api/suricata/alerts", { headers: HEADERS });
      if (res.ok) {
        const sData = await res.json();
        setSuricataAlerts(sData);

        // Extract Stats for History Visualization
        const latestStats = sData.filter(a => (a.event_type || "").toLowerCase() === "stats").sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))[0];
        if (latestStats && latestStats.payload) {
          try {
            const data = typeof latestStats.payload === 'string' ? JSON.parse(latestStats.payload) : latestStats.payload;
            if (data.stats) {
              const stats = data.stats;
              setSuricataHistory(prev => {
                const now = new Date(latestStats.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
                const newPoint = {
                  time: now,
                  packets: stats.capture?.kernel_packets || 0,
                  drops: stats.capture?.kernel_drops || 0,
                  uptime: stats.uptime || 0
                };
                return [...prev, newPoint].slice(-20);
              });
            }
          } catch (e) {
            console.error("Error parsing Suricata stats payload:", e);
          }
        }
      }
    } catch (err) {
      console.error("[fetchSuricata] error:", err);
    }
  }, []);

  // Slow poll: bandwidth chart every 5s (lightweight)
  const fetchBandwidth = useCallback(async (currentOnlineCount) => {
    try {
      const res = await fetch("/api/stats/bandwidth", { headers: HEADERS });
      if (res.ok) {
        const bandData = await res.json();
        const now = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        setThroughputHistory(prev => [...prev, { time: now, value: bandData.mbps }].slice(-20));
        setOnlineHistory(prev => [...prev, { time: now, count: currentOnlineCount }].slice(-20));
      }
    } catch (err) { /* silent */ }
  }, []);

  useEffect(() => {
    let onlineCount = 0;

    const runCritical = async () => {
      await fetchCritical();
      setDevices(prev => { onlineCount = prev.filter(d => d.is_online).length; return prev; });
    };

    runCritical();
    fetchSuricata();
    fetchBandwidth(0);

    const criticalInterval = setInterval(runCritical, 10000);
    const suricataInterval = setInterval(fetchSuricata, 20000);
    const bandwidthInterval = setInterval(() => fetchBandwidth(onlineCount), 5000);

    // Real-time WebSocket
    const ws = new WebSocket(`ws://localhost:8000/ws/status?api_key=${API_KEY}`);
    ws.onmessage = (event) => {
      try {
        const payload = JSON.parse(event.data);
        if (payload.type === "alerts_update") {
          setWazuhAlerts(prev => {
            const combined = [...payload.data, ...prev];
            const unique = Array.from(new Map(combined.map(a => [(a.Timestamp || a.timestamp) + (a.Description || a.description), a])).values());
            return unique.sort((a, b) => new Date(b.Timestamp || b.timestamp) - new Date(a.Timestamp || a.timestamp)).slice(0, 50);
          });
        }
      } catch (err) {
        console.error("WS Parse error:", err);
      }
    };
    ws.onopen = () => console.log("✅ SOC WebSocket Connected");
    ws.onerror = () => console.warn("⚠️ SOC WebSocket Error");
    ws.onclose = () => console.warn("⚠️ SOC WebSocket Closed");

    return () => {
      clearInterval(criticalInterval);
      clearInterval(suricataInterval);
      clearInterval(bandwidthInterval);
      ws.close();
    };
  }, [fetchCritical, fetchSuricata, fetchBandwidth]);

  const startNetworkScan = async (subnet, type = "fast") => {
    setIsScanning(true);
    setScanResults([]);

    // For fast scans, keep it synchronous (faster response)
    if (type === "fast" || type === "ports") {
      try {
        let url = `/api/scan-network?scan_type=${type}`;
        if (subnet && subnet !== "") url += `&subnet=${encodeURIComponent(subnet)}`;

        const r = await fetch(url, { headers: HEADERS });
        if (r.ok) {
          const data = await r.json();
          setScanResults(data);
          toast.info(`Discovery complete: ${data.length} nodes found.`, { theme: "dark" });
        }
      } catch (err) {
        toast.error("Radar failure.", { theme: "dark" });
      } finally {
        setIsScanning(false);
      }
      return;
    }

    // For deep scans, use Celery
    try {
      let url = `/api/tasks/nmap-scan?scan_type=${type}`;
      if (subnet && subnet !== "") url += `&target=${encodeURIComponent(subnet)}`;
      else url += `&target=auto`; // Logic for auto-detect subnet in background if needed

      const r = await fetch(url, { method: 'POST', headers: HEADERS });
      if (r.ok) {
        const { task_id } = await r.json();
        toast.info("Deep scan started in background (Celery)...", { theme: "dark" });

        const interval = setInterval(async () => {
          const res = await fetch(`/api/tasks/status/${task_id}`, { headers: HEADERS });
          if (res.ok) {
            const data = await res.json();
            if (data.status === "SUCCESS") {
              clearInterval(interval);
              // CRITIQUE : Mapper les résultats de Celery vers le format du tableau
              if (data.result && data.result.results) {
                const mappedResults = data.result.results.map(r => ({
                  ip: r.ip,
                  mac: r.mac,
                  status: [r.os, ...(r.ports || [])]
                }));
                setScanResults(mappedResults);
                // Mettre à jour l'état dans le gestionnaire de tâches
                setPendingTasks(prev => prev.map(t =>
                  t.id === task_id ? { ...t, status: "SUCCESS", result: data.result } : t
                ));
              }
              setIsScanning(false);
              toast.success("Scan approfondi terminé !");
            } else if (data.status === "FAILURE") {
              clearInterval(interval);
              setIsScanning(false);
              setPendingTasks(prev => prev.map(t => t.id === task_id ? { ...t, status: "FAILURE" } : t));
              toast.error("Le scan a échoué sur le worker.");
            }
          }
        }, 3000);
      }
    } catch (err) {
      toast.error("Failed to start background scan.");
      setIsScanning(false);
    }
  };

  const formatReport = (text) => {
    if (!text) return null;
    return text
      .split('\n')
      .map((line, i) => {
        const trimmed = line.trim();
        // Handle Headers (up to h4) and remove ALL # symbols
        if (trimmed.startsWith('#')) {
          const level = (trimmed.match(/^#+/) || ['#'])[0].length;
          const cleanText = trimmed.replace(/^#+\s*/, '');
          if (level === 1) return <h1 key={i}>{cleanText}</h1>;
          if (level === 2) return <h2 key={i}>{cleanText}</h2>;
          if (level >= 3) return <h3 key={i}>{cleanText}</h3>;
        }

        // Handle List Items
        if (trimmed.startsWith('- ') || trimmed.startsWith('* ')) {
          const cleanText = trimmed.replace(/^[-*]\s*/, '');
          // Still handle bold within list items
          return <li key={i} style={{ marginLeft: '20px' }}>{renderInlineStyles(cleanText)}</li>;
        }

        if (trimmed === '---') return <hr key={i} />;

        return <p key={i} style={{ margin: '8px 0' }}>{renderInlineStyles(line)}</p>;
      });
  };

  const renderInlineStyles = (text) => {
    // Strip remaining raw markdown symbols if any
    const cleanText = text.replace(/#/g, '').replace(/\*/g, '');
    return cleanText;
  };

  const stopAiAnalysis = () => {
    if (analysisController) {
      analysisController.abort();
      setAnalysisController(null);
      setIsAnalyzingBehavior(false);
      setIsAnalyzing(false);
      setIsAnalyzingGlobal(false);
      toast.info("Analyse IA annulée.");
    }
  };

  const runAiBehavioralAnalysis = async (agentId) => {
    if (!agentId) return;
    const controller = new AbortController();
    setAnalysisController(controller);
    setIsAnalyzingBehavior(true);
    setAiBehaviorReport(null);
    try {
      const res = await fetch(`/api/wazuh/ai-report/${agentId}`, {
        headers: HEADERS,
        signal: controller.signal
      });
      if (!res.ok || !res.body) {
        toast.error("Failed to generate AI report");
        return;
      }
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let text = "";
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        text += decoder.decode(value, { stream: true });
        setAiBehaviorReport(text);
      }
      toast.success("Analyse comportementale terminée.", { theme: "dark" });
    } catch (e) {
      if (e.name === 'AbortError') {
        toast.info("Analyse arrêtée par l'utilisateur");
      } else {
        console.error(e);
        toast.error("Erreur réseau lors de l'analyse IA");
      }
    } finally {
      setIsAnalyzingBehavior(false);
      setAnalysisController(null);
    }
  };


  const runGlobalAiReport = async () => {
    const controller = new AbortController();
    setIsAnalyzingGlobal(true);
    setGlobalAiReport(null);
    try {
      const res = await fetch(`/api/wazuh/ai-report-global`, {
        headers: HEADERS,
        signal: controller.signal
      });
      if (!res.ok || !res.body) {
        toast.error("Failed to generate Global Report");
        return;
      }
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let text = "";
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        text += decoder.decode(value, { stream: true });
        setGlobalAiReport(text);
      }
      toast.success("Rapport global généré.", { theme: "dark" });
    } catch (e) {
      if (e.name !== 'AbortError') {
        console.error(e);
        toast.error("Erreur lors du rapport global");
      }
    } finally {
      setIsAnalyzingGlobal(false);
    }
  };


  const pollTaskStatus = async (taskId, setStatus, setResult, onComplete) => {
    const interval = setInterval(async () => {
      try {
        const res = await fetch(`/api/tasks/status/${taskId}`, { headers: HEADERS });
        if (res.ok) {
          const data = await res.json();
          if (data.status === "SUCCESS") {
            clearInterval(interval);
            const finalResult = data.result.analysis || data.result;
            setResult(finalResult);
            setStatus(false);
            updateTaskStatus(taskId, "SUCCESS", finalResult);
            if (onComplete) onComplete();
          } else if (data.status === "FAILURE") {
            clearInterval(interval);
            setStatus(false);
            updateTaskStatus(taskId, "FAILURE");
            toast.error("Tâche échouée sur le worker.");
          } else {
            // Keep polling, maybe update local status if "STARTED"
            updateTaskStatus(taskId, data.status);
          }
        }
      } catch (err) {
        clearInterval(interval);
        setStatus(false);
        updateTaskStatus(taskId, "ERROR");
      }
    }, 2000);
    return interval;
  };

  const runAiAnalysis = async () => {
    setIsAnalyzing(true);
    setAiAnalysis("Initialisation de l'analyse asynchrone (Celery)...");
    const timeline = wazuhAlerts.map(a => `${a.Timestamp}: [Level ${a.Severity}] ${a.Description} from ${a["Source IP"]}`);

    try {
      const r = await fetch("/api/tasks/analyze-threat", {
        method: "POST",
        headers: HEADERS,
        body: JSON.stringify({ timeline })
      });

      if (r.ok) {
        const { task_id } = await r.json();
        trackTask(task_id, "AI Analysis", "Timeline Synthesis");
        pollTaskStatus(task_id, setIsAnalyzing, setAiAnalysis);
      } else {
        toast.error("Erreur lors de l'envoi au worker Celery.");
        setIsAnalyzing(false);
      }
    } catch (err) {
      toast.error("Échec de la communication avec le backend.");
      setIsAnalyzing(false);
    }
  };


  const getHourlyAlertsData = () => {
    const hours = {};
    const now = new Date();

    // Initialize last 24 hours
    for (let i = 23; i >= 0; i--) {
      const d = new Date(now.getTime() - i * 60 * 60 * 1000);
      const hourStr = d.getHours() + ":00";
      hours[hourStr] = { time: hourStr, Critical: 0, High: 0, Medium: 0, Low: 0 };
    }

    wazuhAlerts.forEach(alert => {
      const dateStr = alert.Timestamp || alert.timestamp;
      if (!dateStr) return;
      const date = new Date(dateStr);
      const hourStr = date.getHours() + ":00";
      if (hours[hourStr]) {
        const sev = parseInt(alert.Severity || alert.severity || 0);
        if (sev >= 12) hours[hourStr].Critical++;
        else if (sev >= 8) hours[hourStr].High++;
        else if (sev >= 4) hours[hourStr].Medium++;
        else hours[hourStr].Low++;
      }
    });

    return Object.values(hours);
  };

  const hourlyData = getHourlyAlertsData();

  return (
    <div className="dashboard-layout">
      <ToastContainer pauseOnHover={false} autoClose={3000} />

      {/* Sidebar */}
      <aside className="sidebar">
        <div className="logo-container">
          <div className="logo-icon"><Shield size={20} color="black" /></div>
          <span className="logo-text">SENTINEL BRIDGE</span>
        </div>

        <nav className="nav-menu">
          {(() => {
            const hasCriticalAlert = wazuhAlerts.some(a => parseInt(a.Severity || a.severity || 0) >= 12) || suricataAlerts.some(a => parseInt(a.severity || 0) >= 12);
            return (
              <>
                {/* --- Group 1: Command Center --- */}
                <div className="nav-group-label">COMMAND CENTER</div>
                <button className={`nav-item ${activeTab === 'dashboard' ? 'active' : ''}`} onClick={() => setActiveTab("dashboard")}>
                  <LayoutDashboard size={18} /> {t("dashboard")}
                </button>
                <button className={`nav-item ${activeTab === 'topology' ? 'active' : ''}`} onClick={() => setActiveTab("topology")}>
                  <Network size={18} /> {t("topology")}
                </button>

                {/* --- Group 2: Asset Management --- */}
                <div className="nav-group-label" style={{ marginTop: '15px' }}>ASSET MANAGEMENT</div>
                <button className={`nav-item ${activeTab === 'inventory' ? 'active' : ''}`} onClick={() => setActiveTab("inventory")}>
                  <Database size={18} /> {t("inventory")}
                </button>
                <button className={`nav-item ${activeTab === 'radar' ? 'active' : ''}`} onClick={() => setActiveTab("radar")}>
                  <Radar size={18} /> {lang === "fr" ? "Scanner Radar" : "Radar Scan"}
                </button>
                <button className={`nav-item ${activeTab === 'tasks' ? 'active' : ''}`} onClick={() => setActiveTab("tasks")}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', width: '100%' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                      <Clock size={18} /> {lang === "fr" ? "Jobs Système" : "System Jobs"}
                    </div>
                    {pendingTasks.filter(t => t.status === "PENDING" || t.status === "STARTED").length > 0 && (
                      <span className="task-badge">{pendingTasks.filter(t => t.status === "PENDING" || t.status === "STARTED").length}</span>
                    )}
                  </div>
                </button>

                {/* --- Group 3: Terminal Security Operations --- */}
                <div className="nav-group-label" style={{ marginTop: '15px' }}>TERMINAL SECURITY OPERATIONS</div>
                <button onClick={() => setActiveTab("terminal")} className={`nav-item ${activeTab === "terminal" ? "active" : ""}`}>
                  <Terminal size={18} />
                  <span>SIEM Control</span>
                </button>
                <button onClick={() => setActiveTab("remediation")} className={`nav-item ${activeTab === "remediation" ? "active" : ""}`}>
                  <ShieldCheck size={18} />
                  <span>Active Defense</span>
                </button>
                <button onClick={() => setActiveTab("alerts")} className={`nav-item ${activeTab === "alerts" ? "active" : ""}`}
                  style={hasCriticalAlert && activeTab !== "alerts" ? { background: 'rgba(255, 77, 77, 0.1)', borderRight: '3px solid var(--danger)' } : {}}
                >
                  <ShieldAlert size={18} color={hasCriticalAlert ? "#ff4d4d" : "currentColor"} />
                  <span style={{ color: hasCriticalAlert ? "#ff4d4d" : "inherit", fontWeight: hasCriticalAlert ? 'bold' : 'normal' }}>
                    Terminal Alerts
                  </span>
                  {hasCriticalAlert && <div className="pulse-dot" style={{ background: 'var(--danger)', marginLeft: 'auto' }}></div>}
                </button>

                {/* --- Group 4: Network Security Operations --- */}
                <div className="nav-group-label" style={{ marginTop: '15px' }}>NETWORK SECURITY OPERATIONS</div>
                <button
                  className={`nav-item ${activeTab === "suricata" ? "active" : ""}`}
                  onClick={() => setActiveTab("suricata")}
                  style={suricataAlerts.some(a => parseInt(a.severity || 0) >= 12) && activeTab !== "suricata" ? { background: 'rgba(255,77,77,0.1)', borderRight: '3px solid var(--danger)' } : {}}
                >
                  <Activity size={18} color={suricataAlerts.some(a => parseInt(a.severity || 0) >= 12) ? "#ff4d4d" : "currentColor"} />
                  <span style={{ color: suricataAlerts.some(a => parseInt(a.severity || 0) >= 12) ? "#ff4d4d" : "inherit", fontWeight: suricataAlerts.some(a => parseInt(a.severity || 0) >= 12) ? 'bold' : 'normal' }}>
                    Network Alerts
                  </span>
                  {suricataAlerts.some(a => parseInt(a.severity || 0) >= 12) && <div className="pulse-dot" style={{ background: 'var(--danger)', marginLeft: 'auto' }}></div>}
                </button>
                <button onClick={() => setActiveTab("network_control")} className={`nav-item ${activeTab === "network_control" ? "active" : ""}`}>
                  <Radio size={18} />
                  <span>Network Control</span>
                </button>
                <div className="nav-group-label" style={{ marginTop: '15px' }}>Intelligence</div>
                <div className={`nav-item ${activeTab === "ai" ? "active" : ""}`} onClick={() => setActiveTab("ai")}>
                  <Cpu size={18} /> {t("ai_copilot")}
                </div>
              </>
            )
          })()}
        </nav>

        <div className="sidebar-footer" style={{ marginTop: 'auto', padding: '20px 16px', borderTop: '1px solid var(--border)', background: 'rgba(255,255,255,0.01)' }}>
          <div className="status-indicator" style={{ marginBottom: '15px' }}>
            <div className="pulse-dot"></div>
            <span style={{ fontSize: '11px', letterSpacing: '0.5px', color: 'var(--text-muted)' }}>SYSTEM: ONLINE</span>
          </div>

          {/* Audio Guard Control */}
          <div style={{ marginBottom: '15px' }}>
            <div style={{ fontSize: '9px', color: 'rgba(255,255,255,0.3)', fontWeight: 800, marginBottom: '8px', textTransform: 'uppercase' }}>Audio Guard</div>
            <div style={{ display: 'flex', gap: '8px' }}>
              <button
                onClick={() => setIsMuted(!isMuted)}
                style={{
                  flex: 1,
                  padding: '10px',
                  borderRadius: '10px',
                  background: isMuted ? 'rgba(239, 68, 68, 0.1)' : 'rgba(16, 185, 129, 0.1)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  gap: '8px',
                  cursor: 'pointer',
                  color: isMuted ? '#ef4444' : '#10b981',
                  border: `1px solid ${isMuted ? 'rgba(239,68,68,0.2)' : 'rgba(16,185,129,0.2)'}`,
                  fontSize: '11px',
                  fontWeight: 'bold'
                }}
              >
                {isMuted ? <VolumeX size={14} /> : <Volume2 size={14} />}
                <span>{isMuted ? "OFF" : "ON"}</span>
              </button>
              <button
                onClick={playAlarm}
                title="Test Alarm"
                style={{
                  width: '40px',
                  borderRadius: '10px',
                  background: 'rgba(255,255,255,0.05)',
                  color: 'var(--text-muted)',
                  border: '1px solid var(--border)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  cursor: 'pointer'
                }}
              >
                <Activity size={14} />
              </button>
            </div>
          </div>

          {/* Language Selector */}
          <button
            onClick={() => setLang(lang === "en" ? "fr" : "en")}
            style={{
              width: '100%',
              background: 'rgba(14, 165, 233, 0.05)',
              border: '1px solid rgba(14, 165, 233, 0.2)',
              borderRadius: '10px',
              padding: '10px 15px',
              color: 'var(--accent-blue)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              cursor: 'pointer'
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <Globe size={14} />
              <span style={{ fontSize: '11px', fontWeight: 700 }}>{lang === "en" ? "ENGLISH" : "FRANÇAIS"}</span>
            </div>
            <span style={{ fontSize: '9px', opacity: 0.5 }}>{lang === "en" ? "To FR" : "To EN"}</span>
          </button>
        </div>

      </aside>

      <main className="main-wrapper">
        <header className="top-bar">
          <div className="header-title">
            <h1>{t(activeTab) || activeTab} Center</h1>
          </div>
          <div className="top-actions">
            <div className="badge-notification"><Lock size={14} /> Encrypted</div>
            <SystemClock />
          </div>
        </header>

        {/* Global Progress Line - Fixed and stable to prevent flickering */}
        <div
          className="global-progress"
          style={{
            position: 'fixed', top: 0, left: 0, right: 0, height: '3px',
            background: 'var(--accent-blue)', zIndex: 9999,
            boxShadow: '0 0 10px var(--accent-blue)',
            opacity: (isScanning || isAnalyzing || isAnalyzingGlobal) ? 1 : 0,
            transition: 'opacity 0.3s ease',
            pointerEvents: 'none'
          }}
        ></div>

        <>
          {activeTab === "dashboard" && (
            <div className="tab-pane animate-fade-in">
              <div className="stats-grid">
                <div className="stat-card">
                  <div className="stat-icon" style={{ background: 'rgba(244, 63, 94, 0.1)', color: 'var(--danger)' }}><ShieldAlert size={20} /></div>
                  <div className="stat-info">
                    <span className="stat-value">{wazuhAlerts.length}</span>
                    <span className="stat-label">{t("active_threats")}</span>
                  </div>
                </div>
                <div className="stat-card">
                  <div className="stat-icon" style={{ background: 'rgba(56, 189, 248, 0.1)', color: 'var(--accent-primary)' }}><Activity size={20} /></div>
                  <div className="stat-info">
                    <span className="stat-value">{wazuhAlerts.filter(a => a.Severity >= 8).length}</span>
                    <span className="stat-label">{t("critical_alerts")}</span>
                  </div>
                </div>
                <div className="stat-card">
                  <div className="stat-icon" style={{ background: 'rgba(56, 189, 248, 0.1)', color: '#38bdf8' }}><Activity size={20} /></div>
                  <div className="stat-info">
                    <span className="stat-value">{suricataHistory[suricataHistory.length - 1]?.packets.toLocaleString() || "0"}</span>
                    <span className="stat-label">IPS Packets</span>
                  </div>
                </div>
                <div className="stat-card">
                  <div className="stat-icon" style={{ background: 'rgba(239, 68, 68, 0.1)', color: '#ef4444' }}><ShieldAlert size={20} /></div>
                  <div className="stat-info">
                    <span className="stat-value" style={{ color: '#ef4444' }}>{suricataHistory[suricataHistory.length - 1]?.drops || "0"}</span>
                    <span className="stat-label">IPS Drops</span>
                  </div>
                </div>
              </div>

              <div className="dashboard-content-grid" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
                {/* Chart 1: Presence Analytics */}
                <div className="section-card" style={{ height: '350px' }}>
                  <div className="section-header">
                    <h2 style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                      <Activity size={18} color="var(--accent-cyan)" /> Network Presence Analytics
                    </h2>
                  </div>
                  <div style={{ width: '100%', height: '280px', marginTop: '10px' }}>
                    <ResponsiveContainer width="100%" height="100%">
                      <AreaChart data={onlineHistory}>
                        <defs>
                          <linearGradient id="colorCount" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor="var(--accent-cyan)" stopOpacity={0.3} />
                            <stop offset="95%" stopColor="var(--accent-cyan)" stopOpacity={0} />
                          </linearGradient>
                        </defs>
                        <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                        <XAxis dataKey="time" stroke="var(--text-muted)" fontSize={10} tickLine={false} />
                        <YAxis stroke="var(--text-muted)" fontSize={10} tickLine={false} axisLine={false} />
                        <Tooltip
                          contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '8px' }}
                        />
                        <Area type="monotone" dataKey="count" stroke="var(--accent-cyan)" fill="url(#colorCount)" strokeWidth={3} animationDuration={1000} />
                      </AreaChart>
                    </ResponsiveContainer>
                  </div>
                </div>

                {/* Chart 2: Bandwidth */}
                <div className="section-card" style={{ height: '350px' }}>
                  <div className="section-header">
                    <h2><Zap size={18} /> Real-time Bandwidth (MB/s)</h2>
                  </div>
                  <div style={{ width: '100%', height: '280px', marginTop: '10px' }}>
                    <ResponsiveContainer width="100%" height="100%">
                      <AreaChart data={throughputHistory}>
                        <defs>
                          <linearGradient id="colorValue" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor="var(--accent-blue)" stopOpacity={0.3} />
                            <stop offset="95%" stopColor="var(--accent-blue)" stopOpacity={0} />
                          </linearGradient>
                        </defs>
                        <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                        <XAxis dataKey="time" stroke="var(--text-muted)" fontSize={10} tickLine={false} />
                        <YAxis stroke="var(--text-muted)" fontSize={10} tickLine={false} axisLine={false} />
                        <Tooltip
                          contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '8px' }}
                        />
                        <Area
                          type="monotone"
                          dataKey="value"
                          stroke="var(--accent-blue)"
                          fillOpacity={1}
                          fill="url(#colorValue)"
                          strokeWidth={3}
                          animationDuration={1500}
                        />
                      </AreaChart>
                    </ResponsiveContainer>
                  </div>
                </div>

                {/* Chart 3: IDS Protection Activity */}
                <div className="section-card" style={{ height: '350px' }}>
                  <div className="section-header">
                    <h2 style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                      <Activity size={18} color="#38bdf8" /> Activité de Protection Réseau (IPS)
                    </h2>
                  </div>
                  <div style={{ width: '100%', height: '220px', marginTop: '20px' }}>
                    <ResponsiveContainer width="100%" height="100%">
                      <AreaChart data={suricataHistory}>
                        <defs>
                          <linearGradient id="colorIDS" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor="#38bdf8" stopOpacity={0.3} />
                            <stop offset="95%" stopColor="#38bdf8" stopOpacity={0} />
                          </linearGradient>
                        </defs>
                        <XAxis dataKey="time" stroke="var(--text-muted)" fontSize={10} hide />
                        <YAxis stroke="var(--text-muted)" fontSize={10} axisLine={false} tickLine={false} />
                        <Tooltip contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '8px' }} />
                        <Area type="monotone" dataKey="packets" stroke="#38bdf8" fillOpacity={1} fill="url(#colorIDS)" strokeWidth={2} name="Flux Inspecté" />
                        <Area type="monotone" dataKey="drops" stroke="#ef4444" fillOpacity={0} strokeWidth={2} name="Anomalies" />
                      </AreaChart>
                    </ResponsiveContainer>
                  </div>
                  <div style={{ display: 'flex', gap: '15px', marginTop: '15px', padding: '10px', background: 'rgba(255,255,255,0.02)', borderRadius: '8px' }}>
                    <div style={{ flex: 1 }}>
                      <span style={{ fontSize: '9px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Inspection en cours</span>
                      <div style={{ fontSize: '16px', fontWeight: 700, color: '#38bdf8' }}>{suricataHistory[suricataHistory.length - 1]?.packets.toLocaleString() || "0"} pkt</div>
                    </div>
                    <div style={{ flex: 1 }}>
                      <span style={{ fontSize: '9px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Anomalies bloquées</span>
                      <div style={{ fontSize: '16px', fontWeight: 700, color: '#ef4444' }}>{suricataHistory[suricataHistory.length - 1]?.drops || "0"}</div>
                    </div>
                  </div>
                </div>

                {/* Chart 4: Threat Distribution */}
                <div className="section-card" style={{ height: '350px' }}>
                  <div className="section-header">
                    <h2 style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                      <ShieldAlert size={18} color="var(--danger)" /> {t("threat_intensity_distribution")} (24h)
                    </h2>
                  </div>
                  <div style={{ width: '100%', height: '240px', marginTop: '15px' }}>
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={hourlyData}>
                        <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
                        <XAxis dataKey="time" stroke="var(--text-muted)" fontSize={10} tickLine={false} />
                        <YAxis stroke="var(--text-muted)" fontSize={10} tickLine={false} axisLine={false} />
                        <Tooltip
                          cursor={{ fill: 'rgba(255,255,255,0.05)' }}
                          contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '12px' }}
                        />
                        <Legend iconType="circle" wrapperStyle={{ fontSize: '10px', paddingTop: '10px' }} />
                        <Bar dataKey="Critical" stackId="a" fill="#f43f5e" radius={[0, 0, 0, 0]} />
                        <Bar dataKey="High" stackId="a" fill="#fb923c" radius={[0, 0, 0, 0]} />
                        <Bar dataKey="Medium" stackId="a" fill="#38bdf8" radius={[0, 0, 0, 0]} />
                        <Bar dataKey="Low" stackId="a" fill="#4ade80" radius={[4, 4, 0, 0]} />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === "inventory" && (
            <div className="tab-pane animate-fade-in">
              <div className="stats-grid" style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '20px', marginBottom: '20px' }}>
                <div className="stat-card">
                  <div className="stat-icon" style={{ background: 'rgba(56, 189, 248, 0.1)', color: 'var(--accent-blue)' }}><Server size={20} /></div>
                  <div className="stat-info">
                    <span className="stat-value">{devices.length}</span>
                    <span className="stat-label">Total Assets</span>
                  </div>
                </div>
                <div className="stat-card">
                  <div className="stat-icon" style={{ background: 'rgba(16, 185, 129, 0.1)', color: '#10b981' }}><Activity size={20} /></div>
                  <div className="stat-info">
                    <span className="stat-value">{devices.filter(d => d.is_online).length}</span>
                    <span className="stat-label">Online Nodes</span>
                  </div>
                </div>
                <div className="stat-card">
                  <div className="stat-icon" style={{ background: 'rgba(239, 68, 68, 0.1)', color: '#ef4444' }}><ShieldAlert size={20} /></div>
                  <div className="stat-info">
                    <span className="stat-value">{devices.filter(d => !d.is_online).length}</span>
                    <span className="stat-label">Inactive / Offline</span>
                  </div>
                </div>
              </div>

              <div className="section-card border-glow" style={{ padding: '0', overflow: 'hidden' }}>
                <div className="section-header" style={{ flexWrap: 'wrap', gap: '15px', paddingLeft: '20px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <Database size={20} color="var(--accent-blue)" />
                    <h2 style={{ margin: 0 }}>Network Asset Inventory</h2>
                  </div>
                  
                  <div style={{ display: 'flex', alignItems: 'center', gap: '15px', marginLeft: 'auto' }}>
                    <div className="search-box" style={{ width: '250px', background: 'rgba(255,255,255,0.05)', borderRadius: '10px', padding: '5px 12px', display: 'flex', alignItems: 'center', gap: '10px', border: '1px solid var(--border)' }}>
                      <Search size={14} color="var(--text-muted)" />
                      <input 
                        type="text" 
                        placeholder="Filter by IP or MAC..." 
                        style={{ background: 'transparent', border: 'none', color: 'white', fontSize: '13px', outline: 'none', width: '100%' }}
                        onChange={(e) => {
                          const val = e.target.value.toLowerCase();
                          const rows = document.querySelectorAll('.inventory-row');
                          rows.forEach(row => {
                            const text = row.textContent.toLowerCase();
                            row.style.display = text.includes(val) ? '' : 'none';
                          });
                        }}
                      />
                    </div>
                    <span className="status-pill status-success">{devices.filter(d => d.is_online).length} Active Now</span>
                  </div>
                </div>
                
                <div className="table-wrapper" style={{ maxHeight: '600px', overflowY: 'auto' }}>
                  {devices.length === 0 ? (
                    <div style={{ textAlign: 'center', padding: '60px', color: 'var(--text-muted)' }}>
                      <div style={{ fontSize: '3rem', marginBottom: '20px', opacity: 0.2 }}>🔍</div>
                      <h3>No devices discovered yet</h3>
                      <p>The background scanner is probing the network. Please wait...</p>
                    </div>
                  ) : (
                    <table className="custom-table">
                      <thead>
                        <tr>
                          <th style={{ width: '120px' }}>Status</th>
                          <th>IP Address</th>
                          <th>MAC Address</th>
                          <th>Identification</th>
                          <th>Last Activity</th>
                        </tr>
                      </thead>
                      <tbody>
                        {[...devices]
                          .sort((a, b) => (b.is_online ? 1 : 0) - (a.is_online ? 1 : 0))
                          .map(d => {
                            const ip = d.ip || "";
                            const isGateway = ip.endsWith('.1');
                            return (
                              <tr key={d.id} className={`inventory-row ${d.is_online ? 'suricata-row-info' : ''}`}>
                                <td>
                                  <div className={`status-pill ${d.is_online ? 'status-success' : 'status-danger'}`} style={{ 
                                    display: 'flex', 
                                    alignItems: 'center', 
                                    gap: '8px', 
                                    padding: '6px 12px',
                                    borderRadius: '20px',
                                    fontSize: '10px',
                                    fontWeight: '800',
                                    letterSpacing: '0.5px',
                                    width: 'fit-content',
                                    boxShadow: d.is_online ? '0 0 10px rgba(16, 185, 129, 0.2)' : 'none',
                                    background: d.is_online ? 'rgba(16, 185, 129, 0.1)' : 'rgba(239, 68, 68, 0.05)',
                                    color: d.is_online ? '#10b981' : '#ef4444',
                                    border: `1px solid ${d.is_online ? 'rgba(16, 185, 129, 0.3)' : 'rgba(239, 68, 68, 0.2)'}`
                                  }}>
                                    <div style={{ 
                                      width: '6px', 
                                      height: '6px', 
                                      borderRadius: '50%', 
                                      background: 'currentColor',
                                      animation: d.is_online ? 'pulse 2s infinite' : 'none'
                                    }} />
                                    {d.is_online ? 'ONLINE' : 'OFFLINE'}
                                  </div>
                                </td>
                                <td style={{ fontWeight: 600, color: d.is_online ? '#fff' : '#94a3b8' }}>{ip || '---'}</td>
                                <td style={{ fontFamily: 'monospace', color: 'var(--text-muted)', fontSize: '12px' }}>{d.mac}</td>
                                <td>
                                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                    {isGateway ? <Shield size={14} color="var(--accent-blue)" /> : <Laptop size={14} color="var(--text-muted)" />}
                                    <span>{isGateway ? 'Gateway / Router' : 'Workstation'}</span>
                                  </div>
                                </td>
                                <td style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                                  {d.is_online ? 'Active Now' : 'Recorded offline'}
                                </td>
                              </tr>
                            );
                          })}
                      </tbody>
                    </table>
                  )}
                </div>
              </div>
            </div>
          )}

          {activeTab === "radar" && (
            <div className="tab-pane animate-fade-in">
              <div className="section-card">
                <div className="section-header">
                  <h2><Radar size={18} /> Network Reconnaissance</h2>
                  <div style={{ display: 'flex', gap: '10px' }}>
                    <input
                      type="text"
                      placeholder="Target Subnet (Auto if empty)"
                      id="subnet-input"
                      style={{ width: '200px' }}
                    />
                    <select
                      id="scan-type-select"
                      style={{
                        background: 'rgba(255,255,255,0.05)',
                        border: '1px solid var(--border)',
                        color: 'white',
                        borderRadius: '12px',
                        padding: '0 15px',
                        fontSize: '13px',
                        cursor: 'pointer'
                      }}
                    >
                      <option value="fast" style={{ background: '#0a0c12' }}>{lang === "fr" ? "Découverte Rapide" : "Fast Discovery"}</option>
                      <option value="ports" style={{ background: '#0a0c12' }}>{lang === "fr" ? "Scan de Ports" : "Port Scan"}</option>
                      <option value="services" style={{ background: '#0a0c12' }}>{lang === "fr" ? "Détection Services" : "Service Detection"}</option>
                      <option value="os" style={{ background: '#0a0c12' }}>{lang === "fr" ? "Détection OS" : "OS Detection"}</option>
                      <option value="vuln" style={{ background: '#0a0c12' }}>{lang === "fr" ? "Audit Vulnérabilité" : "Vulnerability Audit"}</option>
                    </select>
                    <button className="btn-primary" onClick={() => {
                      const subnet = document.getElementById('subnet-input').value;
                      const type = document.getElementById('scan-type-select').value;
                      startNetworkScan(subnet, type);
                    }} disabled={isScanning}>
                      {isScanning ? 'Analyzing...' : 'Run Scan'}
                    </button>
                  </div>
                </div>
                <div className="table-wrapper">
                  <table className="custom-table">
                    <thead><tr><th>IP</th><th>MAC Address</th><th>State</th></tr></thead>
                    <tbody>
                      {scanResults.map((r, i) => (
                        <tr key={i}>
                          <td>{r.ip}</td>
                          <td>{r.mac}</td>
                          <td>
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                              {Array.isArray(r.status) ? r.status.map((item, idx) => (
                                <div key={idx} style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                  <div style={{ width: '4px', height: '4px', borderRadius: '50%', background: 'var(--accent-cyan)' }} />
                                  <span style={{ fontSize: '12px' }}>{item}</span>
                                </div>
                              )) : <span style={{ fontSize: '12px' }}>{r.status}</span>}
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {activeTab === "tasks" && (
            <div className="tab-pane animate-fade-in">
              <div className="section-card">
                <div className="section-header">
                  <h2><Clock size={18} /> {lang === "fr" ? "Historique des Tâches Background" : "Background Jobs History"}</h2>
                  <button className="btn-primary" onClick={() => setPendingTasks([])} style={{ background: 'rgba(239, 68, 68, 0.1)', color: '#ef4444', boxShadow: 'none' }}>
                    {lang === "fr" ? "Vider l'historique" : "Clear History"}
                  </button>
                </div>

                {pendingTasks.length === 0 ? (
                  <div style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)' }}>
                    {lang === "fr" ? "Aucune tâche enregistrée." : "No tasks recorded."}
                  </div>
                ) : (
                  <div className="job-list">
                    {pendingTasks.map((task, idx) => (
                      <div key={idx} className="job-card">
                        <div className="job-info">
                          <h4>{task.type} - {task.target}</h4>
                          <span>ID: {task.id.substring(0, 16)}... | Début: {task.startTime.toLocaleTimeString()}</span>
                        </div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '20px' }}>
                          <span className={`job-status-pill status-${task.status.toLowerCase()}`}>
                            {task.status}
                          </span>
                          {task.result && (
                            <button className="btn-primary"
                              style={{ padding: '4px 10px', fontSize: '10px' }}
                              onClick={() => {
                                if (task.type === "AI Analysis") {
                                  setAiBehaviorReport(task.result);
                                } else {
                                  setScanResults(task.result.results.map(r => ({
                                    ip: r.ip,
                                    mac: r.mac,
                                    status: [r.os, ...r.ports]
                                  })));
                                  setActiveTab("radar");
                                }
                              }}>
                              View Result
                            </button>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {activeTab === "remediation" && (
            <div className="tab-content fadeIn">
              <div className="section-header">
                <h2>🛡️ Active Response History</h2>
              </div>

              <div className="ar-timeline">
                {activeResponses.length === 0 ? (
                  <div className="empty-state card">
                    <span className="icon" style={{ fontSize: '3rem', opacity: 0.3 }}>🛡️</span>
                    <p>Aucune action de défense détectée pour le moment.</p>
                  </div>
                ) : (
                  <div className="section-card border-glow" style={{ padding: '0', overflow: 'hidden', width: '100%', maxWidth: '100%' }}>
                    <div className="section-header" style={{ borderLeft: '4px solid var(--primary)' }}>
                      <h2 style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                        <Shield size={20} color="var(--primary)" />
                        Active Defense Timeline
                      </h2>
                      <span className="status-pill status-success">{activeResponses.length} Actions</span>
                    </div>
                    <div className="table-wrapper" style={{ maxHeight: '500px', overflowY: 'auto', width: '100%' }}>
                      <table className="custom-table" style={{ tableLayout: 'fixed', width: '100%' }}>
                        <thead>
                          <tr>
                            <th style={{ width: '160px' }}>Timestamp</th>
                            <th style={{ width: '180px' }}>Action</th>
                            <th style={{ width: '150px' }}>Target Agent</th>
                            <th style={{ width: '100px' }}>Level</th>
                            <th>Technical Log Preview</th>
                          </tr>
                        </thead>
                        <tbody>
                          {activeResponses
                            .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
                            .map((ar, idx) => {
                              const isUnblock = ar.action.toLowerCase().includes('unblock');
                              const severityLevel = parseInt(ar.level || 0);
                              const isCritical = severityLevel >= 10;
                              return (
                                <tr key={idx} className={`${isUnblock ? 'suricata-row-low' : (severityLevel >= 7 ? 'suricata-row-critical' : 'suricata-row-medium')} ${isCritical ? 'critical-row-pulse' : ''}`}>
                                  <td style={{ color: 'var(--text-muted)', fontSize: '11px', whiteSpace: 'nowrap' }}>
                                    {new Date(ar.timestamp).toLocaleString()}
                                  </td>
                                  <td>
                                    <span className={`suricata-sev-${isUnblock ? 'low' : (severityLevel >= 7 ? 'critical' : 'medium')}`} style={{ textTransform: 'uppercase', fontWeight: 'bold' }}>
                                      {ar.action}
                                    </span>
                                  </td>
                                  <td>
                                    <div style={{ display: 'flex', flexDirection: 'column' }}>
                                      <span style={{ fontWeight: 600, color: '#cbd5e1' }}>{ar.agent_name}</span>
                                      <small style={{ color: 'var(--text-muted)', fontSize: '10px' }}>ID: {ar.agent_id}</small>
                                    </div>
                                  </td>
                                  <td>
                                    <span className={ar.level >= 10 ? 'suricata-sev-critical' : 'suricata-sev-medium'}>
                                      Level {ar.level}
                                    </span>
                                  </td>
                                  <td className="ar-log-cell">
                                    <div className="mini-log" style={{ maxWidth: '100%', width: '100%' }}>
                                      <code>{ar.full_log}</code>
                                    </div>
                                  </td>
                                </tr>
                              );
                            })}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {activeTab === "alerts" && (
            <div className="tab-pane">
              <div className="section-card">
                <div className="section-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '15px', padding: '15px 20px' }}>
                  <h2 style={{ margin: 0, display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <ShieldAlert size={20} color="var(--danger)" /> Orchestrated SOC Alerts
                  </h2>

                  <div className="filters-container" style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
                    <select
                      style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid var(--border)', color: 'var(--text-primary)', padding: '8px 12px', borderRadius: '8px', outline: 'none', fontSize: '13px', cursor: 'pointer', transition: 'all 0.3s ease' }}
                      value={alertFilterTime}
                      onChange={(e) => setAlertFilterTime(e.target.value)}
                      onMouseEnter={e => e.target.style.borderColor = 'var(--accent-blue)'}
                      onMouseLeave={e => e.target.style.borderColor = 'var(--border)'}
                    >
                      <option value="" style={{ background: '#0a0c12' }}>Time: All</option>
                      <option value="5m" style={{ background: '#0a0c12' }}>Last 5 Minutes</option>
                      <option value="1h" style={{ background: '#0a0c12' }}>Last 1 Hour</option>
                      <option value="24h" style={{ background: '#0a0c12' }}>Last 24 Hours</option>
                    </select>

                    <select
                      style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid var(--border)', color: 'var(--text-primary)', padding: '8px 12px', borderRadius: '8px', outline: 'none', fontSize: '13px', cursor: 'pointer', transition: 'all 0.3s ease' }}
                      value={alertFilterSeverity}
                      onChange={(e) => setAlertFilterSeverity(e.target.value)}
                      onMouseEnter={e => e.target.style.borderColor = 'var(--accent-blue)'}
                      onMouseLeave={e => e.target.style.borderColor = 'var(--border)'}
                    >
                      <option value="" style={{ background: '#0a0c12' }}>Severity: All</option>
                      <option value="12" style={{ background: '#0a0c12' }}>Critical (12+)</option>
                      <option value="8" style={{ background: '#0a0c12' }}>High (8-11)</option>
                      <option value="4" style={{ background: '#0a0c12' }}>Medium (4-7)</option>
                      <option value="0" style={{ background: '#0a0c12' }}>Low (0-3)</option>
                    </select>

                    <input
                      type="text"
                      style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid var(--border)', color: 'var(--text-primary)', padding: '8px 12px', borderRadius: '8px', outline: 'none', fontSize: '13px', width: '180px', transition: 'all 0.3s ease' }}
                      placeholder="Search IP (e.g. 192...)"
                      value={alertFilterIP}
                      onChange={(e) => setAlertFilterIP(e.target.value)}
                      onFocus={e => e.target.style.borderColor = 'var(--accent-cyan)'}
                      onBlur={e => e.target.style.borderColor = 'var(--border)'}
                    />

                    <input
                      type="text"
                      style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid var(--border)', color: 'var(--text-primary)', padding: '8px 12px', borderRadius: '8px', outline: 'none', fontSize: '13px', width: '180px', transition: 'all 0.3s ease' }}
                      placeholder="Search MAC..."
                      value={alertFilterMAC}
                      onChange={(e) => setAlertFilterMAC(e.target.value)}
                      onFocus={e => e.target.style.borderColor = 'var(--accent-cyan)'}
                      onBlur={e => e.target.style.borderColor = 'var(--border)'}
                    />
                  </div>
                </div>
                <div className="table-wrapper">
                  <table className="custom-table">
                    <thead><tr><th>Time</th><th>Description</th><th>Severity</th><th>IP</th><th>MAC Address</th><th>Employee</th><th>Action</th></tr></thead>
                    <tbody>
                      {wazuhAlerts.filter(a => {
                        const sev = parseInt(a.Severity || a.severity || 0);
                        const ip = (a["Source IP"] || a.src_ip || a.srcip || "").toLowerCase();
                        const mac = (a["MAC Address"] || a.mac || "").toLowerCase();
                        const alertTime = new Date(a.Timestamp || a.timestamp || 0).getTime();
                        const now = new Date().getTime();

                        let passSeverity = true;
                        if (alertFilterSeverity === "12") passSeverity = sev >= 12;
                        else if (alertFilterSeverity === "8") passSeverity = sev >= 8 && sev < 12;
                        else if (alertFilterSeverity === "4") passSeverity = sev >= 4 && sev < 8;
                        else if (alertFilterSeverity === "0") passSeverity = sev >= 0 && sev < 4;

                        let passTime = true;
                        if (alertFilterTime === "5m") passTime = (now - alertTime) <= 5 * 60 * 1000;
                        else if (alertFilterTime === "1h") passTime = (now - alertTime) <= 60 * 60 * 1000;
                        else if (alertFilterTime === "24h") passTime = (now - alertTime) <= 24 * 60 * 60 * 1000;

                        const passIP = alertFilterIP === "" || ip.includes(alertFilterIP.toLowerCase());
                        const passMAC = alertFilterMAC === "" || mac.includes(alertFilterMAC.toLowerCase());

                        return passSeverity && passIP && passMAC && passTime;
                      }).length > 0 ? wazuhAlerts.filter(a => {
                        const sev = parseInt(a.Severity || a.severity || 0);
                        const ip = (a["Source IP"] || a.src_ip || a.srcip || "").toLowerCase();
                        const mac = (a["MAC Address"] || a.mac || "").toLowerCase();
                        const alertTime = new Date(a.Timestamp || a.timestamp || 0).getTime();
                        const now = new Date().getTime();

                        let passSeverity = true;
                        if (alertFilterSeverity === "12") passSeverity = sev >= 12;
                        else if (alertFilterSeverity === "8") passSeverity = sev >= 8 && sev < 12;
                        else if (alertFilterSeverity === "4") passSeverity = sev >= 4 && sev < 8;
                        else if (alertFilterSeverity === "0") passSeverity = sev >= 0 && sev < 4;

                        let passTime = true;
                        if (alertFilterTime === "5m") passTime = (now - alertTime) <= 5 * 60 * 1000;
                        else if (alertFilterTime === "1h") passTime = (now - alertTime) <= 60 * 60 * 1000;
                        else if (alertFilterTime === "24h") passTime = (now - alertTime) <= 24 * 60 * 60 * 1000;

                        const passIP = alertFilterIP === "" || ip.includes(alertFilterIP.toLowerCase());
                        const passMAC = alertFilterMAC === "" || mac.includes(alertFilterMAC.toLowerCase());

                        return passSeverity && passIP && passMAC && passTime;
                      }).sort((a, b) => parseInt(b.Severity || b.severity || 0) - parseInt(a.Severity || a.severity || 0)).map((a, idx) => {
                        const alertKey = (a.Timestamp || a.timestamp || "") + (a.Description || a.description || "") + idx;
                        return (
                          <AlertRow
                            key={alertKey}
                            alert={a}
                            t={t}
                            onInvestigate={async (target) => {
                              const mac = target["MAC Address"] || target.mac;
                              const ip = target["Source IP"] || target.srcip;
                              const agentId = target["Agent ID"];
                              const dev = devices.find(d => d.mac === mac || d.ip === ip);

                              setInvestigationTarget({ ...target, device: dev });
                              setIsInvestigating(true);
                              setDeepForensics(null); // Reset prev

                              if (agentId && agentId !== "Unknown") {
                                try {
                                  const res = await fetch(`/api/wazuh/investigate/${agentId}`, { headers: HEADERS });
                                  if (res.ok) setDeepForensics(await res.json());
                                } catch (e) { console.error("Forensics error:", e); }
                              }
                            }}
                          />
                        );
                      }) : <tr><td colSpan="7" style={{ textAlign: "center", padding: "40px", color: "var(--text-muted)" }}>No Active Threats Found</td></tr>}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {activeTab === "suricata" && (
            <div className="tab-pane" style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>

              {/* Filtre Global Unique */}
              <div className="section-card border-glow" style={{ padding: '15px 20px', display: 'flex', gap: '15px', alignItems: 'center', background: 'rgba(255,255,255,0.02)' }}>
                <Activity size={20} color="var(--primary)" />
                <h3 style={{ fontSize: '14px', margin: 0, marginRight: 'auto' }}>Filtrage Global du Trafic</h3>
                <div style={{ display: 'flex', gap: '10px' }}>
                  <input
                    type="text"
                    placeholder="Rechercher IP Source..."
                    className="terminal-filter-input"
                    value={suricataSrcFilter}
                    onChange={(e) => setSuricataSrcFilter(e.target.value.replace(/\s/g, ""))}
                    style={{ padding: '6px 12px', background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border)', borderRadius: '6px', color: 'white', fontSize: '12px', width: '200px' }}
                  />
                  <input
                    type="text"
                    placeholder="Rechercher IP Destination..."
                    className="terminal-filter-input"
                    value={suricataDestFilter}
                    onChange={(e) => setSuricataDestFilter(e.target.value.replace(/\s/g, ""))}
                    style={{ padding: '6px 12px', background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border)', borderRadius: '6px', color: 'white', fontSize: '12px', width: '200px' }}
                  />
                </div>
              </div>

              {["alert", "stats", "flow", "http", "dns", "tls", "ssh", "fileinfo", "unknown"].map(eType => {
                const typeAlerts = suricataAlerts
                  .filter(a => (a.event_type || 'unknown').toLowerCase() === eType)
                  .filter(a => (a.src_ip || "").includes(suricataSrcFilter) && (a.dest_ip || "").includes(suricataDestFilter))
                  .sort((a, b) => {
                    const sevDiff = parseInt(b.severity || 0) - parseInt(a.severity || 0);
                    if (sevDiff !== 0) return sevDiff;
                    return new Date(b.timestamp) - new Date(a.timestamp);
                  });
                // Always show alert, http, flow, and dns sections. Hide others if empty.
                const shouldAlwaysShow = ["alert", "http", "flow", "dns"].includes(eType);
                if (typeAlerts.length === 0 && !shouldAlwaysShow) return null;

                if (eType === "stats") return null;

                const isAlert = eType === "alert";

                return (
                  <div className="section-card" key={eType}>
                    <div className="section-header" style={{ borderLeft: `4px solid ${isAlert ? '#ef4444' : '#38bdf8'}` }}>
                      <h2 style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                        {isAlert ? <ShieldAlert size={20} color="#ef4444" /> : <Activity size={20} color="#38bdf8" />}
                        Suricata {eType.toUpperCase()}
                      </h2>
                      <span className={`status-pill ${isAlert ? 'status-danger' : 'status-success'}`}>
                        {typeAlerts.length} Events
                      </span>
                    </div>
                    <div className="table-wrapper" style={eType !== "alert" ? { maxHeight: '350px', overflowY: 'auto' } : {}}>
                      <table className="custom-table">
                        <thead>
                          <tr>
                            <th>Time</th>
                            <th>Message / Type</th>
                            <th>Protocol</th>
                            <th>Source IP</th>
                            <th>Dest IP</th>
                            <th>{isAlert ? "Severity" : "Details"}</th>
                          </tr>
                        </thead>
                        <tbody>
                          {typeAlerts.length > 0 ? typeAlerts.map((a, i) => {
                            const sev = parseInt(a.severity || 0);
                            const isCritical = isAlert && sev >= 12;
                            const isHigh = isAlert && sev >= 7 && sev < 12;
                            const isMedium = isAlert && sev >= 3 && sev < 7;
                            const isLow = isAlert && sev > 0 && sev < 3;

                            const rowClass = isCritical ? 'suricata-row-critical'
                              : isHigh ? 'suricata-row-high'
                                : isMedium ? 'suricata-row-medium'
                                  : isLow ? 'suricata-row-low'
                                    : 'suricata-row';

                            const sevClass = isCritical ? 'suricata-sev-critical'
                              : isHigh ? 'suricata-sev-high'
                                : isMedium ? 'suricata-sev-medium'
                                  : isLow ? 'suricata-sev-low'
                                    : 'suricata-sev-info';

                            const protoTagClass = isAlert ? '' : `suricata-event-${eType}`;

                            return (
                              <tr key={i} className={rowClass}>
                                <td style={{ color: 'var(--text-muted)', fontSize: '11px' }}>{new Date(a.timestamp).toLocaleString()}</td>
                                <td style={{ fontWeight: 600, color: isCritical ? '#ff6b6b' : isHigh ? '#fb923c' : isMedium ? '#fbbf24' : '#cbd5e1' }}>
                                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                    {isCritical && <ShieldAlert size={14} className="critical-icon" />}
                                    {a.alert_msg}
                                  </div>
                                </td>
                                <td>
                                  <span
                                    className={protoTagClass || undefined}
                                    style={{ fontSize: '10px', padding: '3px 8px', borderRadius: '4px', ...(protoTagClass ? {} : { background: 'rgba(255,255,255,0.08)', color: '#94a3b8' }) }}>
                                    {a.proto || (isAlert ? "TCP" : eType)}
                                  </span>
                                </td>
                                <td style={{ fontFamily: 'monospace', fontSize: '12px', color: '#7dd3fc' }}>{a.src_ip || "-"}</td>
                                <td style={{ fontFamily: 'monospace', fontSize: '12px', color: '#94a3b8' }}>{a.dest_ip || "-"}</td>
                                <td>
                                  {isAlert ? (
                                    <span className={sevClass}>Level {sev}</span>
                                  ) : (
                                    <span style={{ fontSize: '11px', color: 'var(--text-muted)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', maxWidth: '350px', display: 'inline-block' }} title={a.payload || ""}>
                                      {formatSuricataDetails(a.payload, eType)}
                                    </span>
                                  )}
                                </td>
                              </tr>
                            );
                          }) : (
                            <tr><td colSpan="6" style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)' }}>No {eType} events detected by Suricata.</td></tr>
                          )}
                        </tbody>
                      </table>
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          {activeTab === "terminal" && (
            <div className="tab-content fadeIn" style={{ height: 'calc(100vh - 100px)' }}>
              <div className="terminal-window">
                <div className="terminal-header">
                  <div className="terminal-dots"><span></span><span></span><span></span></div>
                  <div className="terminal-title">root@sentinel-wazuh:~ (SSH:2222)</div>
                </div>
                <div className="terminal-body" id="terminal-body" ref={terminalBodyRef}>
                  {terminalHistory.map((line, i) => (
                    <div key={i} className={`terminal-line ${line.type}`}>
                      {line.type === 'input' && <span className="prompt"># </span>}
                      <span className="content">{line.content}</span>
                    </div>
                  ))}
                  {isExecutingCmd && <div className="terminal-line system"><span className="content pulse">Executing...</span></div>}
                </div>
                <form className="terminal-input-area" onSubmit={executeCommand} onClick={() => terminalInputRef.current?.focus()}>
                  <span className="prompt"># </span>
                  <input
                    ref={terminalInputRef}
                    type="text"
                    autoFocus
                    value={currentCmd}
                    onChange={(e) => setCurrentCmd(e.target.value)}
                    onBlur={(e) => {
                      if (activeTab === "terminal") {
                        // Empêcher la perte de focus si l'onglet est actif
                        setTimeout(() => e.target.focus(), 0);
                      }
                    }}
                    disabled={isExecutingCmd}
                    placeholder="Enter command..."
                  />
                </form>
              </div>
            </div>
          )}

          {activeTab === "network_control" && (
            <div className="tab-content fadeIn" style={{ height: 'calc(100vh - 100px)' }}>
              <div className="terminal-window">
                <div className="terminal-header" style={{ background: '#064e3b' }}>
                  <div className="terminal-dots"><span></span><span></span><span></span></div>
                  <div className="terminal-title">suricata@suricata-virtual-machine:~ (192.168.133.136) [IPS MODE]</div>
                </div>
                <div className="terminal-body" ref={suricataBodyRef}>
                  {suricataTerminalHistory.map((line, i) => (
                    <div key={i} className={`terminal-line ${line.type}`}>
                      {line.type === 'input' && <span className="prompt">$ </span>}
                      <span className="content">{line.content}</span>
                    </div>
                  ))}
                  {isExecutingCmd && <div className="terminal-line system"><span className="content pulse">Executing on sensor...</span></div>}
                </div>
                <form className="terminal-input-area" onSubmit={(e) => executeCommand(e, 'suricata')} onClick={() => suricataInputRef.current?.focus()}>
                  <span className="prompt">$ </span>
                  <input
                    ref={suricataInputRef}
                    type="text"
                    autoFocus
                    value={suricataCmd}
                    onChange={(e) => setSuricataCmd(e.target.value)}
                    onBlur={(e) => {
                      if (activeTab === "network_control") {
                        setTimeout(() => e.target.focus(), 0);
                      }
                    }}
                    disabled={isExecutingCmd}
                    placeholder="Configure IPS..."
                  />
                </form>
              </div>
            </div>
          )}

          {activeTab === "ai" && (
            <div className="tab-pane">
              <div className="section-card ai-view" style={{ minHeight: '600px' }}>
                <div className="section-header" style={{ padding: '25px', background: 'linear-gradient(90deg, rgba(56, 189, 248, 0.05) 0%, transparent 100%)' }}>
                  <div>
                    <h2 style={{ display: 'flex', alignItems: 'center', gap: '12px', fontSize: '24px' }}>
                      <Cpu size={28} color="var(--accent-cyan)" /> AI Intelligence Center
                    </h2>
                    <p style={{ color: 'var(--text-muted)', margin: '5px 0 0 0' }}>Orchestrating network-wide security insights using qwen2.5</p>
                  </div>
                  <div style={{ display: 'flex', gap: '15px' }}>
                    <button className="btn-primary" onClick={runAiAnalysis} disabled={isAnalyzing}>
                      {isAnalyzing ? 'Analyzing Timeline...' : 'Analyze Threat Timeline'}
                    </button>
                    <button
                      className="btn-primary"
                      onClick={runGlobalAiReport}
                      disabled={isAnalyzingGlobal}
                      style={{ background: 'linear-gradient(90deg, #8b5cf6, #6366f1)', border: 'none' }}
                    >
                      {isAnalyzingGlobal ? 'Generating Executive Report...' : 'Generate Full Network Report'}
                    </button>
                  </div>
                </div>

                <div style={{ padding: '30px' }}>
                  {!globalAiReport && !aiAnalysis && !isAnalyzingGlobal && !isAnalyzing && (
                    <div style={{ textAlign: 'center', padding: '100px 0', opacity: 0.5 }}>
                      <Cpu size={80} style={{ marginBottom: '20px', color: 'var(--accent-blue)' }} />
                      <h3>Ready for Intelligence Orchestration</h3>
                      <p>Select a report type above to start the AI analysis.</p>
                    </div>
                  )}

                  <div style={{ display: 'grid', gridTemplateColumns: (globalAiReport && aiAnalysis) ? '1fr 1fr' : '1fr', gap: '25px' }}>

                    {/* Left/Main Column: Global Report */}
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '25px' }}>
                      {isAnalyzingGlobal && (
                        <div style={{ padding: '60px', textAlign: 'center', background: 'rgba(56, 189, 248, 0.02)', borderRadius: '20px', border: '1px dashed rgba(56, 189, 248, 0.2)' }}>
                          <div className="discovery-pulse" style={{ margin: '0 auto 20px auto', width: '50px', height: '50px' }}></div>
                          <h3 style={{ color: 'var(--accent-cyan)' }}>Generating Global Audit...</h3>
                        </div>
                      )}

                      {globalAiReport && (
                        <div className="report-container ai-report-content animate-fade-in" style={{ borderTop: '4px solid #8b5cf6' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '25px', color: '#a78bfa', borderBottom: '1px solid rgba(255,255,255,0.05)', paddingBottom: '20px', justifyContent: 'space-between' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                              <Activity size={24} /> <strong style={{ fontSize: '18px', letterSpacing: '1px' }}>EXECUTIVE NETWORK AUDIT</strong>
                            </div>
                            <button className="btn-primary" onClick={() => window.print()} style={{ padding: '6px 12px', fontSize: '12px', background: 'rgba(167, 139, 250, 0.1)', border: '1px solid rgba(167, 139, 250, 0.3)' }}>
                              <Printer size={14} style={{ marginRight: '5px' }} /> Print PDF
                            </button>
                          </div>
                          <div style={{ whiteSpace: 'normal' }}>
                            {formatReport(globalAiReport)}
                          </div>
                        </div>
                      )}
                    </div>

                    {/* Right Column: Timeline Analysis */}
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '25px' }}>
                      {isAnalyzing && (
                        <div style={{ padding: '60px', textAlign: 'center', background: 'rgba(0, 118, 255, 0.02)', borderRadius: '20px', border: '1px dashed rgba(0, 118, 255, 0.2)' }}>
                          <div className="discovery-pulse" style={{ margin: '0 auto 20px auto', width: '50px', height: '50px', background: 'var(--accent-blue)' }}></div>
                          <h3 style={{ color: 'var(--accent-blue)' }}>Synthesizing Timeline...</h3>
                        </div>
                      )}

                      {aiAnalysis && (
                        <div className="report-container ai-report-content animate-fade-in" style={{ borderTop: '4px solid var(--accent-blue)' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '25px', color: 'var(--accent-blue)', borderBottom: '1px solid rgba(255,255,255,0.05)', paddingBottom: '20px', justifyContent: 'space-between' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                              <Zap size={24} /> <strong style={{ fontSize: '18px', letterSpacing: '1px' }}>THREAT TIMELINE SYNTHESIS</strong>
                            </div>
                            <button className="btn-primary" onClick={() => window.print()} style={{ padding: '6px 12px', fontSize: '12px', background: 'rgba(0, 118, 255, 0.1)', border: '1px solid rgba(0, 118, 255, 0.3)' }}>
                              <Printer size={14} style={{ marginRight: '5px' }} /> Print
                            </button>
                          </div>
                          <div style={{ whiteSpace: 'normal' }}>
                            {formatReport(aiAnalysis)}
                          </div>
                        </div>
                      )}
                    </div>

                  </div>
                </div>
              </div>
            </div>
          )}

          <div style={{ display: activeTab === "topology" ? "block" : "none" }}>
            <div className="tab-pane animate-fade-in" style={{ padding: '0 10px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '30px', padding: '0 5px' }}>
                <div>
                  <h1 style={{ fontSize: '26px', fontWeight: '900', margin: 0, color: '#f3f4f6', letterSpacing: '-0.03em' }}>NETWORK TOPOLOGY <span style={{ color: '#666', fontSize: '18px', fontWeight: '500' }}>[SENTINEL_SOC]</span></h1>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginTop: '6px' }}>
                    <div style={{ padding: '2px 8px', background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '4px', fontSize: '10px', color: '#aaa', fontWeight: '700' }}>SENTINEL_SOC_MODE</div>
                    <span style={{ color: '#4b5563', fontSize: '12px', fontWeight: '500' }}>Real-time packet flow & endpoint synchronization</span>
                  </div>
                </div>
                <div style={{ textAlign: 'right' }}>
                </div>
              </div>

              <TopologyView
                devices={devices.filter(d => d.is_wazuh_agent)}
                alerts={wazuhAlerts}
                onNodeClick={(node) => {
                  if (node?.data?.ip) {
                    setAlertFilterIP(node.data.ip);
                    setActiveTab('alerts');
                  }
                }}
              />
            </div>
          </div>

          {/* Investigation Modal */}
          {isInvestigating && investigationTarget && (
            <div className="modal-overlay" style={{ position: 'fixed', inset: 0, background: 'rgba(5, 8, 15, 0.85)', backdropFilter: 'blur(15px)', zIndex: 2000, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '20px' }} onClick={() => { setIsInvestigating(false); setAiBehaviorReport(null); }}>
              <div className="section-card" onClick={e => e.stopPropagation()} style={{ maxWidth: '800px', width: '100%', background: 'linear-gradient(145deg, #11141d, #06080c)', border: '1px solid var(--border)', borderRadius: '20px', overflow: 'hidden', animation: 'fadeIn 0.4s cubic-bezier(0.16, 1, 0.3, 1)' }}>

                {/* Header */}
                <div style={{ background: 'linear-gradient(90deg, rgba(255, 77, 77, 0.15) 0%, rgba(11, 14, 20, 0) 100%)', padding: '20px 30px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '15px' }}>
                    <div style={{ width: '40px', height: '40px', borderRadius: '10px', background: 'rgba(255, 77, 77, 0.2)', display: 'flex', alignItems: 'center', justifyContent: 'center', border: '1px solid rgba(255, 77, 77, 0.5)' }}>
                      <ShieldAlert size={24} color="var(--danger)" />
                    </div>
                    <div>
                      <h2 style={{ color: '#fff', fontSize: '20px', margin: 0, fontWeight: 700, letterSpacing: '0.5px' }}>Host Forensics & Diagnostics</h2>
                      <p style={{ color: 'var(--text-muted)', margin: '5px 0 0 0', fontSize: '12px' }}>Real-time deep analysis from Wazuh Syscollector</p>
                    </div>
                  </div>
                  <button className="btn-primary" style={{ padding: '8px 20px', background: 'transparent', border: '1px solid var(--border)', color: 'var(--text-muted)' }} onClick={() => { setIsInvestigating(false); setAiBehaviorReport(null); }}>Esc</button>
                </div>

                {/* Body */}
                <div style={{ padding: '30px', maxHeight: '70vh', overflowY: 'auto' }}>

                  {/* Identification Grid */}
                  <h3 style={{ fontSize: '11px', textTransform: 'uppercase', color: 'var(--accent-blue)', letterSpacing: '1.5px', marginBottom: '15px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <Radar size={14} /> Network Identification
                  </h3>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '15px', marginBottom: '30px' }}>
                    <div style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.05)', padding: '15px', borderRadius: '12px', minWidth: 0 }}>
                      <p style={{ margin: 0, fontSize: '11px', color: 'var(--text-muted)', marginBottom: '5px' }}>IP Address</p>
                      <p style={{ margin: 0, fontSize: '15px', fontWeight: 600, color: '#fff', fontFamily: 'monospace', wordBreak: 'break-all', lineHeight: 1.4 }}>{investigationTarget["Source IP"] || "N/A"}</p>
                    </div>
                    <div style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.05)', padding: '15px', borderRadius: '12px', minWidth: 0 }}>
                      <p style={{ margin: 0, fontSize: '11px', color: 'var(--text-muted)', marginBottom: '5px' }}>MAC Address</p>
                      <p style={{ margin: 0, fontSize: '15px', fontWeight: 600, color: 'var(--accent-cyan)', fontFamily: 'monospace', wordBreak: 'break-all', lineHeight: 1.4 }}>{investigationTarget["MAC Address"] || investigationTarget.mac || "Virtual/Unknown"}</p>
                    </div>
                    <div style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.05)', padding: '15px', borderRadius: '12px' }}>
                      <p style={{ margin: 0, fontSize: '11px', color: 'var(--text-muted)', marginBottom: '5px' }}>Assigned Agent ID</p>
                      <p style={{ margin: 0, fontSize: '16px', fontWeight: 600, color: '#fff' }}>{investigationTarget["Agent ID"] || "000"}</p>
                    </div>
                    <div style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.05)', padding: '15px', borderRadius: '12px' }}>
                      <p style={{ margin: 0, fontSize: '11px', color: 'var(--text-muted)', marginBottom: '5px' }}>Status</p>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '4px' }}>
                        <div className="pulse-dot" style={{ background: 'var(--danger)', boxShadow: '0 0 10px var(--danger)' }}></div>
                        <span style={{ fontSize: '14px', fontWeight: 600, color: 'var(--danger)' }}>High Risk</span>
                      </div>
                    </div>
                  </div>

                  {deepForensics && (
                    <div style={{ animation: 'fadeIn 0.5s ease' }}>
                      <h3 style={{ fontSize: '11px', textTransform: 'uppercase', color: 'var(--accent-blue)', letterSpacing: '1.5px', marginBottom: '15px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <Cpu size={14} /> Hardware & OS Fingerprint
                      </h3>
                      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '15px', marginBottom: '30px' }}>
                        <div style={{ background: '#0a0c12', padding: '15px 20px', borderRadius: '12px', border: '1px solid var(--border)', display: 'flex', alignItems: 'center', gap: '15px' }}>
                          <div style={{ background: 'rgba(0, 118, 255, 0.1)', padding: '10px', borderRadius: '8px', color: 'var(--accent-blue)' }}><Cpu size={20} /></div>
                          <div>
                            <p style={{ margin: 0, fontSize: '11px', color: 'var(--text-muted)' }}>Processor Information</p>
                            <p style={{ margin: '4px 0 0 0', fontSize: '13px', fontWeight: 600 }}>{deepForensics.hardware?.cpu_name || "Scanning Engine..."}</p>
                          </div>
                        </div>

                        <div style={{ background: '#0a0c12', padding: '15px 20px', borderRadius: '12px', border: '1px solid var(--border)', display: 'flex', alignItems: 'center', gap: '15px' }}>
                          <div style={{ background: 'rgba(0, 242, 255, 0.1)', padding: '10px', borderRadius: '8px', color: 'var(--accent-cyan)' }}><Database size={20} /></div>
                          <div>
                            <p style={{ margin: 0, fontSize: '11px', color: 'var(--text-muted)' }}>Memory (RAM)</p>
                            <p style={{ margin: '4px 0 0 0', fontSize: '13px', fontWeight: 600 }}>
                              {deepForensics.hardware?.ram_total ? `${Math.round((deepForensics.hardware.ram_total - deepForensics.hardware.ram_free) / 1024)}MB Used / ${Math.round(deepForensics.hardware.ram_total / 1024)}MB Total` : "Analyzing Memory..."}
                            </p>
                          </div>
                        </div>

                        <div style={{ background: '#0a0c12', padding: '15px 20px', borderRadius: '12px', border: '1px solid var(--border)', display: 'flex', alignItems: 'center', gap: '15px' }}>
                          <div style={{ background: 'rgba(255, 255, 255, 0.05)', padding: '10px', borderRadius: '8px', color: '#fff' }}><Server size={20} /></div>
                          <div>
                            <p style={{ margin: 0, fontSize: '11px', color: 'var(--text-muted)' }}>Operating System</p>
                            <p style={{ margin: '4px 0 0 0', fontSize: '13px', fontWeight: 600 }}>{deepForensics.hardware?.os_name || "Unknown"} {deepForensics.hardware?.os_version || ""}</p>
                          </div>
                        </div>
                      </div>

                      <h3 style={{ fontSize: '11px', textTransform: 'uppercase', color: 'var(--accent-blue)', letterSpacing: '1.5px', marginBottom: '15px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <Plus size={14} /> Installed Packages
                      </h3>
                      <div style={{ padding: '20px', background: '#0a0c12', borderRadius: '12px', border: '1px solid var(--border)', display: 'flex', flexWrap: 'wrap', gap: '8px', marginBottom: '30px' }}>
                        {deepForensics.packages?.map((p, idx) => (
                          <div key={idx} style={{ background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)', padding: '6px 12px', borderRadius: '8px', fontSize: '12px', color: '#fff', display: 'flex', alignItems: 'center', gap: '8px' }}>
                            <span style={{ width: '6px', height: '6px', background: 'var(--success)', borderRadius: '50%' }}></span>
                            <strong>{p.name}</strong> <span style={{ opacity: 0.5 }}>{p.version}</span>
                          </div>
                        )) || <p style={{ fontSize: '13px', color: 'var(--text-muted)' }}>No recent packages detected.</p>}
                      </div>
                      {/* AI Behavioral Intelligence */}
                      <div style={{ marginTop: '30px' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
                          <h3 style={{ fontSize: '11px', textTransform: 'uppercase', color: 'var(--accent-blue)', letterSpacing: '1.5px', margin: 0, display: 'flex', alignItems: 'center', gap: '8px' }}>
                            <Cpu size={14} /> AI Behavioral Intelligence
                          </h3>
                          <div style={{ display: 'flex', gap: '15px' }}>
                            <button
                              className="btn-primary"
                              onClick={() => {
                                const id = investigationTarget["Agent ID"] || investigationTarget.agent_id || "001";
                                runAiBehavioralAnalysis(id);
                              }}
                              disabled={isAnalyzingBehavior}
                              style={{
                                padding: '8px 20px',
                                fontSize: '11px',
                                background: isAnalyzingBehavior ? 'rgba(255,255,255,0.05)' : 'linear-gradient(90deg, #0076ff, #00c6ff)',
                                border: 'none',
                                boxShadow: isAnalyzingBehavior ? 'none' : '0 4px 15px rgba(0, 118, 255, 0.3)'
                              }}
                            >
                              {isAnalyzingBehavior ? 'Deep Analysis...' : 'Run AI Behavioral Audit'}
                            </button>
                            {isAnalyzingBehavior && (
                              <button
                                className="btn-primary"
                                onClick={stopAiAnalysis}
                                style={{ padding: '8px 20px', fontSize: '11px', background: 'rgba(255, 77, 77, 0.1)', border: '1px solid rgba(255, 77, 77, 0.3)', color: 'var(--danger)' }}
                              >
                                Stop
                              </button>
                            )}
                          </div>
                        </div>

                        {isAnalyzingBehavior && (
                          <div style={{ padding: '40px', background: 'rgba(0, 118, 255, 0.05)', borderRadius: '16px', border: '1px dashed var(--accent-blue)', textAlign: 'center' }}>
                            <div className="discovery-pulse" style={{ margin: '0 auto 20px auto', width: '40px', height: '40px', background: 'var(--accent-blue)' }}></div>
                            <h4 style={{ color: 'var(--accent-blue)', marginBottom: '5px' }}>AI Forensic Investigation in Progress...</h4>
                            <p style={{ color: 'var(--text-muted)', fontSize: '12px' }}>Analyzing system logs for behavioral anomalies (qwen2.5:1.5B)</p>
                          </div>
                        )}

                        {aiBehaviorReport && (
                          <div className="report-container ai-report-content" style={{ animation: 'fadeIn 0.5s ease' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '20px', color: 'var(--accent-cyan)', borderBottom: '1px solid rgba(255,255,255,0.05)', paddingBottom: '15px', justifyContent: 'space-between' }}>
                              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                                <ShieldCheck size={22} /> <strong style={{ fontSize: '16px', letterSpacing: '1px' }}>AI BEHAVIORAL INTELLIGENCE REPORT</strong>
                              </div>
                              <button className="btn-primary" onClick={() => window.print()} style={{ padding: '4px 10px', fontSize: '11px', background: 'rgba(0, 242, 255, 0.1)', border: '1px solid rgba(0, 242, 255, 0.3)' }}>
                                <Printer size={12} style={{ marginRight: '4px' }} /> Print Report
                              </button>
                            </div>
                            <div style={{ whiteSpace: 'normal' }}>
                              {formatReport(aiBehaviorReport)}
                            </div>
                          </div>
                        )}
                      </div>

                      {/* Threat Summary Box */}
                      <div style={{ marginTop: '30px', background: 'linear-gradient(145deg, rgba(255, 77, 77, 0.1), rgba(30, 0, 0, 0.5))', padding: '25px', borderRadius: '16px', border: '1px solid rgba(255, 77, 77, 0.3)', position: 'relative', overflow: 'hidden' }}>
                        <div style={{ position: 'absolute', top: '-20px', right: '-20px', opacity: 0.05, transform: 'rotate(-15deg)' }}>
                          <ShieldAlert size={150} />
                        </div>
                        <h4 style={{ color: 'var(--danger)', margin: '0 0 10px 0', fontSize: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}><AlertTriangle size={18} /> SOC Action Required</h4>
                        <p style={{ margin: 0, lineHeight: '1.6', fontSize: '14px', color: '#e2e8f0', position: 'relative', zIndex: 2 }}>
                          This asset triggered a level <strong style={{ color: 'var(--danger)' }}>{investigationTarget.Severity || 12}</strong> alert: <span style={{ background: 'rgba(255, 77, 77, 0.2)', padding: '2px 6px', borderRadius: '4px' }}>{investigationTarget.Description || "Suspicious Activity"}</span>.
                          <br /><br />
                          <strong>Recommended Policy:</strong> Isolate the node via SDN controller and run a full forensic scan using Wazuh active response scripts. Check the AI Copilot tab for automated remediation.
                        </p>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}
        </>
      </main>
    </div>
  );
}