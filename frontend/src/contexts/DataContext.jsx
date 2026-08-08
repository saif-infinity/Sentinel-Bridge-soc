import { createContext, useContext, useState, useCallback, useEffect, useRef } from "react";
import { useAuth } from "./AuthContext";

const DataContext = createContext(null);

export function DataProvider({ children }) {
  const { fetchWithAuth, jwtToken } = useAuth();

  const [wazuhAlerts, setWazuhAlerts] = useState([]);
  const [suricataAlerts, setSuricataAlerts] = useState([]);
  const [devices, setDevices] = useState([]);
  const [inventory, setInventory] = useState([]);
  const [onlineHistory, setOnlineHistory] = useState([]);
  const [throughputHistory, setThroughputHistory] = useState([]);
  const [suricataHistory, setSuricataHistory] = useState([]);
  const [pendingTasks, setPendingTasks] = useState([]);

  const [rules, setRules] = useState([]);
  const [pipelineStats, setPipelineStats] = useState(null);
  const [ruleMatches, setRuleMatches] = useState([]);

  const [cases, setCases] = useState([]);
  const [caseStats, setCaseStats] = useState(null);
  const [hunts, setHunts] = useState([]);

  const prevOnlineCount = useRef(0);

  const trackTask = useCallback((taskId, type, target) => {
    setPendingTasks((prev) => [
      ...prev,
      { id: taskId, type, target, status: "PENDING", startTime: new Date() },
    ]);
  }, []);

  const updateTaskStatus = useCallback((taskId, status, result = null) => {
    setPendingTasks((prev) =>
      prev.map((t) => (t.id === taskId ? { ...t, status, result } : t)),
    );
  }, []);

  const fetchRules = useCallback(async () => {
    try {
      const res = await fetchWithAuth("/api/rules");
      if (res.ok) setRules(await res.json());
    } catch (e) {}
  }, [fetchWithAuth]);

  const fetchPipelineStats = useCallback(async () => {
    try {
      const res = await fetchWithAuth("/api/pipeline/stats");
      if (res.ok) setPipelineStats(await res.json());
    } catch (e) {}
  }, [fetchWithAuth]);

  const fetchRuleMatches = useCallback(async () => {
    try {
      const res = await fetchWithAuth("/api/rules/matches?limit=20");
      if (res.ok) setRuleMatches(await res.json());
    } catch (e) {}
  }, [fetchWithAuth]);

  const refreshRules = useCallback(() => { fetchRules(); }, [fetchRules]);
  const refreshPipelineStats = useCallback(() => { fetchPipelineStats(); }, [fetchPipelineStats]);
  const refreshRuleMatches = useCallback(() => { fetchRuleMatches(); }, [fetchRuleMatches]);

  const fetchCases = useCallback(async () => {
    try {
      const res = await fetchWithAuth("/api/cases?limit=100");
      if (res.ok) {
        const data = await res.json();
        setCases(data.items || []);
      }
    } catch (e) {}
  }, [fetchWithAuth]);

  const fetchCaseStats = useCallback(async () => {
    try {
      const res = await fetchWithAuth("/api/cases/stats");
      if (res.ok) setCaseStats(await res.json());
    } catch (e) {}
  }, [fetchWithAuth]);

  const fetchHunts = useCallback(async () => {
    try {
      const res = await fetchWithAuth("/api/hunts");
      if (res.ok) setHunts(await res.json());
    } catch (e) {}
  }, [fetchWithAuth]);

  const refreshCases = useCallback(() => { fetchCases(); }, [fetchCases]);
  const refreshCaseStats = useCallback(() => { fetchCaseStats(); }, [fetchCaseStats]);
  const refreshHunts = useCallback(() => { fetchHunts(); }, [fetchHunts]);

  useEffect(() => {
    if (!jwtToken) return;

    const fetchCritical = async () => {
      try {
        const [devRes, alertRes] = await Promise.all([
          fetchWithAuth("/devices"),
          fetchWithAuth("/api/real-alerts?limit=200"),
        ]);
        if (devRes.ok) {
          const devData = await devRes.json();
          setDevices(devData);
        }
        if (alertRes.ok) {
          const alertData = await alertRes.json();
          setWazuhAlerts((prev) => {
            const combined = [...alertData, ...prev];
            const seen = new Set();
            return combined
              .filter((a) => {
                const key = (a.Timestamp || a.timestamp) + (a.Description || a.description);
                if (seen.has(key)) return false;
                seen.add(key);
                return true;
              })
              .slice(0, 200);
          });
          const onlineCount = devData?.filter((d) => d.is_online).length || 0;
          setOnlineHistory((prev) => {
            const next = [...prev, { time: new Date().toLocaleTimeString(), count: onlineCount }];
            return next.slice(-20);
          });
          prevOnlineCount.current = onlineCount;
        }
      } catch (e) {
        // polling error
      }
    };

    const fetchSuricata = async () => {
      try {
        const res = await fetchWithAuth("/api/suricata/alerts");
        if (res.ok) {
          const data = await res.json();
          setSuricataAlerts(data);
          const packets = data.filter((a) => a.event_type === "stats").length;
          const drops = data.filter((a) => a.event_type === "alert").length;
          setSuricataHistory((prev) => {
            const next = [
              ...prev,
              { time: new Date().toLocaleTimeString(), packets, drops },
            ];
            return next.slice(-20);
          });
        }
      } catch (e) {
        // polling error
      }
    };

    const fetchBandwidth = async () => {
      try {
        const res = await fetchWithAuth("/api/stats/bandwidth");
        if (res.ok) {
          const data = await res.json();
          setThroughputHistory((prev) => {
            const next = [
              ...prev,
              { time: new Date().toLocaleTimeString(), mbps: data.mbps || 0 },
            ];
            return next.slice(-20);
          });
          // Report bandwidth to sensor endpoint
          const username = localStorage.getItem("auth_username") || "unknown";
          fetch("/api/sensors/record", {
            method: "POST",
            headers: { Authorization: `Bearer ${jwtToken}`, "Content-Type": "application/json" },
            body: JSON.stringify({
              username,
              bandwidth_mbps: data.mbps || 0,
              bytes_sent: 0,
              bytes_recv: 0,
              interface: navigator.connection?.effectiveType || "unknown",
            }),
          }).catch(() => {});
        }
      } catch (e) {
        // polling error
      }
    };

    const fetchInventory = async () => {
      try {
        const res = await fetchWithAuth("/devices/inventory");
        if (res.ok) {
          const data = await res.json();
          setInventory(data);
        }
      } catch (e) {
        // polling error
      }
    };

    fetchCritical();
    fetchSuricata();
    fetchBandwidth();
    fetchInventory();
    fetchRules();
    fetchPipelineStats();
    fetchRuleMatches();
    fetchCases();
    fetchCaseStats();
    fetchHunts();

    const criticalInterval = setInterval(fetchCritical, 15000);
    const suricataInterval = setInterval(fetchSuricata, 30000);
    const bandwidthInterval = setInterval(fetchBandwidth, 10000);
    const inventoryInterval = setInterval(fetchInventory, 120000);
    const rulesInterval = setInterval(fetchRules, 60000);
    const pipelineStatsInterval = setInterval(fetchPipelineStats, 15000);
    const ruleMatchesInterval = setInterval(fetchRuleMatches, 30000);

    const casesInterval = setInterval(fetchCases, 30000);
    const caseStatsInterval = setInterval(fetchCaseStats, 30000);
    const huntsInterval = setInterval(fetchHunts, 60000);

    return () => {
      clearInterval(criticalInterval);
      clearInterval(suricataInterval);
      clearInterval(bandwidthInterval);
      clearInterval(inventoryInterval);
      clearInterval(rulesInterval);
      clearInterval(pipelineStatsInterval);
      clearInterval(ruleMatchesInterval);
      clearInterval(casesInterval);
      clearInterval(caseStatsInterval);
      clearInterval(huntsInterval);
    };
  }, [jwtToken, fetchWithAuth]);

  // WebSocket
  useEffect(() => {
    if (!jwtToken) return;

    const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${proto}//${window.location.host}/ws/status?token=${encodeURIComponent(jwtToken)}`;
    const ws = new WebSocket(wsUrl);

    ws.onmessage = (event) => {
      try {
        const payload = JSON.parse(event.data);
        if (payload.type === "alerts_update") {
          setWazuhAlerts((prev) => {
            const combined = [...payload.data, ...prev];
            const seen = new Map();
            combined.forEach((a) => {
              const key = (a.Timestamp || a.timestamp) + (a.Description || a.description);
              if (!seen.has(key)) seen.set(key, a);
            });
            return Array.from(seen.values()).slice(0, 200);
          });
        }
      } catch (e) {
        // ws parse error
      }
    };

    ws.onerror = () => {};
    ws.onclose = () => {};

    return () => ws.close();
  }, [jwtToken]);

  const value = {
    wazuhAlerts,
    suricataAlerts,
    devices,
    inventory,
    onlineHistory,
    throughputHistory,
    suricataHistory,
    pendingTasks,
    trackTask,
    updateTaskStatus,
    rules,
    pipelineStats,
    ruleMatches,
    refreshRules,
    refreshPipelineStats,
    refreshRuleMatches,
    cases,
    caseStats,
    hunts,
    refreshCases,
    refreshCaseStats,
    refreshHunts,
  };

  return <DataContext.Provider value={value}>{children}</DataContext.Provider>;
}

export function useData() {
  const ctx = useContext(DataContext);
  if (!ctx) throw new Error("useData must be used within DataProvider");
  return ctx;
}
