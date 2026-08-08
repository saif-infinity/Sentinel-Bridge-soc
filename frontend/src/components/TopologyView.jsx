import { useEffect, useState, useCallback, useRef } from "react";
import { 
  Shield, 
  Server, 
  Monitor, 
  Cpu, 
  Activity, 
  AlertCircle, 
  Network,
  Lock,
  Globe,
  Database,
  Router
} from 'lucide-react';

/* ─── Helpers ─────────────────────────────────────────────────── */
// GNS3 Style Icons
const GNS3Icons = {
  MANAGER: "🌐", // Core Router/Manager
  WINDOWS: "🖥️", // Windows PC
  LINUX: "🐧",   // Linux Server
  UNKNOWN: "💻"  // Generic Device
};

function getOsIcon(os = "") {
  const o = os.toLowerCase();
  if (o.includes("windows")) return GNS3Icons.WINDOWS;
  if (o.includes("ubuntu") || o.includes("debian") || o.includes("linux")) return GNS3Icons.LINUX;
  return GNS3Icons.UNKNOWN;
}

/* ─── Legend Component ────────────────────────────────────────── */
function TopologyLegend() {
  return (
    <div style={{
      position: "absolute", bottom: "20px", left: "20px",
      background: "rgba(0, 0, 0, 0.8)",
      border: "1px solid #333",
      borderRadius: "4px", padding: "10px",
      display: "flex", flexDirection: "column", gap: "6px",
      zIndex: 10, boxShadow: "0 4px 15px rgba(0,0,0,0.5)",
      fontSize: "11px", color: "#eee"
    }}>
      <div style={{ fontWeight: "bold", borderBottom: "1px solid #222", marginBottom: "4px", paddingBottom: "2px", color: "#6366f1" }}>System Map Key</div>
      <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
        <span>{GNS3Icons.MANAGER}</span> <span>Security Gateway</span>
      </div>
      <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
        <span>{GNS3Icons.WINDOWS}</span> <span>Endpoint Agent</span>
      </div>
      <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
        <div style={{ width: "15px", height: "2px", background: "#3b82f6" }}></div> <span>Secure Link</span>
      </div>
      <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
        <div style={{ width: "15px", height: "2px", background: "#ef4444" }}></div> <span>Attack Detected</span>
      </div>
    </div>
  );
}

/* ─── Node Component (GNS3 Style) ────────────────────────────── */
function GNS3Node({ node, hasAlert, onClick, nodeRef, isManager = false }) {
  const d = node.data || {};
  
  return (
    <div
      ref={nodeRef}
      onClick={() => onClick && onClick(node)}
      style={{
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        cursor: "pointer",
        width: "100px",
        position: "relative",
        transition: "all 0.2s ease",
      }}
      onMouseEnter={(e) => {
        e.currentTarget.style.transform = "scale(1.1)";
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.transform = "scale(1)";
      }}
    >
      {/* Alert Glow */}
      {hasAlert && (
        <div style={{
          position: "absolute", inset: "-15px",
          background: "rgba(239, 68, 68, 0.2)",
          borderRadius: "50%", zIndex: -1,
          animation: "gns3-pulse 1.5s infinite"
        }} />
      )}

      {/* Icon */}
      <div style={{
        fontSize: isManager ? "48px" : "40px",
        filter: hasAlert ? "drop-shadow(0 0 8px #ef4444)" : "drop-shadow(0 0 2px rgba(255,255,255,0.1))",
        marginBottom: "5px"
      }}>
        {isManager ? GNS3Icons.MANAGER : getOsIcon(d.os)}
      </div>

      {/* Label */}
      <div style={{
        background: hasAlert ? "#ef4444" : "rgba(255,255,255,0.05)",
        color: hasAlert ? "#fff" : "#eee",
        padding: "2px 8px",
        borderRadius: "3px",
        fontSize: "11px",
        fontWeight: "bold",
        textAlign: "center",
        border: hasAlert ? "1px solid #b91c1c" : "1px solid #333",
        boxShadow: "0 2px 4px rgba(0,0,0,0.3)",
        maxWidth: "120px",
        whiteSpace: "nowrap",
        overflow: "hidden",
        textOverflow: "ellipsis"
      }}>
        {d.label}
      </div>
      <div style={{ fontSize: "9px", color: "#888", marginTop: "2px", fontWeight: "bold", fontFamily: "monospace" }}>
        {d.ip}
      </div>
    </div>
  );
}

/* ─── SVG Lines ───────────────────────────────────────────────── */
function ConnectionLines({ agentRefs, managerRef, containerRef, nodeHasAlert }) {
  const [lines, setLines] = useState([]);

  const compute = useCallback(() => {
    if (!managerRef.current || !containerRef.current) return;
    const container = containerRef.current.getBoundingClientRect();
    const mgr = managerRef.current.getBoundingClientRect();

    const mgrX = mgr.left - container.left + mgr.width / 2;
    const mgrY = mgr.top - container.top + mgr.height / 2;

    const newLines = [];
    for (const [id, ref] of Object.entries(agentRefs.current)) {
      if (!ref) continue;
      const r = ref.getBoundingClientRect();
      const ax = r.left - container.left + r.width / 2;
      const ay = r.top - container.top + r.height / 2;

      newLines.push({ id, ax, ay, bx: mgrX, by: mgrY, hasAlert: !!nodeHasAlert[id] });
    }
    setLines(newLines);
  }, [agentRefs, managerRef, containerRef, nodeHasAlert]);

  useEffect(() => {
    compute();
    const obs = new ResizeObserver(compute);
    if (containerRef.current) obs.observe(containerRef.current);
    return () => obs.disconnect();
  }, [compute]);

  return (
    <svg style={{ position: "absolute", inset: 0, width: "100%", height: "100%", pointerEvents: "none", overflow: "visible" }}>
      {lines.map(({ id, ax, ay, bx, by, hasAlert }) => (
        <line
          key={id}
          x1={ax} y1={ay} x2={bx} y2={by}
          stroke={hasAlert ? "#ef4444" : "#3b82f6"}
          strokeWidth={hasAlert ? "2.5" : "1.2"}
          strokeOpacity={hasAlert ? "0.8" : "0.5"}
          strokeDasharray={hasAlert ? "none" : "none"}
        />
      ))}
    </svg>
  );
}

/* ─── Main TopologyView ───────────────────────────────────────── */
export default function TopologyView({ devices = [], alerts = [], jwtToken = null, headers = null, onNodeClick }) {
  const [topology, setTopology] = useState(null);
  const [loading, setLoading] = useState(true);
  
  const managerRef = useRef(null);
  const containerRef = useRef(null);
  const agentRefs = useRef({});

  const threatIps = new Set(
    alerts.filter(a => parseInt(a.Severity || 0) >= 7).map(a => a["Source IP"] || a.src_ip)
  );

  const fetchWithAuth = async (url, options = {}) => {
    const doFetch = (h) => fetch(url, { ...options, headers: h });
    
    const baseHeaders = options.headers || { ...headers };
    if (!baseHeaders.Authorization && jwtToken) baseHeaders.Authorization = `Bearer ${jwtToken}`;

    let res = await doFetch(baseHeaders);
    if ((res.status === 401 || res.status === 403) && jwtToken) {
      localStorage.removeItem("auth_token");
      localStorage.removeItem("auth_username");
      window.location.reload();
    }
    return res;
  };

  const fetchTopology = useCallback(async (isManual = false) => {
    try {
      setLoading(true);
      if (isManual) await fetchWithAuth("/api/wazuh/refresh-cache", { method: "POST" });
      const res = await fetchWithAuth("/api/wazuh/topology");
      if (res.ok) setTopology(await res.json());
    } catch (e) { console.error(e); } finally { setLoading(false); }
  }, [headers, jwtToken]);

  useEffect(() => {
    fetchTopology();
    const t = setInterval(fetchTopology, 5000); // 5s refresh
    return () => clearInterval(t);
  }, [fetchTopology]);

  if (loading && !topology) return <div style={{ textAlign: "center", padding: "100px", color: "#666" }}>Synchronizing Infrastructure Map...</div>;

  const agentNodes = topology?.nodes?.filter(n => n.data?.type === "agent") || [];
  const managerNode = topology?.nodes?.find(n => n.data?.type === "manager");
  
  const nodeHasAlert = {};
  agentNodes.forEach(n => nodeHasAlert[n.id] = threatIps.has(n.data?.ip));

  return (
    <div style={{ 
      background: "#050505", // True black
      borderRadius: "8px", 
      border: "1px solid #222", 
      overflow: "hidden", position: "relative",
      boxShadow: "inset 0 0 100px rgba(0,0,0,0.8)"
    }}>
      <style>{`
        @keyframes gns3-pulse { 0% { opacity: 0.1; } 50% { opacity: 0.4; } 100% { opacity: 0.1; } }
      `}</style>
      
      {/* Title Bar */}
      <div style={{ padding: "8px 15px", background: "#111", borderBottom: "1px solid #222", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
          <Network size={14} color="#6366f1" />
          <span style={{ fontSize: "11px", fontWeight: "bold", color: "#eee", textTransform: "uppercase", letterSpacing: "1px" }}>Infrastructure Topology Map - Sentinel SOC</span>
        </div>
        <div style={{ fontSize: "10px", color: "#666", fontWeight: "bold" }}>
          Status: Synchronized
        </div>
      </div>

      <div ref={containerRef} style={{ position: "relative", padding: "100px 40px", minHeight: "600px", display: "flex", justifyContent: "center", alignItems: "center" }}>
        
        {/* Connection Lines Layer */}
        {managerNode && (
          <ConnectionLines 
            agentRefs={agentRefs} 
            managerRef={managerRef} 
            containerRef={containerRef} 
            nodeHasAlert={nodeHasAlert} 
          />
        )}

        {/* Radial Layout for GNS3 feel */}
        <div style={{ position: "relative", width: "100%", height: "400px" }}>
          
          {/* Manager in the center */}
          {managerNode && (
            <div style={{ position: "absolute", top: "50%", left: "50%", transform: "translate(-50%, -50%)", zIndex: 1 }}>
              <GNS3Node 
                node={managerNode} 
                isManager={true} 
                nodeRef={managerRef} 
              />
            </div>
          )}

          {/* Agents positioned around the manager */}
          {agentNodes.map((node, index) => {
            const angle = (index / agentNodes.length) * 2 * Math.PI;
            const radius = 220; // Distance from center
            const x = Math.cos(angle) * radius;
            const y = Math.sin(angle) * radius;

            return (
              <div 
                key={node.id} 
                style={{ 
                  position: "absolute", 
                  top: `calc(50% + ${y}px)`, 
                  left: `calc(50% + ${x}px)`, 
                  transform: "translate(-50%, -50%)",
                  zIndex: 2
                }}
              >
                <GNS3Node 
                  node={node} 
                  hasAlert={nodeHasAlert[node.id]} 
                  onClick={onNodeClick}
                  nodeRef={el => agentRefs.current[node.id] = el}
                />
              </div>
            );
          })}
        </div>

        {/* Legend */}
        <TopologyLegend />
      </div>
    </div>
  );
}
