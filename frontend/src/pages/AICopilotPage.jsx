import { useState, useRef, useEffect } from "react";
import { Cpu, Zap, Printer } from "lucide-react";
import { useAuth } from "../contexts/AuthContext";
import { useData } from "../contexts/DataContext";
import { formatReport } from "../lib/formatters";

export default function AICopilotPage() {
  const { fetchWithAuth, headers } = useAuth();
  const { trackTask } = useData();
  const [aiAnalysis, setAiAnalysis] = useState("");
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [globalAiReport, setGlobalAiReport] = useState("");
  const [isAnalyzingGlobal, setIsAnalyzingGlobal] = useState(false);

  const pollRef = useRef(null);
  const mountedRef = useRef(true);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, []);

  const pollTaskStatus = (taskId, setStatus, setResult) => {
    if (pollRef.current) clearInterval(pollRef.current);
    pollRef.current = setInterval(async () => {
      try {
        const res = await fetchWithAuth(`/api/tasks/status/${taskId}`, { headers });
        if (res.ok) {
          const data = await res.json();
          if (data.status === "SUCCESS") {
            clearInterval(pollRef.current);
            pollRef.current = null;
            if (mountedRef.current) {
              setResult(data.result.analysis || data.result);
              setStatus(false);
            }
          } else if (data.status === "FAILURE") {
            clearInterval(pollRef.current);
            pollRef.current = null;
            if (mountedRef.current) setStatus(false);
          }
        }
      } catch {
        clearInterval(pollRef.current);
        pollRef.current = null;
        if (mountedRef.current) setStatus(false);
      }
    }, 2000);
  };

  const runAiAnalysis = async () => {
    setIsAnalyzing(true);
    setAiAnalysis("Initialisation...");
    try {
      const r = await fetchWithAuth("/api/tasks/analyze-threat", {
        method: "POST",
        headers: { ...headers, "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });
      if (r.ok) {
        const { task_id } = await r.json();
        trackTask(task_id, "AI Analysis", "Timeline Synthesis");
        pollTaskStatus(task_id, setIsAnalyzing, setAiAnalysis);
      } else {
        setIsAnalyzing(false);
      }
    } catch {
      setIsAnalyzing(false);
    }
  };

  const runGlobalAiReport = async () => {
    setIsAnalyzingGlobal(true);
    setGlobalAiReport("");
    try {
      const r = await fetchWithAuth("/api/tasks/analyze-network-global", {
        method: "POST",
        headers: { ...headers, "Content-Type": "application/json" },
      });
      if (r.ok) {
        const { task_id } = await r.json();
        trackTask(task_id, "AI Analysis", "Global Network Audit");
        pollTaskStatus(task_id, setIsAnalyzingGlobal, setGlobalAiReport);
      } else {
        setIsAnalyzingGlobal(false);
      }
    } catch {
      setIsAnalyzingGlobal(false);
    }
  };

  return (
    <div className="tab-pane">
      <div className="section-card ai-view" style={{ minHeight: "600px" }}>
        <div className="section-header" style={{ padding: "25px", background: "linear-gradient(90deg, rgba(56, 189, 248, 0.05) 0%, transparent 100%)" }}>
          <div>
            <h2 style={{ display: "flex", alignItems: "center", gap: "12px", fontSize: "24px" }}>
              <Cpu size={28} color="var(--accent-cyan)" /> AI Intelligence Center
            </h2>
            <p style={{ color: "var(--text-muted)", margin: "5px 0 0 0" }}>Orchestrating network-wide security insights using qwen2.5</p>
          </div>
          <div style={{ display: "flex", gap: "15px" }}>
            <button className="btn-primary" onClick={runAiAnalysis} disabled={isAnalyzing}>
              {isAnalyzing ? "Analyzing Timeline..." : "Analyze Threat Timeline"}
            </button>
            <button className="btn-primary" onClick={runGlobalAiReport} disabled={isAnalyzingGlobal}
              style={{ background: "linear-gradient(90deg, #8b5cf6, #6366f1)", border: "none" }}>
              {isAnalyzingGlobal ? "Generating Executive Report..." : "Generate Full Network Report"}
            </button>
          </div>
        </div>

        <div style={{ padding: "30px" }}>
          {!globalAiReport && !aiAnalysis && !isAnalyzingGlobal && !isAnalyzing && (
            <div style={{ textAlign: "center", padding: "100px 0", opacity: 0.5 }}>
              <Cpu size={80} style={{ marginBottom: "20px", color: "var(--accent-blue)" }} />
              <h3>Ready for Intelligence Orchestration</h3>
              <p>Select a report type above to start the AI analysis.</p>
            </div>
          )}

          <div style={{ display: "grid", gridTemplateColumns: globalAiReport && aiAnalysis ? "1fr 1fr" : "1fr", gap: "25px" }}>
            {/* Global Report */}
            <div style={{ display: "flex", flexDirection: "column", gap: "25px" }}>
              {isAnalyzingGlobal && (
                <div style={{ padding: "60px", textAlign: "center", background: "rgba(56, 189, 248, 0.02)", borderRadius: "20px", border: "1px dashed rgba(56, 189, 248, 0.2)" }}>
                  <div className="discovery-pulse" style={{ margin: "0 auto 20px auto", width: "50px", height: "50px" }}></div>
                  <h3 style={{ color: "var(--accent-cyan)" }}>Generating Global Audit...</h3>
                </div>
              )}
              {globalAiReport && (
                <div className="report-container ai-report-content animate-fade-in" style={{ borderTop: "4px solid #8b5cf6" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "12px", marginBottom: "25px", color: "#a78bfa", borderBottom: "1px solid rgba(255,255,255,0.05)", paddingBottom: "20px", justifyContent: "space-between" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                      <Zap size={24} /> <strong style={{ fontSize: "18px", letterSpacing: "1px" }}>EXECUTIVE NETWORK AUDIT</strong>
                    </div>
                    <button className="btn-primary" onClick={() => window.print()} style={{ padding: "6px 12px", fontSize: "12px", background: "rgba(167, 139, 250, 0.1)", border: "1px solid rgba(167, 139, 250, 0.3)" }}>
                      <Printer size={14} style={{ marginRight: "5px" }} /> Print PDF
                    </button>
                  </div>
                  <div style={{ whiteSpace: "normal" }}>{formatReport(globalAiReport)}</div>
                </div>
              )}
            </div>

            {/* Timeline Analysis */}
            <div style={{ display: "flex", flexDirection: "column", gap: "25px" }}>
              {isAnalyzing && (
                <div style={{ padding: "60px", textAlign: "center", background: "rgba(0, 118, 255, 0.02)", borderRadius: "20px", border: "1px dashed rgba(0, 118, 255, 0.2)" }}>
                  <div className="discovery-pulse" style={{ margin: "0 auto 20px auto", width: "50px", height: "50px", background: "var(--accent-blue)" }}></div>
                  <h3 style={{ color: "var(--accent-blue)" }}>Synthesizing Timeline...</h3>
                </div>
              )}
              {aiAnalysis && (
                <div className="report-container ai-report-content animate-fade-in" style={{ borderTop: "4px solid var(--accent-blue)" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "12px", marginBottom: "25px", color: "var(--accent-blue)", borderBottom: "1px solid rgba(255,255,255,0.05)", paddingBottom: "20px", justifyContent: "space-between" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                      <Zap size={24} /> <strong style={{ fontSize: "18px", letterSpacing: "1px" }}>THREAT TIMELINE SYNTHESIS</strong>
                    </div>
                    <button className="btn-primary" onClick={() => window.print()} style={{ padding: "6px 12px", fontSize: "12px", background: "rgba(0, 118, 255, 0.1)", border: "1px solid rgba(0, 118, 255, 0.3)" }}>
                      <Printer size={14} style={{ marginRight: "5px" }} /> Print
                    </button>
                  </div>
                  <div style={{ whiteSpace: "normal" }}>{formatReport(aiAnalysis)}</div>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
