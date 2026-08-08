import { ShieldAlert, ShieldCheck, Cpu, Plus, Radar, Database, Server, Printer, AlertTriangle } from "lucide-react";
import { formatReport } from "../lib/formatters";

export default function InvestigationModal({ target, deepForensics, aiBehaviorReport, isAnalyzingBehavior, onClose, onRunAI }) {
  return (
    <div
      className="modal-overlay"
      style={{
        position: "fixed", inset: 0, background: "rgba(5, 8, 15, 0.85)", backdropFilter: "blur(15px)",
        zIndex: 2000, display: "flex", alignItems: "center", justifyContent: "center", padding: "20px",
      }}
      onClick={onClose}
    >
      <div className="section-card" onClick={(e) => e.stopPropagation()} style={{
        maxWidth: "800px", width: "100%", background: "linear-gradient(145deg, #11141d, #06080c)",
        border: "1px solid var(--border)", borderRadius: "20px", overflow: "hidden",
        animation: "fadeIn 0.4s cubic-bezier(0.16, 1, 0.3, 1)",
      }}>
        {/* Header */}
        <div style={{ background: "linear-gradient(90deg, rgba(255, 77, 77, 0.15) 0%, rgba(11, 14, 20, 0) 100%)", padding: "20px 30px", borderBottom: "1px solid var(--border)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "15px" }}>
            <div style={{ width: "40px", height: "40px", borderRadius: "10px", background: "rgba(255, 77, 77, 0.2)", display: "flex", alignItems: "center", justifyContent: "center", border: "1px solid rgba(255, 77, 77, 0.5)" }}>
              <ShieldAlert size={24} color="var(--danger)" />
            </div>
            <div>
              <h2 style={{ color: "#fff", fontSize: "20px", margin: 0, fontWeight: 700, letterSpacing: "0.5px" }}>Host Forensics & Diagnostics</h2>
              <p style={{ color: "var(--text-muted)", margin: "5px 0 0 0", fontSize: "12px" }}>Real-time deep analysis from Wazuh Syscollector</p>
            </div>
          </div>
          <button className="btn-primary" style={{ padding: "8px 20px", background: "transparent", border: "1px solid var(--border)", color: "var(--text-muted)" }} onClick={onClose}>Esc</button>
        </div>

        {/* Body */}
        <div style={{ padding: "30px", maxHeight: "70vh", overflowY: "auto" }}>
          {/* Identification Grid */}
          <h3 style={{ fontSize: "11px", textTransform: "uppercase", color: "var(--accent-blue)", letterSpacing: "1.5px", marginBottom: "15px", display: "flex", alignItems: "center", gap: "8px" }}>
            <Radar size={14} /> Network Identification
          </h3>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: "15px", marginBottom: "30px" }}>
            <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.05)", padding: "15px", borderRadius: "12px" }}>
              <p style={{ margin: 0, fontSize: "11px", color: "var(--text-muted)", marginBottom: "5px" }}>IP Address</p>
              <p style={{ margin: 0, fontSize: "15px", fontWeight: 600, color: "#fff", fontFamily: "monospace" }}>{target["Source IP"] || "N/A"}</p>
            </div>
            <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.05)", padding: "15px", borderRadius: "12px" }}>
              <p style={{ margin: 0, fontSize: "11px", color: "var(--text-muted)", marginBottom: "5px" }}>MAC Address</p>
              <p style={{ margin: 0, fontSize: "15px", fontWeight: 600, color: "var(--accent-cyan)", fontFamily: "monospace" }}>{target["MAC Address"] || target.mac || "Virtual/Unknown"}</p>
            </div>
            <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.05)", padding: "15px", borderRadius: "12px" }}>
              <p style={{ margin: 0, fontSize: "11px", color: "var(--text-muted)", marginBottom: "5px" }}>Assigned Agent ID</p>
              <p style={{ margin: 0, fontSize: "16px", fontWeight: 600, color: "#fff" }}>{target["Agent ID"] || "000"}</p>
            </div>
            <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.05)", padding: "15px", borderRadius: "12px" }}>
              <p style={{ margin: 0, fontSize: "11px", color: "var(--text-muted)", marginBottom: "5px" }}>Status</p>
              <div style={{ display: "flex", alignItems: "center", gap: "8px", marginTop: "4px" }}>
                <div className="pulse-dot" style={{ background: "var(--danger)", boxShadow: "0 0 10px var(--danger)" }}></div>
                <span style={{ fontSize: "14px", fontWeight: 600, color: "var(--danger)" }}>High Risk</span>
              </div>
            </div>
          </div>

          {deepForensics && (
            <div style={{ animation: "fadeIn 0.5s ease" }}>
              <h3 style={{ fontSize: "11px", textTransform: "uppercase", color: "var(--accent-blue)", letterSpacing: "1.5px", marginBottom: "15px", display: "flex", alignItems: "center", gap: "8px" }}>
                <Cpu size={14} /> Hardware & OS Fingerprint
              </h3>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(300px, 1fr))", gap: "15px", marginBottom: "30px" }}>
                <div style={{ background: "#0a0c12", padding: "15px 20px", borderRadius: "12px", border: "1px solid var(--border)", display: "flex", alignItems: "center", gap: "15px" }}>
                  <div style={{ background: "rgba(0, 118, 255, 0.1)", padding: "10px", borderRadius: "8px", color: "var(--accent-blue)" }}><Cpu size={20} /></div>
                  <div>
                    <p style={{ margin: 0, fontSize: "11px", color: "var(--text-muted)" }}>Processor Information</p>
                    <p style={{ margin: "4px 0 0 0", fontSize: "13px", fontWeight: 600 }}>{deepForensics.hardware?.cpu_name || "Scanning Engine..."}</p>
                  </div>
                </div>
                <div style={{ background: "#0a0c12", padding: "15px 20px", borderRadius: "12px", border: "1px solid var(--border)", display: "flex", alignItems: "center", gap: "15px" }}>
                  <div style={{ background: "rgba(0, 242, 255, 0.1)", padding: "10px", borderRadius: "8px", color: "var(--accent-cyan)" }}><Database size={20} /></div>
                  <div>
                    <p style={{ margin: 0, fontSize: "11px", color: "var(--text-muted)" }}>Memory (RAM)</p>
                    <p style={{ margin: "4px 0 0 0", fontSize: "13px", fontWeight: 600 }}>
                      {deepForensics.hardware?.ram_total
                        ? `${Math.round((deepForensics.hardware.ram_total - deepForensics.hardware.ram_free) / 1024)}MB Used / ${Math.round(deepForensics.hardware.ram_total / 1024)}MB Total`
                        : "Analyzing Memory..."}
                    </p>
                  </div>
                </div>
                <div style={{ background: "#0a0c12", padding: "15px 20px", borderRadius: "12px", border: "1px solid var(--border)", display: "flex", alignItems: "center", gap: "15px" }}>
                  <div style={{ background: "rgba(255, 255, 255, 0.05)", padding: "10px", borderRadius: "8px", color: "#fff" }}><Server size={20} /></div>
                  <div>
                    <p style={{ margin: 0, fontSize: "11px", color: "var(--text-muted)" }}>Operating System</p>
                    <p style={{ margin: "4px 0 0 0", fontSize: "13px", fontWeight: 600 }}>{deepForensics.hardware?.os_name || "Unknown"} {deepForensics.hardware?.os_version || ""}</p>
                  </div>
                </div>
              </div>

              <h3 style={{ fontSize: "11px", textTransform: "uppercase", color: "var(--accent-blue)", letterSpacing: "1.5px", marginBottom: "15px", display: "flex", alignItems: "center", gap: "8px" }}>
                <Plus size={14} /> Installed Packages
              </h3>
              <div style={{ padding: "20px", background: "#0a0c12", borderRadius: "12px", border: "1px solid var(--border)", display: "flex", flexWrap: "wrap", gap: "8px", marginBottom: "30px" }}>
                {deepForensics.packages?.map((p, idx) => (
                  <div key={idx} style={{ background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.1)", padding: "6px 12px", borderRadius: "8px", fontSize: "12px", color: "#fff", display: "flex", alignItems: "center", gap: "8px" }}>
                    <span style={{ width: "6px", height: "6px", background: "var(--success)", borderRadius: "50%" }}></span>
                    <strong>{p.name}</strong> <span style={{ opacity: 0.5 }}>{p.version}</span>
                  </div>
                )) || <p style={{ fontSize: "13px", color: "var(--text-muted)" }}>No recent packages detected.</p>}
              </div>

              {/* AI Behavioral Intelligence */}
              <div style={{ marginTop: "30px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "20px" }}>
                  <h3 style={{ fontSize: "11px", textTransform: "uppercase", color: "var(--accent-blue)", letterSpacing: "1.5px", margin: 0, display: "flex", alignItems: "center", gap: "8px" }}>
                    <Cpu size={14} /> AI Behavioral Intelligence
                  </h3>
                  <div style={{ display: "flex", gap: "15px" }}>
                    <button className="btn-primary" onClick={() => onRunAI(target["Agent ID"] || target.agent_id || "001")} disabled={isAnalyzingBehavior}
                      style={{ padding: "8px 20px", fontSize: "11px", background: isAnalyzingBehavior ? "rgba(255,255,255,0.05)" : "linear-gradient(90deg, #0076ff, #00c6ff)", border: "none" }}>
                      {isAnalyzingBehavior ? "Deep Analysis..." : "Run AI Behavioral Audit"}
                    </button>
                  </div>
                </div>

                {isAnalyzingBehavior && (
                  <div style={{ padding: "40px", background: "rgba(0, 118, 255, 0.05)", borderRadius: "16px", border: "1px dashed var(--accent-blue)", textAlign: "center" }}>
                    <div className="discovery-pulse" style={{ margin: "0 auto 20px auto", width: "40px", height: "40px", background: "var(--accent-blue)" }}></div>
                    <h4 style={{ color: "var(--accent-blue)", marginBottom: "5px" }}>AI Forensic Investigation in Progress...</h4>
                    <p style={{ color: "var(--text-muted)", fontSize: "12px" }}>Analyzing system logs for behavioral anomalies (qwen2.5:1.5B)</p>
                  </div>
                )}

                {aiBehaviorReport && (
                  <div className="report-container ai-report-content" style={{ animation: "fadeIn 0.5s ease" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "20px", color: "var(--accent-cyan)", borderBottom: "1px solid rgba(255,255,255,0.05)", paddingBottom: "15px", justifyContent: "space-between" }}>
                      <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                        <ShieldCheck size={22} /> <strong style={{ fontSize: "16px", letterSpacing: "1px" }}>AI BEHAVIORAL INTELLIGENCE REPORT</strong>
                      </div>
                      <button className="btn-primary" onClick={() => window.print()} style={{ padding: "4px 10px", fontSize: "11px", background: "rgba(0, 242, 255, 0.1)", border: "1px solid rgba(0, 242, 255, 0.3)" }}>
                        <Printer size={12} style={{ marginRight: "4px" }} /> Print Report
                      </button>
                    </div>
                    <div style={{ whiteSpace: "normal" }}>{formatReport(aiBehaviorReport)}</div>
                  </div>
                )}
              </div>

              {/* Threat Summary Box */}
              <div style={{ marginTop: "30px", background: "linear-gradient(145deg, rgba(255, 77, 77, 0.1), rgba(30, 0, 0, 0.5))", padding: "25px", borderRadius: "16px", border: "1px solid rgba(255, 77, 77, 0.3)", position: "relative", overflow: "hidden" }}>
                <div style={{ position: "absolute", top: "-20px", right: "-20px", opacity: 0.05, transform: "rotate(-15deg)" }}>
                  <ShieldAlert size={150} />
                </div>
                <h4 style={{ color: "var(--danger)", margin: "0 0 10px 0", fontSize: "16px", display: "flex", alignItems: "center", gap: "8px" }}>
                  <AlertTriangle size={18} /> SOC Action Required
                </h4>
                <p style={{ margin: 0, lineHeight: "1.6", fontSize: "14px", color: "#e2e8f0", position: "relative", zIndex: 2 }}>
                  This asset triggered a level <strong style={{ color: "var(--danger)" }}>{target.Severity || 12}</strong> alert:{" "}
                  <span style={{ background: "rgba(255, 77, 77, 0.2)", padding: "2px 6px", borderRadius: "4px" }}>
                    {target.Description || "Suspicious Activity"}
                  </span>.
                  <br /><br />
                  <strong>Recommended Policy:</strong> Isolate the node via SDN controller and run a full forensic scan using Wazuh active response scripts. Check the AI Copilot tab for automated remediation.
                </p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
