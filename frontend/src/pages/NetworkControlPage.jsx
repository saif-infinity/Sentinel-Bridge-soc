import { useState, useRef, useEffect } from "react";
import { useAuth } from "../contexts/AuthContext";

export default function NetworkControlPage() {
  const { fetchWithAuth, headers } = useAuth();
  const [suricataTerminalHistory, setSuricataTerminalHistory] = useState([]);
  const [suricataCmd, setSuricataCmd] = useState("");
  const [isExecutingCmd, setIsExecutingCmd] = useState(false);
  const suricataInputRef = useRef(null);
  const suricataBodyRef = useRef(null);

  useEffect(() => {
    suricataInputRef.current?.focus();
  }, []);

  useEffect(() => {
    if (suricataBodyRef.current) {
      suricataBodyRef.current.scrollTop = suricataBodyRef.current.scrollHeight;
    }
  }, [suricataTerminalHistory]);

  useEffect(() => {
    const saved = localStorage.getItem("suricata_terminal_history");
    if (saved) {
      try { setSuricataTerminalHistory(JSON.parse(saved)); } catch {}
    }
  }, []);

  useEffect(() => {
    localStorage.setItem("suricata_terminal_history", JSON.stringify(suricataTerminalHistory.slice(-50)));
  }, [suricataTerminalHistory]);

  const executeCommand = async (e) => {
    e.preventDefault();
    if (!suricataCmd.trim()) return;
    setSuricataTerminalHistory((prev) => [...prev, { type: "input", content: suricataCmd }]);
    const cmd = suricataCmd;
    setSuricataCmd("");
    setIsExecutingCmd(true);

    try {
      const res = await fetchWithAuth("/api/terminal/exec", {
        method: "POST",
        headers,
        body: JSON.stringify({ command: cmd, target: "suricata" }),
      });
      const data = await res.json();
      setSuricataTerminalHistory((prev) => [...prev, { type: "output", content: data.output, status: data.status }]);
    } catch {
      setSuricataTerminalHistory((prev) => [...prev, { type: "output", content: "Failed to connect to backend", status: "error" }]);
    } finally {
      setIsExecutingCmd(false);
    }
  };

  return (
    <div className="tab-content fadeIn" style={{ height: "calc(100vh - 100px)" }}>
      <div className="terminal-window">
        <div className="terminal-header" style={{ background: "#064e3b" }}>
          <div className="terminal-dots"><span></span><span></span><span></span></div>
          <div className="terminal-title">suricata@sensor:~ (IPS MODE)</div>
        </div>
        <div className="terminal-body" ref={suricataBodyRef}>
          {suricataTerminalHistory.map((line, i) => (
            <div key={i} className={`terminal-line ${line.type}`}>
              {line.type === "input" && <span className="prompt">$ </span>}
              <span className="content">{line.content}</span>
            </div>
          ))}
          {isExecutingCmd && (
            <div className="terminal-line system">
              <span className="content pulse">Executing on sensor...</span>
            </div>
          )}
        </div>
        <form className="terminal-input-area" onSubmit={executeCommand} onClick={() => suricataInputRef.current?.focus()}>
          <span className="prompt">$ </span>
          <input
            ref={suricataInputRef} type="text" autoFocus value={suricataCmd}
            onChange={(e) => setSuricataCmd(e.target.value)}
            disabled={isExecutingCmd} placeholder="Configure IPS..."
          />
        </form>
      </div>
    </div>
  );
}
