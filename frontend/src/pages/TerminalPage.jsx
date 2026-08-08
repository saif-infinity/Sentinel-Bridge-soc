import { useState, useRef, useEffect } from "react";
import { useAuth } from "../contexts/AuthContext";

export default function TerminalPage() {
  const { fetchWithAuth, headers } = useAuth();
  const [terminalHistory, setTerminalHistory] = useState([]);
  const [currentCmd, setCurrentCmd] = useState("");
  const [isExecutingCmd, setIsExecutingCmd] = useState(false);
  const terminalInputRef = useRef(null);
  const terminalBodyRef = useRef(null);

  useEffect(() => {
    terminalInputRef.current?.focus();
  }, []);

  useEffect(() => {
    if (terminalBodyRef.current) {
      terminalBodyRef.current.scrollTop = terminalBodyRef.current.scrollHeight;
    }
  }, [terminalHistory]);

  useEffect(() => {
    const saved = localStorage.getItem("terminal_history");
    if (saved) {
      try { setTerminalHistory(JSON.parse(saved)); } catch {}
    }
  }, []);

  useEffect(() => {
    localStorage.setItem("terminal_history", JSON.stringify(terminalHistory.slice(-50)));
  }, [terminalHistory]);

  const executeCommand = async (e) => {
    e.preventDefault();
    if (!currentCmd.trim()) return;
    setTerminalHistory((prev) => [...prev, { type: "input", content: currentCmd }]);
    const cmd = currentCmd;
    setCurrentCmd("");
    setIsExecutingCmd(true);

    try {
      const res = await fetchWithAuth("/api/terminal/exec", {
        method: "POST",
        headers,
        body: JSON.stringify({ command: cmd, target: "wazuh" }),
      });
      const data = await res.json();
      setTerminalHistory((prev) => [...prev, { type: "output", content: data.output, status: data.status }]);
    } catch {
      setTerminalHistory((prev) => [...prev, { type: "output", content: "Failed to connect to backend", status: "error" }]);
    } finally {
      setIsExecutingCmd(false);
    }
  };

  return (
    <div className="tab-content fadeIn" style={{ height: "calc(100vh - 100px)" }}>
      <div className="terminal-window">
        <div className="terminal-header">
          <div className="terminal-dots"><span></span><span></span><span></span></div>
          <div className="terminal-title">root@sentinel-wazuh:~ (SSH:2222)</div>
        </div>
        <div className="terminal-body" id="terminal-body" ref={terminalBodyRef}>
          {terminalHistory.map((line, i) => (
            <div key={i} className={`terminal-line ${line.type}`}>
              {line.type === "input" && <span className="prompt"># </span>}
              <span className="content">{line.content}</span>
            </div>
          ))}
          {isExecutingCmd && (
            <div className="terminal-line system">
              <span className="content pulse">Executing...</span>
            </div>
          )}
        </div>
        <form className="terminal-input-area" onSubmit={executeCommand} onClick={() => terminalInputRef.current?.focus()}>
          <span className="prompt"># </span>
          <input
            ref={terminalInputRef} type="text" autoFocus value={currentCmd}
            onChange={(e) => setCurrentCmd(e.target.value)}
            disabled={isExecutingCmd} placeholder="Enter command..."
          />
        </form>
      </div>
    </div>
  );
}
