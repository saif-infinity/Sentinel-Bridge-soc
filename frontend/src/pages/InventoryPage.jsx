import { useState } from "react";
import { Database, Server, Activity, ShieldAlert, Shield, Laptop, Search } from "lucide-react";
import { useData } from "../contexts/DataContext";

export default function InventoryPage() {
  const { devices, inventory } = useData();
  const [searchVal, setSearchVal] = useState("");

  const filteredItems = (inventory.length > 0 ? inventory : devices).filter((d) => {
    if (!searchVal) return true;
    const val = searchVal.toLowerCase();
    return (
      (d.ip || "").toLowerCase().includes(val) ||
      (d.mac || "").toLowerCase().includes(val) ||
      (d.employee_name || d["Employee Name"] || "").toLowerCase().includes(val) ||
      (d.department || d.Department || "").toLowerCase().includes(val)
    );
  });

  return (
    <div className="tab-pane animate-fade-in">
      <div className="inventory-stats-grid">
        <div className="stat-card">
          <div className="stat-icon" style={{ background: "rgba(56, 189, 248, 0.1)", color: "var(--accent-blue)" }}>
            <Server size={20} />
          </div>
          <div className="stat-info">
            <span className="stat-value">{inventory.length || devices.length}</span>
            <span className="stat-label">Total Assets</span>
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-icon" style={{ background: "rgba(16, 185, 129, 0.1)", color: "#10b981" }}>
            <Activity size={20} />
          </div>
          <div className="stat-info">
            <span className="stat-value">
              {inventory.filter((d) => d.is_online).length || devices.filter((d) => d.is_online).length}
            </span>
            <span className="stat-label">Online Nodes</span>
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-icon" style={{ background: "rgba(239, 68, 68, 0.1)", color: "#ef4444" }}>
            <ShieldAlert size={20} />
          </div>
          <div className="stat-info">
            <span className="stat-value">
              {inventory.filter((d) => !d.is_online).length || devices.filter((d) => !d.is_online).length}
            </span>
            <span className="stat-label">Inactive / Offline</span>
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-icon" style={{ background: "rgba(251, 146, 60, 0.1)", color: "#fb923c" }}>
            <Shield size={20} />
          </div>
          <div className="stat-info">
            <span className="stat-value">{inventory.filter((d) => d.is_wazuh_agent).length}</span>
            <span className="stat-label">Wazuh Agents</span>
          </div>
        </div>
      </div>

      <div className="section-card border-glow" style={{ padding: "0", overflow: "hidden" }}>
        <div className="section-header" style={{ flexWrap: "wrap", gap: "15px", paddingLeft: "20px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
            <Database size={20} color="var(--accent-blue)" />
            <h2 style={{ margin: 0 }}>Network Asset Inventory</h2>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: "15px", marginLeft: "auto" }}>
            <div style={{ width: "250px", background: "rgba(255,255,255,0.05)", borderRadius: "10px", padding: "5px 12px", display: "flex", alignItems: "center", gap: "10px", border: "1px solid var(--border)" }}>
              <Search size={14} color="var(--text-muted)" />
              <input
                type="text"
                placeholder="Filter by IP, MAC, Employee..."
                style={{ background: "transparent", border: "none", color: "white", fontSize: "13px", outline: "none", width: "100%" }}
                value={searchVal}
                onChange={(e) => setSearchVal(e.target.value)}
              />
            </div>
            <span className="status-pill status-success">
              {inventory.filter((d) => d.is_online).length || devices.filter((d) => d.is_online).length} Active Now
            </span>
          </div>
        </div>

        <div className="table-wrapper" style={{ maxHeight: "600px", overflowY: "auto" }}>
          {filteredItems.length === 0 ? (
            <div style={{ textAlign: "center", padding: "60px", color: "var(--text-muted)" }}>
              <div style={{ fontSize: "3rem", marginBottom: "20px", opacity: 0.2 }}>
                &#128269;
              </div>
              <h3>No devices discovered yet</h3>
              <p>The background scanner is probing the network. Please wait...</p>
            </div>
          ) : (
            <table className="custom-table">
              <thead>
                <tr>
                  <th style={{ width: "100px" }}>Status</th>
                  <th>IP Address</th>
                  <th>MAC Address</th>
                  <th>Employee / Role</th>
                  <th>Department</th>
                  <th>Agent</th>
                  <th>Traffic In (MB)</th>
                  <th>Traffic Out (MB)</th>
                  <th>Last Activity</th>
                </tr>
              </thead>
              <tbody>
                {filteredItems
                  .sort((a, b) => (b.is_online ? 1 : 0) - (a.is_online ? 1 : 0))
                  .map((d) => {
                    const ip = d.ip || "";
                    const isGateway = ip.endsWith(".1");
                    const isWazuh = d.is_wazuh_agent;
                    const employee = d.employee_name || d["Employee Name"] || "Unknown";
                    const department = d.department || d.Department || "Unassigned";
                    return (
                      <tr key={d.id || d.ip} className={`inventory-row ${d.is_online ? "suricata-row-info" : ""}`}>
                        <td>
                          <div
                            className={`status-pill ${d.is_online ? "status-success" : "status-danger"}`}
                            style={{
                              display: "flex", alignItems: "center", gap: "8px", padding: "6px 12px",
                              borderRadius: "20px", fontSize: "10px", fontWeight: "800", letterSpacing: "0.5px",
                              width: "fit-content", boxShadow: d.is_online ? "0 0 10px rgba(16, 185, 129, 0.2)" : "none",
                              background: d.is_online ? "rgba(16, 185, 129, 0.1)" : "rgba(239, 68, 68, 0.05)",
                              color: d.is_online ? "#10b981" : "#ef4444",
                              border: `1px solid ${d.is_online ? "rgba(16, 185, 129, 0.3)" : "rgba(239, 68, 68, 0.2)"}`,
                            }}
                          >
                            <div style={{ width: "6px", height: "6px", borderRadius: "50%", background: "currentColor", animation: d.is_online ? "pulse 2s infinite" : "none" }} />
                            {d.is_online ? "ONLINE" : "OFFLINE"}
                          </div>
                        </td>
                        <td style={{ fontWeight: 600, color: d.is_online ? "#fff" : "#94a3b8" }}>{ip || "---"}</td>
                        <td style={{ fontFamily: "monospace", color: "var(--text-muted)", fontSize: "12px" }}>{d.mac || "---"}</td>
                        <td>
                          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                            {isGateway ? <Shield size={14} color="var(--accent-blue)" /> : <Laptop size={14} color="var(--text-muted)" />}
                            <div>
                              <span style={{ fontWeight: 500 }}>{employee}</span>
                              {isWazuh && (
                                <span style={{ marginLeft: "8px", fontSize: "10px", color: "var(--accent-blue)", background: "rgba(56, 189, 248, 0.1)", padding: "2px 6px", borderRadius: "4px" }}>
                                  WAZUH
                                </span>
                              )}
                            </div>
                          </div>
                        </td>
                        <td style={{ color: department === "Unassigned" ? "var(--text-muted)" : "#fff" }}>{department}</td>
                        <td style={{ textAlign: "center" }}>
                          {isWazuh ? (
                            <span style={{ color: "var(--accent-blue)", fontWeight: 600 }}>&#10003; Agent</span>
                          ) : (
                            <span style={{ color: "var(--text-muted)", fontSize: "11px" }}>&mdash;</span>
                          )}
                        </td>
                        <td style={{ fontFamily: "monospace", fontSize: "12px", color: d.bandwidth_in > 10 ? "#f97316" : "var(--text-muted)" }}>
                          {d.bandwidth_in?.toFixed(2) || "0.00"}
                        </td>
                        <td style={{ fontFamily: "monospace", fontSize: "12px", color: d.bandwidth_out > 10 ? "#f97316" : "var(--text-muted)" }}>
                          {d.bandwidth_out?.toFixed(2) || "0.00"}
                        </td>
                        <td style={{ fontSize: "11px", color: "var(--text-muted)" }}>
                          {d.is_online ? "Active Now" : "Recorded offline"}
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
  );
}
