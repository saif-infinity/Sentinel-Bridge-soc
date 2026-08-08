import { useNavigate } from "react-router-dom";
import TopologyView from "../components/TopologyView";
import { useAuth } from "../contexts/AuthContext";
import { useData } from "../contexts/DataContext";

export default function TopologyPage() {
  const { jwtToken, headers } = useAuth();
  const { devices, wazuhAlerts } = useData();
  const navigate = useNavigate();

  return (
    <div className="tab-pane animate-fade-in" style={{ padding: "0 10px" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "30px", padding: "0 5px" }}>
        <div>
          <h1 style={{ fontSize: "26px", fontWeight: "900", margin: 0, color: "#f3f4f6", letterSpacing: "-0.03em" }}>
            NETWORK TOPOLOGY <span style={{ color: "#666", fontSize: "18px", fontWeight: "500" }}>[SENTINEL_SOC]</span>
          </h1>
          <div style={{ display: "flex", alignItems: "center", gap: "10px", marginTop: "6px" }}>
            <div style={{ padding: "2px 8px", background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.1)", borderRadius: "4px", fontSize: "10px", color: "#aaa", fontWeight: "700" }}>
              SENTINEL_SOC_MODE
            </div>
            <span style={{ color: "#4b5563", fontSize: "12px", fontWeight: "500" }}>Real-time packet flow & endpoint synchronization</span>
          </div>
        </div>
      </div>

      <TopologyView
        devices={devices.filter((d) => d.is_wazuh_agent)}
        alerts={wazuhAlerts}
        jwtToken={jwtToken}
        headers={headers}
        onNodeClick={(node) => {
          if (node?.data?.ip) {
            navigate("/alerts", { state: { filterIP: node.data.ip } });
          }
        }}
      />
    </div>
  );
}
