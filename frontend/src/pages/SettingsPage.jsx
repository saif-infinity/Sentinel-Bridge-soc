import { useState, useEffect, useCallback } from "react";
import { Settings, Save, Eye, EyeOff, CheckCircle2, AlertCircle, Shield, Server, Cpu, Database, RefreshCw } from "lucide-react";
import { useAuth } from "../contexts/AuthContext";
import { useTranslation } from "../i18n";
import { toast } from "react-toastify";

const SECTION_ICONS = {
  wazuh_api: Shield,
  wazuh_indexer: Database,
  suricata_ssh: Server,
  wazuh_ssh: Server,
  ollama: Cpu,
  redis: Database,
};

const SECTION_ORDER = ["wazuh_api", "wazuh_indexer", "suricata_ssh", "wazuh_ssh", "ollama", "redis"];

export default function SettingsPage() {
  const { fetchWithAuth, headers } = useAuth();
  const { t } = useTranslation();
  const [settings, setSettings] = useState({});
  const [localValues, setLocalValues] = useState({});
  const [visibleSecrets, setVisibleSecrets] = useState({});
  const [saving, setSaving] = useState(null);
  const [loading, setLoading] = useState(true);

  const fetchSettings = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetchWithAuth("/api/settings", { headers });
      if (res.ok) {
        const data = await res.json();
        setSettings(data);
        const vals = {};
        Object.entries(data).forEach(([section, config]) => {
          vals[section] = {};
          Object.entries(config.fields).forEach(([key, field]) => {
            vals[section][key] = "";
          });
        });
        setLocalValues(vals);
      }
    } catch {
      toast.error("Failed to load settings");
    }
    setLoading(false);
  }, [fetchWithAuth, headers]);

  useEffect(() => {
    fetchSettings();
  }, [fetchSettings]);

  const handleSave = async (section) => {
    setSaving(section);
    const data = {};
    Object.entries(localValues[section] || {}).forEach(([key, value]) => {
      if (value) data[key] = value;
    });

    if (Object.keys(data).length === 0) {
      toast.info("No changes to save");
      setSaving(null);
      return;
    }

    try {
      const res = await fetchWithAuth("/api/settings", {
        method: "PUT",
        headers: { ...headers, "Content-Type": "application/json" },
        body: JSON.stringify({ section, data }),
      });
      if (res.ok) {
        toast.success(`${settings[section]?.label || section} saved`);
        setLocalValues((prev) => {
          const next = { ...prev };
          Object.keys(next[section]).forEach((k) => (next[section][k] = ""));
          return next;
        });
        fetchSettings();
      } else {
        toast.error("Failed to save");
      }
    } catch {
      toast.error("Connection error");
    }
    setSaving(null);
  };

  const handleChange = (section, key, value) => {
    setLocalValues((prev) => ({
      ...prev,
      [section]: { ...prev[section], [key]: value },
    }));
  };

  const toggleSecret = (section, key) => {
    const id = `${section}.${key}`;
    setVisibleSecrets((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  if (loading) {
    return (
      <div className="tab-pane animate-fade-in" style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "60vh" }}>
        <div className="discovery-pulse" style={{ width: "50px", height: "50px", background: "var(--accent-blue)" }}></div>
      </div>
    );
  }

  return (
    <div className="tab-pane animate-fade-in" style={{ maxWidth: "900px", margin: "0 auto" }}>
      <div className="section-card" style={{ padding: "25px", marginBottom: "25px", background: "linear-gradient(90deg, rgba(56, 189, 248, 0.05) 0%, transparent 100%)" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <div>
            <h2 style={{ display: "flex", alignItems: "center", gap: "12px", fontSize: "24px", margin: 0 }}>
              <Settings size={28} color="var(--accent-cyan)" /> System Configuration
            </h2>
            <p style={{ color: "var(--text-muted)", margin: "8px 0 0 0", fontSize: "13px" }}>
              Configure external service connections. Changes take effect immediately.
            </p>
          </div>
          <button
            onClick={fetchSettings}
            style={{
              padding: "8px 16px", background: "rgba(56, 189, 248, 0.15)", color: "var(--accent-cyan)",
              border: "1px solid rgba(56, 189, 248, 0.25)", borderRadius: "10px", cursor: "pointer",
              display: "flex", alignItems: "center", gap: "6px", fontSize: "13px", fontWeight: 600,
              transition: "all 0.2s",
            }}
            onMouseEnter={(e) => { e.currentTarget.style.background = "rgba(56, 189, 248, 0.25)"; }}
            onMouseLeave={(e) => { e.currentTarget.style.background = "rgba(56, 189, 248, 0.15)"; }}
          >
            <RefreshCw size={14} /> Refresh
          </button>
        </div>
      </div>

      {SECTION_ORDER.map((section) => {
        const config = settings[section];
        if (!config) return null;
        const Icon = SECTION_ICONS[section] || Settings;

        return (
          <div key={section} className="section-card" style={{ marginBottom: "20px" }}>
            <div className="section-header" style={{ padding: "18px 24px", borderLeft: "4px solid var(--accent-cyan)" }}>
              <h3 style={{ margin: 0, display: "flex", alignItems: "center", gap: "10px", fontSize: "16px" }}>
                <Icon size={18} color="var(--accent-cyan)" /> {config.label}
              </h3>
            </div>

            <div style={{ padding: "20px 24px" }}>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "18px" }}>
                {Object.entries(config.fields).map(([key, field]) => {
                  const inputId = `${section}.${key}`;
                  const isSecret = field.is_secret;
                  const isVisible = visibleSecrets[inputId];

                  return (
                    <div key={key} style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
                      <label style={{ fontSize: "12px", color: "var(--text-muted)", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.5px" }}>
                        {field.label}
                      </label>
                      <div style={{ position: "relative", display: "flex", alignItems: "center" }}>
                        <input
                          type={isSecret && !isVisible ? "password" : "text"}
                          value={localValues[section]?.[key] || ""}
                          onChange={(e) => handleChange(section, key, e.target.value)}
                          placeholder={isSecret && field.has_value ? "******** (configured)" : `Enter ${field.label.toLowerCase()}...`}
                          style={{
                            width: "100%", padding: "10px 14px", paddingRight: isSecret ? "40px" : "14px",
                            background: "rgba(255,255,255,0.03)", border: "1px solid var(--border)",
                            color: "var(--text-primary)", borderRadius: "10px", fontSize: "13px", outline: "none",
                            fontFamily: "monospace", transition: "border-color 0.2s",
                          }}
                          onFocus={(e) => (e.target.style.borderColor = "var(--accent-cyan)")}
                          onBlur={(e) => (e.target.style.borderColor = "var(--border)")}
                        />
                        {isSecret && (
                          <button
                            type="button"
                            onClick={() => toggleSecret(section, key)}
                            style={{
                              position: "absolute", right: "10px", background: "none", border: "none",
                              color: "var(--text-muted)", cursor: "pointer", padding: "4px",
                            }}
                          >
                            {isVisible ? <EyeOff size={16} /> : <Eye size={16} />}
                          </button>
                        )}
                      </div>
                      <div style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "11px" }}>
                        {field.has_value ? (
                          <span style={{ display: "flex", alignItems: "center", gap: "4px", color: "#10b981" }}>
                            <CheckCircle2 size={12} /> Configured
                          </span>
                        ) : (
                          <span style={{ display: "flex", alignItems: "center", gap: "4px", color: "var(--text-muted)" }}>
                            <AlertCircle size={12} /> Not configured
                          </span>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>

              <div style={{ display: "flex", justifyContent: "flex-end", marginTop: "20px", paddingTop: "15px", borderTop: "1px solid rgba(255,255,255,0.05)" }}>
                <button
                  className="btn-primary"
                  onClick={() => handleSave(section)}
                  disabled={saving === section}
                  style={{
                    padding: "8px 24px", fontSize: "13px",
                    opacity: saving === section ? 0.6 : 1,
                  }}
                >
                  <Save size={14} style={{ marginRight: "6px" }} />
                  {saving === section ? "Saving..." : "Save"}
                </button>
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}
