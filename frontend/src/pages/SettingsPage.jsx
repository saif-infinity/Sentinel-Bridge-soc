import { useState, useEffect, useCallback } from "react";
import { Settings, Save, Eye, EyeOff, CheckCircle2, AlertCircle, Shield, Server, Cpu, Database, RefreshCw, Bot, Palette, Check, Sparkles, BrainCircuit } from "lucide-react";
import { useAuth } from "../contexts/AuthContext";
import { useTranslation } from "../i18n";
import { toast } from "react-toastify";
import SourceToggles from "../components/SourceToggles";

const THEMES = [
  { id: "soc-dark", label: "SOC Dark", desc: "Thème sombre par défaut", colors: ["#050a0e", "#00ff88", "#00e5ff"] },
  { id: "light", label: "Clair", desc: "Fonds clairs, texte sombre", colors: ["#f8fafc", "#0ea5e9", "#0284c7"] },
  { id: "cyber-red", label: "Cyber Rouge", desc: "Accent rouge, fonds très sombres", colors: ["#0f0404", "#ef4444", "#f87171"] },
  { id: "matrix", label: "Matrix Vert", desc: "Vert fluo, ambiance terminal", colors: ["#020a02", "#00ff41", "#00ff88"] },
];

const SECTION_ICONS = {
  wazuh_api: Shield,
  wazuh_indexer: Database,
  suricata_ssh: Server,
  wazuh_ssh: Server,
  ollama: Cpu,
  redis: Database,
  host_agent: Bot,
};

const SECTION_ORDER = ["wazuh_api", "wazuh_indexer", "suricata_ssh", "wazuh_ssh", "ollama", "redis", "host_agent"];

export default function SettingsPage() {
  const { fetchWithAuth, headers } = useAuth();
  const { t } = useTranslation();
  const [settings, setSettings] = useState({});
  const [localValues, setLocalValues] = useState({});
  const [visibleSecrets, setVisibleSecrets] = useState({});
  const [saving, setSaving] = useState(null);
  const [loading, setLoading] = useState(true);
  const [theme, setTheme] = useState(() => localStorage.getItem("soc_theme") || "soc-dark");
  const canEditAI = hasRole ? hasRole("analyst") : false;
  const [aiConfig, setAiConfig] = useState({ enabled: false, threshold: 8, send_count: 10, severity_min: 8, window_minutes: 60, model: "meta-llama/Llama-3.1-70B-Instruct:featherless-ai", url: "https://router.huggingface.co/v1" });
  const [aiSaving, setAiSaving] = useState(false);
  const [aiBackendReady, setAiBackendReady] = useState(true);

  const fetchSettings = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetchWithAuth("/api/settings", { headers, silent: true });
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

  const fetchAiConfig = useCallback(async () => {
    if (!canEditAI) return;
    try {
      const res = await fetchWithAuth("/api/settings/ai-auto", { headers, silent: true });
      if (res.ok) {
        const d = await res.json();
        setAiConfig({
          enabled: !!d.enabled,
          threshold: d.threshold ?? 8,
          send_count: d.send_count ?? 10,
          severity_min: d.severity_min ?? 8,
          window_minutes: d.window_minutes ?? 60,
          model: d.model || "meta-llama/Llama-3.1-70B-Instruct:featherless-ai",
          url: d.url || "https://router.huggingface.co/v1",
        });
        setAiBackendReady(true);
      } else if (res.status === 404) {
        setAiBackendReady(false);
      } else if (res.status === 403) {
        setAiBackendReady(false);
      }
    } catch {
      setAiBackendReady(false);
    }
  }, [fetchWithAuth, headers, canEditAI]);

  useEffect(() => {
    fetchAiConfig();
  }, [fetchAiConfig]);

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("soc_theme", theme);
  }, [theme]);

  const handleThemeChange = (id) => {
    setTheme(id);
    document.documentElement.setAttribute("data-theme", id);
    localStorage.setItem("soc_theme", id);
  };

  const handleSaveAi = async () => {
    setAiSaving(true);
    try {
      const payload = {
        enabled: !!aiConfig.enabled,
        threshold: parseInt(aiConfig.threshold, 10),
        send_count: parseInt(aiConfig.send_count, 10),
        severity_min: parseInt(aiConfig.severity_min, 10),
        window_minutes: parseInt(aiConfig.window_minutes, 10),
        model: (aiConfig.model || "").trim(),
        url: (aiConfig.url || "").trim(),
      };
      const res = await fetchWithAuth("/api/settings/ai-auto", {
        method: "PUT",
        headers: { ...headers, "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (res.ok) {
        toast.success("Paramètres d'auto-analyse enregistrés");
        window.dispatchEvent(new CustomEvent("sources-changed"));
        const d = await res.json().catch(() => null);
        if (d) {
          setAiConfig({
            enabled: !!d.enabled,
            threshold: d.threshold ?? payload.threshold,
            send_count: d.send_count ?? payload.send_count,
            severity_min: d.severity_min ?? payload.severity_min,
            window_minutes: d.window_minutes ?? payload.window_minutes,
            model: d.model || payload.model,
            url: d.url || payload.url,
          });
        }
      } else {
        const j = await res.clone().json().catch(() => ({}));
        if (j?.detail) toast.error(typeof j.detail === "string" ? j.detail : JSON.stringify(j.detail));
      }
    } catch {
      toast.error("Erreur réseau");
    } finally {
      setAiSaving(false);
    }
  };

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

      {/* Thème de la plateforme */}
      <div className="section-card" style={{ marginBottom: "20px" }}>
        <div className="section-header" style={{ padding: "18px 24px", borderLeft: "4px solid var(--accent-cyan)" }}>
          <h3 style={{ margin: 0, display: "flex", alignItems: "center", gap: "10px", fontSize: "16px" }}>
            <Palette size={18} color="var(--accent-cyan)" /> Thème de la plateforme
          </h3>
        </div>
        <div style={{ padding: "20px 24px" }}>
          <p style={{ color: "var(--text-muted)", fontSize: "13px", margin: "0 0 16px 0", lineHeight: 1.5 }}>
            Choisissez l’apparence visuelle de la plateforme. Le thème est appliqué immédiatement et mémorisé sur cet appareil.
          </p>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))", gap: "12px" }}>
            {THEMES.map((t) => {
              const active = theme === t.id;
              return (
                <button
                  key={t.id}
                  onClick={() => handleThemeChange(t.id)}
                  style={{
                    textAlign: "left",
                    padding: "14px",
                    borderRadius: "12px",
                    border: active ? "1px solid var(--accent-cyan)" : "1px solid var(--border)",
                    background: active ? "rgba(56,189,248,0.08)" : "rgba(255,255,255,0.03)",
                    cursor: "pointer",
                    position: "relative",
                    transition: "border-color 0.2s, background 0.2s",
                  }}
                >
                  <div style={{ display: "flex", gap: "6px", marginBottom: "10px" }}>
                    {t.colors.map((c) => (
                      <span key={c} style={{ width: "22px", height: "22px", borderRadius: "6px", background: c, border: "1px solid var(--border)", display: "inline-block" }} />
                    ))}
                  </div>
                  <div style={{ fontSize: "13px", fontWeight: 700, color: "var(--text-main)", display: "flex", alignItems: "center", gap: "6px" }}>
                    {t.label} {active && <Check size={14} color="var(--accent-cyan)" />}
                  </div>
                  <div style={{ fontSize: "11px", color: "var(--text-muted)", marginTop: "4px", lineHeight: 1.3 }}>{t.desc}</div>
                </button>
              );
            })}
          </div>
        </div>
      </div>

      {canEditAI && (
        <div className="section-card" style={{ marginBottom: "20px" }}>
          <div className="section-header" style={{ padding: "18px 24px", borderLeft: "4px solid var(--accent-cyan)" }}>
            <h3 style={{ margin: 0, display: "flex", alignItems: "center", gap: "10px", fontSize: "16px" }}>
              <BrainCircuit size={18} color="var(--accent-cyan)" /> Auto-analyse IA des alertes critiques
            </h3>
            {!aiBackendReady && <span style={{ fontSize: "11px", color: "var(--text-muted)", background: "rgba(255,255,255,0.06)", border: "1px solid var(--border)", padding: "4px 8px", borderRadius: "999px" }}>backend pas encore prêt</span>}
          </div>
          <div style={{ padding: "20px 24px" }}>
            <p style={{ color: "var(--text-muted)", fontSize: "13px", margin: "0 0 16px 0", lineHeight: 1.5 }}>
              Quand plus de <b style={{ color: "var(--text-main)" }}>N alertes critiques</b> sont détectées pour un agent, le système envoie les <b style={{ color: "var(--text-main)" }}>M dernières</b> à un modèle Hugging Face.
            </p>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: "16px", padding: "12px 14px", background: "rgba(255,255,255,0.03)", border: "1px solid var(--border)", borderRadius: "12px", marginBottom: "16px" }}>
              <div style={{ display: "flex", gap: "10px", alignItems: "center" }}>
                <div style={{ width: "32px", height: "32px", borderRadius: "8px", background: aiConfig.enabled ? "rgba(56,189,248,0.15)" : "rgba(255,255,255,0.04)", border: "1px solid var(--border)", display: "flex", alignItems: "center", justifyContent: "center" }}>
                  <Sparkles size={14} color={aiConfig.enabled ? "var(--accent-cyan)" : "var(--text-muted)"} />
                </div>
                <div>
                  <div style={{ fontSize: "13px", fontWeight: 700, color: "var(--text-main)" }}>Activer l'analyse automatique</div>
                  <div style={{ fontSize: "11px", color: "var(--text-muted)" }}>Burst d'alertes critiques par agent</div>
                </div>
              </div>
              <button
                type="button"
                role="switch"
                aria-checked={aiConfig.enabled}
                onClick={() => setAiConfig((p) => ({ ...p, enabled: !p.enabled }))}
                style={{ width: "44px", height: "26px", borderRadius: "999px", border: "1px solid var(--border)", background: aiConfig.enabled ? "rgba(56,189,248,0.9)" : "rgba(255,255,255,0.12)", position: "relative", cursor: "pointer", flexShrink: 0, transition: "background 0.2s", padding: 0 }}
              >
                <span style={{ position: "absolute", top: "2px", left: aiConfig.enabled ? "20px" : "2px", width: "20px", height: "20px", borderRadius: "50%", background: "#fff", boxShadow: "0 1px 4px rgba(0,0,0,0.3)", transition: "left 0.2s" }} />
              </button>
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px", marginBottom: "12px" }}>
              <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
                <label style={{ fontSize: "11px", color: "var(--text-muted)", fontWeight: 600, textTransform: "uppercase" }}>Seuil d'alertes critiques</label>
                <input type="number" min={1} value={aiConfig.threshold} onChange={(e) => setAiConfig((p) => ({ ...p, threshold: e.target.value }))} style={{ padding: "8px 10px", background: "rgba(255,255,255,0.03)", border: "1px solid var(--border)", borderRadius: "8px", color: "var(--text-main)", fontSize: "13px", fontFamily: "monospace" }} />
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
                <label style={{ fontSize: "11px", color: "var(--text-muted)", fontWeight: 600, textTransform: "uppercase" }}>Nombre d'alertes envoyées</label>
                <input type="number" min={1} value={aiConfig.send_count} onChange={(e) => setAiConfig((p) => ({ ...p, send_count: e.target.value }))} style={{ padding: "8px 10px", background: "rgba(255,255,255,0.03)", border: "1px solid var(--border)", borderRadius: "8px", color: "var(--text-main)", fontSize: "13px", fontFamily: "monospace" }} />
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
                <label style={{ fontSize: "11px", color: "var(--text-muted)", fontWeight: 600, textTransform: "uppercase" }}>Sévérité minimale (1-15)</label>
                <input type="number" min={1} max={15} value={aiConfig.severity_min} onChange={(e) => setAiConfig((p) => ({ ...p, severity_min: e.target.value }))} style={{ padding: "8px 10px", background: "rgba(255,255,255,0.03)", border: "1px solid var(--border)", borderRadius: "8px", color: "var(--text-main)", fontSize: "13px", fontFamily: "monospace" }} />
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
                <label style={{ fontSize: "11px", color: "var(--text-muted)", fontWeight: 600, textTransform: "uppercase" }}>Fenêtre de détection (min)</label>
                <input type="number" min={1} value={aiConfig.window_minutes} onChange={(e) => setAiConfig((p) => ({ ...p, window_minutes: e.target.value }))} style={{ padding: "8px 10px", background: "rgba(255,255,255,0.03)", border: "1px solid var(--border)", borderRadius: "8px", color: "var(--text-main)", fontSize: "13px", fontFamily: "monospace" }} />
              </div>
            </div>

            <div style={{ display: "flex", flexDirection: "column", gap: "6px", marginBottom: "12px" }}>
              <label style={{ fontSize: "11px", color: "var(--text-muted)", fontWeight: 600, textTransform: "uppercase" }}>Modèle HF</label>
              <input value={aiConfig.model} onChange={(e) => setAiConfig((p) => ({ ...p, model: e.target.value }))} placeholder="meta-llama/Llama-3.1-70B-Instruct:featherless-ai" style={{ padding: "8px 10px", background: "rgba(255,255,255,0.03)", border: "1px solid var(--border)", borderRadius: "8px", color: "var(--text-main)", fontSize: "12px", fontFamily: "monospace" }} />
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: "6px", marginBottom: "16px" }}>
              <label style={{ fontSize: "11px", color: "var(--text-muted)", fontWeight: 600, textTransform: "uppercase" }}>URL du routeur HF</label>
              <input value={aiConfig.url} onChange={(e) => setAiConfig((p) => ({ ...p, url: e.target.value }))} placeholder="https://router.huggingface.co/v1" style={{ padding: "8px 10px", background: "rgba(255,255,255,0.03)", border: "1px solid var(--border)", borderRadius: "8px", color: "var(--text-main)", fontSize: "12px", fontFamily: "monospace" }} />
              <span style={{ fontSize: "11px", color: "var(--text-muted)" }}>Token HF configuré côté serveur (HF_TOKEN) — jamais exposé.</span>
            </div>

            <div style={{ display: "flex", justifyContent: "flex-end" }}>
              <button onClick={handleSaveAi} disabled={aiSaving} style={{ padding: "8px 16px", background: aiSaving ? "rgba(255,255,255,0.12)" : "rgba(56,189,248,0.9)", border: "1px solid var(--border)", borderRadius: "8px", color: aiSaving ? "var(--text-muted)" : "#fff", cursor: aiSaving ? "not-allowed" : "pointer", fontSize: "13px", fontWeight: 600, display: "flex", alignItems: "center", gap: "6px" }}>
                <Save size={14} /> {aiSaving ? "Enregistrement…" : "Enregistrer"}
              </button>
            </div>
          </div>
        </div>
      )}

      <SourceToggles variant="settings" />

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
