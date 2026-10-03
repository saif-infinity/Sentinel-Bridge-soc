import { useState, useEffect, useCallback } from "react";
import { Bot, Shield, Server, Cpu, Lock, PenLine } from "lucide-react";
import { useAuth } from "../contexts/AuthContext";
import { toast } from "react-toastify";
import SourceConfigWizard from "./SourceConfigWizard";

const SOURCES_META = [
  { key: "host_agent", label: "Host-agent", desc: "Agent léger sur les hôtes — collecte et télémétrie en temps réel.", Icon: Bot, isDefault: true },
  { key: "wazuh", label: "Wazuh", desc: "SIEM — corrélations, règles et alertes du manager.", Icon: Shield },
  { key: "suricata", label: "Suricata", desc: "IDS réseau — signatures et détection du trafic.", Icon: Server },
];

export default function SourceToggles({ variant = "settings" }) {
  const { fetchWithAuth, headers, hasRole } = useAuth();
  const canEdit = hasRole ? hasRole("analyst") : false;
  const [sources, setSources] = useState({ host_agent: true, wazuh: false, suricata: false });
  const [saving, setSaving] = useState(null);
  const [wizard, setWizard] = useState({ open: false, source: null, mode: "activate" });

  const fetchSources = useCallback(async () => {
    try {
      const res = await fetchWithAuth("/api/settings/sources", { headers, silent: true });
      if (res.ok) {
        const data = await res.json();
        // contrat: {host_agent:bool, wazuh:bool, suricata:bool}
        setSources({
          host_agent: typeof data.host_agent === "boolean" ? data.host_agent : true,
          wazuh: typeof data.wazuh === "boolean" ? data.wazuh : false,
          suricata: typeof data.suricata === "boolean" ? data.suricata : false,
        });
      } else {
        // 403 viewer ou réseau -> fallback silencieux
        if (res.status !== 403) {
          // fallback déjà en state par défaut, ne pas spammer
        }
      }
    } catch {
      // silent fallback
    }
  }, [fetchWithAuth, headers]);

  useEffect(() => {
    fetchSources();
  }, [fetchSources]);

  const handleToggle = async (key) => {
    const prev = { ...sources };
    const nextVal = !prev[key];
    const isActivating = nextVal === true && (key === "wazuh" || key === "suricata");

    if (isActivating && canEdit) {
      // vérifier si déjà configurée
      try {
        const cfgRes = await fetchWithAuth("/api/settings/sources/config", { headers, silent: true });
        if (cfgRes.ok) {
          const cfg = await cfgRes.json();
          const entry = cfg[key];
          const configured = entry?.configured === true;
          if (!configured) {
            setWizard({ open: true, source: key, mode: "activate" });
            return;
          }
        } else if (cfgRes.status === 404) {
          // backend pas encore à jour -> dégradé : activation directe
        } else if (cfgRes.status === 403) {
          // viewer déjà bloqué par canEdit, mais au cas
        }
      } catch {
        // réseau -> dégradé : activation directe
      }
    }

    const next = { ...prev, [key]: nextVal };
    setSources(next);
    setSaving(key);
    try {
      const res = await fetchWithAuth("/api/settings/sources", {
        method: "PUT",
        headers: { ...headers, "Content-Type": "application/json" },
        body: JSON.stringify({ [key]: nextVal }),
      });
      if (res.ok) {
        toast.success("Source mise à jour");
        window.dispatchEvent(new CustomEvent("sources-changed"));
      } else {
        setSources(prev);
        if (res.status === 403) toast.error("Modification réservée à un compte analyste ou supérieur");
      }
    } catch {
      setSources(prev);
    } finally {
      setSaving(null);
    }
  };

  const handleWizardSuccess = () => {
    fetchSources();
    window.dispatchEvent(new CustomEvent("sources-changed"));
  };

  const isCompact = variant === "dashboard";

  // Dashboard variant: card height 350px like other dashboard cards
  if (isCompact) {
    return (
      <>
      <div className="section-card" style={{ height: "350px", display: "flex", flexDirection: "column", overflow: "hidden" }}>
        <div className="section-header" style={{ marginBottom: isCompact ? "12px" : undefined }}>
          <h2 style={{ display: "flex", alignItems: "center", gap: "10px", fontSize: "15px", margin: 0 }}>
            <Cpu size={18} color="var(--accent-cyan)" /> Sources de détection
          </h2>
          {!canEdit && (
            <span style={{ display: "flex", alignItems: "center", gap: "4px", fontSize: "10px", color: "var(--text-muted)", background: "rgba(255,255,255,0.06)", border: "1px solid var(--border)", padding: "3px 7px", borderRadius: "999px" }}>
              <Lock size={10} /> Nécessite un compte analyste
            </span>
          )}
        </div>
        <div style={{ flex: 1, display: "flex", flexDirection: "column", gap: "10px", overflowY: "auto", paddingRight: "2px" }}>
          {SOURCES_META.map(({ key, label, desc, Icon, isDefault }) => {
            const checked = !!sources[key];
            const isSaving = saving === key;
            const disabled = isSaving || !canEdit;
            return (
              <div
                key={key}
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  gap: "12px",
                  padding: "10px 12px",
                  background: "rgba(255,255,255,0.03)",
                  border: "1px solid var(--border)",
                  borderRadius: "12px",
                  opacity: isSaving ? 0.6 : 1,
                  transition: "opacity 0.2s",
                }}
              >
                <div style={{ display: "flex", gap: "10px", alignItems: "center", minWidth: 0 }}>
                  <div style={{ width: "32px", height: "32px", borderRadius: "8px", background: checked ? "rgba(56,189,248,0.15)" : "rgba(255,255,255,0.04)", border: "1px solid var(--border)", display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
                    <Icon size={14} color={checked ? "var(--accent-cyan)" : "var(--text-muted)"} />
                  </div>
                  <div style={{ minWidth: 0 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "6px", flexWrap: "wrap" }}>
                      <span style={{ fontSize: "13px", fontWeight: 700, color: "var(--text-main)" }}>{label}</span>
                      {isDefault && (
                        <span style={{ fontSize: "9px", fontWeight: 700, letterSpacing: "0.4px", textTransform: "uppercase", color: "var(--accent-cyan)", background: "rgba(56,189,248,0.12)", border: "1px solid rgba(56,189,248,0.25)", padding: "1px 5px", borderRadius: "999px" }}>
                          Par défaut
                        </span>
                      )}
                    </div>
                    <div style={{ fontSize: "11px", color: "var(--text-muted)", marginTop: "2px", lineHeight: 1.3 }}>{desc}</div>
                  </div>
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: "8px", flexShrink: 0 }}>
                  {canEdit && key !== "host_agent" && (
                    <button
                      type="button"
                      title="Modifier la liaison"
                      aria-label={`Modifier la liaison ${label}`}
                      onClick={() => setWizard({ open: true, source: key, mode: "edit" })}
                      style={{
                        width: "28px",
                        height: "28px",
                        borderRadius: "8px",
                        border: "1px solid var(--border)",
                        background: "rgba(255,255,255,0.04)",
                        color: "var(--text-muted)",
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        cursor: "pointer",
                      }}
                    >
                      <PenLine size={14} />
                    </button>
                  )}
                  <button
                    type="button"
                    role="switch"
                    aria-checked={checked}
                    aria-label={`Activer ${label}`}
                    title={canEdit ? (checked ? `Désactiver ${label}` : `Activer ${label}`) : "Nécessite un compte analyste"}
                    disabled={disabled}
                    onClick={() => handleToggle(key)}
                    style={{
                      width: "40px",
                      height: "22px",
                      borderRadius: "999px",
                      border: "1px solid var(--border)",
                      background: checked ? "rgba(56,189,248,0.9)" : "rgba(255,255,255,0.12)",
                      position: "relative",
                      cursor: disabled ? "not-allowed" : "pointer",
                      flexShrink: 0,
                      transition: "background 0.2s",
                      padding: 0,
                    }}
                  >
                    <span
                      style={{
                        position: "absolute",
                        top: "2px",
                        left: checked ? "18px" : "2px",
                        width: "16px",
                        height: "16px",
                        borderRadius: "50%",
                        background: "#fff",
                        boxShadow: "0 1px 4px rgba(0,0,0,0.3)",
                        transition: "left 0.2s",
                      }}
                    />
                  </button>
                </div>
              </div>
            );
          })}
        </div>
        {!canEdit && (
          <div style={{ marginTop: "10px", display: "flex", alignItems: "center", gap: "6px", fontSize: "11px", color: "var(--text-muted)" }}>
            <Lock size={11} /> Réservé aux comptes analyste ou supérieur.
          </div>
        )}
      </div>
      <SourceConfigWizard open={wizard.open} source={wizard.source} mode={wizard.mode} onClose={() => setWizard({ open: false, source: null, mode: "activate" })} onSuccess={handleWizardSuccess} />
    </>
    );
  }

  // Settings variant (full)
  return (
    <>
    <div className="section-card" style={{ marginBottom: "20px" }}>
      <div className="section-header" style={{ padding: "18px 24px", borderLeft: "4px solid var(--accent-cyan)" }}>
        <h3 style={{ margin: 0, display: "flex", alignItems: "center", gap: "10px", fontSize: "16px" }}>
          <Cpu size={18} color="var(--accent-cyan)" /> Sources de détection
        </h3>
        {!canEdit && (
          <span style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "11px", color: "var(--text-muted)", background: "rgba(255,255,255,0.06)", border: "1px solid var(--border)", padding: "4px 8px", borderRadius: "999px" }}>
            <Lock size={12} /> Nécessite un compte analyste
          </span>
        )}
      </div>
      <div style={{ padding: "20px 24px" }}>
        <p style={{ color: "var(--text-muted)", fontSize: "13px", margin: "0 0 16px 0", lineHeight: 1.5 }}>
          Activez ou désactivez les flux qui alimentent la chasse et les alertes. Les changements sont pris en compte immédiatement.
        </p>
        <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
          {SOURCES_META.map(({ key, label, desc, Icon, isDefault }) => {
            const checked = !!sources[key];
            const isSaving = saving === key;
            const disabled = isSaving || !canEdit;
            return (
              <div
                key={key}
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  gap: "16px",
                  padding: "14px 16px",
                  background: "rgba(255,255,255,0.03)",
                  border: "1px solid var(--border)",
                  borderRadius: "12px",
                  opacity: isSaving ? 0.6 : 1,
                  transition: "opacity 0.2s",
                }}
              >
                <div style={{ display: "flex", gap: "12px", alignItems: "flex-start", minWidth: 0 }}>
                  <div style={{ width: "36px", height: "36px", borderRadius: "10px", background: checked ? "rgba(56,189,248,0.15)" : "rgba(255,255,255,0.04)", border: "1px solid var(--border)", display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
                    <Icon size={16} color={checked ? "var(--accent-cyan)" : "var(--text-muted)"} />
                  </div>
                  <div style={{ minWidth: 0 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "8px", flexWrap: "wrap" }}>
                      <span style={{ fontSize: "14px", fontWeight: 700, color: "var(--text-primary)" }}>{label}</span>
                      {isDefault && (
                        <span style={{ fontSize: "10px", fontWeight: 700, letterSpacing: "0.4px", textTransform: "uppercase", color: "var(--accent-cyan)", background: "rgba(56,189,248,0.12)", border: "1px solid rgba(56,189,248,0.25)", padding: "2px 6px", borderRadius: "999px" }}>
                          Par défaut
                        </span>
                      )}
                      {isSaving && <span style={{ fontSize: "11px", color: "var(--text-muted)" }}>enregistrement…</span>}
                    </div>
                    <div style={{ fontSize: "12px", color: "var(--text-muted)", marginTop: "4px", lineHeight: 1.4 }}>{desc}</div>
                  </div>
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: "8px", flexShrink: 0 }}>
                  {canEdit && key !== "host_agent" && (
                    <button
                      type="button"
                      title="Modifier la liaison"
                      aria-label={`Modifier la liaison ${label}`}
                      onClick={() => setWizard({ open: true, source: key, mode: "edit" })}
                      style={{
                        width: "32px",
                        height: "32px",
                        borderRadius: "8px",
                        border: "1px solid var(--border)",
                        background: "rgba(255,255,255,0.04)",
                        color: "var(--text-muted)",
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        cursor: "pointer",
                      }}
                    >
                      <PenLine size={16} />
                    </button>
                  )}
                  <button
                    type="button"
                    role="switch"
                    aria-checked={checked}
                    aria-label={`Activer ${label}`}
                    title={canEdit ? (checked ? `Désactiver ${label}` : `Activer ${label}`) : "Nécessite un compte analyste"}
                    disabled={disabled}
                    onClick={() => handleToggle(key)}
                    style={{
                      width: "44px",
                      height: "26px",
                      borderRadius: "999px",
                      border: "1px solid var(--border)",
                      background: checked ? "rgba(56,189,248,0.9)" : "rgba(255,255,255,0.12)",
                      position: "relative",
                      cursor: disabled ? "not-allowed" : "pointer",
                      flexShrink: 0,
                      transition: "background 0.2s, opacity 0.2s",
                      padding: 0,
                    }}
                  >
                    <span
                      style={{
                        position: "absolute",
                        top: "2px",
                        left: checked ? "20px" : "2px",
                        width: "20px",
                        height: "20px",
                        borderRadius: "50%",
                        background: "#fff",
                        boxShadow: "0 1px 4px rgba(0,0,0,0.3)",
                        transition: "left 0.2s",
                      }}
                    />
                  </button>
                </div>
              </div>
            );
          })}
        </div>
        {!canEdit && (
          <div style={{ marginTop: "12px", display: "flex", alignItems: "center", gap: "6px", fontSize: "12px", color: "var(--text-muted)" }}>
            <Lock size={12} /> La modification des sources est réservée aux comptes analyste ou supérieur.
          </div>
        )}
      </div>
    </div>
    <SourceConfigWizard open={wizard.open} source={wizard.source} mode={wizard.mode} onClose={() => setWizard({ open: false, source: null, mode: "activate" })} onSuccess={handleWizardSuccess} />
    </>
  );
}
