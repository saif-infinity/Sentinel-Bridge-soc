import { useState, useEffect } from "react";
import { X, Eye, EyeOff, Shield, Server, Lock, CheckCircle2, Info, RefreshCw, Copy, Trash2, Check } from "lucide-react";
import { useAuth } from "../contexts/AuthContext";
import { toast } from "react-toastify";

function generateToken() {
  const bytes = new Uint8Array(24);
  crypto.getRandomValues(bytes);
  let binary = "";
  bytes.forEach((b) => (binary += String.fromCharCode(b)));
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function generateSlug() {
  const chars = "abcdefghijklmnopqrstuvwxyz0123456789_-";
  const len = 12;
  const bytes = new Uint8Array(len);
  crypto.getRandomValues(bytes);
  let s = "";
  for (let i = 0; i < len; i++) s += chars[bytes[i] % chars.length];
  return s;
}
const SLUG_REGEX = /^[A-Za-z0-9_-]{1,64}$/;

export default function SourceConfigWizard({ open, source, onClose, onSuccess, mode = "activate" }) {
  const { fetchWithAuth, headers, hasRole } = useAuth();
  const canEdit = hasRole ? hasRole("analyst") : false;
  const [method, setMethod] = useState(null);
  const [fields, setFields] = useState({});
  const [visible, setVisible] = useState({});
  const [saving, setSaving] = useState(false);
  const [passwordSet, setPasswordSet] = useState(false);
  const [indexerPasswordSet, setIndexerPasswordSet] = useState(false);
  const [webhookToken, setWebhookToken] = useState("");
  const [webhookTokenSet, setWebhookTokenSet] = useState(false);
  const [webhookSlug, setWebhookSlug] = useState("");
  const [eraseToken, setEraseToken] = useState(false);
  const [copied, setCopied] = useState(false);
  const [urlCopied, setUrlCopied] = useState(false);
  const [hasLegacyUrl, setHasLegacyUrl] = useState(false);

  const isWazuh = source === "wazuh";
  const isEdit = mode === "edit";
  const title = isWazuh ? "Configurer Wazuh" : "Configurer Suricata";
  const webhookPath = isWazuh ? "/api/wazuh/webhook" : "/api/suricata/webhook";

  // reset on open/source/mode change
  useEffect(() => {
    if (open && source) {
      (async () => {
        try {
          const res = await fetchWithAuth("/api/settings/sources/config", { headers, silent: true });
          if (res.ok) {
            const data = await res.json();
            const cfg = data[source];
            if (cfg?.method) setMethod(cfg.method);
            else setMethod(null);

            if (cfg?.fields) {
              const f = cfg.fields;
              if (mode === "edit") {
                const next = {};
                if (isWazuh) {
                  if (cfg.method === "api_indexer" || f.url || f.user) {
                    next.url = f.url || "";
                    next.user = f.user || "";
                    next.indexer_url = f.indexer_url || f.indexerUrl || "";
                    next.indexer_user = f.indexer_user || f.indexerUser || "";
                  }
                } else {
                  if (cfg.method === "ssh" || f.host) {
                    next.host = f.host || "";
                    next.port = f.port ? String(f.port) : "22";
                    next.user = f.user || "";
                  }
                }
                setFields(next);
              } else {
                setFields({});
              }
              setPasswordSet(!!f.password_set);
              setIndexerPasswordSet(!!(f.indexer_password_set || f.indexerPasswordSet));
              setWebhookTokenSet(!!f.token_set);
              // slug depuis f.url
              if (f.url && typeof f.url === "string" && f.url.startsWith("/api/")) {
                const seg = f.url.split("/").pop();
                // si url == webhookPath (legacy partagé) -> slug vide
                if (f.url === webhookPath) {
                  setWebhookSlug("");
                  setHasLegacyUrl(false);
                } else {
                  setWebhookSlug(seg || "");
                  setHasLegacyUrl(false);
                }
              } else if (f.url === undefined) {
                // backend ancien sans url
                setWebhookSlug("");
                setHasLegacyUrl(true);
              } else {
                setWebhookSlug("");
                setHasLegacyUrl(false);
              }
              // ancien backend sans url champ -> a legacy
              if (!f.url && cfg.method === "webhook") {
                setHasLegacyUrl(true);
              }
            } else {
              setFields({});
              setPasswordSet(false);
              setIndexerPasswordSet(false);
              setWebhookTokenSet(false);
              setWebhookSlug("");
              setHasLegacyUrl(false);
            }
          } else {
            setMethod(null);
            setFields({});
            setPasswordSet(false);
            setIndexerPasswordSet(false);
            setWebhookTokenSet(false);
            setWebhookSlug("");
            setHasLegacyUrl(res.status === 404);
          }
        } catch {
          setMethod(null);
          setFields({});
          setPasswordSet(false);
          setIndexerPasswordSet(false);
          setWebhookTokenSet(false);
          setWebhookSlug("");
          setHasLegacyUrl(true);
        }
        setVisible({});
        setWebhookToken("");
        setEraseToken(false);
        setCopied(false);
        setUrlCopied(false);
      })();
    }
  }, [open, source, mode, fetchWithAuth, headers, isWazuh, webhookPath]);

  if (!open || !source) return null;

  const updateField = (k, v) => setFields((p) => ({ ...p, [k]: v }));
  const toggleVisible = (k) => setVisible((p) => ({ ...p, [k]: !p[k] }));

  const handleGenerate = () => {
    if (!canEdit) return;
    setWebhookToken(generateToken());
    setEraseToken(false);
  };
  const handleGenerateSlug = () => {
    if (!canEdit) return;
    setWebhookSlug(generateSlug());
  };
  const handleCopy = async () => {
    if (!webhookToken) return;
    try {
      await navigator.clipboard.writeText(webhookToken);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      toast.error("Copie impossible");
    }
  };
  const handleCopyUrl = async () => {
    const full = webhookSlug ? `${window.location.origin}${webhookPath}/${webhookSlug}` : `${window.location.origin}${webhookPath}`;
    try {
      await navigator.clipboard.writeText(full);
      setUrlCopied(true);
      setTimeout(() => setUrlCopied(false), 1500);
    } catch {
      toast.error("Copie impossible");
    }
  };

  const isWebhook = method === "webhook";
  const isWazuhApi = isWazuh && method === "api_indexer";
  const isSuricataSsh = !isWazuh && method === "ssh";

  const slugValid = webhookSlug === "" || SLUG_REGEX.test(webhookSlug.trim());
  const fullUrl = webhookSlug ? `${window.location.origin}${webhookPath}/${webhookSlug}` : `${window.location.origin}${webhookPath}`;

  const canActivate = (() => {
    if (!canEdit) return false;
    if (!method) return false;
    if (isWebhook) return slugValid;
    if (isWazuhApi) {
      return ["url", "user", "indexer_url", "indexer_user"].every((k) => (fields[k] || "").trim() !== "") &&
        (isEdit && passwordSet ? true : (fields.password || "").trim() !== "") &&
        (isEdit && indexerPasswordSet ? true : (fields.indexer_password || "").trim() !== "");
    }
    if (isSuricataSsh) {
      return ["host", "port", "user"].every((k) => (fields[k] || "").toString().trim() !== "") &&
        (isEdit && passwordSet ? true : (fields.password || "").toString().trim() !== "");
    }
    return false;
  })();

  const handleSave = async () => {
    if (!canActivate || saving) return;
    if (isWebhook && !slugValid) {
      toast.error("Ce chemin est déjà utilisé — choisissez-en un autre.");
      return;
    }
    setSaving(true);
    try {
      const data = {};
      if (isWazuhApi) {
        data.url = fields.url.trim();
        data.user = fields.user.trim();
        data.indexer_url = fields.indexer_url.trim();
        data.indexer_user = fields.indexer_user.trim();
        if ((fields.password || "").trim() !== "") data.password = fields.password;
        if ((fields.indexer_password || "").trim() !== "") data.indexer_password = fields.indexer_password;
      } else if (isSuricataSsh) {
        data.host = fields.host.trim();
        data.port = parseInt(fields.port, 10) || 22;
        data.user = fields.user.trim();
        if ((fields.password || "").toString().trim() !== "") data.password = fields.password;
      } else if (isWebhook) {
        if (webhookSlug.trim() !== "") {
          if (!SLUG_REGEX.test(webhookSlug.trim())) {
            toast.error("Lettres, chiffres, tirets et underscores uniquement (max 64).");
            setSaving(false);
            return;
          }
          data.slug = webhookSlug.trim();
        }
        if (eraseToken) data.token = "";
        else if ((webhookToken || "").trim() !== "") data.token = webhookToken.trim();
      }

      if (isEdit) {
        const resCfg = await fetchWithAuth("/api/settings/sources/config", {
          method: "PUT",
          headers: { ...headers, "Content-Type": "application/json" },
          body: JSON.stringify({ source, method, data }),
        });
        if (!resCfg.ok) {
          if (resCfg.status === 403) toast.error("Modification réservée à un compte analyste ou supérieur");
          else if (resCfg.status === 409) toast.error("Ce chemin est déjà utilisé — choisissez-en un autre.");
          else {
            const j = await resCfg.clone().json().catch(() => ({}));
            if (j?.detail) toast.error(j.detail);
          }
          setSaving(false);
          return;
        }
        // refetch pour lazy-gen si slug vide
        if (isWebhook) {
          try {
            const r2 = await fetchWithAuth("/api/settings/sources/config", { headers, silent: true });
            if (r2.ok) {
              const d2 = await r2.json();
              const f2 = d2[source]?.fields;
              if (f2?.url) {
                const seg = f2.url.split("/").pop();
                setWebhookSlug(seg || webhookSlug);
              }
            }
          } catch {}
        }
        toast.success("Liaison mise à jour");
        window.dispatchEvent(new CustomEvent("sources-changed"));
        onSuccess && onSuccess();
        onClose();
      } else {
        const resCfg = await fetchWithAuth("/api/settings/sources/config", {
          method: "PUT",
          headers: { ...headers, "Content-Type": "application/json" },
          body: JSON.stringify({ source, method, data }),
        });
        if (!resCfg.ok) {
          if (resCfg.status === 403) toast.error("Modification réservée à un compte analyste ou supérieur");
          else if (resCfg.status === 409) toast.error("Ce chemin est déjà utilisé — choisissez-en un autre.");
          else {
            const j = await resCfg.clone().json().catch(() => ({}));
            if (j?.detail) toast.error(j.detail);
          }
          setSaving(false);
          return;
        }
        // webhook lazy-gen: refetch url si slug vide
        if (isWebhook && !webhookSlug.trim()) {
          try {
            const r2 = await fetchWithAuth("/api/settings/sources/config", { headers, silent: true });
            if (r2.ok) {
              const d2 = await r2.json();
              const f2 = d2[source]?.fields;
              if (f2?.url) setWebhookSlug(f2.url.split("/").pop() || "");
            }
          } catch {}
        }
        const resSrc = await fetchWithAuth("/api/settings/sources", {
          method: "PUT",
          headers: { ...headers, "Content-Type": "application/json" },
          body: JSON.stringify({ [source]: true }),
        });
        if (!resSrc.ok) {
          if (resSrc.status === 403) toast.error("Modification réservée à un compte analyste ou supérieur");
          setSaving(false);
          return;
        }
        toast.success(`${isWazuh ? "Wazuh" : "Suricata"} configurée et activée`);
        window.dispatchEvent(new CustomEvent("sources-changed"));
        onSuccess && onSuccess();
        onClose();
      }
    } catch {
      toast.error("Erreur réseau");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(0,0,0,0.6)",
        backdropFilter: "blur(4px)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        zIndex: 100,
        padding: "16px",
      }}
      onClick={onClose}
    >
      <div
        className="section-card"
        style={{ width: "100%", maxWidth: "560px", maxHeight: "90vh", overflowY: "auto", padding: 0 }}
        onClick={(e) => e.stopPropagation()}
      >
        <div style={{ padding: "20px 24px", borderBottom: "1px solid var(--border)", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
          <h3 style={{ margin: 0, display: "flex", alignItems: "center", gap: "8px", fontSize: "16px" }}>
            {isWazuh ? <Shield size={18} color="var(--accent-cyan)" /> : <Server size={18} color="var(--accent-cyan)" />} {title}
          </h3>
          <button onClick={onClose} style={{ background: "none", border: "none", color: "var(--text-muted)", cursor: "pointer", padding: "4px" }} aria-label="Fermer">
            <X size={18} />
          </button>
        </div>

        <div style={{ padding: "20px 24px", display: "flex", flexDirection: "column", gap: "18px" }}>
          {!canEdit && (
            <div style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "12px", color: "var(--text-muted)", background: "rgba(255,255,255,0.04)", border: "1px solid var(--border)", padding: "8px 10px", borderRadius: "8px" }}>
              <Lock size={12} /> Nécessite un compte analyste — lecture seule.
            </div>
          )}

          <div>
            <div style={{ fontSize: "12px", color: "var(--text-muted)", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.5px", marginBottom: "8px" }}>
              Méthode de connexion
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px" }}>
              {isWazuh ? (
                <>
                  <button
                    type="button"
                    onClick={() => canEdit && setMethod("webhook")}
                    disabled={!canEdit}
                    style={{
                      textAlign: "left",
                      padding: "14px",
                      borderRadius: "12px",
                      border: method === "webhook" ? "1px solid var(--accent-cyan)" : "1px solid var(--border)",
                      background: method === "webhook" ? "rgba(56,189,248,0.08)" : "rgba(255,255,255,0.03)",
                      cursor: canEdit ? "pointer" : "not-allowed",
                      opacity: canEdit ? 1 : 0.7,
                    }}
                  >
                    <div style={{ fontSize: "13px", fontWeight: 700, color: "var(--text-main)", display: "flex", alignItems: "center", gap: "6px" }}>
                      {method === "webhook" && <CheckCircle2 size={14} color="var(--accent-cyan)" />} Webhook
                    </div>
                    <div style={{ fontSize: "11px", color: "var(--text-muted)", marginTop: "4px", lineHeight: 1.4 }}>Réception passive — aucune config requise.</div>
                  </button>
                  <button
                    type="button"
                    onClick={() => canEdit && setMethod("api_indexer")}
                    disabled={!canEdit}
                    style={{
                      textAlign: "left",
                      padding: "14px",
                      borderRadius: "12px",
                      border: method === "api_indexer" ? "1px solid var(--accent-cyan)" : "1px solid var(--border)",
                      background: method === "api_indexer" ? "rgba(56,189,248,0.08)" : "rgba(255,255,255,0.03)",
                      cursor: canEdit ? "pointer" : "not-allowed",
                      opacity: canEdit ? 1 : 0.7,
                    }}
                  >
                    <div style={{ fontSize: "13px", fontWeight: 700, color: "var(--text-main)", display: "flex", alignItems: "center", gap: "6px" }}>
                      {method === "api_indexer" && <CheckCircle2 size={14} color="var(--accent-cyan)" />} API + Indexer
                    </div>
                    <div style={{ fontSize: "11px", color: "var(--text-muted)", marginTop: "4px", lineHeight: 1.4 }}>Lecture des journaux via API Wazuh et Indexer.</div>
                  </button>
                </>
              ) : (
                <>
                  <button
                    type="button"
                    onClick={() => canEdit && setMethod("webhook")}
                    disabled={!canEdit}
                    style={{
                      textAlign: "left",
                      padding: "14px",
                      borderRadius: "12px",
                      border: method === "webhook" ? "1px solid var(--accent-cyan)" : "1px solid var(--border)",
                      background: method === "webhook" ? "rgba(56,189,248,0.08)" : "rgba(255,255,255,0.03)",
                      cursor: canEdit ? "pointer" : "not-allowed",
                      opacity: canEdit ? 1 : 0.7,
                    }}
                  >
                    <div style={{ fontSize: "13px", fontWeight: 700, color: "var(--text-main)", display: "flex", alignItems: "center", gap: "6px" }}>
                      {method === "webhook" && <CheckCircle2 size={14} color="var(--accent-cyan)" />} Webhook
                    </div>
                    <div style={{ fontSize: "11px", color: "var(--text-muted)", marginTop: "4px", lineHeight: 1.4 }}>Réception passive — aucune config requise.</div>
                  </button>
                  <button
                    type="button"
                    onClick={() => canEdit && setMethod("ssh")}
                    disabled={!canEdit}
                    style={{
                      textAlign: "left",
                      padding: "14px",
                      borderRadius: "12px",
                      border: method === "ssh" ? "1px solid var(--accent-cyan)" : "1px solid var(--border)",
                      background: method === "ssh" ? "rgba(56,189,248,0.08)" : "rgba(255,255,255,0.03)",
                      cursor: canEdit ? "pointer" : "not-allowed",
                      opacity: canEdit ? 1 : 0.7,
                    }}
                  >
                    <div style={{ fontSize: "13px", fontWeight: 700, color: "var(--text-main)", display: "flex", alignItems: "center", gap: "6px" }}>
                      {method === "ssh" && <CheckCircle2 size={14} color="var(--accent-cyan)" />} Connexion SSH
                    </div>
                    <div style={{ fontSize: "11px", color: "var(--text-muted)", marginTop: "4px", lineHeight: 1.4 }}>Lecture des journaux via SSH.</div>
                  </button>
                </>
              )}
            </div>
          </div>

          {isWebhook && (
            <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
              <div style={{ display: "flex", gap: "8px", alignItems: "flex-start", background: "rgba(56,189,248,0.06)", border: "1px solid rgba(56,189,248,0.15)", padding: "10px 12px", borderRadius: "8px", fontSize: "12px", color: "var(--text-muted)", lineHeight: 1.4 }}>
                <Info size={14} color="var(--accent-cyan)" style={{ marginTop: "1px", flexShrink: 0 }} />
                <span>Chemin unique de votre choix — le SOC reconnaît la source par ce chemin. Ex. <code style={{ background: "rgba(255,255,255,0.06)", padding: "1px 4px", borderRadius: "4px", fontFamily: "monospace", fontSize: "11px" }}>{webhookPath}/mon-soc</code>.</span>
              </div>

              <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
                <label style={{ fontSize: "11px", color: "var(--text-muted)", fontWeight: 600, textTransform: "uppercase" }}>Chemin du webhook</label>
                <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
                  <div style={{ flex: 1, display: "flex", alignItems: "center", gap: "6px", padding: "8px 10px", background: "rgba(255,255,255,0.03)", border: `1px solid ${!slugValid ? "#ef4444" : "var(--border)"}`, borderRadius: "8px", fontFamily: "monospace", fontSize: "11px", color: "var(--text-main)" }}>
                    <span style={{ color: "var(--text-muted)", whiteSpace: "nowrap" }}>{webhookPath}/</span>
                    <input
                      value={webhookSlug}
                      onChange={(e) => setWebhookSlug(e.target.value)}
                      disabled={!canEdit}
                      placeholder="mon-soc"
                      style={{ flex: 1, background: "transparent", border: "none", outline: "none", color: "var(--text-main)", fontFamily: "monospace", fontSize: "11px", minWidth: 0 }}
                    />
                  </div>
                  <button type="button" onClick={() => { if (canEdit) setWebhookSlug(generateSlug()); }} disabled={!canEdit} title="Générer un chemin" style={{ padding: "8px 10px", background: "rgba(255,255,255,0.06)", border: "1px solid var(--border)", borderRadius: "8px", color: canEdit ? "var(--accent-cyan)" : "var(--text-muted)", cursor: canEdit ? "pointer" : "not-allowed", display: "flex", alignItems: "center", gap: "4px", fontSize: "12px", flexShrink: 0 }}>
                    <RefreshCw size={14} /> Générer
                  </button>
                </div>
                {!slugValid && <div style={{ fontSize: "11px", color: "#ef4444" }}>Lettres, chiffres, tirets et underscores uniquement (max 64).</div>}
                {webhookSlug === "" && <div style={{ fontSize: "11px", color: "var(--text-muted)" }}>Vide → un chemin unique sera généré à l'enregistrement (chemin partagé : <code style={{ fontFamily: "monospace", fontSize: "10px" }}>{webhookPath}</code>).</div>}
                {hasLegacyUrl && webhookSlug === "" && <div style={{ fontSize: "10px", color: "var(--text-muted)" }}>(chemin partagé — backend pas encore à jour)</div>}
              </div>

              <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
                <label style={{ fontSize: "11px", color: "var(--text-muted)", fontWeight: 600, textTransform: "uppercase" }}>URL complète</label>
                <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
                  <input readOnly value={fullUrl} style={{ flex: 1, padding: "8px 10px", background: "rgba(255,255,255,0.03)", border: "1px solid var(--border)", borderRadius: "8px", color: "var(--text-main)", fontSize: "11px", fontFamily: "monospace" }} />
                  <button type="button" onClick={handleCopyUrl} style={{ padding: "8px 10px", background: "rgba(255,255,255,0.06)", border: "1px solid var(--border)", borderRadius: "8px", color: "var(--text-muted)", cursor: "pointer", display: "flex", alignItems: "center", gap: "4px", fontSize: "12px", flexShrink: 0 }}>
                    {urlCopied ? <Check size={14} color="var(--success)" /> : <Copy size={14} />} {urlCopied ? "Copié ✓" : "Copier"}
                  </button>
                </div>
              </div>

              <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
                <label style={{ fontSize: "11px", color: "var(--text-muted)", fontWeight: 600, textTransform: "uppercase" }}>Token webhook {isEdit && webhookTokenSet && <span style={{ textTransform: "none", fontWeight: 400, fontSize: "10px" }}>(laisser vide pour conserver)</span>}</label>
                <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
                  <div style={{ position: "relative", display: "flex", alignItems: "center", flex: 1 }}>
                    <input
                      type={visible.webhookToken ? "text" : "password"}
                      value={webhookToken}
                      onChange={(e) => { setWebhookToken(e.target.value); setEraseToken(false); }}
                      disabled={!canEdit}
                      placeholder={isEdit && webhookTokenSet ? "•••••••• (conservé)" : "Optionnel — laisser vide si non utilisé"}
                      style={{ width: "100%", padding: "8px 32px 8px 10px", background: "rgba(255,255,255,0.03)", border: "1px solid var(--border)", borderRadius: "8px", color: "var(--text-main)", fontSize: "13px", fontFamily: "monospace" }}
                    />
                    <button type="button" onClick={() => toggleVisible("webhookToken")} style={{ position: "absolute", right: "8px", background: "none", border: "none", color: "var(--text-muted)", cursor: "pointer" }}>
                      {visible.webhookToken ? <EyeOff size={14} /> : <Eye size={14} />}
                    </button>
                  </div>
                  <button type="button" onClick={handleGenerate} disabled={!canEdit} title="Générer un token" style={{ padding: "8px 10px", background: "rgba(255,255,255,0.06)", border: "1px solid var(--border)", borderRadius: "8px", color: canEdit ? "var(--accent-cyan)" : "var(--text-muted)", cursor: canEdit ? "pointer" : "not-allowed", display: "flex", alignItems: "center", gap: "4px", fontSize: "12px", flexShrink: 0 }}>
                    <RefreshCw size={14} /> Générer
                  </button>
                  {webhookToken && (
                    <button type="button" onClick={handleCopy} style={{ padding: "8px 10px", background: "rgba(255,255,255,0.06)", border: "1px solid var(--border)", borderRadius: "8px", color: "var(--text-muted)", cursor: "pointer", display: "flex", alignItems: "center", gap: "4px", fontSize: "12px", flexShrink: 0 }}>
                      {copied ? <Check size={14} color="var(--success)" /> : <Copy size={14} />} {copied ? "Copié ✓" : "Copier"}
                    </button>
                  )}
                </div>
                {isEdit && webhookTokenSet && !eraseToken && (
                  <button type="button" onClick={() => { setEraseToken(true); setWebhookToken(""); }} disabled={!canEdit} style={{ alignSelf: "flex-start", background: "none", border: "none", color: "var(--text-muted)", fontSize: "11px", cursor: "pointer", display: "flex", alignItems: "center", gap: "4px", padding: 0 }}>
                    <Trash2 size={12} /> Effacer le token
                  </button>
                )}
                {eraseToken && (
                  <div style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "11px", color: "#f87171" }}>
                    <Trash2 size={12} /> Le token sera effacé à l’enregistrement.
                    <button type="button" onClick={() => setEraseToken(false)} style={{ background: "none", border: "none", color: "var(--accent-cyan)", cursor: "pointer", fontSize: "11px", textDecoration: "underline" }}>Annuler</button>
                  </div>
                )}
              </div>
            </div>
          )}

          {isWazuhApi && (
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px" }}>
              <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
                <label style={{ fontSize: "11px", color: "var(--text-muted)", fontWeight: 600, textTransform: "uppercase" }}>URL API Wazuh</label>
                <input value={fields.url || ""} onChange={(e) => updateField("url", e.target.value)} disabled={!canEdit} placeholder="https://wazuh:55000" style={{ padding: "8px 10px", background: "rgba(255,255,255,0.03)", border: "1px solid var(--border)", borderRadius: "8px", color: "var(--text-main)", fontSize: "13px" }} />
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
                <label style={{ fontSize: "11px", color: "var(--text-muted)", fontWeight: 600, textTransform: "uppercase" }}>Utilisateur API</label>
                <input value={fields.user || ""} onChange={(e) => updateField("user", e.target.value)} disabled={!canEdit} placeholder="wazuh-wui" style={{ padding: "8px 10px", background: "rgba(255,255,255,0.03)", border: "1px solid var(--border)", borderRadius: "8px", color: "var(--text-main)", fontSize: "13px" }} />
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
                <label style={{ fontSize: "11px", color: "var(--text-muted)", fontWeight: 600, textTransform: "uppercase" }}>Mot de passe API {isEdit && passwordSet && <span style={{ textTransform: "none", fontWeight: 400, fontSize: "10px" }}>(laisser vide pour conserver)</span>}</label>
                <div style={{ position: "relative", display: "flex", alignItems: "center" }}>
                  <input type={visible.password ? "text" : "password"} value={fields.password || ""} onChange={(e) => updateField("password", e.target.value)} disabled={!canEdit} placeholder={isEdit && passwordSet ? "•••••••• (conservé)" : "••••••••"} style={{ width: "100%", padding: "8px 32px 8px 10px", background: "rgba(255,255,255,0.03)", border: "1px solid var(--border)", borderRadius: "8px", color: "var(--text-main)", fontSize: "13px" }} />
                  <button type="button" onClick={() => toggleVisible("password")} style={{ position: "absolute", right: "8px", background: "none", border: "none", color: "var(--text-muted)", cursor: "pointer" }}>
                    {visible.password ? <EyeOff size={14} /> : <Eye size={14} />}
                  </button>
                </div>
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
                <label style={{ fontSize: "11px", color: "var(--text-muted)", fontWeight: 600, textTransform: "uppercase" }}>URL Indexer</label>
                <input value={fields.indexer_url || ""} onChange={(e) => updateField("indexer_url", e.target.value)} disabled={!canEdit} placeholder="https://indexer:9200" style={{ padding: "8px 10px", background: "rgba(255,255,255,0.03)", border: "1px solid var(--border)", borderRadius: "8px", color: "var(--text-main)", fontSize: "13px" }} />
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
                <label style={{ fontSize: "11px", color: "var(--text-muted)", fontWeight: 600, textTransform: "uppercase" }}>Utilisateur Indexer</label>
                <input value={fields.indexer_user || ""} onChange={(e) => updateField("indexer_user", e.target.value)} disabled={!canEdit} placeholder="admin" style={{ padding: "8px 10px", background: "rgba(255,255,255,0.03)", border: "1px solid var(--border)", borderRadius: "8px", color: "var(--text-main)", fontSize: "13px" }} />
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
                <label style={{ fontSize: "11px", color: "var(--text-muted)", fontWeight: 600, textTransform: "uppercase" }}>Mot de passe Indexer {isEdit && indexerPasswordSet && <span style={{ textTransform: "none", fontWeight: 400, fontSize: "10px" }}>(laisser vide pour conserver)</span>}</label>
                <div style={{ position: "relative", display: "flex", alignItems: "center" }}>
                  <input type={visible.indexer_password ? "text" : "password"} value={fields.indexer_password || ""} onChange={(e) => updateField("indexer_password", e.target.value)} disabled={!canEdit} placeholder={isEdit && indexerPasswordSet ? "•••••••• (conservé)" : "••••••••"} style={{ width: "100%", padding: "8px 32px 8px 10px", background: "rgba(255,255,255,0.03)", border: "1px solid var(--border)", borderRadius: "8px", color: "var(--text-main)", fontSize: "13px" }} />
                  <button type="button" onClick={() => toggleVisible("indexer_password")} style={{ position: "absolute", right: "8px", background: "none", border: "none", color: "var(--text-muted)", cursor: "pointer" }}>
                    {visible.indexer_password ? <EyeOff size={14} /> : <Eye size={14} />}
                  </button>
                </div>
              </div>
            </div>
          )}

          {isSuricataSsh && (
            <div style={{ display: "grid", gridTemplateColumns: "1fr 80px", gap: "12px" }}>
              <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
                <label style={{ fontSize: "11px", color: "var(--text-muted)", fontWeight: 600, textTransform: "uppercase" }}>Hôte / IP</label>
                <input value={fields.host || ""} onChange={(e) => updateField("host", e.target.value)} disabled={!canEdit} placeholder="192.168.1.10" style={{ padding: "8px 10px", background: "rgba(255,255,255,0.03)", border: "1px solid var(--border)", borderRadius: "8px", color: "var(--text-main)", fontSize: "13px" }} />
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
                <label style={{ fontSize: "11px", color: "var(--text-muted)", fontWeight: 600, textTransform: "uppercase" }}>Port</label>
                <input value={fields.port || ""} onChange={(e) => updateField("port", e.target.value)} disabled={!canEdit} placeholder="22" type="number" style={{ padding: "8px 10px", background: "rgba(255,255,255,0.03)", border: "1px solid var(--border)", borderRadius: "8px", color: "var(--text-main)", fontSize: "13px" }} />
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
                <label style={{ fontSize: "11px", color: "var(--text-muted)", fontWeight: 600, textTransform: "uppercase" }}>Utilisateur</label>
                <input value={fields.user || ""} onChange={(e) => updateField("user", e.target.value)} disabled={!canEdit} placeholder="suricata" style={{ padding: "8px 10px", background: "rgba(255,255,255,0.03)", border: "1px solid var(--border)", borderRadius: "8px", color: "var(--text-main)", fontSize: "13px" }} />
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
                <label style={{ fontSize: "11px", color: "var(--text-muted)", fontWeight: 600, textTransform: "uppercase" }}>Mot de passe {isEdit && passwordSet && <span style={{ textTransform: "none", fontWeight: 400, fontSize: "10px" }}>(laisser vide pour conserver)</span>}</label>
                <div style={{ position: "relative", display: "flex", alignItems: "center" }}>
                  <input type={visible.password ? "text" : "password"} value={fields.password || ""} onChange={(e) => updateField("password", e.target.value)} disabled={!canEdit} placeholder={isEdit && passwordSet ? "•••••••• (conservé)" : "••••••••"} style={{ width: "100%", padding: "8px 32px 8px 10px", background: "rgba(255,255,255,0.03)", border: "1px solid var(--border)", borderRadius: "8px", color: "var(--text-main)", fontSize: "13px" }} />
                  <button type="button" onClick={() => toggleVisible("password")} style={{ position: "absolute", right: "8px", background: "none", border: "none", color: "var(--text-muted)", cursor: "pointer" }}>
                    {visible.password ? <EyeOff size={14} /> : <Eye size={14} />}
                  </button>
                </div>
              </div>
            </div>
          )}

          <div style={{ display: "flex", justifyContent: "flex-end", gap: "10px", paddingTop: "10px", borderTop: "1px solid var(--border)" }}>
            <button onClick={onClose} disabled={saving} style={{ padding: "8px 14px", background: "rgba(255,255,255,0.06)", border: "1px solid var(--border)", borderRadius: "8px", color: "var(--text-muted)", cursor: "pointer", fontSize: "13px" }}>
              Annuler
            </button>
            <button
              onClick={handleSave}
              disabled={!canActivate || saving}
              style={{
                padding: "8px 16px",
                background: canActivate && !saving ? "rgba(56,189,248,0.9)" : "rgba(255,255,255,0.12)",
                border: "1px solid var(--border)",
                borderRadius: "8px",
                color: canActivate && !saving ? "#fff" : "var(--text-muted)",
                cursor: canActivate && !saving ? "pointer" : "not-allowed",
                fontSize: "13px",
                fontWeight: 600,
              }}
            >
              {saving ? (isEdit ? "Enregistrement…" : "Activation…") : isEdit ? "Enregistrer la liaison" : "Activer"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
