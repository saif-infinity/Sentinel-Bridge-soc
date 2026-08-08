import { useState, useEffect, useCallback } from "react";
import { useAuth } from "../contexts/AuthContext";
import { toast } from "react-toastify";

const API = "/api/network-devices";

const DEVICE_ICONS = { switch: "🔌", router: "🌐" };

const BRAND_LABELS = {
  cisco: "Cisco", mikrotik: "MikroTik", huawei: "Huawei", juniper: "Juniper",
  arista: "Arista", aruba: "Aruba", dell: "Dell", fortinet: "Fortinet",
  ubiquiti: "Ubiquiti", extreme: "Extreme", netgear: "Netgear",
  dlink: "D-Link", tplink: "TP-Link", zyxel: "Zyxel",
  paloalto: "Palo Alto", sonicwall: "SonicWall",
};

/* Brand logo images — served from public/brand-logos/ */
const BRAND_LOGO_EXT = {
  cisco: "png", mikrotik: "svg", huawei: "png", juniper: "png",
  arista: "svg", aruba: "png", dell: "png", fortinet: "png",
  ubiquiti: "png", extreme: "svg", netgear: "png", dlink: "png",
  tplink: "png", zyxel: "svg", paloalto: "png", sonicwall: "svg",
};
const BrandLogo = ({ brand, size = 36, style = {} }) => (
  <img
    src={`/brand-logos/${brand}.${BRAND_LOGO_EXT[brand] || "png"}`}
    alt={BRAND_LABELS[brand] || brand}
    style={{ height: size, objectFit: "contain", ...style }}
    onError={(e) => { e.target.style.display = "none"; }}
  />
);

/* ─── Step Indicator ─────────────────────────────────────── */
function StepIndicator({ steps, current }) {
  const total = steps.length;
  const progress = total > 1 ? (current / (total - 1)) * 100 : 0;

  return (
    <div style={{ marginBottom: 28 }}>
      {/* Progress bar */}
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 10 }}>
        <span style={{ fontSize: 12, fontWeight: 700, color: "#00ff88", whiteSpace: "nowrap", fontFamily: "'Orbitron', sans-serif" }}>
          {current + 1}/{total}
        </span>
        <div style={{ flex: 1, height: 6, borderRadius: 3, background: "rgba(0,255,136,0.08)", overflow: "hidden" }}>
          <div style={{
            width: `${progress}%`, height: "100%", borderRadius: 3,
            background: "linear-gradient(90deg, #00ff88, #00cc6a)",
            transition: "width 0.4s ease",
          }} />
        </div>
      </div>
      {/* Current step label + dots */}
      <div style={{ display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap" }}>
        {steps.map((s, i) => {
          const active = i <= current;
          const isCurrent = i === current;
          if (isCurrent) {
            return (
              <span key={i} style={{
                fontSize: 13, fontWeight: 700, color: "#00ff88",
                background: "rgba(0,255,136,0.08)", padding: "4px 12px", borderRadius: 8,
                border: "1px solid rgba(0,255,136,0.2)", whiteSpace: "nowrap",
              }}>{s}</span>
            );
          }
          return (
            <div key={i} title={s} style={{
              width: 8, height: 8, borderRadius: "50%", flexShrink: 0,
              background: active ? "#00cc6a" : "rgba(0,255,136,0.12)",
              transition: "all 0.3s",
            }} />
          );
        })}
      </div>
    </div>
  );
}

/* ─── Reusable Form Fields ──────────────────────────────── */
function Field({ field, value, onChange }) {
  const base = {
    width: "100%", padding: "10px 14px", borderRadius: 10, border: "1px solid rgba(0,255,136,0.12)",
    background: "rgba(5,15,20,0.6)", color: "#c8d6e5", fontSize: 13, outline: "none",
    fontFamily: "'JetBrains Mono', monospace", transition: "border-color 0.2s",
  };
  const labelStyle = { fontSize: 12, fontWeight: 600, color: "#5a7a8a", marginBottom: 4, display: "block" };

  if (field.type === "select") {
    return (
      <div style={{ marginBottom: 14 }}>
        <label style={labelStyle}>{field.label}{field.required && " *"}</label>
        <select style={{ ...base, cursor: "pointer" }} value={value || ""} onChange={(e) => onChange(e.target.value)}>
          <option value="">Choisir...</option>
          {field.options?.map((o) => <option key={o} value={o}>{o}</option>)}
        </select>
      </div>
    );
  }
  if (field.type === "boolean") {
    return (
      <div style={{ marginBottom: 14, display: "flex", alignItems: "center", gap: 10 }}>
        <button
          onClick={() => onChange(!value)}
          style={{
            width: 40, height: 22, borderRadius: 11, border: "none", cursor: "pointer", position: "relative",
            background: value ? "linear-gradient(135deg, #00ff88, #00cc6a)" : "rgba(0,255,136,0.12)",
            transition: "background 0.2s",
          }}
        >
          <span style={{
            position: "absolute", top: 2, left: value ? 20 : 2, width: 18, height: 18,
            borderRadius: "50%", background: value ? "#050a0e" : "#5a7a8a", transition: "all 0.2s",
          }} />
        </button>
        <span style={{ fontSize: 13, color: "#c8d6e5" }}>{field.label}</span>
      </div>
    );
  }
  if (field.type === "password") {
    return (
      <div style={{ marginBottom: 14 }}>
        <label style={labelStyle}>{field.label}</label>
        <input type="password" style={base} value={value || ""} onChange={(e) => onChange(e.target.value)} placeholder="••••••••" />
      </div>
    );
  }
  if (field.type === "textarea") {
    return (
      <div style={{ marginBottom: 14 }}>
        <label style={labelStyle}>{field.label}</label>
        <textarea
          style={{ ...base, minHeight: 70, resize: "vertical" }}
          value={value || ""} onChange={(e) => onChange(e.target.value)}
          placeholder="Un par ligne..."
        />
      </div>
    );
  }
  // default: text / number
  return (
    <div style={{ marginBottom: 14 }}>
      <label style={labelStyle}>{field.label}{field.required && " *"}</label>
      <input
        type={field.type === "number" ? "number" : "text"}
        style={base} value={value || ""} onChange={(e) => onChange(e.target.value)}
      />
    </div>
  );
}

/* ─── List Editor (puzzle pieces) ────────────────────────── */
function ListEditor({ field, values, onChange }) {
  const items = Array.isArray(values) ? values : [];
  const addItem = () => {
    const newItem = {};
    field.item_fields?.forEach((f) => { newItem[f.name] = f.default || (f.type === "boolean" ? false : ""); });
    onChange([...items, newItem]);
  };
  const updateItem = (idx, key, val) => {
    const copy = [...items];
    copy[idx] = { ...copy[idx], [key]: val };
    onChange(copy);
  };
  const removeItem = (idx) => onChange(items.filter((_, i) => i !== idx));

  return (
    <div style={{ marginBottom: 20, border: "1px solid rgba(0,255,136,0.08)", borderRadius: 12, padding: 16 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
        <span style={{ fontSize: 14, fontWeight: 700, color: "#e0f2f1" }}>{field.label}</span>
        <button onClick={addItem} style={{
          padding: "6px 14px", borderRadius: 8, border: "1px solid rgba(0,255,136,0.2)",
          background: "rgba(0,255,136,0.06)", color: "#00ff88", fontSize: 12, fontWeight: 600, cursor: "pointer",
        }}>+ Ajouter</button>
      </div>
      {items.length === 0 && <div style={{ fontSize: 12, color: "var(--text-muted)", fontStyle: "italic" }}>Aucun élément — cliquez "+ Ajouter"</div>}
      {items.map((item, idx) => (
        <div key={idx} style={{
          display: "grid", gridTemplateColumns: `repeat(${Math.min(field.item_fields?.length || 1, 4)}, 1fr)`,
          gap: 10, padding: 12, marginBottom: 8, borderRadius: 10,
          background: "rgba(5,15,20,0.5)", border: "1px solid rgba(0,255,136,0.06)", position: "relative",
        }}>
          {field.item_fields?.map((f) => (
            <Field key={f.name} field={f} value={item[f.name]} onChange={(v) => updateItem(idx, f.name, v)} />
          ))}
          <button
            onClick={() => removeItem(idx)}
            style={{
              position: "absolute", top: 6, right: 6, width: 22, height: 22, borderRadius: "50%",
              border: "none", background: "rgba(255,107,107,0.15)", color: "#ff6b6b", cursor: "pointer",
              fontSize: 12, display: "flex", alignItems: "center", justifyContent: "center",
            }}>×</button>
        </div>
      ))}
    </div>
  );
}

/* ─── Config Section (group or list) ─────────────────────── */
function ConfigSection({ sectionKey, section, config, setConfig }) {
  const sectionConfig = config[sectionKey] || {};
  const setSection = (val) => setConfig((prev) => ({ ...prev, [sectionKey]: val }));

  if (section.type === "list") {
    return <ListEditor field={section} values={sectionConfig} onChange={setSection} />;
  }
  if (section.type === "group") {
    return (
      <div style={{
        border: "1px solid rgba(0,255,136,0.08)", borderRadius: 12, padding: 16, marginBottom: 20,
      }}>
        <div style={{ fontSize: 14, fontWeight: 700, color: "#e0f2f1", marginBottom: 14 }}>{section.label}</div>
        {section.fields?.map((f) => (
          <Field key={f.name} field={f} value={sectionConfig[f.name]} onChange={(v) => setSection({ ...sectionConfig, [f.name]: v })} />
        ))}
      </div>
    );
  }
  return null;
}

/* ─── Commands Preview ────────────────────────────────────── */
function CommandsPreview({ commands }) {
  if (!commands?.length) return null;
  return (
    <div style={{
      background: "#020617", borderRadius: 10, border: "1px solid rgba(0,255,136,0.08)",
      padding: 16, maxHeight: 400, overflowY: "auto", fontFamily: "'JetBrains Mono', monospace", fontSize: 12,
    }}>
      <div style={{ fontSize: 11, color: "#5a7a8a", marginBottom: 8, fontWeight: 700 }}>
        {commands.length} commandes générées
      </div>
      {commands.map((cmd, i) => (
        <div key={i} style={{ padding: "3px 0", color: cmd.startsWith("!") ? "#ff6b6b" : cmd.startsWith(" ") ? "#00e5ff" : "#00ff88" }}>
          <span style={{ color: "#5a7a8a", marginRight: 10 }}>{String(i + 1).padStart(3, " ")}</span>
          {cmd}
        </div>
      ))}
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════
   MAIN PAGE
   ═══════════════════════════════════════════════════════════ */
export default function NetworkDevicesPage() {
  const { fetchWithAuth, headers } = useAuth();

  // ── State ──
  const [view, setView] = useState("list"); // list | add | configure
  const [devices, setDevices] = useState([]);
  const [allTemplates, setAllTemplates] = useState({});  // { switch: { cisco: {...}, ... }, router: {...} }
  const [loading, setLoading] = useState(true);

  // Add wizard state
  const [addStep, setAddStep] = useState(0); // 0=type, 1=brand, 2=connection, 3=confirm
  const [newDevice, setNewDevice] = useState({ name: "", ip: "", device_type: "switch", brand: "cisco", username: "admin", password: "", port: 22, protocol: "ssh", model: "", notes: "" });

  // Configure wizard state
  const [selectedDevice, setSelectedDevice] = useState(null);
  const [configStep, setConfigStep] = useState(0);
  const [config, setConfig] = useState({});
  const [previewCommands, setPreviewCommands] = useState([]);
  const [pushing, setPushing] = useState(false);
  const [pushResult, setPushResult] = useState(null);

  // ── Derived ──
  const availableBrands = Object.keys(allTemplates[newDevice.device_type] || {});
  const templatesForDevice = selectedDevice
    ? (allTemplates[selectedDevice.device_type] || {})[selectedDevice.brand] || {}
    : {};
  const sectionKeys = Object.keys(templatesForDevice);

  // ── Fetch ──
  const fetchDevices = useCallback(async () => {
    try {
      const res = await fetchWithAuth(API, { headers });
      if (res.ok) setDevices(await res.json());
    } catch { } finally { setLoading(false); }
  }, [fetchWithAuth, headers]);

  const fetchTemplates = useCallback(async () => {
    try {
      const res = await fetchWithAuth(`${API}/config-templates/all`, { headers });
      if (res.ok) {
        const data = await res.json();
        setAllTemplates(data);
      }
    } catch (e) { console.error("Failed to fetch templates:", e); }
  }, [fetchWithAuth, headers]);

  useEffect(() => { fetchDevices(); fetchTemplates(); }, [fetchDevices, fetchTemplates]);

  // ── Add Device ──
  const handleAddDevice = async () => {
    try {
      const res = await fetchWithAuth(API, {
        method: "POST", headers,
        body: JSON.stringify({
          name: newDevice.name, ip: newDevice.ip, device_type: newDevice.device_type,
          brand: newDevice.brand, username: newDevice.username, password: newDevice.password,
          port: parseInt(newDevice.port), protocol: newDevice.protocol, model: newDevice.model, notes: newDevice.notes,
        }),
      });
      if (res.ok) {
        toast.success("Appareil ajouté");
        setView("list");
        fetchDevices();
        setNewDevice({ name: "", ip: "", device_type: "switch", brand: "cisco", username: "admin", password: "", port: 22, protocol: "ssh", model: "", notes: "" });
        setAddStep(0);
      } else {
        const err = await res.json();
        toast.error(err.detail || "Erreur");
      }
    } catch { toast.error("Erreur réseau"); }
  };

  // ── Configure Device ──
  const startConfigure = (device) => {
    setSelectedDevice(device);
    setConfig({});
    setConfigStep(0);
    setPreviewCommands([]);
    setPushResult(null);
    setView("configure");
  };

  const previewConfig = async () => {
    if (!selectedDevice) return;
    try {
      const body = {
        device_type: selectedDevice.device_type,
        brand: selectedDevice.brand,
        ...config,
      };
      const res = await fetchWithAuth(`${API}/preview-config`, {
        method: "POST", headers,
        body: JSON.stringify({ config: body }),
      });
      if (res.ok) {
        const data = await res.json();
        setPreviewCommands(data.commands_generated || []);
      }
    } catch { }
  };

  const pushConfig = async () => {
    if (!selectedDevice) return;
    setPushing(true);
    try {
      const body = {
        device_type: selectedDevice.device_type,
        brand: selectedDevice.brand,
        ...config,
      };
      const res = await fetchWithAuth(`${API}/${selectedDevice.id}/push-config`, {
        method: "POST", headers,
        body: JSON.stringify({ config: body }),
      });
      if (res.ok) {
        const data = await res.json();
        setPushResult(data);
        if (data.success) {
          toast.success("Configuration appliquée");
          fetchDevices();
        } else {
          toast.warning(data.error || "Commandes générées sans envoi SSH");
        }
      }
    } catch { toast.error("Erreur réseau"); } finally { setPushing(false); }
  };

  const deleteDevice = async (id) => {
    if (!window.confirm("Supprimer cet appareil ?")) return;
    try {
      const res = await fetchWithAuth(`${API}/${id}`, { method: "DELETE", headers });
      if (res.ok) { toast.success("Supprimé"); fetchDevices(); }
    } catch { toast.error("Erreur"); }
  };

  const testConnection = async (id) => {
    try {
      const res = await fetchWithAuth(`${API}/${id}/test-connection`, { method: "POST", headers });
      if (res.ok) {
        const data = await res.json();
        toast[data.status === "online" ? "success" : "warning"](
          data.status === "online" ? `Connecté (${data.latency_ms}ms)` : `Injoignable: ${data.error || "timeout"}`
        );
        fetchDevices();
      }
    } catch { toast.error("Erreur"); }
  };

  /* ═══════════════════════════════════════════════════════════
     RENDER: DEVICE LIST
     ═══════════════════════════════════════════════════════════ */
  if (view === "list") {
    return (
      <div style={{ padding: 24, maxWidth: 1200, margin: "0 auto" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 28 }}>
          <div>
            <h1 style={{ fontSize: 24, fontWeight: 800, color: "#e0f2f1", fontFamily: "'Orbitron', sans-serif" }}>
              🔧 Configuration Réseau
            </h1>
            <p style={{ fontSize: 13, color: "#5a7a8a", marginTop: 4 }}>
              Liez et configurez vos switches et routeurs à distance
            </p>
          </div>
          <button onClick={() => { setView("add"); setAddStep(0); }} style={{
            padding: "10px 20px", borderRadius: 12, border: "none",
            background: "linear-gradient(135deg, #00ff88, #00cc6a)", color: "#050a0e",
            fontWeight: 700, fontSize: 13, cursor: "pointer",
            boxShadow: "0 8px 20px rgba(0,255,136,0.3)",
          }}>+ Ajouter un appareil</button>
        </div>

        {loading ? (
          <div style={{ textAlign: "center", padding: 60, color: "var(--text-muted)" }}>Chargement...</div>
        ) : devices.length === 0 ? (
          <div style={{
            textAlign: "center", padding: 80, border: "1px dashed rgba(0,255,136,0.15)", borderRadius: 16,
            background: "rgba(5,15,20,0.3)",
          }}>
            <div style={{ fontSize: 48, marginBottom: 16 }}>🔌</div>
            <div style={{ fontSize: 16, fontWeight: 700, color: "#e0f2f1", marginBottom: 8 }}>Aucun appareil configuré</div>
            <div style={{ fontSize: 13, color: "#5a7a8a", marginBottom: 20 }}>Ajoutez un switch ou routeur pour commencer la configuration</div>
            <button onClick={() => { setView("add"); setAddStep(0); }} style={{
              padding: "10px 24px", borderRadius: 12, border: "none",
              background: "linear-gradient(135deg, #00ff88, #00cc6a)", color: "#050a0e",
              fontWeight: 700, fontSize: 13, cursor: "pointer",
            }}>+ Premier appareil</button>
          </div>
        ) : (
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(320px, 1fr))", gap: 16 }}>
            {devices.map((d) => (
              <div key={d.id} style={{
                background: "rgba(5,15,20,0.6)", border: "1px solid rgba(0,255,136,0.08)",
                borderRadius: 14, padding: 20, transition: "border-color 0.2s",
              }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 14 }}>
                  <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
                    <div style={{
                      width: 44, height: 44, borderRadius: 12, display: "flex", alignItems: "center", justifyContent: "center",
                      background: "rgba(0,255,136,0.08)", fontSize: 22,
                    }}>{DEVICE_ICONS[d.device_type] || "📡"}</div>
                    <div>
                      <div style={{ fontSize: 15, fontWeight: 700, color: "#e0f2f1" }}>{d.name}</div>
                      <div style={{ fontSize: 12, color: "#5a7a8a" }}>{d.ip}:{d.port}</div>
                    </div>
                  </div>
                  <span style={{
                    padding: "3px 10px", borderRadius: 6, fontSize: 10, fontWeight: 700, textTransform: "uppercase",
                    background: d.status === "online" ? "rgba(0,255,136,0.12)" : d.status === "error" ? "rgba(255,107,107,0.12)" : "rgba(90,122,138,0.12)",
                    color: d.status === "online" ? "#00ff88" : d.status === "error" ? "#ff6b6b" : "#5a7a8a",
                    border: `1px solid ${d.status === "online" ? "rgba(0,255,136,0.2)" : d.status === "error" ? "rgba(255,107,107,0.2)" : "rgba(90,122,138,0.15)"}`,
                  }}>{d.status || "offline"}</span>
                </div>

                <div style={{ display: "flex", gap: 8, marginBottom: 14, flexWrap: "wrap", alignItems: "center" }}>
                  <span style={{ padding: "3px 8px", borderRadius: 6, fontSize: 10, fontWeight: 600, background: "rgba(0,229,255,0.08)", color: "#00e5ff", border: "1px solid rgba(0,229,255,0.15)" }}>
                    {d.device_type === "switch" ? "Switch" : "Routeur"}
                  </span>
                  <span style={{ display: "inline-flex", alignItems: "center", gap: 6, padding: "3px 8px", borderRadius: 6, fontSize: 10, fontWeight: 600, background: "rgba(0,255,136,0.06)", color: "#00ff88", border: "1px solid rgba(0,255,136,0.1)" }}>
                    <BrandLogo brand={d.brand} size={14} /> {BRAND_LABELS[d.brand] || d.brand}
                  </span>
                  {d.model && <span style={{ padding: "3px 8px", borderRadius: 6, fontSize: 10, color: "#5a7a8a", border: "1px solid rgba(90,122,138,0.15)" }}>{d.model}</span>}
                </div>

                <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                  <button onClick={() => startConfigure(d)} style={{
                    flex: 1, padding: "8px 0", borderRadius: 8, border: "none",
                    background: "linear-gradient(135deg, #00ff88, #00cc6a)", color: "#050a0e",
                    fontWeight: 700, fontSize: 12, cursor: "pointer",
                  }}>⚙️ Configurer</button>
                  <button onClick={() => testConnection(d.id)} style={{
                    padding: "8px 12px", borderRadius: 8, border: "1px solid rgba(0,229,255,0.2)",
                    background: "rgba(0,229,255,0.06)", color: "#00e5ff", fontSize: 12, cursor: "pointer",
                  }}>🔌 Tester</button>
                  <button onClick={() => deleteDevice(d.id)} style={{
                    padding: "8px 12px", borderRadius: 8, border: "1px solid rgba(255,107,107,0.2)",
                    background: "rgba(255,107,107,0.06)", color: "#ff6b6b", fontSize: 12, cursor: "pointer",
                  }}>🗑</button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    );
  }

  /* ═══════════════════════════════════════════════════════════
     RENDER: ADD DEVICE WIZARD
     ═══════════════════════════════════════════════════════════ */
  if (view === "add") {
    const addSteps = ["Type", "Marque", "Connexion", "Résumé"];

    return (
      <div style={{ padding: 24, maxWidth: 700, margin: "0 auto" }}>
        <button onClick={() => setView("list")} style={{ fontSize: 13, color: "#5a7a8a", background: "none", border: "none", cursor: "pointer", marginBottom: 16 }}>← Retour à la liste</button>
        <h2 style={{ fontSize: 20, fontWeight: 800, color: "#e0f2f1", fontFamily: "'Orbitron', sans-serif", marginBottom: 24 }}>Nouvel Appareil</h2>
        <StepIndicator steps={addSteps} current={addStep} />

        {/* Step 0: Device Type */}
        {addStep === 0 && (
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
            {["switch", "router"].map((t) => (
              <button key={t} onClick={() => { setNewDevice((p) => ({ ...p, device_type: t, brand: Object.keys(allTemplates[t] || {})[0] || "cisco" })); setAddStep(1); }}
                style={{
                  padding: 30, borderRadius: 16, border: newDevice.device_type === t ? "2px solid #00ff88" : "1px solid rgba(0,255,136,0.1)",
                  background: newDevice.device_type === t ? "rgba(0,255,136,0.08)" : "rgba(5,15,20,0.5)",
                  cursor: "pointer", textAlign: "center", transition: "all 0.2s",
                }}>
                <div style={{ fontSize: 42, marginBottom: 12 }}>{DEVICE_ICONS[t]}</div>
                <div style={{ fontSize: 16, fontWeight: 700, color: "#e0f2f1" }}>{t === "switch" ? "Switch" : "Routeur"}</div>
                <div style={{ fontSize: 12, color: "#5a7a8a", marginTop: 6 }}>
                  {t === "switch" ? `Commutateur — ${Object.keys(allTemplates[t] || {}).length} marques` : `Routeur — ${Object.keys(allTemplates[t] || {}).length} marques`}
                </div>
              </button>
            ))}
          </div>
        )}

        {/* Step 1: Brand — dynamic from templates */}
        {addStep === 1 && (
          <div>
            <div style={{ fontSize: 12, color: "#5a7a8a", marginBottom: 16 }}>
              {availableBrands.length} marques disponibles pour {newDevice.device_type === "switch" ? "Switch" : "Routeur"}
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(140px, 1fr))", gap: 12 }}>
              {availableBrands.map((b) => (
                  <button key={b} onClick={() => { setNewDevice((p) => ({ ...p, brand: b })); setAddStep(2); }}
                  style={{
                    padding: 20, borderRadius: 16, border: newDevice.brand === b ? "2px solid #00ff88" : "1px solid rgba(0,255,136,0.1)",
                    background: newDevice.brand === b ? "rgba(0,255,136,0.08)" : "rgba(5,15,20,0.5)",
                    cursor: "pointer", textAlign: "center", display: "flex", flexDirection: "column", alignItems: "center", gap: 8,
                  }}>
                  <BrandLogo brand={b} size={40} />
                  <div style={{ fontSize: 13, fontWeight: 700, color: "#e0f2f1" }}>{BRAND_LABELS[b] || b}</div>
                  <div style={{ fontSize: 9, color: "#5a7a8a" }}>{b}</div>
                </button>
              ))}
            </div>
          </div>
        )}

        {/* Step 2: Connection */}
        {addStep === 2 && (
          <div style={{ background: "rgba(5,15,20,0.5)", border: "1px solid rgba(0,255,136,0.08)", borderRadius: 16, padding: 24 }}>
            <Field field={{ label: "Nom de l'appareil", type: "text", required: true }} value={newDevice.name} onChange={(v) => setNewDevice((p) => ({ ...p, name: v }))} />
            <Field field={{ label: "Adresse IP", type: "text", required: true }} value={newDevice.ip} onChange={(v) => setNewDevice((p) => ({ ...p, ip: v }))} />
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12 }}>
              <Field field={{ label: "Port SSH", type: "number" }} value={newDevice.port} onChange={(v) => setNewDevice((p) => ({ ...p, port: v }))} />
              <Field field={{ label: "Protocole", type: "select", options: ["ssh", "telnet"] }} value={newDevice.protocol} onChange={(v) => setNewDevice((p) => ({ ...p, protocol: v }))} />
              <Field field={{ label: "Modèle", type: "text" }} value={newDevice.model} onChange={(v) => setNewDevice((p) => ({ ...p, model: v }))} />
            </div>
            <Field field={{ label: "Nom d'utilisateur", type: "text" }} value={newDevice.username} onChange={(v) => setNewDevice((p) => ({ ...p, username: v }))} />
            <Field field={{ label: "Mot de passe", type: "password" }} value={newDevice.password} onChange={(v) => setNewDevice((p) => ({ ...p, password: v }))} />
            <div style={{ display: "flex", gap: 10, marginTop: 16 }}>
              <button onClick={() => setAddStep(1)} style={{ padding: "10px 20px", borderRadius: 10, border: "1px solid rgba(0,255,136,0.15)", background: "transparent", color: "#5a7a8a", fontSize: 13, cursor: "pointer" }}>← Retour</button>
              <button onClick={() => setAddStep(3)} style={{
                flex: 1, padding: "10px 20px", borderRadius: 10, border: "none",
                background: "linear-gradient(135deg, #00ff88, #00cc6a)", color: "#050a0e",
                fontWeight: 700, fontSize: 13, cursor: "pointer",
              }} disabled={!newDevice.name || !newDevice.ip}>Suivant →</button>
            </div>
          </div>
        )}

        {/* Step 3: Confirm */}
        {addStep === 3 && (
          <div style={{ background: "rgba(5,15,20,0.5)", border: "1px solid rgba(0,255,136,0.08)", borderRadius: 16, padding: 24 }}>
            <div style={{ fontSize: 14, fontWeight: 700, color: "#e0f2f1", marginBottom: 16 }}>Résumé</div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
              {[
                ["Type", newDevice.device_type === "switch" ? "Switch" : "Routeur"],
                ["Marque", BRAND_LABELS[newDevice.brand] || newDevice.brand],
                ["Nom", newDevice.name],
                ["IP", `${newDevice.ip}:${newDevice.port}`],
                ["Protocole", newDevice.protocol.toUpperCase()],
                ["Utilisateur", newDevice.username],
              ].map(([k, v]) => (
                <div key={k} style={{ padding: "10px 14px", borderRadius: 10, background: "rgba(0,255,136,0.04)", border: "1px solid rgba(0,255,136,0.06)" }}>
                  <div style={{ fontSize: 10, color: "#5a7a8a", textTransform: "uppercase", letterSpacing: 1 }}>{k}</div>
                  <div style={{ fontSize: 14, color: "#e0f2f1", fontWeight: 600, marginTop: 2 }}>{v}</div>
                </div>
              ))}
            </div>
            <div style={{ display: "flex", gap: 10, marginTop: 20 }}>
              <button onClick={() => setAddStep(2)} style={{ padding: "10px 20px", borderRadius: 10, border: "1px solid rgba(0,255,136,0.15)", background: "transparent", color: "#5a7a8a", fontSize: 13, cursor: "pointer" }}>← Modifier</button>
              <button onClick={handleAddDevice} style={{
                flex: 1, padding: "10px 20px", borderRadius: 10, border: "none",
                background: "linear-gradient(135deg, #00ff88, #00cc6a)", color: "#050a0e",
                fontWeight: 700, fontSize: 13, cursor: "pointer",
                boxShadow: "0 8px 20px rgba(0,255,136,0.3)",
              }}>✅ Ajouter l'appareil</button>
            </div>
          </div>
        )}
      </div>
    );
  }

  /* ═══════════════════════════════════════════════════════════
     RENDER: CONFIGURE DEVICE (puzzle wizard)
     ═══════════════════════════════════════════════════════════ */
  if (view === "configure" && selectedDevice) {
    const totalSteps = sectionKeys.length + 1; // sections + preview
    const configLabels = sectionKeys.map((k) => templatesForDevice[k]?.label || k);
    const allSteps = [...configLabels, "Aperçu & Appliquer"];

    return (
      <div style={{ padding: 24, maxWidth: 900, margin: "0 auto" }}>
        <button onClick={() => setView("list")} style={{ fontSize: 13, color: "#5a7a8a", background: "none", border: "none", cursor: "pointer", marginBottom: 16 }}>← Retour à la liste</button>

        <div style={{ display: "flex", alignItems: "center", gap: 14, marginBottom: 24 }}>
          <div style={{ fontSize: 32 }}>{DEVICE_ICONS[selectedDevice.device_type]}</div>
          <div>
            <h2 style={{ fontSize: 20, fontWeight: 800, color: "#e0f2f1", fontFamily: "'Orbitron', sans-serif", display: "flex", alignItems: "center", gap: 10 }}>
              Configurer: {selectedDevice.name}
            </h2>
            <div style={{ fontSize: 12, color: "#5a7a8a", display: "flex", alignItems: "center", gap: 6 }}>
              {selectedDevice.ip} · <BrandLogo brand={selectedDevice.brand} size={16} /> {BRAND_LABELS[selectedDevice.brand] || selectedDevice.brand} · {selectedDevice.device_type}
            </div>
          </div>
        </div>

        {sectionKeys.length === 0 ? (
          <div style={{ padding: 40, textAlign: "center", border: "1px dashed rgba(0,255,136,0.15)", borderRadius: 16, background: "rgba(5,15,20,0.3)" }}>
            <div style={{ fontSize: 32, marginBottom: 12 }}>⚠️</div>
            <div style={{ fontSize: 14, color: "#e0f2f1", fontWeight: 600 }}>Aucun template disponible</div>
            <div style={{ fontSize: 12, color: "#5a7a8a", marginTop: 4 }}>
              Marque "{selectedDevice.brand}" pour {selectedDevice.device_type} — templates non chargés
            </div>
          </div>
        ) : (
          <>
            <StepIndicator steps={allSteps} current={configStep} />

            {/* Render current config section */}
            {configStep < sectionKeys.length ? (
              <div>
                <ConfigSection
                  sectionKey={sectionKeys[configStep]}
                  section={templatesForDevice[sectionKeys[configStep]]}
                  config={config}
                  setConfig={setConfig}
                />
                <div style={{ display: "flex", gap: 10, marginTop: 16 }}>
                  {configStep > 0 && (
                    <button onClick={() => setConfigStep((s) => s - 1)} style={{
                      padding: "10px 20px", borderRadius: 10, border: "1px solid rgba(0,255,136,0.15)",
                      background: "transparent", color: "#5a7a8a", fontSize: 13, cursor: "pointer",
                    }}>← Précédent</button>
                  )}
                  <button onClick={() => setConfigStep((s) => s + 1)} style={{
                    flex: 1, padding: "10px 20px", borderRadius: 10, border: "none",
                    background: "linear-gradient(135deg, #00ff88, #00cc6a)", color: "#050a0e",
                    fontWeight: 700, fontSize: 13, cursor: "pointer",
                  }}>Suivant →</button>
                </div>
              </div>
            ) : (
              /* Final step: preview & push */
              <div>
                <div style={{ display: "flex", gap: 10, marginBottom: 16 }}>
                  <button onClick={() => setConfigStep((s) => s - 1)} style={{
                    padding: "10px 20px", borderRadius: 10, border: "1px solid rgba(0,255,136,0.15)",
                    background: "transparent", color: "#5a7a8a", fontSize: 13, cursor: "pointer",
                  }}>← Modifier</button>
                  <button onClick={previewConfig} style={{
                    padding: "10px 20px", borderRadius: 10, border: "1px solid rgba(0,229,255,0.25)",
                    background: "rgba(0,229,255,0.06)", color: "#00e5ff", fontWeight: 600, fontSize: 13, cursor: "pointer",
                  }}>👁 Aperçu des commandes</button>
                  <button onClick={pushConfig} disabled={pushing} style={{
                    flex: 1, padding: "10px 20px", borderRadius: 10, border: "none",
                    background: pushing ? "rgba(0,255,136,0.2)" : "linear-gradient(135deg, #00ff88, #00cc6a)", color: "#050a0e",
                    fontWeight: 700, fontSize: 13, cursor: pushing ? "wait" : "pointer",
                    boxShadow: "0 8px 20px rgba(0,255,136,0.3)",
                  }}>{pushing ? "⏳ Application..." : "🚀 Appliquer la configuration"}</button>
                </div>

                <CommandsPreview commands={previewCommands} />

                {pushResult && (
                  <div style={{
                    marginTop: 16, padding: 16, borderRadius: 12,
                    background: pushResult.success ? "rgba(0,255,136,0.06)" : "rgba(255,107,107,0.06)",
                    border: `1px solid ${pushResult.success ? "rgba(0,255,136,0.2)" : "rgba(255,107,107,0.2)"}`,
                  }}>
                    <div style={{ fontSize: 14, fontWeight: 700, color: pushResult.success ? "#00ff88" : "#ff6b6b", marginBottom: 8 }}>
                      {pushResult.success ? "✅ Configuration appliquée" : "⚠️ Commandes générées"}
                    </div>
                    {pushResult.error && <div style={{ fontSize: 12, color: "#ff6b6b", marginBottom: 8 }}>{pushResult.error}</div>}
                    {pushResult.commands_generated?.length > 0 && (
                      <div style={{ fontSize: 12, color: "#5a7a8a" }}>{pushResult.commands_generated.length} commandes générées</div>
                    )}
                    {pushResult.output && (
                      <pre style={{ marginTop: 8, padding: 12, borderRadius: 8, background: "#020617", fontSize: 11, color: "#c8d6e5", overflowX: "auto", whiteSpace: "pre-wrap" }}>{pushResult.output}</pre>
                    )}
                  </div>
                )}
              </div>
            )}
          </>
        )}
      </div>
    );
  }

  return null;
}
