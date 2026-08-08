import { useState } from "react";
import { Plus, Trash2, Edit, Crosshair, X, Save, Play, FlaskConical, Download } from "lucide-react";
import { useAuth } from "../contexts/AuthContext";
import { useData } from "../contexts/DataContext";
import { toast } from "react-toastify";

const OPS = [
  { value: "eq", label: "est égal à" },
  { value: "ne", label: "n'est pas égal à" },
  { value: "gt", label: "> supérieur à" },
  { value: "ge", label: ">= supérieur ou égal à" },
  { value: "lt", label: "< inférieur à" },
  { value: "le", label: "<= inférieur ou égal à" },
  { value: "in", label: "dans la liste" },
  { value: "contains", label: "contient" },
  { value: "startswith", label: "commence par" },
  { value: "regex", label: "correspond au regex" },
  { value: "exists", label: "existe" },
];

const FIELDS = [
  { value: "src_ip", label: "IP source" },
  { value: "dest_ip", label: "IP destination" },
  { value: "proto", label: "Protocole" },
  { value: "severity", label: "Sévérité brute" },
  { value: "normalized_severity", label: "Sévérité normalisée" },
  { value: "signature", label: "Signature / description" },
  { value: "event_type", label: "Type d'événement" },
  { value: "agent_id", label: "Agent ID" },
  { value: "source", label: "Source" },
];

const EMPTY_COND = { field: "normalized_severity", op: "ge", value: 7 };

const TARGETS = [
  { value: "both", label: "Alertes + Suricata" },
  { value: "alert", label: "Alertes SIEM (Wazuh)" },
  { value: "suricata", label: "Alertes Suricata" },
];

const emptyForm = () => ({
  name: "",
  description: "",
  target: "both",
  conditions: [{ ...EMPTY_COND }],
});

const sevClass = (s) =>
  s >= 12 ? "text-red-400" : s >= 8 ? "text-orange-400" : s >= 5 ? "text-yellow-400" : "text-gray-400";

export default function HuntingPage() {
  const { fetchWithAuth } = useAuth();
  const { hunts, refreshHunts } = useData();

  const [form, setForm] = useState(emptyForm());
  const [editingId, setEditingId] = useState(null);
  const [saving, setSaving] = useState(false);
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState(null);

  const setCond = (idx, patch) =>
    setForm((f) => ({
      ...f,
      conditions: f.conditions.map((c, i) => (i === idx ? { ...c, ...patch } : c)),
    }));

  const openNew = () => {
    setEditingId(null);
    setForm(emptyForm());
    setResult(null);
  };

  const openEdit = (h) => {
    setEditingId(h.id);
    setForm({
      name: h.name,
      description: h.description || "",
      target: h.target || "both",
      conditions: h.conditions && h.conditions.length ? h.conditions : [{ ...EMPTY_COND }],
    });
    setResult(null);
  };

  const buildPayload = () => ({
    name: form.name,
    description: form.description,
    target: form.target,
    conditions: form.conditions,
  });

  const handleSave = async () => {
    if (!form.name.trim()) return toast.error("Le nom de la chasse est requis");
    if (!form.conditions.length) return toast.error("Au moins une condition est requise");
    setSaving(true);
    try {
      const res = await fetchWithAuth(editingId ? `/api/hunts/${editingId}` : "/api/hunts", {
        method: editingId ? "PUT" : "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(buildPayload()),
      });
      if (res.ok) {
        toast.success(editingId ? "Chasse mise à jour" : "Chasse enregistrée");
        refreshHunts();
      } else {
        const err = await res.json().catch(() => ({}));
        toast.error(err.detail || "Erreur lors de l'enregistrement");
      }
    } catch {
      toast.error("Erreur réseau");
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (h) => {
    if (!window.confirm(`Supprimer la chasse « ${h.name} » ?`)) return;
    try {
      const res = await fetchWithAuth(`/api/hunts/${h.id}`, { method: "DELETE" });
      if (res.ok) {
        toast.success("Chasse supprimée");
        refreshHunts();
      } else toast.error("Erreur lors de la suppression");
    } catch {
      toast.error("Erreur réseau");
    }
  };

  const runPreview = async () => {
    setRunning(true);
    setResult(null);
    try {
      const res = await fetchWithAuth("/api/hunts/preview", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: form.target, conditions: form.conditions, limit: 500 }),
      });
      if (res.ok) setResult(await res.json());
      else {
        const err = await res.json().catch(() => ({}));
        toast.error(err.detail || "Erreur lors de la prévisualisation");
      }
    } catch {
      toast.error("Erreur réseau");
    } finally {
      setRunning(false);
    }
  };

  const runSaved = async (h) => {
    setRunning(true);
    setResult(null);
    try {
      const res = await fetchWithAuth(`/api/hunts/${h.id}/run`, { method: "POST" });
      if (res.ok) {
        setResult(await res.json());
        refreshHunts();
      } else {
        const err = await res.json().catch(() => ({}));
        toast.error(err.detail || "Erreur lors de l'exécution");
      }
    } catch {
      toast.error("Erreur réseau");
    } finally {
      setRunning(false);
    }
  };

  const exportCsv = () => {
    const rows = result?.results || [];
    if (!rows.length) return toast.error("Aucun résultat à exporter");
    const headers = ["alert_type", "alert_id", "timestamp", "source", "severity", "normalized_severity", "signature", "src_ip", "dest_ip", "agent_id", "proto"];
    const esc = (v) => `"${String(v ?? "").replace(/"/g, '""')}"`;
    const lines = [
      headers.join(","),
      ...rows.map((r) => headers.map((h) => esc(r[h])).join(",")),
    ];
    const blob = new Blob([lines.join("\n")], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `hunt-results-${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const results = result?.results || [];

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Crosshair className="text-emerald-400" /> Chasse aux menaces
          </h1>
          <p className="text-gray-400 text-sm">
            Requêtes enregistrées évaluées sur les alertes SIEM et Suricata (moteur F1)
          </p>
        </div>
        <button onClick={openNew} className="flex items-center gap-2 bg-emerald-600 hover:bg-emerald-500 px-4 py-2 rounded-lg">
          <Plus size={16} /> Nouvelle chasse
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Chasses enregistrées */}
        <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
          <div className="px-4 py-3 border-b border-gray-800 font-semibold">Chasses enregistrées ({hunts.length})</div>
          <div className="divide-y divide-gray-800">
            {(hunts || []).map((h) => (
              <div key={h.id} className="px-4 py-3 hover:bg-gray-800/50">
                <div className="flex items-center justify-between">
                  <div>
                    <div className="font-medium">{h.name}</div>
                    <div className="text-xs text-gray-500">{h.description || "—"}</div>
                  </div>
                  <div className="flex gap-2">
                    <button onClick={() => runSaved(h)} disabled={running} className="text-emerald-400 hover:text-emerald-300" title="Exécuter">
                      <Play size={16} />
                    </button>
                    <button onClick={() => openEdit(h)} className="text-gray-400 hover:text-white" title="Modifier">
                      <Edit size={16} />
                    </button>
                    <button onClick={() => handleDelete(h)} className="text-gray-400 hover:text-red-400" title="Supprimer">
                      <Trash2 size={16} />
                    </button>
                  </div>
                </div>
                <div className="text-xs text-gray-500 mt-1 flex flex-wrap gap-x-3">
                  <span>Cible : {h.target}</span>
                  <span>{h.conditions?.length || 0} condition(s)</span>
                  {h.last_run_at && (
                    <span>Dernière exécution : {new Date(h.last_run_at).toLocaleString()} · {h.last_run_count ?? 0} résultat(s)</span>
                  )}
                  {h.last_error && <span className="text-red-400">Erreur : {h.last_error}</span>}
                </div>
              </div>
            ))}
            {(!hunts || hunts.length === 0) && (
              <div className="px-4 py-8 text-center text-gray-500 text-sm">Aucune chasse enregistrée</div>
            )}
          </div>
        </div>

        {/* Éditeur */}
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-5 space-y-4">
          <div className="font-semibold">{editingId ? "Modifier la chasse" : "Nouvelle chasse"}</div>
          <div>
            <label className="block text-xs text-gray-400 mb-1">Nom *</label>
            <input className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2"
              value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
          </div>
          <div>
            <label className="block text-xs text-gray-400 mb-1">Description</label>
            <textarea className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2"
              value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
          </div>
          <div>
            <label className="block text-xs text-gray-400 mb-1">Cible</label>
            <select className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2"
              value={form.target} onChange={(e) => setForm({ ...form, target: e.target.value })}>
              {TARGETS.map((t) => <option key={t.value} value={t.value}>{t.label}</option>)}
            </select>
          </div>

          <div>
            <label className="block text-xs text-gray-400 mb-1">Conditions (toutes doivent être satisfaites)</label>
            <div className="space-y-2">
              {form.conditions.map((cond, idx) => (
                <div key={idx} className="flex gap-2 items-center">
                  <select className="flex-1 bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm"
                    value={cond.field} onChange={(e) => setCond(idx, { field: e.target.value })}>
                    {FIELDS.map((f) => <option key={f.value} value={f.value}>{f.label}</option>)}
                  </select>
                  <select className="bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm"
                    value={cond.op} onChange={(e) => setCond(idx, { op: e.target.value })}>
                    {OPS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
                  </select>
                  <input className="flex-1 bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm"
                    value={cond.value ?? ""} placeholder="valeur"
                    onChange={(e) => setCond(idx, { value: e.target.value })} />
                  <button className="text-gray-500 hover:text-red-400"
                    onClick={() => setForm((f) => ({ ...f, conditions: f.conditions.filter((_, i) => i !== idx) }))}>
                    <X size={16} />
                  </button>
                </div>
              ))}
            </div>
            <button className="text-emerald-400 text-sm mt-2"
              onClick={() => setForm((f) => ({ ...f, conditions: [...f.conditions, { ...EMPTY_COND }] }))}>
              + Ajouter une condition
            </button>
          </div>

          <div className="flex justify-end gap-3 pt-2">
            <button onClick={runPreview} disabled={running} className="flex items-center gap-2 bg-gray-800 hover:bg-gray-700 px-4 py-2 rounded-lg">
              <FlaskConical size={16} /> {running ? "Exécution…" : "Prévisualiser"}
            </button>
            <button onClick={handleSave} disabled={saving} className="flex items-center gap-2 bg-emerald-600 hover:bg-emerald-500 px-4 py-2 rounded-lg">
              <Save size={16} /> {saving ? "Enregistrement…" : "Enregistrer"}
            </button>
          </div>
        </div>
      </div>

      {/* Résultats */}
      {result && (
        <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
          <div className="px-4 py-3 border-b border-gray-800 flex items-center justify-between">
            <div className="font-semibold">
              Résultats ({result.matched ?? 0} correspondance(s){result.preview ? " · aperçu" : ""})
            </div>
            <div className="flex items-center gap-3 text-xs text-gray-400">
              <span>Scanné : {result.scanned}</span>
              <span>Durée : {result.duration_ms} ms</span>
              {result.error && <span className="text-red-400">Erreur : {result.error}</span>}
              <button onClick={exportCsv} className="flex items-center gap-1 text-emerald-400 hover:text-emerald-300">
                <Download size={14} /> CSV
              </button>
            </div>
          </div>
          <table className="w-full text-sm">
            <thead className="bg-gray-800 text-gray-300">
              <tr>
                <th className="text-left px-4 py-2">Type</th>
                <th className="text-left px-4 py-2">ID</th>
                <th className="text-left px-4 py-2">Horodatage</th>
                <th className="text-left px-4 py-2">Source</th>
                <th className="text-left px-4 py-2">Sévérité</th>
                <th className="text-left px-4 py-2">Signature</th>
                <th className="text-left px-4 py-2">Src IP</th>
                <th className="text-left px-4 py-2">Dst IP</th>
                <th className="text-left px-4 py-2">Agent</th>
                <th className="text-left px-4 py-2">Proto</th>
              </tr>
            </thead>
            <tbody>
              {results.map((r, i) => (
                <tr key={`${r.alert_type}-${r.alert_id}-${i}`} className="border-t border-gray-800 hover:bg-gray-800/50">
                  <td className="px-4 py-2 text-xs">{r.alert_type}</td>
                  <td className="px-4 py-2 text-gray-400">#{r.alert_id}</td>
                  <td className="px-4 py-2 text-gray-500">{r.timestamp ? new Date(r.timestamp).toLocaleString() : "—"}</td>
                  <td className="px-4 py-2 text-gray-400">{r.source || "—"}</td>
                  <td className={`px-4 py-2 font-bold ${sevClass(r.normalized_severity ?? r.severity)}`}>{r.normalized_severity ?? r.severity}</td>
                  <td className="px-4 py-2 text-gray-300 truncate max-w-[200px]">{r.signature || "—"}</td>
                  <td className="px-4 py-2 text-gray-400">{r.src_ip || "—"}</td>
                  <td className="px-4 py-2 text-gray-400">{r.dest_ip || "—"}</td>
                  <td className="px-4 py-2 text-gray-400">{r.agent_id || "—"}</td>
                  <td className="px-4 py-2 text-gray-400">{r.proto || "—"}</td>
                </tr>
              ))}
              {results.length === 0 && (
                <tr><td colSpan={10} className="px-4 py-8 text-center text-gray-500">Aucun résultat</td></tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}