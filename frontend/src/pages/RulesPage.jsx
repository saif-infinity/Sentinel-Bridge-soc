import { useState, useEffect, useCallback } from "react";
import {
  Plus, RefreshCw, Trash2, Edit, Shield, FlaskConical, X, Save,
  CheckCircle2, AlertTriangle, GitBranch,
} from "lucide-react";
import { useAuth } from "../contexts/AuthContext";
import { useData } from "../contexts/DataContext";
import { useTranslation } from "../i18n";
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

const EMPTY_COND = { field: "normalized_severity", op: "ge", value: 7 };

const emptyForm = () => ({
  name: "",
  description: "",
  severity: 8,
  enabled: true,
  tags: "",
  conditions: [{ ...EMPTY_COND }],
  correlation: {
    enabled: false,
    window_seconds: 60,
    sequence_override: "",
    require_same_src: true,
    require_same_dest: false,
  },
});

export default function RulesPage() {
  const { fetchWithAuth } = useAuth();
  const { rules, pipelineStats, ruleMatches, refreshRules, refreshPipelineStats, refreshRuleMatches } = useData();
  const { t } = useTranslation();
  const [modalOpen, setModalOpen] = useState(false);
  const [editingId, setEditingId] = useState(null);
  const [form, setForm] = useState(emptyForm());
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState(null);

  useEffect(() => {
    refreshPipelineStats();
    refreshRuleMatches();
  }, [refreshPipelineStats, refreshRuleMatches]);

  const openNew = () => {
    setEditingId(null);
    setForm(emptyForm());
    setTestResult(null);
    setModalOpen(true);
  };

  const openEdit = (rule) => {
    setEditingId(rule.id);
    setForm({
      name: rule.name,
      description: rule.description || "",
      severity: rule.severity,
      enabled: !!rule.enabled,
      tags: (rule.tags || []).join(", "),
      conditions: (rule.conditions && rule.conditions.length ? rule.conditions : [{ ...EMPTY_COND }]),
      correlation: {
        enabled: !!(rule.correlation && rule.correlation.sequence && rule.correlation.sequence.length >= 2),
        window_seconds: rule.correlation?.window_seconds || 60,
        sequence_override: "",
        require_same_src: !!rule.correlation?.require_same_src,
        require_same_dest: !!rule.correlation?.require_same_dest,
      },
    });
    setTestResult(null);
    setModalOpen(true);
  };

  const setCond = (idx, patch) =>
    setForm((f) => ({
      ...f,
      conditions: f.conditions.map((c, i) => (i === idx ? { ...c, ...patch } : c)),
    }));

  const buildRulePayload = () => ({
    name: form.name,
    description: form.description,
    enabled: form.enabled,
    severity: Number(form.severity),
    tags: form.tags.split(",").map((s) => s.trim()).filter(Boolean),
    conditions: form.conditions,
    correlation: form.correlation.enabled
      ? {
          window_seconds: Number(form.correlation.window_seconds) || 60,
          sequence: form.correlation.sequence_override
            ? form.correlation.sequence_override.split(",").map((s) => Number(s.trim())).filter((n) => !Number.isNaN(n))
            : form.conditions.map((_, i) => i),
          require_same_src: form.correlation.require_same_src,
          require_same_dest: form.correlation.require_same_dest,
        }
      : null,
    action_flags: {},
  });

  const handleSave = async () => {
    if (!form.name.trim()) return toast.error("Le nom de la règle est requis");
    setSaving(true);
    try {
      const res = await fetchWithAuth(editingId ? `/api/rules/${editingId}` : "/api/rules", {
        method: editingId ? "PUT" : "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(buildRulePayload()),
      });
      if (res.ok) {
        toast.success(editingId ? "Règle mise à jour" : "Règle créée");
        setModalOpen(false);
        refreshRules();
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

  const handleTest = async () => {
    setTesting(true);
    setTestResult(null);
    try {
      const res = await fetchWithAuth("/api/rules/test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          rule: buildRulePayload(),
          sample_alert: {
            source: "wazuh",
            severity: 10,
            signature: "Exemple de signature",
            description: "Exemple d'alerte",
            src_ip: "10.0.0.1",
            dest_ip: "10.0.0.2",
          },
        }),
      });
      if (res.ok) setTestResult(await res.json());
      else toast.error("Erreur lors du test");
    } catch {
      toast.error("Erreur réseau");
    } finally {
      setTesting(false);
    }
  };

  const handleDelete = async (rule) => {
    if (!window.confirm(`Supprimer la règle « ${rule.name} » ?`)) return;
    try {
      const res = await fetchWithAuth(`/api/rules/${rule.id}`, { method: "DELETE" });
      if (res.ok) {
        toast.success("Règle supprimée");
        refreshRules();
      } else toast.error("Erreur lors de la suppression");
    } catch {
      toast.error("Erreur réseau");
    }
  };

  const sevClass = (s) =>
    s >= 12 ? "text-red-400" : s >= 8 ? "text-orange-400" : s >= 5 ? "text-yellow-400" : "text-gray-400";

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Shield className="text-emerald-400" /> Règles de corrélation
          </h1>
          <p className="text-gray-400 text-sm">
            Moteur de règles F1 — conditions simples et corrélations fenêtrées (MITRE ATT&CK)
          </p>
        </div>
        <button onClick={openNew} className="flex items-center gap-2 bg-emerald-600 hover:bg-emerald-500 px-4 py-2 rounded-lg">
          <Plus size={16} /> Nouvelle règle
        </button>
      </div>

      {/* Pipeline stats */}
      {pipelineStats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
            <div className="text-gray-400 text-xs">Buffer</div>
            <div className="text-xl font-bold">{pipelineStats.buffer.current} / {pipelineStats.buffer.capacity}</div>
          </div>
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
            <div className="text-gray-400 text-xs">Taux de déduplication</div>
            <div className="text-xl font-bold">{(pipelineStats.dedup.dedup_rate * 100).toFixed(1)}%</div>
          </div>
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
            <div className="text-gray-400 text-xs">Matchs de règles</div>
            <div className="text-xl font-bold">{pipelineStats.rule_matches_total}</div>
          </div>
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
            <div className="text-gray-400 text-xs">Sources principales</div>
            <div className="text-sm truncate">
              {(pipelineStats.top_sources || []).slice(0, 2).map((s) => `${s.ip} (${s.count})`).join(", ") || "—"}
            </div>
          </div>
        </div>
      )}

      {/* Rules table */}
      <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-gray-800 text-gray-300">
            <tr>
              <th className="text-left px-4 py-2">Nom</th>
              <th className="text-left px-4 py-2">Sévérité</th>
              <th className="text-left px-4 py-2">Tags</th>
              <th className="text-left px-4 py-2">Type</th>
              <th className="text-left px-4 py-2">Statut</th>
              <th className="text-left px-4 py-2">Actions</th>
            </tr>
          </thead>
          <tbody>
            {(rules || []).map((r) => (
              <tr key={r.id} className="border-t border-gray-800 hover:bg-gray-800/50">
                <td className="px-4 py-2">
                  <div className="font-medium">{r.name}</div>
                  <div className="text-xs text-gray-500">{r.description}</div>
                </td>
                <td className={`px-4 py-2 font-bold ${sevClass(r.severity)}`}>{r.severity}</td>
                <td className="px-4 py-2">
                  <div className="flex flex-wrap gap-1">
                    {(r.tags || []).map((tag) => (
                      <span key={tag} className="bg-gray-800 text-xs px-1.5 py-0.5 rounded">{tag}</span>
                    ))}
                  </div>
                </td>
                <td className="px-4 py-2">
                  {r.correlation?.sequence?.length >= 2 ? (
                    <span className="flex items-center gap-1 text-cyan-400"><GitBranch size={14} /> Corrélation</span>
                  ) : (
                    <span className="text-gray-400">Simple</span>
                  )}
                </td>
                <td className="px-4 py-2">
                  <span className={r.enabled ? "text-emerald-400" : "text-gray-500"}>
                    {r.enabled ? "Active" : "Désactivée"}
                  </span>
                </td>
                <td className="px-4 py-2">
                  <div className="flex gap-2">
                    <button onClick={() => openEdit(r)} className="text-gray-400 hover:text-white"><Edit size={16} /></button>
                    <button onClick={() => handleDelete(r)} className="text-gray-400 hover:text-red-400"><Trash2 size={16} /></button>
                  </div>
                </td>
              </tr>
            ))}
            {(!rules || rules.length === 0) && (
              <tr><td colSpan={6} className="px-4 py-8 text-center text-gray-500">Aucune règle définie</td></tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Recent matches */}
      <div>
        <h2 className="text-lg font-semibold mb-2">Matchs récents</h2>
        <div className="bg-gray-900 border border-gray-800 rounded-lg divide-y divide-gray-800">
          {(ruleMatches || []).slice(0, 5).map((m) => (
            <div key={m.event_id} className="px-4 py-2 text-sm flex justify-between">
              <span className="text-gray-300">
                {m.matched_rules?.map((r) => r.rule_name).join(", ") || "—"}
              </span>
              <span className="text-gray-500">{m.source === "catch_up" ? "rattrapage" : "pipeline"} · {m.timestamp}</span>
            </div>
          ))}
          {(!ruleMatches || ruleMatches.length === 0) && (
            <div className="px-4 py-6 text-center text-gray-500">Aucun match pour le moment</div>
          )}
        </div>
      </div>

      {/* Editor modal */}
      {modalOpen && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <div className="bg-gray-900 border border-gray-700 rounded-xl w-full max-w-2xl max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between px-5 py-4 border-b border-gray-800">
              <h3 className="font-bold">{editingId ? "Modifier la règle" : "Nouvelle règle"}</h3>
              <button onClick={() => setModalOpen(false)} className="text-gray-400 hover:text-white"><X size={18} /></button>
            </div>
            <div className="p-5 space-y-4">
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
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs text-gray-400 mb-1">Sévérité (0-15)</label>
                  <input type="number" min={0} max={15} className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2"
                    value={form.severity} onChange={(e) => setForm({ ...form, severity: Number(e.target.value) })} />
                </div>
                <div>
                  <label className="block text-xs text-gray-400 mb-1">Tags MITRE ATT&CK (séparés par des virgules)</label>
                  <input className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2"
                    value={form.tags} onChange={(e) => setForm({ ...form, tags: e.target.value })} />
                </div>
              </div>

              <div>
                <label className="block text-xs text-gray-400 mb-1">Conditions (toutes doivent être satisfaites)</label>
                <div className="space-y-2">
                  {form.conditions.map((cond, idx) => (
                    <div key={idx} className="flex gap-2 items-center">
                      <input className="flex-1 bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm"
                        value={cond.field} placeholder="champ (ex: normalized_severity)"
                        onChange={(e) => setCond(idx, { field: e.target.value })} />
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

              <div className="border border-gray-800 rounded p-3">
                <label className="flex items-center gap-2 text-sm">
                  <input type="checkbox" checked={form.correlation.enabled}
                    onChange={(e) => setForm((f) => ({ ...f, correlation: { ...f.correlation, enabled: e.target.checked } }))} />
                  Corrélation fenêtrée (séquence de conditions)
                </label>
                {form.correlation.enabled && (
                  <div className="grid grid-cols-3 gap-3 mt-2">
                    <div>
                      <label className="block text-xs text-gray-400">Fenêtre (s)</label>
                      <input type="number" min={1} className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5"
                        value={form.correlation.window_seconds}
                        onChange={(e) => setForm((f) => ({ ...f, correlation: { ...f.correlation, window_seconds: Number(e.target.value) } }))} />
                    </div>
                    <div>
                      <label className="block text-xs text-gray-400">Séquence (index, ex: 0,1)</label>
                      <input className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5"
                        value={form.correlation.sequence_override}
                        onChange={(e) => setForm((f) => ({ ...f, correlation: { ...f.correlation, sequence_override: e.target.value } }))} />
                    </div>
                    <div className="flex items-end gap-2 pb-1">
                      <label className="flex items-center gap-1 text-xs text-gray-400">
                        <input type="checkbox" checked={form.correlation.require_same_src}
                          onChange={(e) => setForm((f) => ({ ...f, correlation: { ...f.correlation, require_same_src: e.target.checked } }))} />
                        même src
                      </label>
                      <label className="flex items-center gap-1 text-xs text-gray-400">
                        <input type="checkbox" checked={form.correlation.require_same_dest}
                          onChange={(e) => setForm((f) => ({ ...f, correlation: { ...f.correlation, require_same_dest: e.target.checked } }))} />
                        même dst
                      </label>
                    </div>
                  </div>
                )}
              </div>

              {testResult && (
                <div className={`rounded p-3 text-sm ${testResult.matched ? "bg-emerald-900/40 text-emerald-300" : "bg-gray-800 text-gray-300"}`}>
                  <div className="flex items-center gap-2 font-medium">
                    {testResult.matched ? <CheckCircle2 size={16} /> : <AlertTriangle size={16} />}
                    {testResult.matched ? "La règle matche l'échantillon" : "La règle ne matche pas l'échantillon"}
                  </div>
                  <div className="text-xs mt-1">
                    Conditions satisfaites : {testResult.matched_conditions?.length ?? 0}/{testResult.condition_count ?? 0}
                    {testResult.correlation?.configured ? ` · ${testResult.correlation.note}` : ""}
                  </div>
                </div>
              )}
            </div>
            <div className="flex justify-end gap-3 px-5 py-4 border-t border-gray-800">
              <button onClick={handleTest} disabled={testing} className="flex items-center gap-2 bg-gray-800 hover:bg-gray-700 px-4 py-2 rounded-lg">
                <FlaskConical size={16} /> {testing ? "Test en cours…" : "Tester"}
              </button>
              <button onClick={() => setModalOpen(false)} className="px-4 py-2 rounded-lg text-gray-400 hover:text-white">Annuler</button>
              <button onClick={handleSave} disabled={saving} className="flex items-center gap-2 bg-emerald-600 hover:bg-emerald-500 px-4 py-2 rounded-lg">
                <Save size={16} /> {saving ? "Enregistrement…" : "Enregistrer"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
