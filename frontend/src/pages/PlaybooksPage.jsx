import { useState, useEffect, useCallback } from "react";
import {
  Plus, RefreshCw, Trash2, Edit, Workflow, X, Save, CheckCircle2,
  AlertTriangle, Power, Play, Ban, ListChecks, ShieldCheck,
} from "lucide-react";
import { useAuth } from "../contexts/AuthContext";
import { useData } from "../contexts/DataContext";
import { useTranslation } from "../i18n";
import { toast } from "react-toastify";

const STEP_TYPES = [
  { value: "notify", label: "Notification" },
  { value: "log", label: "Journaliser" },
  { value: "sleep", label: "Pause (sleep)" },
  { value: "run_task", label: "Tâche (reload_suricata / run_nmap)" },
  { value: "block_ip", label: "Bloquer IP (active-response)" },
];

const SOURCE_OPTIONS = ["wazuh", "suricata"];

const emptyStep = () => ({ type: "notify", params: { message: "" } });

const emptyForm = () => ({
  name: "",
  description: "",
  trigger_rule_ids: [],
  trigger_min_severity: 7,
  trigger_sources: [],
  requires_approval: false,
  enabled: true,
  steps: [emptyStep()],
});

const statusClass = (s) => {
  switch (s) {
    case "success": return "text-emerald-400";
    case "failed": return "text-red-400";
    case "pending_approval": return "text-yellow-400";
    case "approved":
    case "running": return "text-cyan-400";
    case "cancelled": return "text-gray-500";
    case "skipped": return "text-gray-400";
    default: return "text-gray-400";
  }
};

const statusLabel = (s) => {
  switch (s) {
    case "pending_approval": return "En attente d'approbation";
    case "approved": return "Approuvé";
    case "running": return "En cours";
    case "success": return "Succès";
    case "failed": return "Échec";
    case "skipped": return "Ignoré";
    case "cancelled": return "Annulé";
    default: return s || "—";
  }
};

export default function PlaybooksPage() {
  const { fetchWithAuth } = useAuth();
  const { rules } = useData();
  const { t } = useTranslation();
  const [playbooks, setPlaybooks] = useState([]);
  const [runs, setRuns] = useState([]);
  const [loading, setLoading] = useState(true);
  const [modalOpen, setModalOpen] = useState(false);
  const [editingId, setEditingId] = useState(null);
  const [form, setForm] = useState(emptyForm());
  const [saving, setSaving] = useState(false);
  const [expandedRun, setExpandedRun] = useState(null);
  const [runSteps, setRunSteps] = useState(null);

  const load = useCallback(async () => {
    try {
      const [pbRes, runsRes] = await Promise.all([
        fetchWithAuth("/api/playbooks"),
        fetchWithAuth("/api/playbooks/runs?limit=20"),
      ]);
      if (pbRes.ok) setPlaybooks(await pbRes.json());
      if (runsRes.ok) setRuns(await runsRes.json());
    } catch {
      toast.error("Erreur réseau");
    } finally {
      setLoading(false);
    }
  }, [fetchWithAuth]);

  useEffect(() => {
    load();
  }, [load]);

  const openNew = () => {
    setEditingId(null);
    setForm(emptyForm());
    setModalOpen(true);
  };

  const openEdit = (pb) => {
    setEditingId(pb.id);
    setForm({
      name: pb.name,
      description: pb.description || "",
      trigger_rule_ids: pb.trigger_rule_ids || [],
      trigger_min_severity: pb.trigger_min_severity ?? 7,
      trigger_sources: pb.trigger_sources || [],
      requires_approval: !!pb.requires_approval,
      enabled: !!pb.enabled,
      steps: (pb.steps && pb.steps.length ? pb.steps : [emptyStep()]).map((s) => ({
        type: s.type,
        params: { ...(s.params || {}) },
      })),
    });
    setModalOpen(true);
  };

  const buildPayload = () => ({
    name: form.name,
    description: form.description || null,
    trigger_rule_ids: form.trigger_rule_ids,
    trigger_min_severity: form.trigger_min_severity,
    trigger_sources: form.trigger_sources,
    requires_approval: form.requires_approval,
    enabled: form.enabled,
    steps: form.steps,
  });

  const handleSave = async () => {
    if (!form.name.trim()) {
      toast.error("Le nom est requis");
      return;
    }
    setSaving(true);
    try {
      const res = await fetchWithAuth(
        editingId ? `/api/playbooks/${editingId}` : "/api/playbooks",
        {
          method: editingId ? "PATCH" : "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(buildPayload()),
        },
      );
      if (res.ok) {
        toast.success(editingId ? "Playbook mis à jour" : "Playbook créé");
        setModalOpen(false);
        load();
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

  const handleToggle = async (pb) => {
    try {
      const res = await fetchWithAuth(`/api/playbooks/${pb.id}/toggle`, { method: "POST" });
      if (res.ok) {
        toast.success(pb.enabled ? "Playbook désactivé" : "Playbook activé");
        load();
      } else toast.error("Erreur lors du changement d'état");
    } catch {
      toast.error("Erreur réseau");
    }
  };

  const handleDelete = async (pb) => {
    if (!window.confirm(`Supprimer le playbook « ${pb.name} » ?`)) return;
    try {
      const res = await fetchWithAuth(`/api/playbooks/${pb.id}`, { method: "DELETE" });
      if (res.ok) {
        toast.success("Playbook supprimé");
        load();
      } else toast.error("Erreur lors de la suppression");
    } catch {
      toast.error("Erreur réseau");
    }
  };

  const handleApprove = async (run) => {
    try {
      const res = await fetchWithAuth(`/api/playbooks/runs/${run.id}/approve`, { method: "POST" });
      if (res.ok) {
        toast.success("Run approuvé — exécution lancée");
        load();
      } else {
        const err = await res.json().catch(() => ({}));
        toast.error(err.detail || "Erreur lors de l'approbation");
      }
    } catch {
      toast.error("Erreur réseau");
    }
  };

  const handleCancel = async (run) => {
    try {
      const res = await fetchWithAuth(`/api/playbooks/runs/${run.id}/cancel`, { method: "POST" });
      if (res.ok) {
        toast.success("Run annulé");
        load();
      } else {
        const err = await res.json().catch(() => ({}));
        toast.error(err.detail || "Erreur lors de l'annulation");
      }
    } catch {
      toast.error("Erreur réseau");
    }
  };

  const toggleRunSteps = async (run) => {
    if (expandedRun === run.id) {
      setExpandedRun(null);
      setRunSteps(null);
      return;
    }
    setExpandedRun(run.id);
    setRunSteps(null);
    try {
      const res = await fetchWithAuth(`/api/playbooks/runs/${run.id}/steps`);
      if (res.ok) setRunSteps(await res.json());
      else setRunSteps([]);
    } catch {
      setRunSteps([]);
    }
  };

  const setStep = (idx, patch) => {
    setForm((f) => ({
      ...f,
      steps: f.steps.map((s, i) => (i === idx ? { ...s, ...patch } : s)),
    }));
  };

  const setStepParam = (idx, key, value) => {
    setForm((f) => ({
      ...f,
      steps: f.steps.map((s, i) =>
        i === idx ? { ...s, params: { ...s.params, [key]: value } } : s,
      ),
    }));
  };

  const toggleRule = (id) => {
    setForm((f) => ({
      ...f,
      trigger_rule_ids: f.trigger_rule_ids.includes(id)
        ? f.trigger_rule_ids.filter((x) => x !== id)
        : [...f.trigger_rule_ids, id],
    }));
  };

  const toggleSource = (src) => {
    setForm((f) => ({
      ...f,
      trigger_sources: f.trigger_sources.includes(src)
        ? f.trigger_sources.filter((x) => x !== src)
        : [...f.trigger_sources, src],
    }));
  };

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Workflow className="text-emerald-400" /> Playbooks (Mini-SOAR)
          </h1>
          <p className="text-gray-400 text-sm">
            Automatisation F3 — déclencheurs sur règles, actions (notify / log / sleep / tâche / blocage IP) et approbations
          </p>
        </div>
        <div className="flex gap-2">
          <button onClick={load} className="flex items-center gap-2 bg-gray-800 hover:bg-gray-700 px-4 py-2 rounded-lg">
            <RefreshCw size={16} /> Actualiser
          </button>
          <button onClick={openNew} className="flex items-center gap-2 bg-emerald-600 hover:bg-emerald-500 px-4 py-2 rounded-lg">
            <Plus size={16} /> Nouveau playbook
          </button>
        </div>
      </div>

      {/* Playbooks table */}
      <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-gray-800 text-gray-300">
            <tr>
              <th className="text-left px-4 py-2">Nom</th>
              <th className="text-left px-4 py-2">Déclencheurs</th>
              <th className="text-left px-4 py-2">Étapes</th>
              <th className="text-left px-4 py-2">Mode</th>
              <th className="text-left px-4 py-2">Statut</th>
              <th className="text-left px-4 py-2">Actions</th>
            </tr>
          </thead>
          <tbody>
            {(playbooks || []).map((pb) => (
              <tr key={pb.id} className="border-t border-gray-800 hover:bg-gray-800/50">
                <td className="px-4 py-2">
                  <div className="font-medium">{pb.name}</div>
                  <div className="text-xs text-gray-500">{pb.description}</div>
                </td>
                <td className="px-4 py-2">
                  <div className="text-xs">
                    {pb.trigger_rule_ids?.length > 0
                      ? `${pb.trigger_rule_ids.length} règle(s)`
                      : "Toutes règles"}
                    {pb.trigger_min_severity != null && (
                      <span className="text-gray-500"> · sev ≥ {pb.trigger_min_severity}</span>
                    )}
                    {pb.trigger_sources?.length > 0 && (
                      <span className="text-gray-500"> · {pb.trigger_sources.join(", ")}</span>
                    )}
                  </div>
                </td>
                <td className="px-4 py-2 text-gray-400">{(pb.steps || []).length}</td>
                <td className="px-4 py-2">
                  {pb.requires_approval ? (
                    <span className="flex items-center gap-1 text-yellow-400"><ShieldCheck size={14} /> Approbation</span>
                  ) : (
                    <span className="text-gray-400">Auto</span>
                  )}
                </td>
                <td className="px-4 py-2">
                  <span className={pb.enabled ? "text-emerald-400" : "text-gray-500"}>
                    {pb.enabled ? "Active" : "Désactivé"}
                  </span>
                </td>
                <td className="px-4 py-2">
                  <div className="flex gap-2">
                    <button onClick={() => handleToggle(pb)} title={pb.enabled ? "Désactiver" : "Activer"}
                      className="text-gray-400 hover:text-emerald-400"><Power size={16} /></button>
                    <button onClick={() => openEdit(pb)} className="text-gray-400 hover:text-white"><Plus size={16} className="rotate-45" /></button>
                    <button onClick={() => handleDelete(pb)} className="text-gray-400 hover:text-red-400"><Trash2 size={16} /></button>
                  </div>
                </td>
              </tr>
            ))}
            {(!playbooks || playbooks.length === 0) && (
              <tr><td colSpan={6} className="px-4 py-8 text-center text-gray-500">
                {loading ? "Chargement…" : "Aucun playbook défini"}
              </td></tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Runs */}
      <div>
        <h2 className="text-lg font-semibold mb-2 flex items-center gap-2">
          <ListChecks size={18} className="text-cyan-400" /> Exécutions récentes
        </h2>
        <div className="bg-gray-900 border border-gray-800 rounded-lg divide-y divide-gray-800">
          {(runs || []).map((run) => (
            <div key={run.id}>
              <div className="px-4 py-2 text-sm flex items-center justify-between">
                <button onClick={() => toggleRunSteps(run)} className="flex items-center gap-3 text-left flex-1">
                  <span className="text-gray-300">Run #{run.id}</span>
                  <span className="text-gray-500 text-xs">playbook {run.playbook_id}</span>
                  <span className={`font-medium ${statusClass(run.status)}`}>{statusLabel(run.status)}</span>
                  <span className="text-gray-500 text-xs">{run.created_at}</span>
                </button>
                <div className="flex gap-2">
                  {run.status === "pending_approval" && (
                    <button onClick={() => handleApprove(run)}
                      className="flex items-center gap-1 text-emerald-400 hover:text-emerald-300 text-xs">
                      <CheckCircle2 size={14} /> Approuver
                    </button>
                  )}
                  {["pending_approval", "approved", "running"].includes(run.status) && (
                    <button onClick={() => handleCancel(run)}
                      className="flex items-center gap-1 text-red-400 hover:text-red-300 text-xs">
                      <Ban size={14} /> Annuler
                    </button>
                  )}
                </div>
              </div>
              {expandedRun === run.id && (
                <div className="px-6 pb-3">
                  {runSteps === null ? (
                    <div className="text-xs text-gray-500">Chargement des étapes…</div>
                  ) : runSteps.length === 0 ? (
                    <div className="text-xs text-gray-500">Aucune étape enregistrée</div>
                  ) : (
                    <div className="space-y-1">
                      {runSteps.map((s) => (
                        <div key={s.step_index} className="flex items-center gap-2 text-xs">
                          <span className="text-gray-500">#{s.step_index}</span>
                          <span className="text-gray-300">{s.step_type}</span>
                          <span className={statusClass(s.status)}>{statusLabel(s.status)}</span>
                          {s.duration_ms != null && <span className="text-gray-500">{s.duration_ms}ms</span>}
                          {s.error && <span className="text-red-400">{s.error}</span>}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          ))}
          {(!runs || runs.length === 0) && (
            <div className="px-4 py-6 text-center text-gray-500">Aucune exécution pour le moment</div>
          )}
        </div>
      </div>

      {/* Editor modal */}
      {modalOpen && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <div className="bg-gray-900 border border-gray-700 rounded-xl w-full max-w-3xl max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between px-5 py-4 border-b border-gray-800">
              <h3 className="font-bold">{editingId ? "Modifier le playbook" : "Nouveau playbook"}</h3>
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
                  <label className="block text-xs text-gray-400 mb-1">Sévérité minimale (0-15)</label>
                  <input type="number" min={0} max={15} className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2"
                    value={form.trigger_min_severity}
                    onChange={(e) => setForm({ ...form, trigger_min_severity: Number(e.target.value) })} />
                </div>
                <div>
                  <label className="block text-xs text-gray-400 mb-1">Sources déclencheuses</label>
                  <div className="flex gap-3 pt-1">
                    {SOURCE_OPTIONS.map((src) => (
                      <label key={src} className="flex items-center gap-1 text-sm">
                        <input type="checkbox" checked={form.trigger_sources.includes(src)}
                          onChange={() => toggleSource(src)} />
                        {src}
                      </label>
                    ))}
                  </div>
                </div>
              </div>

              <div>
                <label className="block text-xs text-gray-400 mb-1">Règles déclencheuses (vide = toutes)</label>
                <div className="flex flex-wrap gap-2">
                  {(rules || []).map((r) => (
                    <button key={r.id} type="button"
                      onClick={() => toggleRule(r.id)}
                      className={`px-2 py-1 rounded text-xs border ${
                        form.trigger_rule_ids.includes(r.id)
                          ? "bg-emerald-900/40 border-emerald-600 text-emerald-300"
                          : "bg-gray-800 border-gray-700 text-gray-400"
                      }`}>
                      {r.name}
                    </button>
                  ))}
                  {(!rules || rules.length === 0) && (
                    <span className="text-xs text-gray-500">Aucune règle disponible</span>
                  )}
                </div>
              </div>

              <div className="flex items-center gap-4">
                <label className="flex items-center gap-2 text-sm">
                  <input type="checkbox" checked={form.requires_approval}
                    onChange={(e) => setForm({ ...form, requires_approval: e.target.checked })} />
                  Exiger une approbation avant exécution
                </label>
                <label className="flex items-center gap-2 text-sm">
                  <input type="checkbox" checked={form.enabled}
                    onChange={(e) => setForm({ ...form, enabled: e.target.checked })} />
                  Actif
                </label>
              </div>

              <div>
                <label className="block text-xs text-gray-400 mb-1">Étapes (exécutées dans l'ordre)</label>
                <div className="space-y-2">
                  {form.steps.map((step, idx) => (
                    <div key={idx} className="border border-gray-800 rounded p-3 space-y-2">
                      <div className="flex items-center gap-2">
                        <span className="text-xs text-gray-500">#{idx + 1}</span>
                        <select className="flex-1 bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm"
                          value={step.type} onChange={(e) => setStep(idx, { type: e.target.value, params: {} })}>
                          {STEP_TYPES.map((s) => <option key={s.value} value={s.value}>{s.label}</option>)}
                        </select>
                        <button className="text-gray-500 hover:text-red-400"
                          onClick={() => setForm((f) => ({ ...f, steps: f.steps.filter((_, i) => i !== idx) }))}>
                          <X size={16} />
                        </button>
                      </div>
                      {step.type === "notify" && (
                        <input className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm"
                          placeholder="Message (supporte {{src_ip}}, {{dest_ip}}…)"
                          value={step.params.message || ""}
                          onChange={(e) => setStepParam(idx, "message", e.target.value)} />
                      )}
                      {step.type === "log" && (
                        <input className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm"
                          placeholder="Message à journaliser"
                          value={step.params.message || ""}
                          onChange={(e) => setStepParam(idx, "message", e.target.value)} />
                      )}
                      {step.type === "sleep" && (
                        <input type="number" min={0} max={60} className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm"
                          placeholder="Secondes (max 60)"
                          value={step.params.timeout_seconds ?? ""}
                          onChange={(e) => setStepParam(idx, "timeout_seconds", Number(e.target.value))} />
                      )}
                      {step.type === "run_task" && (
                        <select className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm"
                          value={step.params.task || ""}
                          onChange={(e) => setStepParam(idx, "task", e.target.value)}>
                          <option value="">— choisir une tâche —</option>
                          <option value="reload_suricata">reload_suricata</option>
                          <option value="run_nmap">run_nmap</option>
                        </select>
                      )}
                      {step.type === "block_ip" && (
                        <div className="grid grid-cols-2 gap-2">
                          <input className="bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm"
                            placeholder="IP (défaut {{src_ip}})"
                            value={step.params.ip || ""}
                            onChange={(e) => setStepParam(idx, "ip", e.target.value)} />
                          <input className="bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm"
                            placeholder="Agent ID (défaut 000)"
                            value={step.params.agent_id || ""}
                            onChange={(e) => setStepParam(idx, "agent_id", e.target.value)} />
                        </div>
                      )}
                    </div>
                  ))}
                </div>
                <button className="text-emerald-400 text-sm mt-2"
                  onClick={() => setForm((f) => ({ ...f, steps: [...f.steps, emptyStep()] }))}>
                  + Ajouter une étape
                </button>
              </div>
            </div>
            <div className="flex justify-end gap-3 px-5 py-4 border-t border-gray-800">
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