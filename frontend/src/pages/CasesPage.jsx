import { useState, useCallback } from "react";
import {
  Plus, Trash2, Edit, FolderKanban, X, Save, ChevronLeft, Link2, Search,
  XCircle,
} from "lucide-react";
import { useAuth } from "../contexts/AuthContext";
import { useData } from "../contexts/DataContext";
import { toast } from "react-toastify";
import Timeline from "../components/Timeline";

const CASE_STATUSES = ["open", "in_progress", "resolved", "closed"];
const LINK_STATUSES = ["open", "in_progress", "resolved", "dismissed"];

const STATUS_LABEL = {
  open: "Ouverte", in_progress: "En cours", resolved: "Résolue", closed: "Clôturée",
  dismissed: "Écartée",
};

const emptyForm = () => ({ title: "", description: "", severity: 8, assignee: "" });

const sevClass = (s) =>
  s >= 12 ? "text-red-400" : s >= 8 ? "text-orange-400" : s >= 5 ? "text-yellow-400" : "text-gray-400";

const pillClass = (status) => {
  switch (status) {
    case "open": return "bg-blue-500/10 text-blue-400 border border-blue-500/20";
    case "in_progress": return "bg-amber-500/10 text-amber-400 border border-amber-500/20";
    case "resolved": return "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20";
    case "dismissed": return "bg-gray-500/10 text-gray-400 border border-gray-500/20";
    default: return "bg-gray-500/10 text-gray-400 border border-gray-500/20";
  }
};

export default function CasesPage() {
  const { fetchWithAuth } = useAuth();
  const { cases, caseStats, refreshCases, refreshCaseStats } = useData();

  const [view, setView] = useState("list"); // "list" | "detail"
  const [selectedId, setSelectedId] = useState(null);
  const [detail, setDetail] = useState(null);
  const [links, setLinks] = useState([]);
  const [timeline, setTimeline] = useState([]);

  const [modalOpen, setModalOpen] = useState(false);
  const [editingId, setEditingId] = useState(null);
  const [form, setForm] = useState(emptyForm());
  const [saving, setSaving] = useState(false);

  const [closeModal, setCloseModal] = useState(false);
  const [resolution, setResolution] = useState("");

  const [linkModal, setLinkModal] = useState(false);
  const [linkable, setLinkable] = useState([]);
  const [linkSource, setLinkSource] = useState("alert");
  const [pickedAlert, setPickedAlert] = useState(null);

  const [statusFilter, setStatusFilter] = useState("");
  const [search, setSearch] = useState("");

  const loadDetail = useCallback(async (caseId) => {
    try {
      const [caseRes, linksRes, tlRes] = await Promise.all([
        fetchWithAuth(`/api/cases/${caseId}`),
        fetchWithAuth(`/api/cases/${caseId}/alerts`),
        fetchWithAuth(`/api/cases/${caseId}/timeline?limit=100`),
      ]);
      if (caseRes.ok) setDetail(await caseRes.json());
      if (linksRes.ok) setLinks(await linksRes.json());
      if (tlRes.ok) setTimeline(await tlRes.json());
    } catch (e) {
      toast.error("Erreur réseau");
    }
  }, [fetchWithAuth]);

  const openDetail = (caseId) => {
    setSelectedId(caseId);
    setView("detail");
    loadDetail(caseId);
  };

  const backToList = () => {
    setView("list");
    setSelectedId(null);
    setDetail(null);
    setLinks([]);
    setTimeline([]);
    refreshCases();
    refreshCaseStats();
  };

  const openNew = () => { setEditingId(null); setForm(emptyForm()); setModalOpen(true); };

  const openEdit = (c) => {
    setEditingId(c.id);
    setForm({ title: c.title, description: c.description || "", severity: c.severity, assignee: c.assignee || "" });
    setModalOpen(true);
  };

  const handleSave = async () => {
    if (!form.title.trim()) return toast.error("Le titre est requis");
    setSaving(true);
    try {
      const payload = {
        title: form.title,
        description: form.description,
        severity: Number(form.severity),
        assignee: form.assignee || null,
      };
      const res = await fetchWithAuth(editingId ? `/api/cases/${editingId}` : "/api/cases", {
        method: editingId ? "PUT" : "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (res.ok) {
        toast.success(editingId ? "Affaire mise à jour" : "Affaire créée");
        setModalOpen(false);
        refreshCases();
        refreshCaseStats();
        if (editingId) loadDetail(editingId);
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

  const handleClose = async () => {
    setSaving(true);
    try {
      const res = await fetchWithAuth(`/api/cases/${selectedId}/close`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ resolution }),
      });
      if (res.ok) {
        toast.success("Affaire clôturée");
        setCloseModal(false);
        setResolution("");
        loadDetail(selectedId);
        refreshCases();
        refreshCaseStats();
      } else {
        const err = await res.json().catch(() => ({}));
        toast.error(err.detail || "Erreur lors de la clôture");
      }
    } catch {
      toast.error("Erreur réseau");
    } finally {
      setSaving(false);
    }
  };

  const handleReopen = async () => {
    try {
      const res = await fetchWithAuth(`/api/cases/${selectedId}/reopen`, { method: "POST" });
      if (res.ok) {
        toast.success("Affaire réouverte");
        loadDetail(selectedId);
        refreshCases();
        refreshCaseStats();
      } else toast.error("Erreur lors de la réouverture");
    } catch {
      toast.error("Erreur réseau");
    }
  };

  const handleDelete = async (c) => {
    if (!window.confirm(`Supprimer l'affaire « ${c.title} » ?`)) return;
    try {
      const res = await fetchWithAuth(`/api/cases/${c.id}`, { method: "DELETE" });
      if (res.ok) {
        toast.success("Affaire supprimée");
        refreshCases();
        refreshCaseStats();
      } else toast.error("Erreur lors de la suppression");
    } catch {
      toast.error("Erreur réseau");
    }
  };

  const openLinkModal = async () => {
    setLinkModal(true);
    setPickedAlert(null);
    await loadLinkable(linkSource);
  };

  const loadLinkable = async (src) => {
    try {
      const res = await fetchWithAuth(`/api/cases/linkable-alerts?source=${src}&limit=100`);
      if (res.ok) setLinkable(await res.json());
      else setLinkable([]);
    } catch {
      setLinkable([]);
    }
  };

  const changeLinkSource = async (src) => {
    setLinkSource(src);
    setPickedAlert(null);
    await loadLinkable(src);
  };

  const handleLink = async () => {
    if (!pickedAlert) return toast.error("Choisissez une alerte");
    try {
      const res = await fetchWithAuth(`/api/cases/${selectedId}/alerts`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ alert_type: pickedAlert.alert_type, alert_id: pickedAlert.alert_id }),
      });
      if (res.ok) {
        toast.success("Alerte liée");
        setLinkModal(false);
        loadDetail(selectedId);
        refreshCases();
      } else {
        const err = await res.json().catch(() => ({}));
        toast.error(err.detail || "Erreur lors du lien");
      }
    } catch {
      toast.error("Erreur réseau");
    }
  };

  const handleUnlink = async (link) => {
    if (!window.confirm("Retirer cette alerte de l'affaire ?")) return;
    try {
      const res = await fetchWithAuth(`/api/cases/${selectedId}/alerts/${link.link_id}`, { method: "DELETE" });
      if (res.ok) {
        toast.success("Alerte retirée");
        loadDetail(selectedId);
        refreshCases();
      } else toast.error("Erreur lors du retrait");
    } catch {
      toast.error("Erreur réseau");
    }
  };

  const handleTriage = async (link, newStatus) => {
    try {
      const res = await fetchWithAuth(`/api/cases/${selectedId}/alerts/${link.link_id}/triage`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: newStatus, note: link.link_note || null }),
      });
      if (res.ok) {
        toast.success("Triage enregistré");
        loadDetail(selectedId);
        refreshCases();
      } else {
        const err = await res.json().catch(() => ({}));
        toast.error(err.detail || "Erreur lors du triage");
      }
    } catch {
      toast.error("Erreur réseau");
    }
  };

  const handleAddNote = async (note) => {
    try {
      const res = await fetchWithAuth(`/api/cases/${selectedId}/timeline`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ note }),
      });
      if (res.ok) {
        toast.success("Note ajoutée");
        const tl = await fetchWithAuth(`/api/cases/${selectedId}/timeline?limit=100`);
        if (tl.ok) setTimeline(await tl.json());
      } else toast.error("Erreur lors de l'ajout de la note");
    } catch {
      toast.error("Erreur réseau");
    }
  };

  const updateLinkNote = (linkId, note) => {
    setLinks((prev) => prev.map((l) => (l.link_id === linkId ? { ...l, link_note: note } : l)));
  };

  const filteredCases = (cases || []).filter((c) => {
    if (statusFilter && c.status !== statusFilter) return false;
    if (search && !`${c.title} ${c.description}`.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  const stats = caseStats || { open: 0, in_progress: 0, resolved: 0, closed: 0, total: 0, high_severity_active: 0 };

  // ── Vue LISTE ─────────────────────────────────────────────────────
  if (view === "list") {
    return (
      <div className="p-6 space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold flex items-center gap-2">
              <FolderKanban className="text-emerald-400" /> Gestion des affaires
            </h1>
            <p className="text-gray-400 text-sm">Cas d'investigation, triage des alertes et timeline (F2)</p>
          </div>
          <button onClick={openNew} className="flex items-center gap-2 bg-emerald-600 hover:bg-emerald-500 px-4 py-2 rounded-lg">
            <Plus size={16} /> Nouvelle affaire
          </button>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
            <div className="text-gray-400 text-xs">Ouvertes</div>
            <div className="text-xl font-bold text-blue-400">{stats.open}</div>
          </div>
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
            <div className="text-gray-400 text-xs">En cours</div>
            <div className="text-xl font-bold text-amber-400">{stats.in_progress}</div>
          </div>
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
            <div className="text-gray-400 text-xs">Résolues</div>
            <div className="text-xl font-bold text-emerald-400">{stats.resolved}</div>
          </div>
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
            <div className="text-gray-400 text-xs">Clôturées</div>
            <div className="text-xl font-bold text-gray-400">{stats.closed}</div>
          </div>
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
            <div className="text-gray-400 text-xs">Critiques actives (sev ≥ 8)</div>
            <div className="text-xl font-bold text-red-400">{stats.high_severity_active}</div>
          </div>
        </div>

        <div className="flex gap-3 items-center">
          <div className="relative flex-1 max-w-md">
            <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
            <input
              className="w-full bg-gray-900 border border-gray-800 rounded-lg pl-9 pr-3 py-2 text-sm"
              placeholder="Rechercher (titre, description)…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
          <select
            className="bg-gray-900 border border-gray-800 rounded-lg px-3 py-2 text-sm"
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
          >
            <option value="">Tous les statuts</option>
            {CASE_STATUSES.map((s) => (
              <option key={s} value={s}>{STATUS_LABEL[s]}</option>
            ))}
          </select>
        </div>

        <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-gray-800 text-gray-300">
              <tr>
                <th className="text-left px-4 py-2">Titre</th>
                <th className="text-left px-4 py-2">Sévérité</th>
                <th className="text-left px-4 py-2">Statut</th>
                <th className="text-left px-4 py-2">Assignée à</th>
                <th className="text-left px-4 py-2">Alertes</th>
                <th className="text-left px-4 py-2">Mise à jour</th>
                <th className="text-left px-4 py-2">Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredCases.map((c) => (
                <tr key={c.id} className="border-t border-gray-800 hover:bg-gray-800/50">
                  <td className="px-4 py-2">
                    <button onClick={() => openDetail(c.id)} className="font-medium text-left hover:text-emerald-400">
                      {c.title}
                    </button>
                    <div className="text-xs text-gray-500 truncate max-w-xs">{c.description}</div>
                  </td>
                  <td className={`px-4 py-2 font-bold ${sevClass(c.severity)}`}>{c.severity}</td>
                  <td className="px-4 py-2">
                    <span className={`status-pill ${pillClass(c.status)}`}>{STATUS_LABEL[c.status]}</span>
                  </td>
                  <td className="px-4 py-2 text-gray-400">{c.assignee || "—"}</td>
                  <td className="px-4 py-2 text-gray-400">{c.links_count || 0}</td>
                  <td className="px-4 py-2 text-gray-500">{c.updated_at ? new Date(c.updated_at).toLocaleString() : "—"}</td>
                  <td className="px-4 py-2">
                    <div className="flex gap-2">
                      <button onClick={() => openEdit(c)} className="text-gray-400 hover:text-white" title="Modifier"><Edit size={16} /></button>
                      <button onClick={() => handleDelete(c)} className="text-gray-400 hover:text-red-400" title="Supprimer"><Trash2 size={16} /></button>
                    </div>
                  </td>
                </tr>
              ))}
              {filteredCases.length === 0 && (
                <tr><td colSpan={7} className="px-4 py-8 text-center text-gray-500">Aucune affaire</td></tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Modal création / édition */}
        {modalOpen && (
          <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
            <div className="bg-gray-900 border border-gray-700 rounded-xl w-full max-w-lg">
              <div className="flex items-center justify-between px-5 py-4 border-b border-gray-800">
                <h3 className="font-bold">{editingId ? "Modifier l'affaire" : "Nouvelle affaire"}</h3>
                <button onClick={() => setModalOpen(false)} className="text-gray-400 hover:text-white"><X size={18} /></button>
              </div>
              <div className="p-5 space-y-4">
                <div>
                  <label className="block text-xs text-gray-400 mb-1">Titre *</label>
                  <input className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2"
                    value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })} />
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
                    <label className="block text-xs text-gray-400 mb-1">Assignée à (username)</label>
                    <input className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2"
                      value={form.assignee} onChange={(e) => setForm({ ...form, assignee: e.target.value })} />
                  </div>
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

  // ── Vue DÉTAIL ────────────────────────────────────────────────────
  return (
    <div className="p-6 space-y-6">
      <button onClick={backToList} className="flex items-center gap-1 text-gray-400 hover:text-white text-sm">
        <ChevronLeft size={16} /> Retour à la liste
      </button>

      {detail && (
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-5">
          <div className="flex items-start justify-between">
            <div>
              <h1 className="text-2xl font-bold">{detail.title}</h1>
              <p className="text-gray-400 text-sm mt-1">{detail.description}</p>
            </div>
            <div className="flex items-center gap-2">
              <span className={`status-pill ${pillClass(detail.status)}`}>{STATUS_LABEL[detail.status]}</span>
              <span className={`font-bold ${sevClass(detail.severity)}`}>sev {detail.severity}</span>
            </div>
          </div>
          <div className="flex flex-wrap gap-4 mt-4 text-sm text-gray-400">
            <span>Créée par <b className="text-gray-200">{detail.created_by}</b></span>
            <span>Assignée à <b className="text-gray-200">{detail.assignee || "—"}</b></span>
            <span>{detail.links_count || 0} alerte(s) · {detail.open_links_count || 0} non triée(s)</span>
            {detail.closed_at && (
              <span>Clôturée le {new Date(detail.closed_at).toLocaleString()} par <b className="text-gray-200">{detail.closed_by}</b></span>
            )}
          </div>
          <div className="flex gap-2 mt-4">
            <button onClick={openLinkModal} className="flex items-center gap-1 bg-emerald-600 hover:bg-emerald-500 px-3 py-2 rounded-lg text-sm">
              <Link2 size={14} /> Lier une alerte
            </button>
            {detail.status === "closed" ? (
              <button onClick={handleReopen} className="flex items-center gap-1 bg-gray-800 hover:bg-gray-700 px-3 py-2 rounded-lg text-sm">
                Réouvrir
              </button>
            ) : (
              <button onClick={() => setCloseModal(true)} className="flex items-center gap-1 bg-gray-800 hover:bg-gray-700 px-3 py-2 rounded-lg text-sm">
                <XCircle size={14} /> Clôturer
              </button>
            )}
            <button onClick={() => openEdit(detail)} className="flex items-center gap-1 bg-gray-800 hover:bg-gray-700 px-3 py-2 rounded-lg text-sm">
              <Edit size={14} /> Modifier
            </button>
            <button onClick={() => handleDelete(detail)} className="flex items-center gap-1 bg-gray-800 hover:bg-red-900/40 px-3 py-2 rounded-lg text-sm">
              <Trash2 size={14} /> Supprimer
            </button>
          </div>
        </div>
      )}

      {/* Alertes liées + triage */}
      <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-gray-800 font-semibold">Alertes liées ({links.length})</div>
        <table className="w-full text-sm">
          <thead className="bg-gray-800 text-gray-300">
            <tr>
              <th className="text-left px-4 py-2">Alerte</th>
              <th className="text-left px-4 py-2">Source</th>
              <th className="text-left px-4 py-2">Sévérité</th>
              <th className="text-left px-4 py-2">Triage</th>
              <th className="text-left px-4 py-2">Note</th>
              <th className="text-left px-4 py-2">Actions</th>
            </tr>
          </thead>
          <tbody>
            {links.map((l) => (
              <tr key={l.link_id} className="border-t border-gray-800 hover:bg-gray-800/50">
                <td className="px-4 py-2">
                  <div className="font-medium">{l.signature || "—"}</div>
                  <div className="text-xs text-gray-500">
                    #{l.alert_id} · {l.src_ip || "—"}{l.dest_ip ? ` → ${l.dest_ip}` : ""} · {l.timestamp ? new Date(l.timestamp).toLocaleString() : ""}
                  </div>
                </td>
                <td className="px-4 py-2">
                  <span className="text-xs bg-gray-800 px-1.5 py-0.5 rounded">{l.alert_type}</span>
                  <span className="text-xs text-gray-500"> · {l.source}</span>
                </td>
                <td className={`px-4 py-2 font-bold ${sevClass(l.normalized_severity ?? l.severity)}`}>
                  {l.normalized_severity ?? l.severity}
                </td>
                <td className="px-4 py-2">
                  <select
                    className="bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs"
                    value={l.link_status}
                    onChange={(e) => handleTriage(l, e.target.value)}
                  >
                    {LINK_STATUSES.map((s) => (
                      <option key={s} value={s}>{STATUS_LABEL[s]}</option>
                    ))}
                  </select>
                  {l.triaged_by && <div className="text-[10px] text-gray-500 mt-1">par {l.triaged_by}</div>}
                </td>
                <td className="px-4 py-2">
                  <input
                    className="bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs w-full"
                    placeholder="Note de triage…"
                    value={l.link_note || ""}
                    onChange={(e) => updateLinkNote(l.link_id, e.target.value)}
                    onBlur={() => handleTriage(l, l.link_status)}
                  />
                </td>
                <td className="px-4 py-2">
                  <button onClick={() => handleUnlink(l)} className="text-gray-400 hover:text-red-400" title="Retirer">
                    <Trash2 size={16} />
                  </button>
                </td>
              </tr>
            ))}
            {links.length === 0 && (
              <tr><td colSpan={6} className="px-4 py-8 text-center text-gray-500">Aucune alerte liée — cliquez « Lier une alerte »</td></tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Timeline */}
      <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
        <div className="font-semibold mb-3">Timeline d'investigation</div>
        <Timeline events={timeline} onAddNote={handleAddNote} emptyText="Aucun événement pour le moment" />
      </div>

      {/* Modal lien alerte */}
      {linkModal && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <div className="bg-gray-900 border border-gray-700 rounded-xl w-full max-w-2xl max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between px-5 py-4 border-b border-gray-800">
              <h3 className="font-bold">Lier une alerte</h3>
              <button onClick={() => setLinkModal(false)} className="text-gray-400 hover:text-white"><X size={18} /></button>
            </div>
            <div className="p-5">
              <div className="flex gap-2 mb-3">
                {[
                  { value: "alert", label: "Alertes SIEM (Wazuh)" },
                  { value: "suricata", label: "Alertes Suricata" },
                ].map((opt) => (
                  <button
                    key={opt.value}
                    onClick={() => changeLinkSource(opt.value)}
                    className={`px-3 py-1.5 rounded-lg text-sm ${linkSource === opt.value ? "bg-emerald-600" : "bg-gray-800 hover:bg-gray-700"}`}
                  >
                    {opt.label}
                  </button>
                ))}
              </div>
              <div className="space-y-1 max-h-80 overflow-y-auto">
                {linkable.map((a) => (
                  <button
                    key={`${a.alert_type}-${a.alert_id}`}
                    onClick={() => setPickedAlert(a)}
                    className={`w-full text-left px-3 py-2 rounded-lg border text-sm ${pickedAlert?.alert_id === a.alert_id && pickedAlert?.alert_type === a.alert_type ? "border-emerald-500 bg-emerald-900/20" : "border-gray-800 bg-gray-800/40 hover:bg-gray-800"}`}
                  >
                    <div className="flex justify-between">
                      <span className="font-medium truncate">{a.signature || a.event_type || "—"}</span>
                      <span className={`font-bold ${sevClass(a.normalized_severity ?? a.severity)}`}>{a.normalized_severity ?? a.severity}</span>
                    </div>
                    <div className="text-xs text-gray-500">
                      #{a.alert_id} · {a.src_ip || "—"}{a.dest_ip ? ` → ${a.dest_ip}` : ""} · {a.timestamp ? new Date(a.timestamp).toLocaleString() : ""}
                    </div>
                  </button>
                ))}
                {linkable.length === 0 && (
                  <div className="text-center text-gray-500 py-6 text-sm">Aucune alerte liable ({linkSource})</div>
                )}
              </div>
            </div>
            <div className="flex justify-end gap-3 px-5 py-4 border-t border-gray-800">
              <button onClick={() => setLinkModal(false)} className="px-4 py-2 rounded-lg text-gray-400 hover:text-white">Annuler</button>
              <button onClick={handleLink} disabled={!pickedAlert} className="flex items-center gap-2 bg-emerald-600 hover:bg-emerald-500 px-4 py-2 rounded-lg">
                <Link2 size={16} /> Lier
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Modal clôture */}
      {closeModal && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <div className="bg-gray-900 border border-gray-700 rounded-xl w-full max-w-md">
            <div className="flex items-center justify-between px-5 py-4 border-b border-gray-800">
              <h3 className="font-bold">Clôturer l'affaire</h3>
              <button onClick={() => setCloseModal(false)} className="text-gray-400 hover:text-white"><X size={18} /></button>
            </div>
            <div className="p-5">
              <label className="block text-xs text-gray-400 mb-1">Résolution (optionnel)</label>
              <textarea
                className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2"
                placeholder="Résolution / conclusion…"
                value={resolution}
                onChange={(e) => setResolution(e.target.value)}
              />
            </div>
            <div className="flex justify-end gap-3 px-5 py-4 border-t border-gray-800">
              <button onClick={() => setCloseModal(false)} className="px-4 py-2 rounded-lg text-gray-400 hover:text-white">Annuler</button>
              <button onClick={handleClose} disabled={saving} className="flex items-center gap-2 bg-emerald-600 hover:bg-emerald-500 px-4 py-2 rounded-lg">
                <XCircle size={16} /> Clôturer
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}