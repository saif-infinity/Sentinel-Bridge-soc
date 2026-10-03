import { useState } from "react";
import {
  Send, History, FilePlus2, RefreshCcw, Link2, Unlink,
  CheckCircle2, XCircle, MessageSquare, UserCheck,
  Search, Layers, Gauge, FileText, Lightbulb,
} from "lucide-react";

const TYPE_ICON = {
  created: FilePlus2,
  status_changed: RefreshCcw,
  alert_linked: Link2,
  alert_unlinked: Unlink,
  alert_triaged: CheckCircle2,
  note_added: MessageSquare,
  closed: XCircle,
  reopened: RefreshCcw,
  assigned: UserCheck,
  investigation_started: Search,
  evidence_added: Layers,
  scored: Gauge,
  summary_generated: FileText,
  recommendations_ready: Lightbulb,
};

const TYPE_LABEL = {
  created: "Création",
  status_changed: "Statut modifié",
  alert_linked: "Alerte liée",
  alert_unlinked: "Alerte retirée",
  alert_triaged: "Triage",
  note_added: "Note",
  closed: "Clôture",
  reopened: "Réouverture",
  assigned: "Assignation",
  investigation_started: "Enquête démarrée",
  evidence_added: "Preuves collectées",
  scored: "Score calculé",
  summary_generated: "Résumé généré",
  recommendations_ready: "Recommandations prêtes",
};

export default function Timeline({
  events = [],
  onAddNote = null,
  loading = false,
  emptyText = "Aucun événement pour le moment",
}) {
  const [note, setNote] = useState("");

  const submit = () => {
    if (!note.trim()) return;
    onAddNote(note.trim());
    setNote("");
  };

  return (
    <div className="space-y-3">
      {onAddNote && (
        <div className="flex gap-2">
          <input
            className="flex-1 bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm"
            placeholder="Ajouter une note d'investigation…"
            value={note}
            onChange={(e) => setNote(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter") submit(); }}
          />
          <button
            onClick={submit}
            className="flex items-center gap-1 bg-emerald-600 hover:bg-emerald-500 px-3 py-2 rounded-lg text-sm"
          >
            <Send size={14} /> Ajouter
          </button>
        </div>
      )}
      {loading && <div className="text-gray-500 text-sm">Chargement…</div>}
      {!loading && events.length === 0 && (
        <div className="text-gray-500 text-sm text-center py-6">{emptyText}</div>
      )}
      <div className="relative border-l border-gray-800 ml-2 space-y-4">
        {events.map((ev) => {
          const Icon = TYPE_ICON[ev.event_type] || History;
          return (
            <div key={ev.id} className="ml-4 relative">
              <span className="absolute -left-[23px] top-0 w-6 h-6 rounded-full bg-gray-800 flex items-center justify-center">
                <Icon size={12} className="text-emerald-400" />
              </span>
              <div className="text-xs text-gray-500 flex justify-between">
                <span className="font-semibold text-gray-400">
                  {TYPE_LABEL[ev.event_type] || ev.event_type} · {ev.actor}
                </span>
                <span>{new Date(ev.created_at).toLocaleString()}</span>
              </div>
              <div className="text-sm text-gray-300 mt-0.5">{ev.message}</div>
            </div>
          );
        })}
      </div>
    </div>
  );
}