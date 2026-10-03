import { useState, useMemo } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  HardDrive,
  Monitor,
  Cpu,
  Activity,
  ShieldAlert,
  ShieldCheck,
  Clock,
  RefreshCw,
  Terminal,
  Send,
  AlertTriangle,
  Server,
  FileText,
  Zap,
  Search,
  Settings,
  Wrench,
} from "lucide-react";
import { useAuth } from "../contexts/AuthContext";
import { toast } from "react-toastify";

const ACTION_TYPES = [
  { value: "block_ip", label: "Bloquer IP", hint: "Ex : 192.168.1.50" },
  { value: "unblock_ip", label: "Débloquer IP", hint: "Ex : 192.168.1.50" },
  { value: "kill_process", label: "Tuer le processus", hint: "Ex : 1842 ou chrome.exe" },
  { value: "quarantine_file", label: "Mettre en quarantaine", hint: "Ex : C:\\Windows\\Temp\\suspect.exe ou /tmp/malware" },
  { value: "terminate_session", label: "Terminer la session", hint: "Ex : utilisateur ou ID de session" },
  { value: "restart_service", label: "Redémarrer le service", hint: "Ex : spooler, sshd, wuauserv" },
];

const CHECK_FR = {
  firewall_disabled: "Pare-feu désactivé",
  firewall_default_accept: "Politique pare-feu permissive",
  no_firewall: "Aucun pare-feu",
  ufw_default_forward: "UFW : forward permissif",
  ssh_permit_root_login: "SSH : root autorisé",
  ssh_password_auth: "SSH : authentification par mot de passe",
  shadow_world_readable: "/etc/shadow lisible par tous",
  fail2ban_not_running: "fail2ban inactif",
  empty_password_accounts: "Compte sans mot de passe",
  world_writable_etc: "Fichier modifiable par tous dans /etc",
  sudoers_world_writable: "sudoers modifiable par tous",
};

const CATEGORY_FR = {
  process: "Processus",
  network: "Réseau",
  file: "Fichier",
  registry: "Registre",
  logon: "Connexion",
  authentication: "Authentification",
  system: "Système",
  execution: "Exécution",
  persistence: "Persistance",
  defense_evasion: "Évasion",
  discovery: "Reconnaissance",
  alert: "Alerte",
  anomaly: "Anomalie",
  host: "Hôte",
  command: "Commande",
  misconfig: "Mauvaise configuration",
};

function categoryLabel(cat) {
  if (!cat) return "Autre";
  const k = String(cat).toLowerCase();
  return CATEGORY_FR[k] || cat;
}

function severityBadge(sev) {
  const s = String(sev || "").toLowerCase();
  if (s === "critical" || s === "critique" || s === "high" || s === "élevé" || s === "eleve" || s === "5" || s === "4") {
    // handle numeric strings too
  }
  // numeric severity
  const num = parseInt(sev, 10);
  if (!isNaN(num)) {
    if (num >= 8 || s === "critical" || s === "high") {
      return { label: s === "critical" || num >= 12 ? "Critique" : "Élevée", cls: "bg-red-500/10 text-red-400 border-red-500/20" };
    }
    if (num >= 4) return { label: "Moyenne", cls: "bg-amber-500/10 text-amber-400 border-amber-500/20" };
    return { label: "Faible", cls: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20" };
  }
  if (s === "critical" || s === "critique" || s.includes("crit")) return { label: "Critique", cls: "bg-red-500/10 text-red-400 border-red-500/20" };
  if (s === "high" || s === "eleve" || s === "élevée") return { label: "Élevée", cls: "bg-red-500/10 text-red-400 border-red-500/20" };
  if (s === "medium" || s === "moyen" || s === "moyenne") return { label: "Moyenne", cls: "bg-amber-500/10 text-amber-400 border-amber-500/20" };
  if (s === "low" || s === "faible") return { label: "Faible", cls: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20" };
  return { label: sev || "Info", cls: "bg-gray-500/10 text-gray-400 border-gray-500/20" };
}

function orderStatusBadge(status) {
  const s = String(status || "").toLowerCase();
  if (s === "pending") return { label: "En attente", cls: "bg-amber-500/10 text-amber-400 border-amber-500/20" };
  if (s === "dispatched" || s === "sent") return { label: "Expédié", cls: "bg-cyan-500/10 text-cyan-400 border-cyan-500/20" };
  if (s === "done" || s === "completed" || s === "success") return { label: "Terminé", cls: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20" };
  if (s === "error" || s === "failed" || s === "failure") return { label: "Erreur", cls: "bg-red-500/10 text-red-400 border-red-500/20" };
  return { label: status || "—", cls: "bg-gray-500/10 text-gray-400 border-gray-500/20" };
}

function severityRank(sev) {
  const s = String(sev || "").toLowerCase();
  const n = parseInt(sev, 10);
  if (!isNaN(n)) {
    if (n >= 12 || s === "critical") return 0;
    if (n >= 8 || s === "high") return 0;
    if (n >= 4 || s === "medium") return 1;
    return 2;
  }
  if (s === "critical" || s === "critique") return 0;
  if (s === "high" || s === "élevée" || s === "elevee") return 0;
  if (s === "medium" || s === "moyen" || s === "moyenne") return 1;
  if (s === "low" || s === "faible") return 2;
  return 3;
}

function formatTimestamp(ts) {
  if (!ts) return "—";
  try {
    const d = new Date(ts);
    if (isNaN(d.getTime())) return String(ts);
    return d.toLocaleString("fr-FR", { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit", second: "2-digit" });
  } catch {
    return String(ts);
  }
}

function formatLastSeen(ts) {
  if (!ts) return "Jamais vu";
  try {
    const d = new Date(ts);
    if (isNaN(d.getTime())) return String(ts);
    const diff = Date.now() - d.getTime();
    if (diff < 60000) return "À l'instant";
    if (diff < 3600000) return `Il y a ${Math.floor(diff / 60000)} min`;
    if (diff < 86400000) return `Il y a ${Math.floor(diff / 3600000)} h`;
    return d.toLocaleString("fr-FR", { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" });
  } catch {
    return String(ts);
  }
}

function describePayload(ev) {
  const p = ev.payload;
  if (!p) return ev.description || ev.message || "Événement sans détail";
  if (typeof p === "string") {
    if (p.length > 180) return p.slice(0, 180) + "…";
    return p;
  }
  if (typeof p === "object") {
    // common fields
    if (p.description) return p.description;
    if (p.msg) return p.msg;
    if (p.message) return p.message;
    if (p.command) return `Commande : ${p.command}`;
    if (p.process) return `Processus : ${p.process} ${p.pid ? `(PID ${p.pid})` : ""}`;
    if (p.file) return `Fichier : ${p.file}`;
    if (p.path) return `Chemin : ${p.path}`;
    if (p.src_ip || p.dst_ip) return `Flux ${p.src_ip || "?"} → ${p.dst_ip || "?"} ${p.dst_port ? `:${p.dst_port}` : ""}`;
    if (p.ip) return `IP : ${p.ip}`;
    if (p.user) return `Utilisateur : ${p.user}`;
    // fallback compact JSON
    try {
      const s = JSON.stringify(p);
      return s.length > 180 ? s.slice(0, 180) + "…" : s;
    } catch {
      return String(p);
    }
  }
  return String(p);
}

function SkeletonRow({ cols = 4 }) {
  return (
    <tr>
      {Array.from({ length: cols }).map((_, i) => (
        <td key={i} className="px-4 py-3">
          <div className="h-4 bg-gray-800 rounded animate-pulse" style={{ width: `${60 + (i * 17) % 40}%` }} />
        </td>
      ))}
    </tr>
  );
}

function SectionError({ message, onRetry }) {
  return (
    <div className="flex flex-col items-center justify-center py-8 px-4 text-center border border-red-500/20 bg-red-500/5 rounded-lg">
      <AlertTriangle size={20} className="text-red-400 mb-2" />
      <p className="text-sm text-red-300 mb-3 max-w-md break-words">{message || "Erreur lors du chargement"}</p>
      {onRetry && (
        <button onClick={onRetry} className="flex items-center gap-2 bg-gray-800 hover:bg-gray-700 border border-gray-700 px-4 py-1.5 rounded-lg text-sm">
          <RefreshCw size={14} /> Réessayer
        </button>
      )}
    </div>
  );
}

function EmptyState({ icon: Icon = FileText, title, subtitle }) {
  return (
    <div className="flex flex-col items-center justify-center py-10 px-4 text-center border border-dashed border-gray-800 rounded-lg bg-gray-900/30">
      <Icon size={32} className="text-gray-600 mb-3" />
      <p className="text-sm font-semibold text-gray-300">{title}</p>
      {subtitle && <p className="text-xs text-gray-500 mt-1 max-w-md">{subtitle}</p>}
    </div>
  );
}

export default function HostAgentsPage() {
  const { fetchWithAuth } = useAuth();
  const queryClient = useQueryClient();
  const [selectedId, setSelectedId] = useState(null);
  const [actionType, setActionType] = useState("block_ip");
  const [target, setTarget] = useState("");
  const [paramsText, setParamsText] = useState("");
  const [paramsError, setParamsError] = useState("");
  const [showConfirm, setShowConfirm] = useState(false);
  const [orderBanner, setOrderBanner] = useState(null); // {type:'success'|'error', msg}
  const [processSearch, setProcessSearch] = useState("");

  const selectedAction = useMemo(() => ACTION_TYPES.find((a) => a.value === actionType), [actionType]);

  // ── Agents ──
  const agentsQuery = useQuery({
    queryKey: ["host-agents"],
    queryFn: async () => {
      const res = await fetchWithAuth("/api/agent/status", { silent: true });
      if (!res.ok) {
        const txt = await res.text().catch(() => "");
        let msg = `Erreur ${res.status}`;
        try { const j = JSON.parse(txt); msg = j.detail || j.error || j.message || msg; } catch { if (txt) msg = txt.slice(0, 300); }
        throw new Error(msg);
      }
      const data = await res.json();
      const list = data.agents || data.data || data.items || (Array.isArray(data) ? data : []);
      return Array.isArray(list) ? list : [];
    },
    refetchInterval: 15000,
    refetchIntervalInBackground: false,
    retry: 1,
  });

  const agents = agentsQuery.data || [];
  const selectedAgent = agents.find((a) => (a.agent_id || a.id) === selectedId) || null;

  // auto-select first agent if none selected and list loads
  // useEffect not strictly needed but we handle via render logic
  if (!selectedId && agents.length > 0 && !agentsQuery.isLoading) {
    // we avoid setState during render by using microtask
    // Instead handle lazily: next tick
    setTimeout(() => setSelectedId(agents[0].agent_id || agents[0].id), 0);
  }

  // ── Processes ──
  const processesQuery = useQuery({
    queryKey: ["host-agent-processes", selectedId],
    enabled: !!selectedId,
    queryFn: async () => {
      const res = await fetchWithAuth(`/api/agent/processes?agent_id=${encodeURIComponent(selectedId)}`, { silent: true });
      if (!res.ok) {
        const txt = await res.text().catch(() => "");
        let msg = `Erreur ${res.status}`;
        try { const j = JSON.parse(txt); msg = j.detail || j.error || j.message || msg; } catch { if (txt) msg = txt.slice(0, 300); }
        throw new Error(msg);
      }
      const data = await res.json();
      return data.processes || data.data || data.items || (Array.isArray(data) ? data : []);
    },
    refetchInterval: 10000,
    refetchIntervalInBackground: false,
    retry: 1,
  });

  // ── Events ──
  const eventsQuery = useQuery({
    queryKey: ["host-agent-events", selectedId],
    enabled: !!selectedId,
    queryFn: async () => {
      const res = await fetchWithAuth(`/api/agent/events?agent_id=${encodeURIComponent(selectedId)}&limit=100`, { silent: true });
      if (!res.ok) {
        const txt = await res.text().catch(() => "");
        let msg = `Erreur ${res.status}`;
        try { const j = JSON.parse(txt); msg = j.detail || j.error || j.message || msg; } catch { if (txt) msg = txt.slice(0, 300); }
        throw new Error(msg);
      }
      const data = await res.json();
      return data.events || data.data || data.items || (Array.isArray(data) ? data : []);
    },
    refetchInterval: 10000,
    refetchIntervalInBackground: false,
    retry: 1,
  });

  // ── Misconfigurations (dédié category=misconfig, bare array) ──
  const misconfigQuery = useQuery({
    queryKey: ["host-agent-misconfig", selectedId],
    enabled: !!selectedId,
    queryFn: async () => {
      const res = await fetchWithAuth(`/api/agent/events?agent_id=${encodeURIComponent(selectedId)}&category=misconfig&limit=200`, { silent: true });
      if (!res.ok) {
        const txt = await res.text().catch(() => "");
        let msg = `Erreur ${res.status}`;
        try { const j = JSON.parse(txt); msg = j.detail || j.error || j.message || msg; } catch { if (txt) msg = txt.slice(0, 300); }
        throw new Error(msg);
      }
      const data = await res.json();
      if (Array.isArray(data)) return data;
      return data.events || data.data || data.items || (Array.isArray(data?.payload) ? data.payload : []);
    },
    refetchInterval: 10000,
    refetchIntervalInBackground: false,
    retry: 1,
  });

  // ── Orders history ──
  const ordersQuery = useQuery({
    queryKey: ["host-agent-orders-history", selectedId],
    enabled: !!selectedId,
    queryFn: async () => {
      const res = await fetchWithAuth(`/api/agent/orders/history?agent_id=${encodeURIComponent(selectedId)}&limit=100`, { silent: true });
      if (!res.ok) {
        const txt = await res.text().catch(() => "");
        let msg = `Erreur ${res.status}`;
        try { const j = JSON.parse(txt); msg = j.detail || j.error || j.message || msg; } catch { if (txt) msg = txt.slice(0, 300); }
        throw new Error(msg);
      }
      const data = await res.json();
      // may be {orders:[...]} or {items:[...]} or {history:[...]}
      return data.orders || data.history || data.items || data.data || (Array.isArray(data) ? data : []);
    },
    refetchInterval: 10000,
    refetchIntervalInBackground: false,
    retry: 1,
  });

  // ── Dispatch order ──
  const orderMutation = useMutation({
    mutationFn: async ({ agent_id, action_type, target: tgt, params }) => {
      const res = await fetchWithAuth("/api/agent/orders", {
        method: "POST",
        body: JSON.stringify({ agent_id, action_type, target: tgt, params }),
      });
      if (!res.ok) {
        const txt = await res.text().catch(() => "");
        let msg = `Erreur ${res.status}`;
        try { const j = JSON.parse(txt); msg = j.detail || j.error || j.message || msg; } catch { if (txt) msg = txt.slice(0, 400); }
        throw new Error(msg);
      }
      return res.json().catch(() => ({}));
    },
    onSuccess: () => {
      setOrderBanner({ type: "success", msg: "Ordre envoyé avec succès — l'agent va l'exécuter." });
      toast.success("Ordre expédié");
      setTarget("");
      setParamsText("");
      setParamsError("");
      setShowConfirm(false);
      if (selectedId) queryClient.invalidateQueries({ queryKey: ["host-agent-orders-history", selectedId] });
    },
    onError: (err) => {
      const msg = err.message || "Échec de l'envoi";
      setOrderBanner({ type: "error", msg });
      toast.error(msg);
      setShowConfirm(false);
    },
  });

  const handleSubmitOrder = () => {
    setParamsError("");
    setOrderBanner(null);
    if (!selectedId) {
      toast.error("Sélectionnez d'abord un agent");
      return;
    }
    if (!target.trim()) {
      toast.error("La cible est requise");
      return;
    }
    let parsedParams = undefined;
    if (paramsText.trim() !== "") {
      try {
        parsedParams = JSON.parse(paramsText);
      } catch (e) {
        setParamsError("JSON invalide — vérifiez les guillemets et virgules. Exemple : {\"force\": true}");
        return;
      }
    }
    // confirm dialog
    setShowConfirm(true);
  };

  const confirmSend = () => {
    let parsedParams = undefined;
    if (paramsText.trim() !== "") {
      try { parsedParams = JSON.parse(paramsText); } catch { return; }
    }
    orderMutation.mutate({
      agent_id: selectedId,
      action_type: actionType,
      target: target.trim(),
      params: parsedParams ?? {},
    });
  };

  const filteredProcesses = useMemo(() => {
    const list = processesQuery.data || [];
    if (!processSearch) return list;
    const q = processSearch.toLowerCase();
    return list.filter((p) =>
      String(p.pid || "").toLowerCase().includes(q) ||
      String(p.name || "").toLowerCase().includes(q) ||
      String(p.user || "").toLowerCase().includes(q) ||
      String(p.cmdline || "").toLowerCase().includes(q)
    );
  }, [processesQuery.data, processSearch]);

  // Dédup misconfig: check + path, garde la plus récente, compte occurrences
  const dedupedMisconfigs = useMemo(() => {
    const raw = misconfigQuery.data || [];
    const batchOf = (it) => String(it.received_at || it.receivedAt || "");
    let latestBatch = "";
    for (const item of raw) {
      const b = batchOf(item);
      if (b && b > latestBatch) latestBatch = b;
    }
    const map = new Map();
    for (const item of raw) {
      const payload = item.payload && typeof item.payload === "object" ? item.payload : {};
      const check = payload.check || item.check || "unknown";
      const path = payload.path || item.path || "";
      const key = `${String(check)}::${String(path)}`;
      const ts = item.ts || payload.ts || item.timestamp || item.time || "";
      const batch = batchOf(item);
      const existing = map.get(key);
      if (!existing) {
        map.set(key, { item, payload, check, path, ts, count: 1, inLatest: batch !== "" && batch === latestBatch });
      } else {
        existing.count += 1;
        const existingTime = new Date(existing.ts).getTime();
        const newTime = new Date(ts).getTime();
        const isMoreRecent = !isNaN(newTime) && (isNaN(existingTime) || newTime > existingTime);
        if (isMoreRecent) {
          existing.item = item;
          existing.payload = payload;
          existing.ts = ts;
        }
        if (batch !== "" && batch === latestBatch) existing.inLatest = true;
      }
    }
    // A misconfiguration is a STATE, not an event log: only keep findings reported by the
    // most recent scan, otherwise a finding that has since been fixed lingers forever.
    // Fallback: if the backend does not expose received_at, keep everything.
    const arr = Array.from(map.values()).filter((e) => latestBatch === "" || e.inLatest);
    arr.sort((a, b) => {
      const sevA = a.payload.severity || a.item.severity || "";
      const sevB = b.payload.severity || b.item.severity || "";
      const rankA = severityRank(sevA);
      const rankB = severityRank(sevB);
      if (rankA !== rankB) return rankA - rankB;
      return String(a.check).localeCompare(String(b.check));
    });
    return arr;
  }, [misconfigQuery.data]);

  const agentsOnline = agents.filter((a) => a.online === true || a.online === 1 || String(a.status).toLowerCase() === "online" || a.is_online).length;

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <HardDrive className="text-emerald-400" /> Agents hôtes
          </h1>
          <p className="text-gray-400 text-sm mt-1">
            Supervision des agents de terminaux — processus, événements et exécution d'ordres à distance
          </p>
        </div>
        <button
          onClick={() => agentsQuery.refetch()}
          disabled={agentsQuery.isFetching}
          className="flex items-center gap-2 bg-gray-900 hover:bg-gray-800 border border-gray-800 px-3 py-2 rounded-lg text-sm disabled:opacity-50"
        >
          <RefreshCw size={14} className={agentsQuery.isFetching ? "animate-spin" : ""} /> Actualiser
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
          <div className="flex items-center gap-2 text-gray-400 text-xs uppercase tracking-wide">
            <Server size={14} /> Total agents
          </div>
          <div className="text-2xl font-bold text-white mt-1">{agentsQuery.isLoading ? "—" : agents.length}</div>
          <div className="text-xs text-gray-500 mt-1">Enregistrés auprès du contrôleur</div>
        </div>
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
          <div className="flex items-center gap-2 text-emerald-400 text-xs uppercase tracking-wide">
            <ShieldCheck size={14} /> En ligne
          </div>
          <div className="text-2xl font-bold text-emerald-400 mt-1">{agentsOnline}</div>
          <div className="text-xs text-gray-500 mt-1">Agents joignables</div>
        </div>
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
          <div className="flex items-center gap-2 text-red-400 text-xs uppercase tracking-wide">
            <ShieldAlert size={14} /> Hors ligne
          </div>
          <div className="text-2xl font-bold text-red-400 mt-1">{agents.length - agentsOnline}</div>
          <div className="text-xs text-gray-500 mt-1">Injoignables ou inactifs</div>
        </div>
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
          <div className="flex items-center gap-2 text-cyan-400 text-xs uppercase tracking-wide">
            <Activity size={14} /> Agent sélectionné
          </div>
          <div className="text-sm font-semibold text-white mt-1 truncate">{selectedAgent ? (selectedAgent.hostname || selectedAgent.agent_id || selectedId) : "Aucun"}</div>
          <div className="text-xs text-gray-500 mt-1 truncate">{selectedAgent ? (selectedAgent.os ? `${selectedAgent.os} ${selectedAgent.arch || ""}`.trim() : selectedAgent.agent_id) : "Choisissez un agent ci-dessous"}</div>
        </div>
      </div>

      {/* Agents list */}
      <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-gray-800 flex items-center justify-between">
          <div className="font-semibold flex items-center gap-2">
            <Monitor size={16} className="text-emerald-400" /> Liste des agents
            {agentsQuery.isFetching && <span className="text-xs text-gray-500 font-normal ml-2">Actualisation…</span>}
          </div>
          <span className="text-xs bg-gray-800 border border-gray-700 text-gray-300 px-2 py-0.5 rounded-full">
            {agents.length} agent(s) · rafraîchi toutes les 15 s
          </span>
        </div>

        {agentsQuery.isLoading ? (
          <div className="p-6 space-y-3">
            {Array.from({ length: 3 }).map((_, i) => (
              <div key={i} className="h-20 bg-gray-800 rounded-lg animate-pulse" />
            ))}
          </div>
        ) : agentsQuery.isError ? (
          <div className="p-4">
            <SectionError message={agentsQuery.error.message} onRetry={() => agentsQuery.refetch()} />
          </div>
        ) : agents.length === 0 ? (
          <div className="p-6">
            <EmptyState icon={HardDrive} title="Aucun agent enregistré" subtitle="Aucun agent hôte n'a encore communiqué avec le serveur. Vérifiez que l'agent Rust est démarré et que la connectivité vers /api/agent est opérationnelle." />
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-gray-800 text-gray-300 text-xs uppercase">
                <tr>
                  <th className="text-left px-4 py-2">Statut</th>
                  <th className="text-left px-4 py-2">Agent</th>
                  <th className="text-left px-4 py-2">Hôte</th>
                  <th className="text-left px-4 py-2">OS / Arch</th>
                  <th className="text-left px-4 py-2">Version</th>
                  <th className="text-left px-4 py-2">Dernière vue</th>
                </tr>
              </thead>
              <tbody>
                {agents.map((a) => {
                  const id = a.agent_id || a.id || a.hostname || "unknown";
                  const online = a.online === true || a.online === 1 || String(a.status).toLowerCase() === "online" || a.is_online === true;
                  const isSelected = String(id) === String(selectedId);
                  return (
                    <tr
                      key={id}
                      onClick={() => setSelectedId(id)}
                      className={`border-t border-gray-800 cursor-pointer transition-colors ${isSelected ? "bg-emerald-900/20 hover:bg-emerald-900/30" : "hover:bg-gray-800/50"}`}
                    >
                      <td className="px-4 py-3">
                        <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-bold border ${online ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/20" : "bg-red-500/10 text-red-400 border-red-500/20"}`}>
                          <span className={`w-1.5 h-1.5 rounded-full ${online ? "bg-emerald-400 animate-pulse" : "bg-red-400"}`} />
                          {online ? "EN LIGNE" : "HORS LIGNE"}
                        </span>
                      </td>
                      <td className="px-4 py-3 font-mono text-xs text-cyan-400">{id}</td>
                      <td className="px-4 py-3 font-medium text-white">{a.hostname || "—"}</td>
                      <td className="px-4 py-3 text-gray-400">{[a.os, a.arch].filter(Boolean).join(" / ") || "—"}</td>
                      <td className="px-4 py-3 text-gray-400 font-mono text-xs">{a.version || "—"}</td>
                      <td className="px-4 py-3 text-gray-500 text-xs">{formatLastSeen(a.last_seen || a.lastSeen || a.seen_at)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Detail area */}
      {!selectedId ? (
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-8 text-center">
          <HardDrive size={36} className="mx-auto text-gray-600 mb-3" />
          <p className="text-sm font-semibold text-gray-300">Sélectionnez un agent</p>
          <p className="text-xs text-gray-500 mt-1">Choisissez un agent dans la liste ci-dessus pour afficher ses processus, événements et historique d'ordres.</p>
        </div>
      ) : (
        <>
          {/* Processus */}
          <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
            <div className="px-4 py-3 border-b border-gray-800 flex flex-wrap items-center justify-between gap-3">
              <div className="font-semibold flex items-center gap-2">
                <Cpu size={16} className="text-cyan-400" /> Processus
                {processesQuery.isFetching && <span className="text-xs text-gray-500 font-normal">Actualisation…</span>}
              </div>
              <div className="flex items-center gap-2">
                <div className="relative">
                  <Search size={14} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-gray-500" />
                  <input
                    className="bg-gray-800 border border-gray-700 rounded-lg pl-8 pr-3 py-1.5 text-sm w-56"
                    placeholder="Filtrer PID, nom, utilisateur…"
                    value={processSearch}
                    onChange={(e) => setProcessSearch(e.target.value)}
                  />
                </div>
                <button
                  onClick={() => processesQuery.refetch()}
                  disabled={processesQuery.isFetching}
                  className="p-1.5 bg-gray-800 border border-gray-700 rounded-lg hover:bg-gray-700 disabled:opacity-50"
                  title="Actualiser"
                >
                  <RefreshCw size={14} className={processesQuery.isFetching ? "animate-spin" : ""} />
                </button>
              </div>
            </div>

            {processesQuery.isLoading ? (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead className="bg-gray-800 text-gray-300 text-xs uppercase"><tr><th className="px-4 py-2 text-left">PID</th><th className="px-4 py-2 text-left">Nom</th><th className="px-4 py-2 text-left">Utilisateur</th><th className="px-4 py-2 text-left">CPU %</th><th className="px-4 py-2 text-left">Mémoire Mo</th></tr></thead>
                  <tbody>
                    <SkeletonRow cols={5} />
                    <SkeletonRow cols={5} />
                    <SkeletonRow cols={5} />
                  </tbody>
                </table>
              </div>
            ) : processesQuery.isError ? (
              <div className="p-4"><SectionError message={processesQuery.error.message} onRetry={() => processesQuery.refetch()} /></div>
            ) : !processesQuery.data || processesQuery.data.length === 0 ? (
              <div className="p-6"><EmptyState icon={Cpu} title="Aucun processus" subtitle="L'agent n'a renvoyé aucun processus. Vérifiez que l'agent est en ligne et autorisé à collecter la liste des processus." /></div>
            ) : filteredProcesses.length === 0 ? (
              <div className="p-6"><EmptyState icon={Search} title="Aucun résultat" subtitle={`Aucun processus ne correspond à « ${processSearch} ».`} /></div>
            ) : (
              <div className="overflow-x-auto max-h-[380px] overflow-y-auto">
                <table className="w-full text-sm">
                  <thead className="bg-gray-800 text-gray-300 text-xs uppercase sticky top-0">
                    <tr>
                      <th className="text-left px-4 py-2">PID</th>
                      <th className="text-left px-4 py-2">Nom</th>
                      <th className="text-left px-4 py-2">Utilisateur</th>
                      <th className="text-left px-4 py-2">CPU %</th>
                      <th className="text-left px-4 py-2">Mémoire Mo</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredProcesses.slice(0, 200).map((p, idx) => (
                      <tr key={`${p.pid}-${p.name}-${idx}`} className="border-t border-gray-800 hover:bg-gray-800/50">
                        <td className="px-4 py-2 font-mono text-cyan-400">{p.pid ?? "—"}</td>
                        <td className="px-4 py-2 font-medium text-white max-w-[260px] truncate" title={p.cmdline || p.name}>{p.name || "—"}</td>
                        <td className="px-4 py-2 text-gray-400">{p.user || p.username || "—"}</td>
                        <td className="px-4 py-2 text-gray-300">{p.cpu_pct != null ? Number(p.cpu_pct).toFixed(1) : p.cpu != null ? Number(p.cpu).toFixed(1) : "—"}</td>
                        <td className="px-4 py-2 text-gray-300">{p.mem_kb != null ? (Number(p.mem_kb) / 1024).toFixed(1) : p.mem_mb != null ? Number(p.mem_mb).toFixed(1) : p.memory_mb != null ? Number(p.memory_mb).toFixed(1) : "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {filteredProcesses.length > 200 && (
                  <div className="px-4 py-2 text-xs text-gray-500 text-center border-t border-gray-800">Affichage limité à 200 processus sur {filteredProcesses.length}</div>
                )}
              </div>
            )}
          </div>

          {/* Événements */}
          <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
            <div className="px-4 py-3 border-b border-gray-800 flex items-center justify-between">
              <div className="font-semibold flex items-center gap-2">
                <Activity size={16} className="text-amber-400" /> Événements
                {eventsQuery.isFetching && <span className="text-xs text-gray-500 font-normal">Actualisation…</span>}
              </div>
              <button
                onClick={() => eventsQuery.refetch()}
                disabled={eventsQuery.isFetching}
                className="flex items-center gap-1.5 bg-gray-800 border border-gray-700 px-3 py-1.5 rounded-lg text-sm hover:bg-gray-700 disabled:opacity-50"
              >
                <RefreshCw size={14} className={eventsQuery.isFetching ? "animate-spin" : ""} /> Actualiser
              </button>
            </div>

            {eventsQuery.isLoading ? (
              <div className="p-6 space-y-3">
                {Array.from({ length: 3 }).map((_, i) => (
                  <div key={i} className="h-16 bg-gray-800 rounded-lg animate-pulse" />
                ))}
              </div>
            ) : eventsQuery.isError ? (
              <div className="p-4"><SectionError message={eventsQuery.error.message} onRetry={() => eventsQuery.refetch()} /></div>
            ) : !eventsQuery.data || eventsQuery.data.length === 0 ? (
              <div className="p-6"><EmptyState icon={ShieldCheck} title="Aucun événement" subtitle="Aucun événement récent pour cet agent. Les événements apparaîtront ici dès leur collecte (limite 100)." /></div>
            ) : (
              <div className="divide-y divide-gray-800 max-h-[520px] overflow-y-auto">
                {eventsQuery.data.map((ev, idx) => {
                  const sev = ev.severity || ev.level || ev.sev || "low";
                  const badge = severityBadge(sev);
                  const cat = ev.category || ev.type || ev.source || "";
                  return (
                    <div key={`${ev.ts || ev.timestamp || idx}-${idx}`} className="px-4 py-3 hover:bg-gray-800/40">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-bold border ${badge.cls}`}>{badge.label}</span>
                        <span className="text-xs bg-gray-800 border border-gray-700 text-gray-300 px-2 py-0.5 rounded-full">{categoryLabel(cat)}</span>
                        <span className="text-xs text-gray-500 flex items-center gap-1"><Clock size={12} />{formatTimestamp(ev.ts || ev.timestamp || ev.time)}</span>
                        {ev.source && <span className="text-xs text-gray-500">Source : <span className="text-gray-300">{ev.source}</span></span>}
                      </div>
                      <p className="text-sm text-gray-200 mt-2 leading-snug break-words">{describePayload(ev)}</p>
                      {ev.payload && typeof ev.payload === "object" && (
                        <details className="mt-2">
                          <summary className="text-xs text-gray-500 hover:text-gray-300 cursor-pointer">Voir le détail JSON</summary>
                          <pre className="mt-2 bg-gray-950 border border-gray-800 rounded-lg p-3 text-xs text-gray-300 overflow-x-auto whitespace-pre-wrap break-words">{JSON.stringify(ev.payload, null, 2)}</pre>
                        </details>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* Mauvaises configurations — category=misconfig dédié, dédupliqué */}
          <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
            <div className="px-4 py-3 border-b border-gray-800 flex items-center justify-between">
              <div className="font-semibold flex items-center gap-2">
                <Wrench size={16} className="text-orange-400" /> Mauvaises configurations
                {misconfigQuery.isFetching && <span className="text-xs text-gray-500 font-normal">Actualisation…</span>}
              </div>
              <div className="flex items-center gap-2">
                {!misconfigQuery.isLoading && !misconfigQuery.isError && (
                  <span className="text-xs bg-gray-800 border border-gray-700 text-gray-300 px-2.5 py-0.5 rounded-full">
                    {dedupedMisconfigs.length} configuration{dedupedMisconfigs.length !== 1 ? "s" : ""} · {(misconfigQuery.data || []).length} occurrence{(misconfigQuery.data || []).length !== 1 ? "s" : ""}
                  </span>
                )}
                <button
                  onClick={() => misconfigQuery.refetch()}
                  disabled={misconfigQuery.isFetching}
                  className="flex items-center gap-1.5 bg-gray-800 border border-gray-700 px-3 py-1.5 rounded-lg text-sm hover:bg-gray-700 disabled:opacity-50"
                  title="Actualiser les mauvaises configurations"
                >
                  <RefreshCw size={14} className={misconfigQuery.isFetching ? "animate-spin" : ""} /> Actualiser
                </button>
              </div>
            </div>

            {misconfigQuery.isLoading ? (
              <div className="p-6 space-y-3">
                {Array.from({ length: 2 }).map((_, i) => (
                  <div key={i} className="h-24 bg-gray-800 rounded-lg animate-pulse" />
                ))}
              </div>
            ) : misconfigQuery.isError ? (
              <div className="p-4"><SectionError message={misconfigQuery.error.message} onRetry={() => misconfigQuery.refetch()} /></div>
            ) : dedupedMisconfigs.length === 0 ? (
              <div className="p-6">
                <EmptyState
                  icon={Settings}
                  title="Aucune mauvaise configuration détectée"
                  subtitle="Vérifiez que la collecte est active et que l'agent est à jour."
                />
              </div>
            ) : (
              <div className="divide-y divide-gray-800">
                {dedupedMisconfigs.map((entry, idx) => {
                  const { payload, check, path, ts, count } = entry;
                  const sev = payload.severity || entry.item.severity || "medium";
                  const badge = severityBadge(sev);
                  const label = CHECK_FR[String(check)] || String(check);
                  const description = payload.description || "";
                  const recommendation = payload.recommendation || "";
                  return (
                    <div key={`${check}::${path}::${idx}`} className="px-4 py-4 hover:bg-gray-800/40">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-bold border ${badge.cls}`}>{badge.label}</span>
                        <span className="text-sm font-semibold text-white">{label}</span>
                        <span className="text-xs font-mono bg-gray-800 border border-gray-700 text-gray-400 px-1.5 py-0.5 rounded">{check}</span>
                        {count > 1 && (
                          <span className="text-xs bg-amber-500/10 border border-amber-500/20 text-amber-300 px-2 py-0.5 rounded-full">vu {count} fois</span>
                        )}
                        <span className="text-xs text-gray-500 flex items-center gap-1"><Clock size={12} />{formatTimestamp(ts)}</span>
                      </div>
                      {description && <p className="text-sm text-gray-300 mt-2 leading-snug">{description}</p>}
                      {path && (
                        <div className="mt-2 flex flex-wrap items-center gap-2">
                          <span className="text-xs text-gray-500">Chemin :</span>
                          <code className="text-xs font-mono bg-gray-950 border border-gray-800 text-cyan-400 px-2 py-0.5 rounded break-all">{path}</code>
                        </div>
                      )}
                      {recommendation && (
                        <div className="mt-2 flex flex-wrap gap-1.5">
                          <span className="text-xs text-gray-500">Recommandation :</span>
                          <span className="text-xs text-gray-400 leading-snug">{recommendation}</span>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* Commandes + Historique grid */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Commandes */}
            <div className="bg-gray-900 border border-gray-800 rounded-lg p-5">
              <div className="font-semibold flex items-center gap-2 mb-1">
                <Terminal size={16} className="text-emerald-400" /> Envoyer une commande
              </div>
              <p className="text-xs text-gray-500 mb-4">L'ordre sera mis en file d'attente et récupéré par l'agent à sa prochaine interrogation.</p>

              {orderBanner && (
                <div className={`mb-4 px-3 py-2 rounded-lg text-sm border ${orderBanner.type === "success" ? "bg-emerald-500/10 text-emerald-300 border-emerald-500/20" : "bg-red-500/10 text-red-300 border-red-500/20"}`}>
                  {orderBanner.msg}
                </div>
              )}

              <div className="space-y-4">
                <div>
                  <label className="block text-xs text-gray-400 mb-1">Type d'action *</label>
                  <select
                    className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm"
                    value={actionType}
                    onChange={(e) => setActionType(e.target.value)}
                  >
                    {ACTION_TYPES.map((a) => (
                      <option key={a.value} value={a.value}>{a.label} ({a.value})</option>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="block text-xs text-gray-400 mb-1">Cible *</label>
                  <input
                    className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm"
                    placeholder={selectedAction?.hint || "Saisissez la cible"}
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                  />
                  <p className="text-[11px] text-gray-500 mt-1">{selectedAction?.hint}</p>
                </div>

                <div>
                  <label className="block text-xs text-gray-400 mb-1">Paramètres (JSON, optionnel)</label>
                  <textarea
                    className={`w-full bg-gray-800 border rounded-lg px-3 py-2 text-sm font-mono min-h-[90px] ${paramsError ? "border-red-500/50" : "border-gray-700"}`}
                    placeholder={'Ex : {"force": true, "timeout": 30}'}
                    value={paramsText}
                    onChange={(e) => { setParamsText(e.target.value); if (paramsError) setParamsError(""); }}
                  />
                  {paramsError ? (
                    <p className="text-xs text-red-400 mt-1">{paramsError}</p>
                  ) : (
                    <p className="text-[11px] text-gray-500 mt-1">Laissez vide si aucun paramètre. Le contenu doit être un JSON valide.</p>
                  )}
                </div>

                <button
                  onClick={handleSubmitOrder}
                  disabled={orderMutation.isPending || !selectedId}
                  className="w-full flex items-center justify-center gap-2 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 disabled:cursor-not-allowed px-4 py-2.5 rounded-lg text-sm font-semibold"
                >
                  {orderMutation.isPending ? <RefreshCw size={16} className="animate-spin" /> : <Send size={16} />}
                  Envoyer l'ordre
                </button>
                <p className="text-[11px] text-gray-500 text-center">L'agent sélectionné : <span className="text-gray-300 font-mono">{selectedId}</span></p>
              </div>
            </div>

            {/* Historique */}
            <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden flex flex-col">
              <div className="px-4 py-3 border-b border-gray-800 flex items-center justify-between">
                <div className="font-semibold flex items-center gap-2">
                  <Clock size={16} className="text-violet-400" /> Historique des ordres
                  {ordersQuery.isFetching && <span className="text-xs text-gray-500 font-normal">Actualisation…</span>}
                </div>
                <button
                  onClick={() => ordersQuery.refetch()}
                  disabled={ordersQuery.isFetching}
                  className="flex items-center gap-1.5 bg-gray-800 border border-gray-700 px-3 py-1.5 rounded-lg text-sm hover:bg-gray-700 disabled:opacity-50"
                >
                  <RefreshCw size={14} className={ordersQuery.isFetching ? "animate-spin" : ""} /> Actualiser
                </button>
              </div>

              <div className="flex-1 overflow-hidden flex flex-col">
                {ordersQuery.isLoading ? (
                  <div className="p-6 space-y-3">
                    {Array.from({ length: 3 }).map((_, i) => (
                      <div key={i} className="h-12 bg-gray-800 rounded-lg animate-pulse" />
                    ))}
                  </div>
                ) : ordersQuery.isError ? (
                  <div className="p-4"><SectionError message={ordersQuery.error.message} onRetry={() => ordersQuery.refetch()} /></div>
                ) : !ordersQuery.data || ordersQuery.data.length === 0 ? (
                  <div className="p-6 flex-1 flex items-center justify-center">
                    <EmptyState icon={FileText} title="Aucun ordre" subtitle="Aucun ordre n'a encore été envoyé à cet agent. Utilisez le panneau de gauche pour expédier une commande." />
                  </div>
                ) : (
                  <div className="overflow-x-auto overflow-y-auto max-h-[460px]">
                    <table className="w-full text-sm">
                      <thead className="bg-gray-800 text-gray-300 text-xs uppercase sticky top-0">
                        <tr>
                          <th className="text-left px-3 py-2">Date</th>
                          <th className="text-left px-3 py-2">Action</th>
                          <th className="text-left px-3 py-2">Cible</th>
                          <th className="text-left px-3 py-2">Statut</th>
                          <th className="text-left px-3 py-2">Résultat</th>
                        </tr>
                      </thead>
                      <tbody>
                        {ordersQuery.data.map((o, idx) => {
                          const st = orderStatusBadge(o.status || o.state);
                          return (
                            <tr key={o.id || o.order_id || idx} className="border-t border-gray-800 hover:bg-gray-800/50">
                              <td className="px-3 py-2 text-gray-400 text-xs whitespace-nowrap">{formatTimestamp(o.ts || o.created_at || o.timestamp || o.date)}</td>
                              <td className="px-3 py-2">
                                <span className="inline-flex px-2 py-0.5 rounded text-xs font-mono bg-gray-800 border border-gray-700 text-gray-200">{o.action_type || o.action || "—"}</span>
                              </td>
                              <td className="px-3 py-2 font-mono text-xs text-cyan-400 max-w-[160px] truncate" title={o.target || ""}>{o.target || "—"}</td>
                              <td className="px-3 py-2"><span className={`inline-flex px-2 py-0.5 rounded-full text-[11px] font-bold border ${st.cls}`}>{st.label}</span></td>
                              <td className="px-3 py-2 text-xs text-gray-300 max-w-[200px] truncate" title={o.result || o.error || o.output || ""}>{o.error ? <span className="text-red-400">{o.error}</span> : (o.result || o.output || "—")}</td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                )}
                <div className="px-4 py-2 border-t border-gray-800 text-[11px] text-gray-500 text-center">
                  Rafraîchi toutes les 10 s · {ordersQuery.data?.length || 0} ordre(s) · limite 100
                </div>
              </div>
            </div>
          </div>

          {/* Confirm dialog */}
          {showConfirm && (
            <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
              <div className="bg-gray-900 border border-gray-700 rounded-xl w-full max-w-md">
                <div className="px-5 py-4 border-b border-gray-800 flex items-center gap-2">
                  <Zap size={18} className="text-amber-400" />
                  <h3 className="font-bold">Confirmer l'envoi</h3>
                </div>
                <div className="p-5 space-y-3">
                  <p className="text-sm text-gray-300">
                    Vous allez envoyer <span className="font-semibold text-white">{ACTION_TYPES.find((a) => a.value === actionType)?.label}</span> à l'agent
                    <span className="font-mono text-cyan-400"> {selectedId}</span> avec la cible <span className="font-mono text-amber-400">{target}</span>.
                  </p>
                  <div className="bg-amber-500/10 border border-amber-500/20 rounded-lg px-3 py-2 flex gap-2">
                    <AlertTriangle size={16} className="text-amber-400 shrink-0 mt-0.5" />
                    <p className="text-xs text-amber-200">Cette action peut être destructrice (blocage, arrêt de processus, quarantaine). Vérifiez la cible avant de confirmer.</p>
                  </div>
                  {paramsText.trim() && (
                    <div>
                      <div className="text-xs text-gray-400 mb-1">Paramètres JSON :</div>
                      <pre className="bg-gray-950 border border-gray-800 rounded-lg p-3 text-xs text-gray-300 overflow-x-auto whitespace-pre-wrap">{paramsText}</pre>
                    </div>
                  )}
                </div>
                <div className="flex justify-end gap-3 px-5 py-4 border-t border-gray-800">
                  <button onClick={() => setShowConfirm(false)} className="px-4 py-2 rounded-lg text-gray-400 hover:text-white">Annuler</button>
                  <button onClick={confirmSend} disabled={orderMutation.isPending} className="flex items-center gap-2 bg-red-600 hover:bg-red-500 disabled:opacity-50 px-4 py-2 rounded-lg text-sm font-semibold">
                    {orderMutation.isPending ? <RefreshCw size={14} className="animate-spin" /> : <Send size={14} />} Confirmer et envoyer
                  </button>
                </div>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
