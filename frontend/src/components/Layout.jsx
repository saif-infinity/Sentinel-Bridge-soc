import { useState, useEffect, memo } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { useAuth } from "../contexts/AuthContext";
import { useData } from "../contexts/DataContext";
import { useTranslation } from "../i18n";
import clsx from "clsx";
import {
  Shield, Server, Radar, Activity, Plus, Search, ShieldAlert, ShieldCheck,
  Cpu, Clock, Zap, Lock, Network, Database, Globe, AlertTriangle,
  Volume2, VolumeX, Printer, LayoutDashboard, Monitor, Laptop, HardDrive,
  Terminal, Radio, FileText, X, LogIn, Users, Fingerprint, Settings, ScrollText,
  FolderKanban, Crosshair, Workflow, Camera,
} from "lucide-react";

const SystemClock = memo(() => {
  const [time, setTime] = useState(new Date().toLocaleTimeString());
  useEffect(() => {
    const timer = setInterval(() => setTime(new Date().toLocaleTimeString()), 1000);
    return () => clearInterval(timer);
  }, []);
  return <span className="text-gray-400 text-xs font-mono">{time}</span>;
});

// Single lazy AudioContext reused across beeps (browsers cap concurrent contexts).
let sharedAudioCtx = null;
function getAudioContext() {
  if (!sharedAudioCtx) {
    try {
      sharedAudioCtx = new (window.AudioContext || window.webkitAudioContext)();
    } catch (e) {
      sharedAudioCtx = null;
    }
  }
  return sharedAudioCtx;
}

const NAV_ITEMS = [
  { group: "command_center", items: [
    { key: "dashboard", icon: LayoutDashboard, path: "/", minRole: "viewer" },
    { key: "topology", icon: Network, path: "/topology", minRole: "viewer" },
    { key: "surveillance", icon: Camera, path: "/surveillance", minRole: "analyst" },
  ]},
  { group: "asset_management", items: [
    { key: "inventory", icon: Database, path: "/inventory", minRole: "viewer" },
    { key: "radar", icon: Radar, path: "/radar", minRole: "analyst" },
    { key: "tasks", icon: Clock, path: "/tasks", minRole: "analyst" },
  ]},
  { group: "terminal_ops", items: [
    { key: "terminal", icon: Terminal, path: "/terminal", minRole: "viewer" },
    { key: "remediation", icon: ShieldCheck, path: "/remediation", minRole: "analyst" },
    { key: "alerts", icon: ShieldAlert, path: "/alerts", minRole: "viewer" },
  ]},
  { group: "network_ops", items: [
    { key: "suricata", icon: Radio, path: "/suricata", minRole: "viewer" },
    { key: "network_control", icon: Globe, path: "/network-control", minRole: "analyst" },
    { key: "network_devices", icon: Monitor, path: "/network-devices", minRole: "analyst" },
  ]},
  { group: "intelligence", items: [
    { key: "ai", icon: Cpu, path: "/ai", minRole: "analyst" },
    { key: "ai_history", icon: FileText, path: "/ai-history", minRole: "analyst" },
    { key: "rules", icon: ScrollText, path: "/rules", minRole: "admin" },
  ]},
  { group: "case_management", items: [
    { key: "cases", icon: FolderKanban, path: "/cases", minRole: "viewer" },
    { key: "hunting", icon: Crosshair, path: "/hunting", minRole: "viewer" },
  ]},
  { group: "automation", items: [
    { key: "playbooks", icon: Workflow, path: "/playbooks", minRole: "analyst" },
  ]},
  { group: "system", items: [
    { key: "settings", icon: Settings, path: "/settings", minRole: "admin" },
    { key: "admin", icon: ShieldCheck, path: "/admin", minRole: "admin" },
    { key: "super_admin", icon: ShieldAlert, path: "/super-admin", minRole: "super_admin" },
  ]},
];

// Roles strictly lower than the given role cannot see items requiring it.
const canSee = (hasRole, minRole) => hasRole(minRole);

export default function Layout({ children }) {
  const { username, logout, isAuthenticated, hasRole } = useAuth();
  const { wazuhAlerts, suricataAlerts } = useData();
  const { lang, t, switchLang } = useTranslation();
  const navigate = useNavigate();
  const location = useLocation();
  const [isMuted, setIsMuted] = useState(false);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(window.innerWidth < 768);
  const [mobileOpen, setMobileOpen] = useState(false);

  const criticalCount = wazuhAlerts.filter((a) => (a.Severity || a.severity || 0) >= 8).length;
  const networkCriticalCount = suricataAlerts.filter(
    (a) => a.event_type === "alert" && (a.severity || 0) >= 7,
  ).length;

  useEffect(() => {
    if ((criticalCount > 0 || networkCriticalCount > 0) && !isMuted) {
      try {
        const ctx = getAudioContext();
        if (!ctx) return;
        if (ctx.state === "suspended") ctx.resume().catch(() => {});
        const osc = ctx.createOscillator();
        const gain = ctx.createGain();
        osc.connect(gain);
        gain.connect(ctx.destination);
        osc.frequency.value = 880;
        osc.type = "sine";
        gain.gain.value = 0.1;
        osc.start();
        osc.stop(ctx.currentTime + 0.5);
      } catch (e) {}
    }
  }, [criticalCount, networkCriticalCount, isMuted]);

  if (!isAuthenticated) return children;

  return (
    <div className="flex h-screen bg-gray-950 text-white overflow-hidden">
      {/* Sidebar */}
      <aside
        className={clsx(
          "flex flex-col bg-gray-900 border-r border-gray-800 transition-all duration-300",
          "max-md:fixed max-md:inset-y-0 max-md:left-0 max-md:z-50 max-md:w-60",
          sidebarCollapsed ? "w-16" : "w-60",
          mobileOpen ? "max-md:translate-x-0" : "max-md:-translate-x-full",
        )}
      >
        <div className="flex items-center justify-between p-3 border-b border-gray-800">
          {!sidebarCollapsed && (
            <div className="flex items-center gap-2">
              <Shield className="w-6 h-6 text-emerald-400" />
              <span className="font-bold text-sm">Sentinel</span>
            </div>
          )}
          <button
            onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
            className="text-gray-400 hover:text-white"
          >
            {sidebarCollapsed ? <Plus className="w-4 h-4 rotate-45" /> : <X className="w-4 h-4" />}
          </button>
        </div>

        <nav className="flex-1 overflow-y-auto py-2">
          {NAV_ITEMS.map((section) => {
            const visibleItems = section.items.filter((item) => canSee(hasRole, item.minRole));
            if (visibleItems.length === 0) return null;
            return (
            <div key={section.group} className="mb-2">
              {!sidebarCollapsed && (
                <div className="px-3 py-1 text-[10px] font-semibold text-gray-500 uppercase tracking-wider">
                  {t(section.group)}
                </div>
              )}
              {visibleItems.map((item) => {
                const Icon = item.icon;
                const isActive = location.pathname === item.path;
                const hasCritical =
                  (item.key === "alerts" && criticalCount > 0) ||
                  (item.key === "suricata" && networkCriticalCount > 0);
                return (
                  <button
                    key={item.key}
                    onClick={() => { navigate(item.path); setMobileOpen(false); }}
                    className={clsx(
                      "w-full flex items-center gap-3 px-3 py-2 text-sm transition-colors relative",
                      isActive
                        ? "bg-emerald-600/20 text-emerald-400 border-r-2 border-emerald-400"
                        : "text-gray-400 hover:bg-gray-800 hover:text-white",
                    )}
                    title={sidebarCollapsed ? t(item.key) : undefined}
                  >
                    <Icon className="w-4 h-4 flex-shrink-0" />
                    {!sidebarCollapsed && <span>{t(item.key)}</span>}
                    {hasCritical && (
                      <span className="absolute right-2 top-1/2 -translate-y-1/2 w-2 h-2 bg-red-500 rounded-full animate-pulse" />
                    )}
                  </button>
                );
              })}
            </div>
            );
          })}
        </nav>

        <div className="p-3 border-t border-gray-800">
          {!sidebarCollapsed && (
            <div className="text-xs text-gray-500 mb-2 truncate">{username}</div>
          )}
          <button
            onClick={logout}
            className="w-full flex items-center justify-center gap-2 px-3 py-2 text-sm text-gray-400 hover:text-red-400 hover:bg-gray-800 rounded transition-colors"
          >
            <LogIn className="w-4 h-4 rotate-180" />
            {!sidebarCollapsed && <span>{t("logout")}</span>}
          </button>
        </div>
      </aside>

      {/* Mobile overlay */}
      {mobileOpen && (
        <div
          className="md:hidden fixed inset-0 bg-black/50 z-40"
          onClick={() => setMobileOpen(false)}
        />
      )}

      {/* Main Content */}
      <main className="flex-1 flex flex-col overflow-hidden">
        {/* Header */}
        <header className="flex items-center justify-between px-4 py-2 bg-gray-900 border-b border-gray-800">
          <div className="flex items-center gap-4">
            <button
              onClick={() => setMobileOpen(!mobileOpen)}
              className="md:hidden flex items-center justify-center w-8 h-8 rounded border border-gray-700 bg-gray-800 text-emerald-400"
            >
              <Plus className="w-4 h-4" />
            </button>
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-red-400" />
              <span className="text-sm font-semibold">
                {criticalCount + networkCriticalCount} Active Threats
              </span>
            </div>
          </div>
          <div className="flex items-center gap-4">
            <button
              onClick={() => setIsMuted(!isMuted)}
              className="text-gray-400 hover:text-white"
              title={isMuted ? "Unmute" : "Mute"}
            >
              {isMuted ? <VolumeX className="w-4 h-4" /> : <Volume2 className="w-4 h-4" />}
            </button>
            <button
              onClick={() => window.print()}
              className="text-gray-400 hover:text-white"
            >
              <Printer className="w-4 h-4" />
            </button>
            <div className="flex items-center gap-1 text-xs">
              <button
                onClick={() => switchLang("en")}
                className={clsx(
                  "px-1.5 py-0.5 rounded",
                  lang === "en" ? "bg-emerald-600 text-white" : "text-gray-400 hover:text-white",
                )}
              >
                EN
              </button>
              <button
                onClick={() => switchLang("fr")}
                className={clsx(
                  "px-1.5 py-0.5 rounded",
                  lang === "fr" ? "bg-emerald-600 text-white" : "text-gray-400 hover:text-white",
                )}
              >
                FR
              </button>
            </div>
            <SystemClock />
          </div>
        </header>

        {/* Page Content */}
        <div className="flex-1 overflow-y-auto p-4 bg-gray-950">{children}</div>
      </main>
    </div>
  );
}
