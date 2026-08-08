import { useState, useEffect, useCallback } from "react";
import {
  Users, ShieldAlert, RefreshCw, AlertTriangle, CheckCircle2, Loader2, X,
} from "lucide-react";
import { useAuth } from "../contexts/AuthContext";
import { useTranslation } from "../i18n";
import { toast } from "react-toastify";

// A super_admin may assign any role, including super_admin itself.
const ROLE_OPTIONS = ["viewer", "analyst", "admin", "super_admin"];
const ROLE_RANK = { viewer: 0, analyst: 1, admin: 2, super_admin: 3 };

// The backend lane may return a bare array, {items: [...]}, or {users: [...]}.
const normalizeUsers = (data) => {
  if (Array.isArray(data)) return data;
  if (data && Array.isArray(data.items)) return data.items;
  if (data && Array.isArray(data.users)) return data.users;
  return [];
};

const roleBadgeClass = (role) => {
  switch (role) {
    case "super_admin": return "bg-purple-900/40 text-purple-300 border border-purple-700";
    case "admin": return "bg-red-900/40 text-red-300 border border-red-700";
    case "analyst": return "bg-cyan-900/40 text-cyan-300 border border-cyan-700";
    default: return "bg-gray-800 text-gray-300 border border-gray-700";
  }
};

export default function SuperAdminPage() {
  const { username: currentUser, role: currentRole, fetchWithAuth, refreshRole } = useAuth();
  const { t } = useTranslation();
  const [users, setUsers] = useState(null); // null = loading
  const [error, setError] = useState("");
  const [savingUser, setSavingUser] = useState(null);
  const [confirmTarget, setConfirmTarget] = useState(null); // self-demotion modal

  const loadUsers = useCallback(async () => {
    setError("");
    setUsers(null);
    try {
      const res = await fetchWithAuth("/api/super-admin/users");
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || t("admin_load_error"));
      }
      const data = await res.json();
      setUsers(normalizeUsers(data));
    } catch (e) {
      setError(e.message || t("admin_network_error"));
    }
  }, [fetchWithAuth, t]);

  useEffect(() => {
    loadUsers();
  }, [loadUsers]);

  const applyRoleChange = useCallback(
    async (user, newRole) => {
      setSavingUser(user.username);
      try {
        const res = await fetchWithAuth(
          `/api/super-admin/users/${encodeURIComponent(user.username)}/role`,
          {
            method: "PATCH",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ role: newRole }),
          },
        );
        if (res.ok) {
          toast.success(t("admin_role_saved").replace("{user}", user.username));
          setUsers((prev) =>
            (prev || []).map((u) =>
              u.username === user.username ? { ...u, role: newRole } : u,
            ),
          );
          // If the current user demoted themselves, re-sync the auth role so the
          // nav and guards reflect the new permissions immediately.
          if (user.username === currentUser) refreshRole();
        } else {
          const err = await res.json().catch(() => ({}));
          toast.error(err.detail || t("admin_role_failed"));
        }
      } catch {
        toast.error(t("admin_network_error"));
      } finally {
        setSavingUser(null);
        setConfirmTarget(null);
      }
    },
    [fetchWithAuth, currentUser, refreshRole, t],
  );

  const handleRoleChange = (user, newRole) => {
    if (!newRole || newRole === user.role) return;
    const isSelf = user.username === currentUser;
    const isDemotion = isSelf && ROLE_RANK[newRole] < ROLE_RANK[currentRole];
    if (isDemotion) {
      setConfirmTarget({ user, newRole });
    } else {
      applyRoleChange(user, newRole);
    }
  };

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <ShieldAlert className="text-purple-400" /> {t("super_admin_title")}
          </h1>
          <p className="text-gray-400 text-sm">{t("super_admin_subtitle")}</p>
        </div>
        <button
          onClick={loadUsers}
          className="flex items-center gap-2 bg-gray-800 hover:bg-gray-700 px-4 py-2 rounded-lg text-sm"
        >
          <RefreshCw size={16} /> {t("refresh")}
        </button>
      </div>

      {/* Loading */}
      {users === null && !error && (
        <div className="flex items-center justify-center py-16 text-gray-400">
          <Loader2 size={20} className="animate-spin mr-2" /> {t("loading")}
        </div>
      )}

      {/* Error */}
      {error && (
        <div className="flex items-center justify-between bg-red-900/30 border border-red-700 rounded-lg px-4 py-3 text-red-300">
          <span className="flex items-center gap-2">
            <AlertTriangle size={16} /> {error}
          </span>
          <button onClick={loadUsers} className="text-sm underline hover:text-white">
            {t("retry")}
          </button>
        </div>
      )}

      {/* Cross-tenant users table */}
      {users !== null && !error && (
        <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-gray-800 text-gray-300">
              <tr>
                <th className="text-left px-4 py-2">{t("admin_user")}</th>
                <th className="text-left px-4 py-2">{t("admin_role")}</th>
                <th className="text-left px-4 py-2">{t("admin_tenant")}</th>
                <th className="text-left px-4 py-2">{t("admin_actions")}</th>
              </tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <tr key={`${u.tenant_id || "default"}-${u.username}`} className="border-t border-gray-800 hover:bg-gray-800/50">
                  <td className="px-4 py-2">
                    <div className="flex items-center gap-2">
                      <Users size={14} className="text-gray-500" />
                      <span className="font-medium">{u.username}</span>
                      {u.username === currentUser && (
                        <span className="text-xs text-emerald-400">({t("admin_you")})</span>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-2">
                    <span className={`text-xs px-2 py-0.5 rounded ${roleBadgeClass(u.role)}`}>
                      {t(`role_${u.role}`)}
                    </span>
                  </td>
                  <td className="px-4 py-2 text-gray-400">{u.tenant_id || "default"}</td>
                  <td className="px-4 py-2">
                    <select
                      value={u.role || "viewer"}
                      disabled={savingUser === u.username}
                      onChange={(e) => handleRoleChange(u, e.target.value)}
                      className="bg-gray-800 border border-gray-700 rounded px-2 py-1 text-sm disabled:opacity-50"
                    >
                      {ROLE_OPTIONS.map((r) => (
                        <option key={r} value={r}>{t(`role_${r}`)}</option>
                      ))}
                    </select>
                    {savingUser === u.username && (
                      <Loader2 size={14} className="inline ml-2 animate-spin text-emerald-400" />
                    )}
                  </td>
                </tr>
              ))}
              {users.length === 0 && (
                <tr>
                  <td colSpan={4} className="px-4 py-8 text-center text-gray-500">
                    {t("admin_empty")}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {/* Self-demotion warning modal */}
      {confirmTarget && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <div className="bg-gray-900 border border-amber-700 rounded-xl w-full max-w-md">
            <div className="flex items-center justify-between px-5 py-4 border-b border-gray-800">
              <h3 className="font-bold flex items-center gap-2 text-amber-400">
                <AlertTriangle size={18} /> {t("admin_self_demotion_title")}
              </h3>
              <button
                onClick={() => setConfirmTarget(null)}
                className="text-gray-400 hover:text-white"
              >
                <X size={18} />
              </button>
            </div>
            <div className="p-5">
              <p className="text-sm text-gray-300">
                {t("admin_self_demotion_body").replace("{role}", t(`role_${confirmTarget.newRole}`))}
              </p>
            </div>
            <div className="flex justify-end gap-3 px-5 py-4 border-t border-gray-800">
              <button
                onClick={() => setConfirmTarget(null)}
                className="px-4 py-2 rounded-lg text-gray-400 hover:text-white"
              >
                {t("cancel")}
              </button>
              <button
                onClick={() => applyRoleChange(confirmTarget.user, confirmTarget.newRole)}
                className="flex items-center gap-2 bg-red-600 hover:bg-red-500 px-4 py-2 rounded-lg"
              >
                <CheckCircle2 size={16} /> {t("confirm")}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}