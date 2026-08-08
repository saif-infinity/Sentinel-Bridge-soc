import { createContext, useContext, useState, useCallback, useEffect } from "react";
import { createFetchWithAuth } from "../lib/api";

const AuthContext = createContext(null);

// Role hierarchy: viewer < analyst < admin < super_admin
const ROLE_RANK = { viewer: 0, analyst: 1, admin: 2, super_admin: 3 };

export function AuthProvider({ children }) {
  const [jwtToken, setJwtToken] = useState(localStorage.getItem("auth_token") || "");
  const [username, setUsername] = useState(localStorage.getItem("auth_username") || "");
  const [tenantId, setTenantIdState] = useState(localStorage.getItem("auth_tenant_id") || "default");
  const [role, setRole] = useState(localStorage.getItem("auth_role") || null);
  const [isAuthenticated, setIsAuthenticated] = useState(!!localStorage.getItem("auth_token"));

  const setTenantId = useCallback((id) => {
    const tid = id || "default";
    localStorage.setItem("auth_tenant_id", tid);
    setTenantIdState(tid);
  }, []);

  // AUTO-LOGIN BYPASS — only active when VITE_AUTOLOGIN=1 (dev escape hatch).
  // Default behavior: no auto-registration, login required.
  useEffect(() => {
    if (import.meta.env.VITE_AUTOLOGIN !== "1") return;
    if (localStorage.getItem("auth_token")) return;
    fetch("/auth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "dev_user", password: "DevPass123", role: "analyst" }),
      })
        .then((r) => (r.ok ? r.json() : r.status === 409 ? fetch("/auth/token", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: "username=dev_user&password=DevPass123" }).then((r2) => r2.json()) : null))
        .then((data) => {
          if (data?.access_token) {
            localStorage.setItem("auth_token", data.access_token);
            localStorage.setItem("auth_username", data.username || "dev_user");
            if (data.role) {
              localStorage.setItem("auth_role", data.role);
              setRole(data.role);
            }
            setJwtToken(data.access_token);
            setUsername(data.username || "dev_user");
            setTenantId(data.tenant_id);
            setIsAuthenticated(true);
          }
        })
.catch(() => {});
  }, []);

  const handleUnauthorized = useCallback(() => {
    localStorage.removeItem("auth_token");
    localStorage.removeItem("auth_username");
    localStorage.removeItem("auth_tenant_id");
    localStorage.removeItem("auth_role");
    setJwtToken("");
    setUsername("");
    setTenantIdState("default");
    setRole(null);
    setIsAuthenticated(false);
  }, []);

  const getToken = useCallback(() => jwtToken, [jwtToken]);

  const fetchWithAuth = createFetchWithAuth(getToken, handleUnauthorized);

  const login = useCallback((token, user, tid, userRole) => {
    localStorage.setItem("auth_token", token);
    localStorage.setItem("auth_username", user);
    if (userRole) {
      localStorage.setItem("auth_role", userRole);
      setRole(userRole);
    }
    setJwtToken(token);
    setUsername(user);
    setTenantId(tid);
    setIsAuthenticated(true);
  }, [setTenantId]);

  const logout = useCallback(() => {
    if (username && jwtToken) {
      fetch(`/api/surveillance/logout?${new URLSearchParams({ username })}`, {
        method: "POST",
        headers: { Authorization: `Bearer ${jwtToken}` },
      }).catch(() => {});
    }
    localStorage.removeItem("auth_token");
    localStorage.removeItem("auth_username");
    localStorage.removeItem("auth_tenant_id");
    localStorage.removeItem("auth_role");
    setJwtToken("");
    setUsername("");
    setTenantIdState("default");
    setRole(null);
    setIsAuthenticated(false);
  }, [username, jwtToken]);

  // Fetches the authoritative identity from GET /api/auth/me and syncs state.
  // Returns the payload (or null on failure/401).
  const refreshRole = useCallback(async () => {
    const token = localStorage.getItem("auth_token");
    if (!token) return null;
    try {
      const res = await fetch("/api/auth/me", {
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
          "X-Tenant-ID": localStorage.getItem("auth_tenant_id") || "default",
        },
      });
      if (res.status === 401) {
        handleUnauthorized();
        return null;
      }
      if (!res.ok) return null;
      const data = await res.json();
      if (data.role) {
        localStorage.setItem("auth_role", data.role);
        setRole(data.role);
      }
      if (data.username) {
        localStorage.setItem("auth_username", data.username);
        setUsername(data.username);
      }
      if (data.tenant_id) setTenantId(data.tenant_id);
      return data;
    } catch {
      return null;
    }
  }, [handleUnauthorized, setTenantId]);

  // On app load, refresh the authoritative role/identity from GET /api/auth/me.
  // The JWT does not carry the role; this endpoint is the source of truth.
  // If it 401s we treat the session as logged-out; any other failure keeps
  // the locally cached identity (role from login response) intact.
  useEffect(() => {
    if (!localStorage.getItem("auth_token")) return;
    refreshRole();
  }, [refreshRole]);

  // hasRole(minRole): true when the current role is at or above minRole in the
  // hierarchy. super_admin passes everything; a null/unknown role counts as viewer.
  const hasRole = useCallback(
    (minRole) => {
      if (!minRole) return true;
      const current = ROLE_RANK[role] ?? ROLE_RANK.viewer;
      const required = ROLE_RANK[minRole];
      if (required === undefined) return true;
      return current >= required;
    },
    [role],
  );

  useEffect(() => {
    if (isAuthenticated && jwtToken) {
      fetch("/api/surveillance/login", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${jwtToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          username,
          login_method: "password",
          face_verified: false,
        }),
      }).catch(() => {});
    }
  }, []);

  const value = {
    jwtToken,
    username,
    isAuthenticated,
    tenantId,
    role,
    login,
    logout,
    setTenantId,
    hasRole,
    refreshRole,
    fetchWithAuth,
    headers: jwtToken
      ? {
          Authorization: `Bearer ${jwtToken}`,
          "Content-Type": "application/json",
          "X-Tenant-ID": tenantId || "default",
        }
      : {},
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
