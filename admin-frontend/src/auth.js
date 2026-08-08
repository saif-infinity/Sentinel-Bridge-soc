// src/auth.js
// Auth state helpers + admin/face API calls.
import { apiFetch, getToken, setToken, clearToken } from "./api";

export { getToken, setToken, clearToken };

export const API = "/api/admin";
export const FACES_API = "/api/faces";

// ── Login flow ──────────────────────────────────────────────

export async function login(username, password) {
  const res = await fetch(`${API}/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ username, password }),
  });
  if (!res.ok) throw new Error("Identifiants admin incorrects");
  return res.json();
}

export async function getFaceStatus(token) {
  const res = await fetch(`${API}/face/status`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) return null;
  return res.json();
}

// Face verify/register run during the login flow with the interim
// token, so a 401 there means "face check failed", not "session
// expired" — hence on401: false.
export async function verifyFace(token, username, image) {
  const res = await apiFetch(`${FACES_API}/verify`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({ username, image }),
    on401: false,
  });
  if (!res.ok) {
    const d = await res.json().catch(() => ({}));
    throw new Error(d.detail || "Vérification échouée");
  }
  return res.json();
}

export async function registerFace(token, username, image) {
  const res = await apiFetch(`${FACES_API}/register`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({ username, image }),
    on401: false,
  });
  if (!res.ok) {
    const d = await res.json().catch(() => ({}));
    throw new Error(d.detail || "Enregistrement échoué");
  }
  return res.json();
}

// ── Authenticated admin actions ─────────────────────────────

export async function forceLogout(username) {
  return apiFetch(`${API}/analysts/${username}/force-logout`, {
    method: "POST",
  });
}

export async function changePassword(currentPassword, newPassword) {
  const res = await apiFetch(`${API}/change-password`, {
    method: "POST",
    body: JSON.stringify({
      current_password: currentPassword,
      new_password: newPassword,
    }),
  });
  if (!res.ok) {
    const d = await res.json().catch(() => ({}));
    throw new Error(d.detail || "Erreur lors du changement de mot de passe");
  }
  return res.json();
}