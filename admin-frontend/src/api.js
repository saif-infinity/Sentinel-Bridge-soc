// src/api.js
// Shared authenticated fetch helpers + auth token storage.
//
// On any 401 response the stored token is cleared and registered
// listeners are notified so the app can return to the login screen
// instead of silently showing an empty dashboard.

const TOKEN_KEY = "admin_token";

const unauthorizedListeners = new Set();

export function getToken() {
  return localStorage.getItem(TOKEN_KEY);
}

export function setToken(token) {
  localStorage.setItem(TOKEN_KEY, token);
}

export function clearToken() {
  localStorage.removeItem(TOKEN_KEY);
}

/**
 * Register a callback invoked whenever an authenticated request
 * receives a 401 response. Returns an unsubscribe function.
 */
export function onUnauthorized(listener) {
  unauthorizedListeners.add(listener);
  return () => unauthorizedListeners.delete(listener);
}

function dispatchUnauthorized() {
  clearToken();
  unauthorizedListeners.forEach((listener) => {
    try {
      listener();
    } catch (err) {
      console.error("Unauthorized listener error:", err);
    }
  });
}

/**
 * Authenticated fetch helper.
 * - Attaches `Authorization: Bearer <token>` from storage unless an
 *   Authorization header is already provided.
 * - Adds `Content-Type: application/json` for JSON bodies.
 * - On a 401 response (unless `on401` is false) clears the token and
 *   notifies registered listeners so the app returns to login.
 */
export async function apiFetch(
  path,
  { method = "GET", headers = {}, body, on401 = true } = {}
) {
  const finalHeaders = { ...headers };
  if (!finalHeaders.Authorization) {
    const token = getToken();
    if (token) finalHeaders.Authorization = `Bearer ${token}`;
  }
  if (
    body !== undefined &&
    !(body instanceof FormData) &&
    !finalHeaders["Content-Type"]
  ) {
    finalHeaders["Content-Type"] = "application/json";
  }
  const res = await fetch(path, { method, headers: finalHeaders, body });
  if (res.status === 401 && on401) {
    dispatchUnauthorized();
  }
  return res;
}