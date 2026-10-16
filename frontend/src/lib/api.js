// src/lib/api.js
// Shared authenticated fetch factory for the SOC frontend.
//
// createFetchWithAuth(getToken, onUnauthorized) -> fetchWithAuth(path, options)
//
// Contract (deduced from every call-site in the app):
//   - returns the raw Response so callers can keep doing `res.ok` / `res.json()`
//   - attaches `Authorization: Bearer <token>` unless the caller already set it
//   - attaches `X-Tenant-ID` from localStorage unless the caller already set it
//     (the backend prefers the tenant claim inside the JWT; the header is only
//      honoured for the X-API-Key lane)
//   - JSON-encodes plain object bodies and sets Content-Type automatically
//   - on 401 -> onUnauthorized() so the app drops back to the login screen
//   - on any other failure a toast is raised, unless `silent: true` is passed
//     (background pollers use silent so they never spam the analyst)

import { toast } from "react-toastify";

const TENANT_KEY = "auth_tenant_id";

function isPlainObject(value) {
  return (
    typeof value === "object" &&
    value !== null &&
    !(value instanceof FormData) &&
    !(value instanceof URLSearchParams) &&
    !(value instanceof Blob) &&
    !(value instanceof ArrayBuffer)
  );
}

/**
 * @param {() => string} getToken        returns the current JWT (may be "")
 * @param {() => void}   onUnauthorized   called on 401 — clears session state
 * @returns {(path: string, options?: object) => Promise<Response>}
 */
export function createFetchWithAuth(getToken, onUnauthorized) {
  return async function fetchWithAuth(path, options = {}) {
    const { silent = false, headers = {}, body, ...rest } = options;

    const finalHeaders = { ...headers };

    // Case-insensitive "already provided?" checks so callers can pass
    // either `Authorization` or `authorization`.
    const has = (name) =>
      Object.keys(finalHeaders).some((k) => k.toLowerCase() === name.toLowerCase());

    const token = typeof getToken === "function" ? getToken() : getToken;
    if (token && !has("Authorization")) {
      finalHeaders.Authorization = `Bearer ${token}`;
    }

    if (!has("X-Tenant-ID")) {
      const tenantId = localStorage.getItem(TENANT_KEY);
      if (tenantId) finalHeaders["X-Tenant-ID"] = tenantId;
    }

    let finalBody = body;
    if (isPlainObject(body)) {
      finalBody = JSON.stringify(body);
    }
    if (
      finalBody !== undefined &&
      finalBody !== null &&
      !(finalBody instanceof FormData) &&
      !has("Content-Type")
    ) {
      finalHeaders["Content-Type"] = "application/json";
    }

    let res;
    try {
      res = await fetch(path, { ...rest, headers: finalHeaders, body: finalBody });
    } catch (err) {
      // Network failure / backend down. Callers wrap in try/catch and inspect
      // `res.ok`, so surface a toast (unless silent) and rethrow.
      if (!silent) {
        toast.error("Backend unreachable — check that the API is running.");
      }
      throw err;
    }

    if (res.status === 401) {
      if (typeof onUnauthorized === "function") onUnauthorized();
      return res;
    }

    if (!res.ok && !silent) {
      let detail = `${res.status} ${res.statusText || ""}`.trim();
      try {
        const data = await res.clone().json();
        if (data && typeof data.detail === "string") detail = data.detail;
        else if (data && typeof data.detail === "object") {
          detail = data.detail.msg || JSON.stringify(data.detail);
        }
      } catch {
        /* non-JSON error body — keep the status line */
      }
      toast.error(detail || "Request failed");
    }

    return res;
  };
}

export default createFetchWithAuth;
