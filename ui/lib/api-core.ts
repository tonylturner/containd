const API_BASE =
  typeof window === "undefined" ? process.env.NEXT_PUBLIC_API_BASE || "" : "";
const ENV_TOKEN = process.env.NEXT_PUBLIC_API_TOKEN || "";
const TOKEN_KEY = "containd.auth.token";
const ROLE_KEY = "containd.auth.role";
const SESSION_TOKEN_KEY = "containd.session.token";
const AUTH_ERROR_KEY = "containd.auth.last_error";

let authExpiredEmitted = false;
let authExpiredTimer: ReturnType<typeof setTimeout> | null = null;

export function getSessionToken(): string | null {
  if (typeof window === "undefined") return null;
  try {
    return sessionStorage.getItem(SESSION_TOKEN_KEY);
  } catch {
    return null;
  }
}

export function setSessionToken(token: string | null) {
  if (typeof window === "undefined") return;
  try {
    if (!token) sessionStorage.removeItem(SESSION_TOKEN_KEY);
    else sessionStorage.setItem(SESSION_TOKEN_KEY, token);
  } catch {}
}

export function setLastAuthError(msg: string | null) {
  if (typeof window === "undefined") return;
  try {
    if (!msg) sessionStorage.removeItem(AUTH_ERROR_KEY);
    else sessionStorage.setItem(AUTH_ERROR_KEY, msg);
  } catch {}
}

export function getLastAuthError(): string | null {
  if (typeof window === "undefined") return null;
  try {
    return sessionStorage.getItem(AUTH_ERROR_KEY);
  } catch {
    return null;
  }
}

export function setStoredRole(role: string | null) {
  if (typeof window === "undefined") return;
  try {
    if (!role) localStorage.removeItem(ROLE_KEY);
    else localStorage.setItem(ROLE_KEY, role);
  } catch {}
}

export function clearLocalAuth() {
  if (typeof window !== "undefined") {
    try {
      localStorage.removeItem(TOKEN_KEY);
    } catch {}
  }
  setSessionToken(null);
  setStoredRole(null);
  clearAuthExpired();
}

export function getStoredRole(): "admin" | "view" | null {
  if (typeof window === "undefined") return null;
  try {
    const r = localStorage.getItem(ROLE_KEY);
    if (r === "admin" || r === "view") return r;
    return null;
  } catch {
    return null;
  }
}

export function isAdmin(): boolean {
  return getStoredRole() === "admin";
}

export function authHeaders(): Record<string, string> {
  if (!ENV_TOKEN) return {};
  return { Authorization: `Bearer ${ENV_TOKEN}` };
}

function updateSessionTokenFromResponse(res: Response) {
  if (typeof window === "undefined") return;
  const next = res.headers.get("x-auth-token");
  if (next) setSessionToken(next);
}

async function captureAuthError(res: Response) {
  if (typeof window === "undefined") return;
  if (res.status !== 401 && res.status !== 403) return;
  try {
    const ct = (res.headers.get("content-type") || "").toLowerCase();
    if (!ct.includes("application/json")) return;
    const j = await res.clone().json();
    const msg =
      typeof j?.error === "string"
        ? j.error
        : typeof j?.message === "string"
          ? j.message
          : null;
    if (msg) setLastAuthError(msg);
    if (res.status === 403 && msg && /password change required/i.test(msg)) {
      window.dispatchEvent(
        new CustomEvent("containd:auth:password_change_required"),
      );
    }
    if (res.status === 403 && msg && /mfa setup required/i.test(msg)) {
      window.dispatchEvent(new CustomEvent("containd:auth:mfa_setup_required"));
    }
  } catch {
    // ignore
  }
}

export async function fetchWithSession(
  path: string,
  init: RequestInit,
  signal?: AbortSignal,
): Promise<Response> {
  const url = `${API_BASE}${path}`;
  const res = await fetch(url, {
    ...init,
    credentials: "include",
    cache: "no-store",
    signal,
  });

  if (res.status === 401 && !ENV_TOKEN) {
    const fallback = getSessionToken();
    if (fallback) {
      const h = (init.headers ?? {}) as Record<string, string>;
      const hasAuth = Object.keys(h).some(
        (k) => k.toLowerCase() === "authorization",
      );
      if (!hasAuth) {
        const retry = await fetch(url, {
          ...init,
          headers: { ...h, Authorization: `Bearer ${fallback}` },
          credentials: "include",
          cache: "no-store",
          signal,
        });
        await captureAuthError(retry);
        updateSessionTokenFromResponse(retry);
        return retry;
      }
    }
  }

  await captureAuthError(res);
  updateSessionTokenFromResponse(res);
  return res;
}

export function apiURL(path: string): string {
  return `${API_BASE}${path}`;
}

export function handleUnauthorized(res: Response) {
  if (res.status !== 401) return false;
  if (typeof window !== "undefined") {
    if (!authExpiredEmitted) {
      authExpiredEmitted = true;
      if (authExpiredTimer) clearTimeout(authExpiredTimer);
      authExpiredTimer = setTimeout(() => {
        if (authExpiredEmitted) {
          window.dispatchEvent(new CustomEvent("containd:auth:expired"));
        }
      }, 1500);
    }
  }
  return true;
}

export function clearAuthExpired() {
  authExpiredEmitted = false;
  if (authExpiredTimer) {
    clearTimeout(authExpiredTimer);
    authExpiredTimer = null;
  }
}
