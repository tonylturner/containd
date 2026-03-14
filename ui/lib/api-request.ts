import {
  authHeaders,
  clearAuthExpired,
  fetchWithSession,
  handleUnauthorized,
} from "./api-core";

import type { ApiResult } from "./api";

export async function getJSON<T>(
  path: string,
  signal?: AbortSignal,
): Promise<T | null> {
  try {
    const res = await fetchWithSession(
      path,
      {
        cache: "no-store",
        headers: authHeaders(),
      },
      signal,
    );
    if (handleUnauthorized(res)) return null;
    clearAuthExpired();
    if (!res.ok) return null;
    return (await res.json()) as T;
  } catch (e) {
    if (e instanceof DOMException && e.name === "AbortError") throw e;
    return null;
  }
}

export async function getJSONWithStatus<T>(
  path: string,
): Promise<{ status: number; data: T | null }> {
  try {
    const res = await fetchWithSession(path, {
      cache: "no-store",
      headers: authHeaders(),
    });
    if (handleUnauthorized(res)) return { status: 401, data: null };
    clearAuthExpired();
    if (!res.ok) return { status: res.status, data: null };
    return { status: res.status, data: (await res.json()) as T };
  } catch {
    return { status: 0, data: null };
  }
}

export async function postJSON<T>(
  path: string,
  payload: unknown,
): Promise<T | null> {
  try {
    const res = await fetchWithSession(path, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...authHeaders() },
      body: JSON.stringify(payload),
    });
    if (handleUnauthorized(res)) return null;
    clearAuthExpired();
    if (!res.ok) return null;
    return (await res.json()) as T;
  } catch {
    return null;
  }
}

export async function patchJSON<T>(
  path: string,
  payload: unknown,
): Promise<T | null> {
  try {
    const res = await fetchWithSession(path, {
      method: "PATCH",
      headers: { "Content-Type": "application/json", ...authHeaders() },
      body: JSON.stringify(payload),
    });
    if (handleUnauthorized(res)) return null;
    clearAuthExpired();
    if (!res.ok) return null;
    return (await res.json()) as T;
  } catch {
    return null;
  }
}

export async function deleteJSON(path: string): Promise<boolean> {
  try {
    const res = await fetchWithSession(path, {
      method: "DELETE",
      headers: authHeaders(),
    });
    if (handleUnauthorized(res)) return false;
    clearAuthExpired();
    return res.ok;
  } catch {
    return false;
  }
}

export async function parseErrorBody(res: Response): Promise<string> {
  try {
    const body = await res.json();
    return body.error || body.message || res.statusText;
  } catch {
    return res.statusText;
  }
}

export async function parseSuccessBody<T>(res: Response): Promise<T> {
  const text = await res.text();
  if (!text.trim()) {
    return undefined as T;
  }
  return JSON.parse(text) as T;
}

export function parseWarningHeader(res: Response): string | undefined {
  const warning = (res.headers.get("x-containd-warnings") || "").trim();
  return warning || undefined;
}

export async function postJSONResult<T>(
  path: string,
  payload: unknown,
): Promise<ApiResult<T>> {
  try {
    const res = await fetchWithSession(path, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...authHeaders() },
      body: JSON.stringify(payload),
    });
    if (handleUnauthorized(res)) return { ok: false, error: "Unauthorized" };
    clearAuthExpired();
    if (!res.ok) return { ok: false, error: await parseErrorBody(res) };
    return {
      ok: true,
      data: await parseSuccessBody<T>(res),
      warning: parseWarningHeader(res),
    };
  } catch (e) {
    return {
      ok: false,
      error: e instanceof Error ? e.message : "Network error",
    };
  }
}

export async function patchJSONResult<T>(
  path: string,
  payload: unknown,
): Promise<ApiResult<T>> {
  try {
    const res = await fetchWithSession(path, {
      method: "PATCH",
      headers: { "Content-Type": "application/json", ...authHeaders() },
      body: JSON.stringify(payload),
    });
    if (handleUnauthorized(res)) return { ok: false, error: "Unauthorized" };
    clearAuthExpired();
    if (!res.ok) return { ok: false, error: await parseErrorBody(res) };
    return {
      ok: true,
      data: await parseSuccessBody<T>(res),
      warning: parseWarningHeader(res),
    };
  } catch (e) {
    return {
      ok: false,
      error: e instanceof Error ? e.message : "Network error",
    };
  }
}

export async function deleteJSONResult(path: string): Promise<ApiResult<void>> {
  try {
    const res = await fetchWithSession(path, {
      method: "DELETE",
      headers: authHeaders(),
    });
    if (handleUnauthorized(res)) return { ok: false, error: "Unauthorized" };
    clearAuthExpired();
    if (!res.ok) return { ok: false, error: await parseErrorBody(res) };
    return { ok: true, data: undefined, warning: parseWarningHeader(res) };
  } catch (e) {
    return {
      ok: false,
      error: e instanceof Error ? e.message : "Network error",
    };
  }
}
