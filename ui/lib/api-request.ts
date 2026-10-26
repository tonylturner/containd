import { notifyConfigMutation } from "./config-events";
import {
  authHeaders,
  clearAuthExpired,
  fetchWithSession,
  handleUnauthorized,
} from "./api-core";

import type { ApiResult } from "./api";

/**
 * A JSON object body type. Lists have a length, so `getJSON<Zone[]>` does
 * not type-check: list endpoints use getJSONList.
 */
export type ObjectBody = object & { length?: never };

/** A JSON object: not null, not an array. */
export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Reads a successful body of the expected shape. Any other body, such as a
 * list endpoint answering an object, is malformed: callers treat it like an
 * unavailable endpoint, never as data or as a verified-empty list.
 */
type Shape = "object" | "list";

function fits(body: unknown, shape: Shape): boolean {
  return shape === "list" ? Array.isArray(body) : isRecord(body);
}

async function getBody(
  path: string,
  shape: Shape,
  signal?: AbortSignal,
): Promise<{ status: number; body: unknown } | { status: number; error: string }> {
  const res = await fetchWithSession(path, { cache: "no-store", headers: authHeaders() }, signal);
  if (handleUnauthorized(res)) return { status: 401, error: "Unauthorized" };
  clearAuthExpired();
  if (!res.ok) return { status: res.status, error: await parseErrorBody(res) };
  const body: unknown = await res.json().catch(() => undefined);
  if (!fits(body, shape)) return { status: res.status, error: `malformed response from ${path}` };
  return { status: res.status, body };
}

function isAbort(e: unknown): boolean {
  return e instanceof DOMException && e.name === "AbortError";
}

/** GET of a JSON object; null when unavailable or malformed. */
export async function getJSON<T extends ObjectBody>(
  path: string,
  signal?: AbortSignal,
): Promise<T | null> {
  try {
    const res = await getBody(path, "object", signal);
    return "body" in res ? (res.body as T) : null;
  } catch (e) {
    if (isAbort(e)) throw e;
    return null;
  }
}

/** Fields of an object body that pages read without checking. */
export type RequiredFields<T> = {
  lists?: (keyof T & string)[];
  objects?: (keyof T & string)[];
};

function hasFields(body: unknown, required: { lists?: string[]; objects?: string[] }): boolean {
  const record = body as Record<string, unknown>;
  return (required.lists ?? []).every((k) => Array.isArray(record[k])) &&
    (required.objects ?? []).every((k) => isRecord(record[k]));
}

/**
 * GET of a JSON object with required list and object fields, such as a page
 * of events; null when unavailable or any of them has the wrong shape.
 */
export async function getJSONShaped<T extends ObjectBody>(
  path: string,
  required: RequiredFields<T>,
  signal?: AbortSignal,
): Promise<T | null> {
  const body = await getJSON<T>(path, signal);
  return body && hasFields(body, required) ? body : null;
}

/** GET of a JSON list; null when unavailable or malformed. */
export async function getJSONList<T>(
  path: string,
  signal?: AbortSignal,
): Promise<T[] | null> {
  try {
    const res = await getBody(path, "list", signal);
    return "body" in res ? (res.body as T[]) : null;
  } catch (e) {
    if (isAbort(e)) throw e;
    return null;
  }
}

export async function getJSONWithStatus<T extends ObjectBody>(
  path: string,
  required: RequiredFields<T> = {},
): Promise<{ status: number; data: T | null }> {
  try {
    const res = await getBody(path, "object");
    const ok = "body" in res && hasFields(res.body, required);
    return { status: res.status, data: ok ? (res.body as T) : null };
  } catch {
    return { status: 0, data: null };
  }
}

/** GET of a JSON object that surfaces the server's error message instead of a bare null. */
export async function getJSONResult<T extends ObjectBody>(path: string): Promise<ApiResult<T>> {
  return getResult<T>(path, "object");
}

/** GET of a JSON list that surfaces the server's error message. */
export async function getJSONListResult<T>(path: string): Promise<ApiResult<T[]>> {
  return getResult<T[]>(path, "list");
}

async function getResult<T>(path: string, shape: Shape): Promise<ApiResult<T>> {
  try {
    const res = await getBody(path, shape);
    return "body" in res ? { ok: true, data: res.body as T } : { ok: false, error: res.error };
  } catch (e) {
    return {
      ok: false,
      error: e instanceof Error ? e.message : "Network error",
    };
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
    notifyConfigMutation(res);
    return await parseSuccessBody<T>(res);
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
    notifyConfigMutation(res);
    return await parseSuccessBody<T>(res);
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
    if (res.ok) notifyConfigMutation(res);
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
    notifyConfigMutation(res);
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
    notifyConfigMutation(res);
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
    notifyConfigMutation(res);
    return { ok: true, data: undefined, warning: parseWarningHeader(res) };
  } catch (e) {
    return {
      ok: false,
      error: e instanceof Error ? e.message : "Network error",
    };
  }
}
