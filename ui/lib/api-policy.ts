import { notifyConfigMutation } from "./config-events";
import {
  apiURL,
  authHeaders,
  clearAuthExpired,
  fetchWithSession,
  handleUnauthorized,
} from "./api-core";
import {
  deleteJSONResult,
  getJSON,
  parseErrorBody,
  patchJSONResult,
  postJSON,
  postJSONResult,
} from "./api-request";

import type {
  ApiResult,
  Asset,
  AuditRecord,
  DashboardData,
  IDSConfig,
  IDSImportResult,
  IDSRule,
  IDSRuleSource,
  TLSInfo,
} from "./api";

/** Outcome of a trusted CA bundle upload. `stored` means management saved
 * the bundle but the engine could not apply it; the next commit retries. */
export type TrustedCAUploadResult =
  | { state: "applied"; revision: string }
  | { state: "stored"; detail: string }
  | { state: "failed"; error: string };

export const policyAPI = {
  listAssets: () => getJSON<Asset[]>("/api/v1/assets"),
  createAsset: (a: Asset) => postJSONResult<Asset>("/api/v1/assets", a),
  updateAsset: (id: string, a: Partial<Asset>) =>
    patchJSONResult<Asset>(`/api/v1/assets/${encodeURIComponent(id)}`, a),
  deleteAsset: (id: string) =>
    deleteJSONResult(`/api/v1/assets/${encodeURIComponent(id)}`),

  getIDS: () => getJSON<IDSConfig>("/api/v1/ids/rules"),
  setIDS: (cfg: IDSConfig) =>
    postJSONResult<IDSConfig>("/api/v1/ids/rules", cfg),
  convertSigma: (sigmaYAML: string) =>
    postJSON<IDSRule>("/api/v1/ids/convert/sigma", { sigmaYAML }),
  importIDSRules: async (
    file: File,
    format?: string,
  ): Promise<ApiResult<IDSImportResult>> => {
    const form = new FormData();
    form.append("file", file);
    if (format) form.append("format", format);
    try {
      const res = await fetchWithSession("/api/v1/ids/import", {
        method: "POST",
        body: form,
        credentials: "include",
        headers: authHeaders(),
      });
      if (handleUnauthorized(res)) return { ok: false, error: "Unauthorized" };
      clearAuthExpired();
      if (!res.ok) return { ok: false, error: await parseErrorBody(res) };
      notifyConfigMutation(res);
      return { ok: true, data: (await res.json()) as IDSImportResult };
    } catch (e) {
      return {
        ok: false,
        error: e instanceof Error ? e.message : "Network error",
      };
    }
  },
  exportIDSRules: async (format: string): Promise<boolean> => {
    const res = await fetch(
      apiURL(`/api/v1/ids/export?format=${encodeURIComponent(format)}`),
      {
        credentials: "include",
        headers: authHeaders(),
      },
    );
    if (!res.ok) return false;
    const blob = await res.blob();
    const ext: Record<string, string> = {
      suricata: ".rules",
      snort: ".rules",
      yara: ".yar",
      sigma: ".yml",
    };
    const now = new Date();
    const yy = String(now.getFullYear()).slice(2);
    const mm = String(now.getMonth() + 1).padStart(2, "0");
    const dd = String(now.getDate()).padStart(2, "0");
    const filename = `${format}-${yy}${mm}${dd}${ext[format] || ".txt"}`;
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    return true;
  },
  getIDSSources: () => getJSON<IDSRuleSource[]>("/api/v1/ids/sources"),

  listAudit: () => getJSON<AuditRecord[]>("/api/v1/audit"),
  getDashboard: (signal?: AbortSignal) =>
    getJSON<DashboardData>("/api/v1/dashboard", signal),

  getTLSInfo: () => getJSON<TLSInfo>("/api/v1/system/tls"),
  setTLSCert: (certPEM: string, keyPEM: string) =>
    postJSONResult<{ status: string }>("/api/v1/system/tls/cert", {
      certPEM,
      keyPEM,
    }),
  setTrustedCA: async (pem: string): Promise<TrustedCAUploadResult> => {
    try {
      const res = await fetchWithSession("/api/v1/system/tls/trusted-ca", {
        method: "POST",
        headers: { "Content-Type": "application/json", ...authHeaders() },
        body: JSON.stringify({ pem }),
      });
      if (handleUnauthorized(res)) return { state: "failed", error: "Unauthorized" };
      clearAuthExpired();
      const body = (await res.json().catch(() => ({}))) as {
        revision?: string;
        error?: string;
        detail?: string;
      };
      if (res.ok) return { state: "applied", revision: body.revision ?? "" };
      // 503: the bundle is stored, but the engine is unavailable or did not apply it.
      if (res.status === 503) {
        return { state: "stored", detail: body.detail || body.error || res.statusText };
      }
      const error = body.error || res.statusText;
      return { state: "failed", error: body.detail ? `${error}: ${body.detail}` : error };
    } catch (e) {
      return { state: "failed", error: e instanceof Error ? e.message : "Network error" };
    }
  },
};
