import {
  authHeaders,
  clearAuthExpired,
  fetchWithSession,
  handleUnauthorized,
} from "./api-core";
import {
  deleteJSONResult,
  failureOf,
  getJSON,
  getJSONList,
  getJSONShaped,
  patchJSONResult,
  postJSONResult,
} from "./api-request";

import type {
  Asset,
  AuditRecord,
  DashboardData,
  TLSCertUpload,
  TLSInfo,
} from "./api";

/** Outcome of a trusted CA bundle upload. `stored` means management saved
 * the bundle but the engine did not apply it; the next commit retries. */
export type TrustedCAUploadResult =
  | { state: "applied"; revision: string }
  | { state: "stored"; revision: string; warnings: string[] }
  | { state: "failed"; error: string };

export const policyAPI = {
  listAssets: () => getJSONList<Asset>("/api/v1/assets"),
  createAsset: (a: Asset) => postJSONResult<Asset>("/api/v1/assets", a),
  updateAsset: (id: string, a: Partial<Asset>) =>
    patchJSONResult<Asset>(`/api/v1/assets/${encodeURIComponent(id)}`, a),
  deleteAsset: (id: string) =>
    deleteJSONResult(`/api/v1/assets/${encodeURIComponent(id)}`),


  listAudit: () => getJSONList<AuditRecord>("/api/v1/audit"),
  getDashboard: (signal?: AbortSignal) =>
    getJSONShaped<DashboardData>("/api/v1/dashboard", { objects: ["health", "counts", "eventStats"] }, signal),

  getTLSInfo: () => getJSON<TLSInfo>("/api/v1/system/tls"),
  setTLSCert: (certPEM: string, keyPEM: string) =>
    postJSONResult<TLSCertUpload>("/api/v1/system/tls/cert", {
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
      if (handleUnauthorized(res)) return { state: "failed", error: (await failureOf(res)).error };
      clearAuthExpired();
      if (!res.ok) return { state: "failed", error: (await failureOf(res)).error };
      const body = (await res.json().catch(() => ({}))) as {
        status?: string;
        revision?: string;
        warnings?: string[];
      };
      const revision = body.revision ?? "";
      if (body.status === "stored") {
        return { state: "stored", revision, warnings: body.warnings ?? [] };
      }
      return { state: "applied", revision };
    } catch (e) {
      return { state: "failed", error: e instanceof Error ? e.message : "Network error" };
    }
  },
};
