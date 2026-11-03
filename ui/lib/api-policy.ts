import { PROTECTION_TARGET_CHANGED } from "./protection-store";
import {
  authHeaders,
  clearAuthExpired,
  fetchWithSession,
  handleUnauthorized,
} from "./api-core";
import {
  getConfigJSON,
  deleteJSONResult,
  failureOf,
  getJSON,
  getJSONList,
  getJSONShaped,
  isRecord,
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
 * the bundle without matching trust-owner acknowledgement; convergence retries. */
export type TrustedCAUploadResult =
  | { state: "applied"; revision: string }
  | { state: "stored"; revision: string; warnings: string[] }
  | { state: "failed"; error: string };

/** Accept older TLS status payloads while rejecting malformed warning values. */
export function parseTLSInfo(value: unknown): TLSInfo | null {
  if (!isRecord(value) || (value.certificateWarning !== undefined && typeof value.certificateWarning !== "string")) {
    return null;
  }
  return value as unknown as TLSInfo;
}

export const policyAPI = {
  listAssets: () => getConfigJSON<Asset[]>("/api/v1/assets", "list"),
  createAsset: (expectedRevision: string, a: Asset) => postJSONResult<Asset>("/api/v1/assets", a, expectedRevision),
  updateAsset: (expectedRevision: string, id: string, a: Partial<Asset>) =>
    patchJSONResult<Asset>(`/api/v1/assets/${encodeURIComponent(id)}`, a, expectedRevision),
  deleteAsset: (expectedRevision: string, id: string) =>
    deleteJSONResult(`/api/v1/assets/${encodeURIComponent(id)}`, expectedRevision),


  listAudit: () => getJSONList<AuditRecord>("/api/v1/audit"),
  getDashboard: (signal?: AbortSignal) =>
    getJSONShaped<DashboardData>("/api/v1/dashboard", { objects: ["health", "counts"] }, signal),

  getTLSInfo: async () => parseTLSInfo(await getJSON<TLSInfo>("/api/v1/system/tls")),
  setTLSCert: (certPEM: string, keyPEM: string) =>
    postJSONResult<TLSCertUpload>("/api/v1/system/tls/cert", {
      certPEM,
      keyPEM,
    }),
  setTrustedCA: async (pem: string | { clear: true }): Promise<TrustedCAUploadResult> => {
    try {
      const res = await fetchWithSession("/api/v1/system/tls/trusted-ca", {
        method: "POST",
        headers: { "Content-Type": "application/json", ...authHeaders() },
        body: JSON.stringify(typeof pem === "string" ? { pem } : pem),
      });
      if (handleUnauthorized(res)) return { state: "failed", error: (await failureOf(res)).error };
      clearAuthExpired();
      if (!res.ok) return { state: "failed", error: (await failureOf(res)).error };
      if (typeof window !== "undefined") window.dispatchEvent(new Event(PROTECTION_TARGET_CHANGED));
      const body: unknown = await res.json().catch(() => undefined);
      if (!isRecord(body) || !["stored", "updated"].includes(body.status as string)
        || typeof body.revision !== "string" || !body.revision
        || !Array.isArray(body.warnings) || !body.warnings.every(w => typeof w === "string")) {
        return { state: "failed", error: "Trust owner acknowledgement could not be verified. Refresh protection status." };
      }
      return body.status === "stored"
        ? { state: "stored", revision: body.revision, warnings: body.warnings }
        : { state: "applied", revision: body.revision };
    } catch (e) {
      return { state: "failed", error: e instanceof Error ? e.message : "Network error" };
    }
  },
};
