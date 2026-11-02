import { authHeaders, fetchWithSession, handleUnauthorized } from "./api-core";
import {
  getConfigJSON,
  responseRevision,
  deleteJSONResult,
  getJSONList,
  isRecord,
  postJSONResult,
} from "./api-request";

import type { ConfigBackup, ConfigBundle } from "./api";

export type IDSBankSummary = { count: number; sha256: string };
export type ConfigDiff = {
  changed: boolean;
  changedSections: string[];
  pendingConfirm: { deadline: string } | null;
  running: ConfigBundle | null;
  candidate: ConfigBundle | null;
  /** Absent when the response did not carry both bank summaries. */
  idsBank?: { running: IDSBankSummary; candidate: IDSBankSummary };
};

function normalizeConfigDiff(diff: ConfigDiff | null): ConfigDiff | null {
  if (!diff || typeof diff.changed !== "boolean" || !Array.isArray(diff.changedSections)) return null;
  const bank: unknown = diff.idsBank;
  return isRecord(bank) && isRecord(bank.running) && isRecord(bank.candidate)
    ? diff
    : { ...diff, idsBank: undefined };
}

export const configAPI = {
  getRunningConfig: (signal?: AbortSignal) => getConfigJSON<ConfigBundle>("/api/v1/config", "object", signal),
  getCandidateConfig: () => getConfigJSON<ConfigBundle>("/api/v1/config/candidate", "object"),
  setCandidateConfig: (expectedRevision: string, cfg: ConfigBundle) =>
    postJSONResult<{ status: string }>("/api/v1/config/candidate", cfg, expectedRevision),
  validateConfig: (cfg: ConfigBundle) =>
    postJSONResult<{ status: string }>("/api/v1/config/validate", cfg),
  factoryReset: (expectedRevision: string) =>
    postJSONResult<{ message: string; loggedOut: boolean; warnings: string[] }>(
      "/api/v1/system/factory-reset", { confirm: "NUCLEAR" }, expectedRevision,
    ),
  diffConfig: async () => {
    const snapshot = await getConfigJSON<ConfigDiff>("/api/v1/config/diff");
    const data = normalizeConfigDiff(snapshot?.data ?? null);
    return snapshot && data ? { data, revision: snapshot.revision } : null;
  },
  exportConfig: (redacted = true) =>
    getConfigJSON<ConfigBundle>(
      `/api/v1/config/export?redacted=${redacted ? "1" : "0"}`, "object",
    ),
  importConfig: (expectedRevision: string, cfg: ConfigBundle) =>
    postJSONResult<{ status: string }>("/api/v1/config/import", cfg, expectedRevision),
  listConfigBackups: () => getJSONList<ConfigBackup>("/api/v1/config/backups"),
  createConfigBackup: (req: { name?: string; redacted: boolean }) =>
    postJSONResult<ConfigBackup>("/api/v1/config/backups", req),
  deleteConfigBackup: (id: string) =>
    deleteJSONResult(`/api/v1/config/backups/${encodeURIComponent(id)}`),
  downloadConfigBackup: async (id: string) => {
    const res = await fetchWithSession(
      `/api/v1/config/backups/${encodeURIComponent(id)}`,
      {
        headers: { ...authHeaders() },
        cache: "no-store",
      },
    );
    if (handleUnauthorized(res) || !res.ok) return null;
    return await res.blob();
  },
  backupIDSRules: async () => {
    const res = await fetchWithSession("/api/v1/ids/backup", {
      headers: { ...authHeaders() },
      cache: "no-store",
    });
    if (handleUnauthorized(res) || !res.ok) return null;
    const revision = responseRevision(res);
    return revision ? { data: await res.blob(), revision } : null;
  },
  restoreIDSRules: async (expectedRevision: string, rules: unknown[]) =>
    postJSONResult<{ status: string; count: number }>(
      "/api/v1/ids/restore",
      rules, expectedRevision,
    ),
  commit: (expectedRevision: string) => postJSONResult<{ status: string }>("/api/v1/config/commit", {}, expectedRevision),
  commitConfirmed: (expectedRevision: string, ttlSeconds?: number) =>
    postJSONResult<{ status: string }>(
      "/api/v1/config/commit_confirmed",
      ttlSeconds ? { ttl_seconds: ttlSeconds } : {}, expectedRevision,
    ),
  confirmCommit: (expectedRevision: string) =>
    postJSONResult<{ status: string }>("/api/v1/config/confirm", {}, expectedRevision),
  rollback: (expectedRevision: string) =>
    postJSONResult<{ status: string }>("/api/v1/config/rollback", {}, expectedRevision),
};
