import { authHeaders, fetchWithSession, handleUnauthorized } from "./api-core";
import {
  deleteJSONResult,
  getJSON,
  getJSONList,
  isRecord,
  postJSONResult,
} from "./api-request";

import type { ConfigBackup, ConfigBundle } from "./api";

export type IDSBankSummary = { count: number; sha256: string };
export type ConfigDiff = {
  changed: boolean;
  changedSections: string[];
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
  getRunningConfig: (signal?: AbortSignal) => getJSON<ConfigBundle>("/api/v1/config", signal),
  getCandidateConfig: () => getJSON<ConfigBundle>("/api/v1/config/candidate"),
  setCandidateConfig: (cfg: ConfigBundle) =>
    postJSONResult<{ status: string }>("/api/v1/config/candidate", cfg),
  diffConfig: async () => normalizeConfigDiff(await getJSON<ConfigDiff>("/api/v1/config/diff")),
  exportConfig: (redacted = true) =>
    getJSON<ConfigBundle>(
      `/api/v1/config/export?redacted=${redacted ? "1" : "0"}`,
    ),
  importConfig: (cfg: ConfigBundle) =>
    postJSONResult<{ status: string }>("/api/v1/config/import", cfg),
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
    return await res.blob();
  },
  restoreIDSRules: async (rules: unknown[]) =>
    postJSONResult<{ status: string; count: number }>(
      "/api/v1/ids/restore",
      rules,
    ),
  commit: () => postJSONResult<{ status: string }>("/api/v1/config/commit", {}),
  commitConfirmed: (ttlSeconds?: number) =>
    postJSONResult<{ status: string }>(
      "/api/v1/config/commit_confirmed",
      ttlSeconds ? { ttl_seconds: ttlSeconds } : {},
    ),
  confirmCommit: () =>
    postJSONResult<{ status: string }>("/api/v1/config/confirm", {}),
  rollback: () =>
    postJSONResult<{ status: string }>("/api/v1/config/rollback", {}),
};
