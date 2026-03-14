import { authHeaders, fetchWithSession, handleUnauthorized } from "./api-core";
import {
  deleteJSONResult,
  getJSON,
  patchJSONResult,
  postJSONResult,
} from "./api-request";

import type { ConfigBackup, ConfigBundle } from "./api";

export const configAPI = {
  getRunningConfig: () => getJSON<ConfigBundle>("/api/v1/config"),
  getCandidateConfig: () => getJSON<ConfigBundle>("/api/v1/config/candidate"),
  setCandidateConfig: (cfg: ConfigBundle) =>
    postJSONResult<{ status: string }>("/api/v1/config/candidate", cfg),
  diffConfig: () =>
    getJSON<{ running: ConfigBundle | null; candidate: ConfigBundle | null }>(
      "/api/v1/config/diff",
    ),
  exportConfig: (redacted = true) =>
    getJSON<ConfigBundle>(
      `/api/v1/config/export?redacted=${redacted ? "1" : "0"}`,
    ),
  importConfig: (cfg: ConfigBundle) =>
    postJSONResult<{ status: string }>("/api/v1/config/import", cfg),
  listConfigBackups: () => getJSON<ConfigBackup[]>("/api/v1/config/backups"),
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
