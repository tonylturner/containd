import { notifyConfigMutation } from "./config-events";
import {
  authHeaders,
  clearAuthExpired,
  fetchWithSession,
  handleUnauthorized,
} from "./api-core";
import { getConfigJSON, failureOf, getJSON, getJSONShaped, isRecord, postJSONResult } from "./api-request";

import type {
  AVConfig,
  DHCPConfig,
  DHCPLease,
  DNSConfig,
  ForwardProxyConfig,
  NTPConfig,
  ReverseProxyConfig,
  SyslogConfig,
  SystemInspection,
  SystemStats,
} from "./api";
import type { ServicesStatus } from "./api-service-status";

/** A custom ClamAV database stored on the engine. */
export type AVDefinition = {
  name: string;
  size: number;
  modified: string;
  /** A running clamd is loading the definition. */
  active: boolean;
};

export type AVDefinitionList = {
  path: string;
  files: string[];
  definitions: AVDefinition[];
};

export const servicesAPI = {
  getServicesStatus: async (signal?: AbortSignal): Promise<ServicesStatus | null> => {
    const status = await getJSON<ServicesStatus>("/api/v1/services/status", signal);
    if (!status) return null;
    // The engine's antivirus entry is always present; a missing one reads as unreachable.
    return isRecord(status.av) ? status : { ...status, av: { available: false, error: "antivirus status not reported" } };
  },
  getSystemStats: (signal?: AbortSignal) =>
    getJSONShaped<SystemStats>("/api/v1/system/stats", {
      objects: ["cpu", "memory", "disk", "ruleEval", "container", "runtime"],
    }, signal),
  getSystemInspection: (signal?: AbortSignal) =>
    getJSONShaped<SystemInspection>("/api/v1/system/inspection", {
      objects: ["host", "runtime", "container", "process", "security"],
    }, signal),
  getSyslog: () => getConfigJSON<SyslogConfig>("/api/v1/services/syslog", "object"),
  setSyslog: (expectedRevision: string, cfg: SyslogConfig) =>
    postJSONResult<SyslogConfig>("/api/v1/services/syslog", cfg, expectedRevision),
  getAV: () => getConfigJSON<AVConfig>("/api/v1/services/av", "object"),
  setAV: (expectedRevision: string, cfg: AVConfig) =>
    postJSONResult<AVConfig>("/api/v1/services/av", cfg, expectedRevision),
  runAVUpdate: () =>
    postJSONResult<{ status: string }>("/api/v1/services/av/update", {}),
  listAVDefs: () => getJSONShaped<AVDefinitionList>("/api/v1/services/av/defs", { lists: ["files"] }),
  uploadAVDef: async (
    file: File,
  ): Promise<{ ok: true; data: { status: string; file: string; active: boolean } } | { ok: false; error: string }> => {
    const form = new FormData();
    form.append("file", file);
    try {
      const res = await fetchWithSession("/api/v1/services/av/defs", {
        method: "POST",
        body: form,
        headers: authHeaders(),
      });
      if (handleUnauthorized(res)) return failureOf(res);
      clearAuthExpired();
      if (!res.ok) return failureOf(res);
      notifyConfigMutation(res);
      return {
        ok: true,
        data: (await res.json()) as { status: string; file: string; active: boolean },
      };
    } catch (e) {
      return {
        ok: false,
        error: e instanceof Error ? e.message : "Network error",
      };
    }
  },
  deleteAVDef: async (
    file: string,
  ): Promise<{ ok: true; data: { status: string; file: string } } | { ok: false; error: string }> => {
    const params = new URLSearchParams({ file });
    try {
      const res = await fetchWithSession(
        `/api/v1/services/av/defs?${params.toString()}`,
        {
          method: "DELETE",
          headers: authHeaders(),
        },
      );
      if (handleUnauthorized(res)) return failureOf(res);
      clearAuthExpired();
      if (!res.ok) return failureOf(res);
      notifyConfigMutation(res);
      return {
        ok: true,
        data: (await res.json()) as { status: string; file: string },
      };
    } catch (e) {
      return {
        ok: false,
        error: e instanceof Error ? e.message : "Network error",
      };
    }
  },
  getDNS: () => getConfigJSON<DNSConfig>("/api/v1/services/dns", "object"),
  setDNS: (expectedRevision: string, cfg: DNSConfig) =>
    postJSONResult<DNSConfig>("/api/v1/services/dns", cfg, expectedRevision),
  getForwardProxy: () =>
    getConfigJSON<ForwardProxyConfig>("/api/v1/services/proxy/forward", "object"),
  setForwardProxy: (expectedRevision: string, cfg: ForwardProxyConfig) =>
    postJSONResult<ForwardProxyConfig>("/api/v1/services/proxy/forward", cfg, expectedRevision),
  getReverseProxy: () =>
    getConfigJSON<ReverseProxyConfig>("/api/v1/services/proxy/reverse", "object"),
  setReverseProxy: (expectedRevision: string, cfg: ReverseProxyConfig) =>
    postJSONResult<ReverseProxyConfig>("/api/v1/services/proxy/reverse", cfg, expectedRevision),
  getNTP: () => getConfigJSON<NTPConfig>("/api/v1/services/ntp", "object"),
  setNTP: (expectedRevision: string, cfg: NTPConfig) =>
    postJSONResult<NTPConfig>("/api/v1/services/ntp", cfg, expectedRevision),
  getDHCP: () => getConfigJSON<DHCPConfig>("/api/v1/services/dhcp", "object"),
  setDHCP: (expectedRevision: string, cfg: DHCPConfig) =>
    postJSONResult<DHCPConfig>("/api/v1/services/dhcp", cfg, expectedRevision),
  listDHCPLeases: () => getJSONShaped<{ leases: DHCPLease[] }>("/api/v1/dhcp/leases", { lists: ["leases"] }),
};
