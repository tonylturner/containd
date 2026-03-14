import {
  authHeaders,
  clearAuthExpired,
  fetchWithSession,
  handleUnauthorized,
} from "./api-core";
import { getJSON, parseErrorBody, postJSONResult } from "./api-request";

import type {
  AVConfig,
  DHCPConfig,
  DHCPLease,
  DNSConfig,
  ForwardProxyConfig,
  NTPConfig,
  OpenVPNProfileUploadResponse,
  ReverseProxyConfig,
  SyslogConfig,
  SystemInspection,
  SystemStats,
  ServicesStatus,
  VPNConfig,
  WireGuardStatus,
} from "./api";

export const servicesAPI = {
  getServicesStatus: (signal?: AbortSignal) =>
    getJSON<ServicesStatus>("/api/v1/services/status", signal),
  getSystemStats: (signal?: AbortSignal) =>
    getJSON<SystemStats>("/api/v1/system/stats", signal),
  getSystemInspection: (signal?: AbortSignal) =>
    getJSON<SystemInspection>("/api/v1/system/inspection", signal),
  getSyslog: () => getJSON<SyslogConfig>("/api/v1/services/syslog"),
  setSyslog: (cfg: SyslogConfig) =>
    postJSONResult<SyslogConfig>("/api/v1/services/syslog", cfg),
  getAV: () => getJSON<AVConfig>("/api/v1/services/av"),
  setAV: (cfg: AVConfig) =>
    postJSONResult<AVConfig>("/api/v1/services/av", cfg),
  runAVUpdate: () =>
    postJSONResult<{ status: string }>("/api/v1/services/av/update", {}),
  listAVDefs: () =>
    getJSON<{ files: string[]; path?: string }>("/api/v1/services/av/defs"),
  uploadAVDef: async (
    file: File,
  ): Promise<{ ok: true; data: { status: string; file: string } } | { ok: false; error: string }> => {
    const form = new FormData();
    form.append("file", file);
    try {
      const res = await fetchWithSession("/api/v1/services/av/defs", {
        method: "POST",
        body: form,
        headers: authHeaders(),
      });
      if (handleUnauthorized(res)) return { ok: false, error: "Unauthorized" };
      clearAuthExpired();
      if (!res.ok) return { ok: false, error: await parseErrorBody(res) };
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
      if (handleUnauthorized(res)) return { ok: false, error: "Unauthorized" };
      clearAuthExpired();
      if (!res.ok) return { ok: false, error: await parseErrorBody(res) };
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
  getDNS: () => getJSON<DNSConfig>("/api/v1/services/dns"),
  setDNS: (cfg: DNSConfig) =>
    postJSONResult<DNSConfig>("/api/v1/services/dns", cfg),
  getForwardProxy: () =>
    getJSON<ForwardProxyConfig>("/api/v1/services/proxy/forward"),
  setForwardProxy: (cfg: ForwardProxyConfig) =>
    postJSONResult<ForwardProxyConfig>("/api/v1/services/proxy/forward", cfg),
  getReverseProxy: () =>
    getJSON<ReverseProxyConfig>("/api/v1/services/proxy/reverse"),
  setReverseProxy: (cfg: ReverseProxyConfig) =>
    postJSONResult<ReverseProxyConfig>("/api/v1/services/proxy/reverse", cfg),
  getNTP: () => getJSON<NTPConfig>("/api/v1/services/ntp"),
  setNTP: (cfg: NTPConfig) =>
    postJSONResult<NTPConfig>("/api/v1/services/ntp", cfg),
  getDHCP: () => getJSON<DHCPConfig>("/api/v1/services/dhcp"),
  setDHCP: (cfg: DHCPConfig) =>
    postJSONResult<DHCPConfig>("/api/v1/services/dhcp", cfg),
  listDHCPLeases: () => getJSON<{ leases: DHCPLease[] }>("/api/v1/dhcp/leases"),
  getVPN: () => getJSON<VPNConfig>("/api/v1/services/vpn"),
  setVPN: (cfg: VPNConfig) =>
    postJSONResult<VPNConfig>("/api/v1/services/vpn", cfg),
  uploadOpenVPNProfile: (name: string, ovpn: string) =>
    postJSONResult<OpenVPNProfileUploadResponse>(
      "/api/v1/services/vpn/openvpn/profile",
      { name, ovpn },
    ),
  listOpenVPNClients: () =>
    getJSON<{ clients: string[] }>("/api/v1/services/vpn/openvpn/clients"),
  createOpenVPNClient: (name: string) =>
    postJSONResult<{ name: string }>("/api/v1/services/vpn/openvpn/clients", {
      name,
    }),
  downloadOpenVPNClientURL: (name: string) =>
    `/api/v1/services/vpn/openvpn/clients/${encodeURIComponent(name)}`,
  getWireGuardStatus: (iface?: string) =>
    getJSON<WireGuardStatus>(
      `/api/v1/services/vpn/wireguard/status${iface ? `?iface=${encodeURIComponent(iface)}` : ""}`,
    ),
};
