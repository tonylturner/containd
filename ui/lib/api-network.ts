import {
  deleteJSONResult,
  getJSON,
  patchJSONResult,
  postJSONResult,
} from "./api-request";

import type {
  ConduitMap,
  FirewallRule,
  Interface,
  InterfaceState,
  NATConfig,
  OSRoutingSnapshot,
  RoutingConfig,
  Zone,
} from "./api";

export const networkAPI = {
  listZones: (signal?: AbortSignal) => getJSON<Zone[]>("/api/v1/zones", signal),
  createZone: (z: Zone) => postJSONResult<Zone>("/api/v1/zones", z),
  updateZone: (name: string, z: Partial<Zone>) =>
    patchJSONResult<Zone>(`/api/v1/zones/${encodeURIComponent(name)}`, z),
  deleteZone: (name: string) =>
    deleteJSONResult(`/api/v1/zones/${encodeURIComponent(name)}`),
  getSecurityConduits: (signal?: AbortSignal) =>
    getJSON<ConduitMap>("/api/v1/security/conduits", signal),

  listInterfaces: (signal?: AbortSignal) =>
    getJSON<Interface[]>("/api/v1/interfaces", signal),
  listInterfaceState: (signal?: AbortSignal) =>
    getJSON<InterfaceState[]>("/api/v1/interfaces/state", signal),
  assignInterfaces: (
    mode: "auto" | "explicit",
    mappings?: Record<string, string>,
  ) =>
    postJSONResult<{ interfaces: Interface[] }>("/api/v1/interfaces/assign", {
      mode,
      mappings: mappings ?? {},
    }),
  reconcileInterfacesReplace: () =>
    postJSONResult<{ status: string }>("/api/v1/interfaces/reconcile", {
      confirm: "REPLACE",
    }),
  createInterface: (i: Interface) =>
    postJSONResult<Interface>("/api/v1/interfaces", i),
  updateInterface: (name: string, i: Partial<Interface>) =>
    patchJSONResult<Interface>(
      `/api/v1/interfaces/${encodeURIComponent(name)}`,
      i,
    ),
  deleteInterface: (name: string) =>
    deleteJSONResult(`/api/v1/interfaces/${encodeURIComponent(name)}`),

  getRouting: (signal?: AbortSignal) =>
    getJSON<RoutingConfig>("/api/v1/routing", signal),
  getOSRouting: (signal?: AbortSignal) =>
    getJSON<OSRoutingSnapshot>("/api/v1/routing/os", signal),
  setRouting: (cfg: RoutingConfig) =>
    postJSONResult<RoutingConfig>("/api/v1/routing", cfg),
  reconcileRoutingReplace: () =>
    postJSONResult<{ status: string }>("/api/v1/routing/reconcile", {
      confirm: "REPLACE",
    }),

  listFirewallRules: (signal?: AbortSignal) =>
    getJSON<FirewallRule[]>("/api/v1/firewall/rules", signal),
  createFirewallRule: (r: FirewallRule) =>
    postJSONResult<FirewallRule>("/api/v1/firewall/rules", r),
  updateFirewallRule: (id: string, r: Partial<FirewallRule>) =>
    patchJSONResult<FirewallRule>(
      `/api/v1/firewall/rules/${encodeURIComponent(id)}`,
      r,
    ),
  deleteFirewallRule: (id: string) =>
    deleteJSONResult(`/api/v1/firewall/rules/${encodeURIComponent(id)}`),
  getNAT: () => getJSON<NATConfig>("/api/v1/firewall/nat"),
  setNAT: (cfg: NATConfig) =>
    postJSONResult<NATConfig>("/api/v1/firewall/nat", cfg),
};
