import {
  getConfigJSON,
  deleteJSONResult,
  getJSON,
  getJSONList,
  patchJSONResult,
  postJSONResult,
} from "./api-request";

import type {
  ConduitMap,
  Interface,
  InterfaceState,
  NATConfig,
  OSRoutingSnapshot,
  RoutingConfig,
  Zone,
} from "./api";

export const networkAPI = {
  listZones: (signal?: AbortSignal) => getConfigJSON<Zone[]>("/api/v1/zones", "list", signal),
  createZone: (expectedRevision: string, z: Zone) => postJSONResult<Zone>("/api/v1/zones", z, expectedRevision),
  updateZone: (expectedRevision: string, name: string, z: Partial<Zone>) =>
    patchJSONResult<Zone>(`/api/v1/zones/${encodeURIComponent(name)}`, z, expectedRevision),
  deleteZone: (expectedRevision: string, name: string) =>
    deleteJSONResult(`/api/v1/zones/${encodeURIComponent(name)}`, expectedRevision),
  getSecurityConduits: (signal?: AbortSignal) =>
    getJSON<ConduitMap>("/api/v1/security/conduits", signal),

  listInterfaces: (signal?: AbortSignal) =>
    getConfigJSON<Interface[]>("/api/v1/interfaces", "list", signal),
  listInterfaceState: (signal?: AbortSignal) =>
    getJSONList<InterfaceState>("/api/v1/interfaces/state", signal),
  assignInterfaces: (
    expectedRevision: string,
    mode: "auto" | "explicit",
    mappings?: Record<string, string>,
  ) =>
    postJSONResult<{ interfaces: Interface[] }>("/api/v1/interfaces/assign", {
      mode,
      mappings: mappings ?? {},
    }, expectedRevision),
  reconcileInterfacesReplace: (expectedRevision: string) =>
    postJSONResult<{ status: string }>("/api/v1/interfaces/reconcile", {
      confirm: "REPLACE",
    }, expectedRevision),
  createInterface: (expectedRevision: string, i: Interface) =>
    postJSONResult<Interface>("/api/v1/interfaces", i, expectedRevision),
  updateInterface: (expectedRevision: string, name: string, i: Partial<Interface>) =>
    patchJSONResult<Interface>(
      `/api/v1/interfaces/${encodeURIComponent(name)}`,
      i, expectedRevision,
    ),
  deleteInterface: (expectedRevision: string, name: string) =>
    deleteJSONResult(`/api/v1/interfaces/${encodeURIComponent(name)}`, expectedRevision),

  getRouting: (signal?: AbortSignal) =>
    getConfigJSON<RoutingConfig>("/api/v1/routing", "object", signal),
  getOSRouting: (signal?: AbortSignal) =>
    getJSON<OSRoutingSnapshot>("/api/v1/routing/os", signal),
  setRouting: (expectedRevision: string, cfg: RoutingConfig) =>
    postJSONResult<RoutingConfig>("/api/v1/routing", cfg, expectedRevision),
  reconcileRoutingReplace: (expectedRevision: string) =>
    postJSONResult<{ status: string }>("/api/v1/routing/reconcile", {
      confirm: "REPLACE",
    }, expectedRevision),

  getNAT: () => getConfigJSON<NATConfig>("/api/v1/firewall/nat", "object"),
  setNAT: (expectedRevision: string, cfg: NATConfig) =>
    postJSONResult<NATConfig>("/api/v1/firewall/nat", cfg, expectedRevision),
};
