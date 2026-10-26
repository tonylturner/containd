import { apiURL } from "./api-core";
import { getJSON, getJSONShaped, postJSONResult } from "./api-request";

// VPN: WireGuard and OpenVPN configuration, OpenVPN client profiles and
// WireGuard runtime status.

export type WGPeer = {
  name?: string;
  publicKey: string;
  allowedIPs?: string[];
  endpoint?: string;
  persistentKeepalive?: number;
};

export type WireGuardConfig = {
  enabled?: boolean;
  interface?: string;
  listenPort?: number;
  listenZone?: string;
  listenInterfaces?: string[];
  addressCIDR?: string;
  privateKey?: string;
  peers?: WGPeer[];
};

export type OpenVPNConfig = {
  enabled?: boolean;
  mode?: string;
  configPath?: string;
  managed?: OpenVPNManagedClientConfig;
  server?: OpenVPNManagedServerConfig;
};

export type OpenVPNManagedClientConfig = {
  remote?: string;
  port?: number;
  proto?: string;
  username?: string;
  password?: string;
  ca?: string;
  cert?: string;
  key?: string;
};

export type OpenVPNManagedServerConfig = {
  listenPort?: number;
  proto?: string;
  listenZone?: string;
  listenInterfaces?: string[];
  tunnelCIDR?: string;
  publicEndpoint?: string;
  pushDNS?: string[];
  pushRoutes?: string[];
  clientToClient?: boolean;
};

export type VPNConfig = {
  wireguard?: WireGuardConfig;
  openvpn?: OpenVPNConfig;
};

export type OpenVPNProfileUploadResponse = {
  configPath: string;
  vpn: VPNConfig;
};

export type WireGuardPeerStatus = {
  publicKey: string;
  endpoint?: string;
  lastHandshake?: string;
  rxBytes?: number;
  txBytes?: number;
  allowedIPs?: string[];
};

export type WireGuardStatus = {
  interface: string;
  present: boolean;
  publicKey?: string;
  listenPort?: number;
  peers?: WireGuardPeerStatus[];
};

export const vpnAPI = {
  getVPN: () => getJSON<VPNConfig>("/api/v1/services/vpn"),
  setVPN: (cfg: VPNConfig) =>
    postJSONResult<VPNConfig>("/api/v1/services/vpn", cfg),
  uploadOpenVPNProfile: (name: string, ovpn: string) =>
    postJSONResult<OpenVPNProfileUploadResponse>(
      "/api/v1/services/vpn/openvpn/profile",
      { name, ovpn },
    ),
  listOpenVPNClients: () =>
    getJSONShaped<{ clients: string[] }>("/api/v1/services/vpn/openvpn/clients", { lists: ["clients"] }),
  createOpenVPNClient: (name: string) =>
    postJSONResult<{ name: string }>("/api/v1/services/vpn/openvpn/clients", {
      name,
    }),
  downloadOpenVPNClientURL: (name: string) =>
    apiURL(`/api/v1/services/vpn/openvpn/clients/${encodeURIComponent(name)}`),
  getWireGuardStatus: (iface?: string) =>
    getJSON<WireGuardStatus>(
      `/api/v1/services/vpn/wireguard/status${iface ? `?iface=${encodeURIComponent(iface)}` : ""}`,
    ),
};
