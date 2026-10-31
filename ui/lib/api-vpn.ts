import { apiURL, authHeaders, clearAuthExpired, fetchWithSession, handleUnauthorized } from "./api-core";
import { failureOf, getJSON, getJSONShaped, postJSONResult } from "./api-request";

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

export type OpenVPNCredential = {
  id: string;
  issuer: string;
  serial: string;
  name: string;
  issuedAt: string;
  expiresAt: string;
  revokedAt?: string;
};

export type OpenVPNRevokeResult = {
  credential: OpenVPNCredential;
  revoked: boolean;
  applied: boolean;
  error?: string;
};

type RevokeResponse =
  | { ok: true; data: OpenVPNRevokeResult }
  | { ok: false; error: string; revocation?: OpenVPNRevokeResult };

async function revokeOpenVPNClient(id: string): Promise<RevokeResponse> {
  try {
    const res = await fetchWithSession(
      `/api/v1/services/vpn/openvpn/clients/${encodeURIComponent(id)}/revoke`,
      { method: "POST", headers: authHeaders() },
    );
    if (handleUnauthorized(res)) return failureOf(res);
    clearAuthExpired();
    if (res.ok) return { ok: true, data: await res.json() };
    // A 503 can report a durable revocation, not a failed mutation. Preserve
    // its credential and runtime acknowledgement instead of discarding them.
    if (res.status === 503) {
      const body = await res.clone().json().catch(() => null);
      if (body?.revoked === true && body?.applied === false && body?.credential?.id === id) {
        return { ok: false, error: body.error, revocation: body };
      }
    }
    return failureOf(res);
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : "Network error" };
  }
}

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
    getJSONShaped<{ clients: OpenVPNCredential[] }>("/api/v1/services/vpn/openvpn/clients", { lists: ["clients"] }),
  createOpenVPNClient: (name: string) =>
    postJSONResult<OpenVPNCredential>("/api/v1/services/vpn/openvpn/clients", {
      name,
    }),
  downloadOpenVPNClientURL: (id: string) =>
    apiURL(`/api/v1/services/vpn/openvpn/clients/${encodeURIComponent(id)}`),
  revokeOpenVPNClient,
  getWireGuardStatus: (iface?: string) =>
    getJSON<WireGuardStatus>(
      `/api/v1/services/vpn/wireguard/status${iface ? `?iface=${encodeURIComponent(iface)}` : ""}`,
    ),
};
