export type HealthResponse = {
  status: string;
  component: string;
  build?: string;
  time?: string;
};

// In the browser we always use same-origin relative URLs so cookies/localStorage
// are scoped consistently (localhost vs 127.0.0.1 vs 0.0.0.0 can otherwise break auth).
const API_BASE = typeof window === "undefined" ? (process.env.NEXT_PUBLIC_API_BASE || "") : "";
const ENV_TOKEN = process.env.NEXT_PUBLIC_API_TOKEN || "";
// Deprecated: we no longer rely on localStorage JWTs for browser auth (cookie-only),
// but we still clear this key for users upgrading from older builds.
const TOKEN_KEY = "containd.auth.token";
const ROLE_KEY = "containd.auth.role";
const SESSION_TOKEN_KEY = "containd.session.token";
const AUTH_ERROR_KEY = "containd.auth.last_error";
let redirectingToLogin = false;
let authExpiredEmitted = false;

function getSessionToken(): string | null {
  if (typeof window === "undefined") return null;
  try {
    return sessionStorage.getItem(SESSION_TOKEN_KEY);
  } catch {
    return null;
  }
}

function setSessionToken(token: string | null) {
  if (typeof window === "undefined") return;
  try {
    if (!token) sessionStorage.removeItem(SESSION_TOKEN_KEY);
    else sessionStorage.setItem(SESSION_TOKEN_KEY, token);
  } catch {}
}

function setLastAuthError(msg: string | null) {
  if (typeof window === "undefined") return;
  try {
    if (!msg) sessionStorage.removeItem(AUTH_ERROR_KEY);
    else sessionStorage.setItem(AUTH_ERROR_KEY, msg);
  } catch {}
}

export function getLastAuthError(): string | null {
  if (typeof window === "undefined") return null;
  try {
    return sessionStorage.getItem(AUTH_ERROR_KEY);
  } catch {
    return null;
  }
}

function setStoredRole(role: string | null) {
  if (typeof window === "undefined") return;
  try {
    if (!role) localStorage.removeItem(ROLE_KEY);
    else localStorage.setItem(ROLE_KEY, role);
  } catch {}
}

export function clearLocalAuth() {
  if (typeof window !== "undefined") {
    try {
      localStorage.removeItem(TOKEN_KEY);
    } catch {}
  }
  setSessionToken(null);
  setStoredRole(null);
  authExpiredEmitted = false;
}

export function getStoredRole(): UserRole | null {
  if (typeof window === "undefined") return null;
  try {
    const r = localStorage.getItem(ROLE_KEY);
    if (r === "admin" || r === "view") return r;
    return null;
  } catch {
    return null;
  }
}

export function isAdmin(): boolean {
  return getStoredRole() === "admin";
}

function authHeaders(): Record<string, string> {
  // Browser sessions are cookie-only. Only attach a bearer token when explicitly configured
  // (e.g. local dev tooling or external API clients).
  if (!ENV_TOKEN) return {};
  return { Authorization: `Bearer ${ENV_TOKEN}` };
}

function updateSessionTokenFromResponse(res: Response) {
  // When sliding expiration extends a session, the server may return a refreshed JWT.
  // Persist it in sessionStorage (tab-scoped) as a fallback for environments where cookies
  // are blocked or unreliable.
  if (typeof window === "undefined") return;
  const next = res.headers.get("x-auth-token");
  if (next) setSessionToken(next);
}

async function captureAuthError(res: Response) {
  if (typeof window === "undefined") return;
  if (res.status !== 401 && res.status !== 403) return;
  try {
    const ct = (res.headers.get("content-type") || "").toLowerCase();
    if (!ct.includes("application/json")) return;
    const j = await res.clone().json();
    const msg =
      typeof j?.error === "string"
        ? j.error
        : typeof j?.message === "string"
          ? j.message
          : null;
    if (msg) setLastAuthError(msg);
  } catch {
    // ignore
  }
}

async function fetchWithSession(path: string, init: RequestInit): Promise<Response> {
  const url = `${API_BASE}${path}`;

  // Attempt cookie-first (no Authorization) unless an explicit env token is configured.
  // If the cookie is blocked, retry once with a tab-scoped bearer token from sessionStorage.
  const res = await fetch(url, {
    ...init,
    credentials: "include",
  });

  if (res.status === 401 && !ENV_TOKEN) {
    const fallback = getSessionToken();
    if (fallback) {
      const h = (init.headers ?? {}) as Record<string, string>;
      const hasAuth = Object.keys(h).some((k) => k.toLowerCase() === "authorization");
      if (!hasAuth) {
        const retry = await fetch(url, {
          ...init,
          headers: { ...h, Authorization: `Bearer ${fallback}` },
          credentials: "include",
        });
        await captureAuthError(retry);
        updateSessionTokenFromResponse(retry);
        return retry;
      }
    }
  }

  await captureAuthError(res);
  updateSessionTokenFromResponse(res);
  return res;
}

function handleUnauthorized(res: Response) {
  if (res.status !== 401) return false;
  // 401 means the session is not valid anymore; clear local state and force re-auth.
  if (typeof window !== "undefined") {
    try {
      localStorage.removeItem(TOKEN_KEY);
    } catch {}
  }
  setSessionToken(null);
  setStoredRole(null);
  if (typeof window !== "undefined") {
    // Centralize redirects in the Shell to avoid multiple simultaneous navigation events
    // (which causes visible flicker when many parallel API calls 401).
    if (!authExpiredEmitted) {
      authExpiredEmitted = true;
      window.dispatchEvent(new CustomEvent("containd:auth:expired"));
    }
  }
  return true;
}

export type DataPlaneConfig = {
  captureInterfaces?: string[];
  enforcement?: boolean;
  enforceTable?: string;
  dpiMock?: boolean;
};

export type Zone = {
  name: string;
  description?: string;
};

export type Interface = {
  name: string;
  device?: string;
  zone?: string;
  addressMode?: string;
  addresses?: string[];
  gateway?: string;
  access?: {
    mgmt?: boolean;
    http?: boolean;
    https?: boolean;
    ssh?: boolean;
  };
};

export type InterfaceState = {
  name: string;
  index: number;
  up: boolean;
  mtu: number;
  mac: string;
  addrs: string[];
};

export type StaticRoute = {
  dst: string;
  gateway?: string;
  iface?: string;
  table?: number;
  metric?: number;
};

export type PolicyRule = {
  priority?: number;
  src?: string;
  dst?: string;
  table: number;
};

export type RoutingConfig = {
  routes?: StaticRoute[];
  rules?: PolicyRule[];
};

export type Protocol = {
  name: string;
  port?: string;
};

export type ICSPredicate = {
  protocol?: string;
  functionCode?: number[];
  unitId?: number;
  addresses?: string[];
  readOnly?: boolean;
  writeOnly?: boolean;
};

export type FirewallRule = {
  id: string;
  description?: string;
  sourceZones?: string[];
  destZones?: string[];
  sources?: string[];
  destinations?: string[];
  protocols?: Protocol[];
  ics?: ICSPredicate;
  action: "ALLOW" | "DENY";
};

export type Asset = {
  id: string;
  name: string;
  type?: string;
  zone?: string;
  ips?: string[];
  hostnames?: string[];
  criticality?: string;
  tags?: string[];
  description?: string;
};

export type AuditRecord = {
  id: number;
  timestamp: string;
  actor: string;
  source: string;
  action: string;
  target: string;
  result: string;
  detail?: string;
};

export type SyslogForwarder = {
  address: string;
  port: number;
  proto?: "udp" | "tcp";
};

export type SyslogConfig = {
  forwarders: SyslogForwarder[];
};

export type UserRole = "admin" | "view";

export type User = {
  id: string;
  username: string;
  firstName?: string;
  lastName?: string;
  email?: string;
  role: UserRole;
  createdAt?: string;
  updatedAt?: string;
};

export type LoginResponse = {
  token: string;
  expiresAt: string;
  user: User;
};

export type TLSInfo = {
  httpListenAddr?: string;
  httpsListenAddr?: string;
  httpEnabled: boolean;
  httpsEnabled: boolean;
  certFile?: string;
  keyFile?: string;
  certSubject?: string;
  certIssuer?: string;
  certNotAfter?: string;
  certDnsNames?: string[];
  certIps?: string[];
};

export type UpdateMeRequest = {
  firstName?: string;
  lastName?: string;
  email?: string;
};

export type ChangePasswordRequest = {
  currentPassword: string;
  newPassword: string;
};

export type DNSConfig = {
  enabled?: boolean;
  listenPort?: number;
  listenZones?: string[];
  upstreamServers?: string[];
  cacheSizeMB?: number;
};

export type NTPConfig = {
  enabled?: boolean;
  servers?: string[];
  intervalSeconds?: number;
};

export type TelemetryEvent = {
  id: number;
  flowId: string;
  proto: string;
  kind: string;
  attributes?: Record<string, unknown>;
  timestamp: string;
  srcIp?: string;
  dstIp?: string;
  srcPort?: number;
  dstPort?: number;
  transport?: string;
};

export type FlowSummary = {
  flowId: string;
  firstSeen: string;
  lastSeen: string;
  srcIp?: string;
  dstIp?: string;
  srcPort?: number;
  dstPort?: number;
  transport?: string;
  application?: string;
  eventCount: number;
};

export type ForwardProxyConfig = {
  enabled?: boolean;
  listenPort?: number;
  listenZones?: string[];
  allowedClients?: string[];
  allowedDomains?: string[];
  upstream?: string;
  logRequests?: boolean;
};

export type ReverseProxySite = {
  name: string;
  listenPort: number;
  hostnames?: string[];
  backends?: string[];
  tlsEnabled?: boolean;
  certRef?: string;
  description?: string;
};

export type ReverseProxyConfig = {
  enabled?: boolean;
  sites?: ReverseProxySite[];
};

export type ServicesStatus = Record<string, unknown>;

export type IDSCondition = {
  all?: IDSCondition[];
  any?: IDSCondition[];
  not?: IDSCondition;
  field?: string;
  op?: string;
  value?: unknown;
};

export type IDSRule = {
  id: string;
  title?: string;
  description?: string;
  proto?: string;
  kind?: string;
  when?: IDSCondition;
  severity?: string;
  message?: string;
  labels?: Record<string, string>;
};

export type IDSConfig = {
  enabled?: boolean;
  rules?: IDSRule[];
};

export type CLIExecuteResponse = {
  output: string;
  error?: string;
};

export type ConfigBundle = {
  schema_version?: string;
  version?: string;
  description?: string;
  system?: { hostname?: string };
  zones?: Zone[];
  interfaces?: Interface[];
  assets?: Asset[];
  dataplane?: DataPlaneConfig;
  firewall?: {
    defaultAction?: "ALLOW" | "DENY";
    rules?: FirewallRule[];
  };
  services?: unknown;
};

export async function fetchHealth(): Promise<HealthResponse | null> {
  try {
    const res = await fetchWithSession("/api/v1/health", {
      cache: "no-store",
    });
    if (!res.ok) return null;
    return (await res.json()) as HealthResponse;
  } catch {
    return null;
  }
}

export async function fetchDataPlane(): Promise<DataPlaneConfig | null> {
  try {
    const res = await fetchWithSession("/api/v1/dataplane", {
      headers: { ...authHeaders() },
      cache: "no-store",
    });
    if (handleUnauthorized(res) || !res.ok) return null;
    return (await res.json()) as DataPlaneConfig;
  } catch {
    return null;
  }
}

export async function setDataPlane(
  cfg: DataPlaneConfig,
): Promise<DataPlaneConfig | null> {
  try {
    const res = await fetchWithSession("/api/v1/dataplane", {
      method: "POST",
      headers: { "Content-Type": "application/json", ...authHeaders() },
      body: JSON.stringify(cfg),
    });
    if (handleUnauthorized(res) || !res.ok) return null;
    return (await res.json()) as DataPlaneConfig;
  } catch {
    return null;
  }
}

async function getJSON<T>(path: string): Promise<T | null> {
  try {
    const res = await fetchWithSession(path, {
      cache: "no-store",
      headers: authHeaders(),
    });
    if (handleUnauthorized(res) || !res.ok) return null;
    return (await res.json()) as T;
  } catch {
    return null;
  }
}

async function getJSONWithStatus<T>(path: string): Promise<{ status: number; data: T | null }> {
  try {
    const res = await fetchWithSession(path, {
      cache: "no-store",
      headers: authHeaders(),
    });
    if (handleUnauthorized(res)) return { status: 401, data: null };
    if (!res.ok) return { status: res.status, data: null };
    return { status: res.status, data: (await res.json()) as T };
  } catch {
    return { status: 0, data: null };
  }
}

async function postJSON<T>(path: string, payload: unknown): Promise<T | null> {
  try {
    const res = await fetchWithSession(path, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...authHeaders() },
      body: JSON.stringify(payload),
    });
    if (handleUnauthorized(res) || !res.ok) return null;
    return (await res.json()) as T;
  } catch {
    return null;
  }
}

async function patchJSON<T>(path: string, payload: unknown): Promise<T | null> {
  try {
    const res = await fetchWithSession(path, {
      method: "PATCH",
      headers: { "Content-Type": "application/json", ...authHeaders() },
      body: JSON.stringify(payload),
    });
    if (handleUnauthorized(res) || !res.ok) return null;
    return (await res.json()) as T;
  } catch {
    return null;
  }
}

async function deleteJSON(path: string): Promise<boolean> {
  try {
    const res = await fetchWithSession(path, {
      method: "DELETE",
      headers: authHeaders(),
    });
    if (handleUnauthorized(res)) return false;
    return res.ok;
  } catch {
    return false;
  }
}

export const api = {
  // Auth
  login: async (username: string, password: string) => {
    const res = await postJSON<LoginResponse>("/api/v1/auth/login", {
      username,
      password,
    });
    // Store token tab-scoped as a fallback if cookies are blocked; cookie remains primary.
    if (res?.token) setSessionToken(res.token);
    if (res?.user?.role) setStoredRole(res.user.role);
    if (res) {
      // Allow future session-expired notifications after a successful login.
      authExpiredEmitted = false;
      setLastAuthError(null);
    }
    return res;
  },
  logout: async () => {
    const ok = await postJSON<{ status: string }>("/api/v1/auth/logout", {});
    clearLocalAuth();
    // If we logged out, allow future session-expired notifications too.
    return ok;
  },
  me: async () => {
    const u = await getJSON<User>("/api/v1/auth/me");
    if (u?.role) setStoredRole(u.role);
    if (u) {
      authExpiredEmitted = false;
      setLastAuthError(null);
    }
    return u;
  },
  meStatus: async () => {
    const res = await getJSONWithStatus<User>("/api/v1/auth/me");
    if (res.data?.role) setStoredRole(res.data.role);
    if (res.status === 200) {
      authExpiredEmitted = false;
      setLastAuthError(null);
    }
    return res;
  },
  updateMe: (patch: UpdateMeRequest) =>
    patchJSON<User>("/api/v1/auth/me", patch),
  changeMyPassword: (currentPassword: string, newPassword: string) =>
    postJSON<{ status: string }>("/api/v1/auth/me/password", {
      currentPassword,
      newPassword,
    } as ChangePasswordRequest),

  // Users
  listUsers: () => getJSON<User[]>("/api/v1/users"),
  createUser: (u: Omit<User, "id"> & { password: string }) =>
    postJSON<User>("/api/v1/users", u),
  updateUser: (id: string, patch: Partial<User>) =>
    patchJSON<User>(`/api/v1/users/${encodeURIComponent(id)}`, patch),
  setUserPassword: (id: string, password: string) =>
    postJSON<{ status: string }>(
      `/api/v1/users/${encodeURIComponent(id)}/password`,
      { password },
    ),

  listZones: () => getJSON<Zone[]>("/api/v1/zones"),
  createZone: (z: Zone) => postJSON<Zone>("/api/v1/zones", z),
  updateZone: (name: string, z: Partial<Zone>) =>
    patchJSON<Zone>(`/api/v1/zones/${encodeURIComponent(name)}`, z),
  deleteZone: (name: string) =>
    deleteJSON(`/api/v1/zones/${encodeURIComponent(name)}`),

  listInterfaces: () => getJSON<Interface[]>("/api/v1/interfaces"),
  listInterfaceState: () => getJSON<InterfaceState[]>("/api/v1/interfaces/state"),
  assignInterfaces: (mode: "auto" | "explicit", mappings?: Record<string, string>) =>
    postJSON<{ interfaces: Interface[] }>("/api/v1/interfaces/assign", {
      mode,
      mappings: mappings ?? {},
    }),
  reconcileInterfacesReplace: () =>
    postJSON<{ status: string }>("/api/v1/interfaces/reconcile", { confirm: "REPLACE" }),
  createInterface: (i: Interface) =>
    postJSON<Interface>("/api/v1/interfaces", i),
  updateInterface: (name: string, i: Partial<Interface>) =>
    patchJSON<Interface>(`/api/v1/interfaces/${encodeURIComponent(name)}`, i),
  deleteInterface: (name: string) =>
    deleteJSON(`/api/v1/interfaces/${encodeURIComponent(name)}`),

  getRouting: () => getJSON<RoutingConfig>("/api/v1/routing"),
  setRouting: (cfg: RoutingConfig) => postJSON<RoutingConfig>("/api/v1/routing", cfg),

  listFirewallRules: () => getJSON<FirewallRule[]>("/api/v1/firewall/rules"),
  createFirewallRule: (r: FirewallRule) =>
    postJSON<FirewallRule>("/api/v1/firewall/rules", r),
  updateFirewallRule: (id: string, r: Partial<FirewallRule>) =>
    patchJSON<FirewallRule>(`/api/v1/firewall/rules/${encodeURIComponent(id)}`, r),
  deleteFirewallRule: (id: string) =>
    deleteJSON(`/api/v1/firewall/rules/${encodeURIComponent(id)}`),

  listAssets: () => getJSON<Asset[]>("/api/v1/assets"),
  createAsset: (a: Asset) => postJSON<Asset>("/api/v1/assets", a),
  updateAsset: (id: string, a: Partial<Asset>) =>
    patchJSON<Asset>(`/api/v1/assets/${encodeURIComponent(id)}`, a),
  deleteAsset: (id: string) =>
    deleteJSON(`/api/v1/assets/${encodeURIComponent(id)}`),

  // IDS / Sigma
  getIDS: () => getJSON<IDSConfig>("/api/v1/ids/rules"),
  setIDS: (cfg: IDSConfig) => postJSON<IDSConfig>("/api/v1/ids/rules", cfg),
  convertSigma: (sigmaYAML: string) =>
    postJSON<IDSRule>("/api/v1/ids/convert/sigma", { sigmaYAML }),

  executeCLI: (line: string) =>
    postJSON<CLIExecuteResponse>("/api/v1/cli/execute", { line }),

  // Config lifecycle
  getRunningConfig: () => getJSON<ConfigBundle>("/api/v1/config"),
  getCandidateConfig: () => getJSON<ConfigBundle>("/api/v1/config/candidate"),
  setCandidateConfig: (cfg: ConfigBundle) =>
    postJSON<{ status: string }>("/api/v1/config/candidate", cfg),
  diffConfig: () =>
    getJSON<{ running: ConfigBundle | null; candidate: ConfigBundle | null }>(
      "/api/v1/config/diff",
    ),
  commit: () => postJSON<{ status: string }>("/api/v1/config/commit", {}),
  commitConfirmed: (ttlSeconds?: number) =>
    postJSON<{ status: string }>(
      "/api/v1/config/commit_confirmed",
      ttlSeconds ? { ttl_seconds: ttlSeconds } : {},
    ),
  confirmCommit: () =>
    postJSON<{ status: string }>("/api/v1/config/confirm", {}),
  rollback: () => postJSON<{ status: string }>("/api/v1/config/rollback", {}),

  // Audit
  listAudit: () => getJSON<AuditRecord[]>("/api/v1/audit"),

  // System TLS
  getTLSInfo: () => getJSON<TLSInfo>("/api/v1/system/tls"),
  setTLSCert: (certPEM: string, keyPEM: string) =>
    postJSON<{ status: string }>("/api/v1/system/tls/cert", { certPEM, keyPEM }),
  setTrustedCA: (pem: string) =>
    postJSON<{ status: string }>("/api/v1/system/tls/trusted-ca", { pem }),

  // Proxies
  getForwardProxy: () =>
    getJSON<ForwardProxyConfig>("/api/v1/services/proxy/forward"),
  setForwardProxy: (cfg: ForwardProxyConfig) =>
    postJSON<ForwardProxyConfig>("/api/v1/services/proxy/forward", cfg),
  getReverseProxy: () =>
    getJSON<ReverseProxyConfig>("/api/v1/services/proxy/reverse"),
  setReverseProxy: (cfg: ReverseProxyConfig) =>
    postJSON<ReverseProxyConfig>("/api/v1/services/proxy/reverse", cfg),
  getServicesStatus: () =>
    getJSON<ServicesStatus>("/api/v1/services/status"),
  getSyslog: () => getJSON<SyslogConfig>("/api/v1/services/syslog"),
  setSyslog: (cfg: SyslogConfig) =>
    postJSON<SyslogConfig>("/api/v1/services/syslog", cfg),
  getDNS: () => getJSON<DNSConfig>("/api/v1/services/dns"),
  setDNS: (cfg: DNSConfig) => postJSON<DNSConfig>("/api/v1/services/dns", cfg),
  getNTP: () => getJSON<NTPConfig>("/api/v1/services/ntp"),
  setNTP: (cfg: NTPConfig) => postJSON<NTPConfig>("/api/v1/services/ntp", cfg),

  // Telemetry
  listEvents: (limit = 500) =>
    getJSON<TelemetryEvent[]>(`/api/v1/events?limit=${limit}`),
  listFlows: (limit = 200) =>
    getJSON<FlowSummary[]>(`/api/v1/flows?limit=${limit}`),
};
