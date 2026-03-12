export type HealthResponse = {
  status: string;
  component: string;
  build?: string;
  time?: string;
};

/** Discriminated result type for mutation API calls that surfaces backend error messages. */
export type ApiResult<T> = { ok: true; data: T; warning?: string } | { ok: false; error: string };

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

export function getSessionToken(): string | null {
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
  clearAuthExpired();
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
    // When the server returns 403 "password change required", notify the UI
    // so Shell can force-open the password modal even if detected mid-session.
    if (res.status === 403 && msg && /password change required/i.test(msg)) {
      window.dispatchEvent(new CustomEvent("containd:auth:password_change_required"));
    }
  } catch {
    // ignore
  }
}

async function fetchWithSession(path: string, init: RequestInit, signal?: AbortSignal): Promise<Response> {
  const url = `${API_BASE}${path}`;

  // Attempt cookie-first (no Authorization) unless an explicit env token is configured.
  // If the cookie is blocked, retry once with a tab-scoped bearer token from sessionStorage.
  const res = await fetch(url, {
    ...init,
    credentials: "include",
    // Avoid stale UI after writes: these endpoints are dynamic appliance state.
    cache: "no-store",
    signal,
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
          cache: "no-store",
          signal,
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

// Debounce 401 handling: only emit the expired event after a short delay so that
// transient 401s (e.g. during token refresh) don't immediately log out the user.
// The Shell listener re-verifies the session before actually redirecting.
let authExpiredTimer: ReturnType<typeof setTimeout> | null = null;

function handleUnauthorized(res: Response) {
  if (res.status !== 401) return false;
  if (typeof window !== "undefined") {
    // Debounce: wait 1.5s before emitting the expired event.  If another request
    // succeeds in the meantime (resetting authExpiredEmitted), the event won't fire.
    if (!authExpiredEmitted) {
      authExpiredEmitted = true;
      if (authExpiredTimer) clearTimeout(authExpiredTimer);
      authExpiredTimer = setTimeout(() => {
        // Only dispatch if still flagged (no successful request intervened).
        if (authExpiredEmitted) {
          window.dispatchEvent(new CustomEvent("containd:auth:expired"));
        }
      }, 1500);
    }
  }
  return true;
}

/** Call after any successful authenticated response to cancel pending logout. */
function clearAuthExpired() {
  authExpiredEmitted = false;
  if (authExpiredTimer) {
    clearTimeout(authExpiredTimer);
    authExpiredTimer = null;
  }
}

export type DPIExclusion = {
  value: string;
  type: "ip" | "cidr" | "domain";
  reason?: string;
};

export type DataPlaneConfig = {
  captureInterfaces?: string[];
  enforcement?: boolean;
  enforceTable?: string;
  dpiMock?: boolean;
  dpiEnabled?: boolean;
  dpiMode?: "learn" | "enforce";
  dpiProtocols?: Record<string, boolean>;
  dpiIcsProtocols?: Record<string, boolean>;
  dpiExclusions?: DPIExclusion[];
};

export type PcapForwardTarget = {
  interface?: string;
  enabled?: boolean;
  host?: string;
  port?: number;
  proto?: "tcp" | "udp";
};

export type PcapFilter = {
  src?: string;
  dst?: string;
  proto?: "any" | "tcp" | "udp" | "icmp";
};

export type PcapConfig = {
  enabled?: boolean;
  interfaces?: string[];
  snaplen?: number;
  maxSizeMB?: number;
  maxFiles?: number;
  mode?: "rolling" | "once";
  promisc?: boolean;
  bufferMB?: number;
  rotateSeconds?: number;
  filePrefix?: string;
  filter?: PcapFilter;
  forwardTargets?: PcapForwardTarget[];
};

export type PcapStatus = {
  running: boolean;
  interfaces?: string[];
  startedAt?: string;
  lastError?: string;
};

export type PcapItem = {
  name: string;
  interface: string;
  sizeBytes: number;
  createdAt: string;
  tags?: string[];
  status?: string;
};

export type PcapReplayRequest = {
  name: string;
  interface: string;
  ratePps?: number;
};

export type PcapTagRequest = {
  name: string;
  tags: string[];
};

export type Zone = {
  name: string;
  alias?: string;
  description?: string;
  slTarget?: number;
  consequence?: string;
  slOverrides?: Record<string, boolean>;
};

export type ConduitProto = {
  n: string;
  t: "allowed" | "denied" | "inspect";
};

export type Conduit = {
  state: "allow" | "block" | "partial" | "unmodeled";
  ids: "full" | "partial" | "none";
  proto: ConduitProto[];
  traffic: number;
  rules: string[];
  gaps: string[];
  mitre: string[];
  defaultDeny: boolean;
  tlsEnforced: boolean;
  protoWhitelist: boolean;
  mfaRequired: boolean;
  auditLogged: boolean;
  avEnabled: boolean;
};

export type ConduitMap = Record<string, Conduit>;

export type Interface = {
  name: string;
  alias?: string;
  device?: string;
  type?: string;
  parent?: string;
  vlanId?: number;
  members?: string[];
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

export type Gateway = {
  name: string;
  alias?: string;
  address: string;
  iface?: string;
  description?: string;
};

export type PolicyRule = {
  priority?: number;
  src?: string;
  dst?: string;
  table: number;
};

export type RoutingConfig = {
  gateways?: Gateway[];
  routes?: StaticRoute[];
  rules?: PolicyRule[];
};

export type OSRoute = {
  dst: string;
  gateway?: string;
  iface?: string;
  metric?: number;
};

export type OSRoutingSnapshot = {
  routes: OSRoute[];
  defaultRoute?: OSRoute;
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
  objectClasses?: number[];
  readOnly?: boolean;
  writeOnly?: boolean;
  direction?: "request" | "response";
  mode?: "enforce" | "learn";
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
  log?: boolean;
};

export type NATConfig = {
  enabled: boolean;
  egressZone?: string;
  sourceZones?: string[];
  portForwards?: PortForward[];
};

export type PortForward = {
  id: string;
  enabled: boolean;
  description?: string;
  ingressZone: string;
  proto: "tcp" | "udp";
  listenPort: number;
  destIp: string;
  destPort?: number;
  allowedSources?: string[];
};

export type Asset = {
  id: string;
  name: string;
  alias?: string;
  type?: string;
  zone?: string;
  ips?: string[];
  hostnames?: string[];
  criticality?: string;
  tags?: string[];
  description?: string;
};

export type DashboardData = {
  health: HealthResponse & { commit?: string; hostname?: string };
  counts: { assets: number; zones: number; interfaces: number; rules: number; icsRules: number };
  eventStats: { total: number; idsAlerts: number; modbusWrites: number; avDetections: number; avBlocks: number };
  services: Record<string, unknown> | null;
  user: User | null;
  lastActivity: AuditRecord | null;
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
  format?: "rfc5424" | "json";
  batchSize?: number;
  flushEvery?: number; // seconds
};

export type ClamAVConfig = {
  socketPath?: string;
  updateSchedule?: string;
  customDefsPath?: string;
  freshclamEnabled?: boolean;
};

export type AVConfig = {
  enabled: boolean;
  mode?: "icap" | "clamav";
  failPolicy?: "open" | "closed";
  failOpenIcs?: boolean;
  blockTtlSeconds?: number;
  maxSizeBytes?: number;
  timeoutSec?: number;
  cacheTtl?: string;
  icap?: {
    servers?: { address: string; useTls?: boolean; service?: string }[];
  };
  clamav?: ClamAVConfig;
};

export type UserRole = "admin" | "view";

export type User = {
  id: string;
  username: string;
  firstName?: string;
  lastName?: string;
  email?: string;
  role: UserRole;
  mustChangePassword?: boolean;
  labMode?: boolean;
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

export type DHCPPool = {
  iface: string;
  start: string;
  end: string;
};

export type DHCPReservation = {
  iface: string;
  mac: string;
  ip: string;
};

export type DHCPConfig = {
  enabled?: boolean;
  listenIfaces?: string[];
  pools?: DHCPPool[];
  reservations?: DHCPReservation[];
  leaseSeconds?: number;
  router?: string;
  dnsServers?: string[];
  domain?: string;
  authoritative?: boolean;
};

export type DHCPLease = {
  iface: string;
  mac: string;
  ip: string;
  expiresAt: string;
  hostname?: string;
};

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

export type ConntrackEntry = {
  proto: string;
  state?: string;
  src?: string;
  dst?: string;
  sport?: string;
  dport?: string;
  replySrc?: string;
  replyDst?: string;
  replySport?: string;
  replyDport?: string;
  mark?: string;
  assured?: boolean;
  timeoutSecs?: number;
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
  avDetected?: boolean;
  avBlocked?: boolean;
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

export type SystemStats = {
  cpu: { usagePercent: number; numCPU: number };
  memory: {
    totalBytes: number;
    usedBytes: number;
    availableBytes: number;
    usagePercent: number;
  };
  disk: {
    totalBytes: number;
    usedBytes: number;
    availableBytes: number;
    usagePercent: number;
  };
  ruleEval: { rulesLoaded: number; avgLatencyMs: number };
  container: {
    running: boolean;
    id?: string;
    image?: string;
    uptime?: string;
    memUsedBytes: number;
    memLimitBytes: number;
    memPercent: number;
  };
  runtime: {
    goroutines: number;
    heapAllocMB: number;
    heapSysMB: number;
    gcPauseMsAvg: number;
    uptime: string;
  };
  collectedAt: string;
};

export type InspectionMount = {
  hostPath: string;
  containerPath: string;
  mode: string;
};

export type InspectionEnvVar = {
  key: string;
  value: string;
};

export type SystemInspection = {
  host: {
    kernel: string;
    os: string;
    arch: string;
    hostUptime: string;
    numCPU: number;
  };
  runtime: {
    dockerVersion: string;
    containerdVersion: string;
    cgroupDriver: string;
    storageDriver: string;
  };
  container: {
    id: string;
    image: string;
    restartPolicy: string;
    restartCount: number;
    networkMode: string;
    privileged: boolean;
    seccompProfile: string;
    apparmorProfile: string;
    readonlyRootfs: boolean;
    noNewPrivileges: boolean;
    capabilities: string[];
    mounts: InspectionMount[];
    envVars: InspectionEnvVar[];
  };
  process: {
    pid: number;
    goVersion: string;
    fdCount: number;
    fdSoftLimit: number;
    fdHardLimit: number;
  };
  security: {
    dockerSocketMounted: boolean;
    cgroupCPUQuota: string;
    cgroupPIDsLimit: string;
  };
};

export type IDSCondition = {
  all?: IDSCondition[];
  any?: IDSCondition[];
  not?: IDSCondition;
  field?: string;
  op?: string;
  value?: unknown;
};

export type ContentMatch = {
  pattern: string;
  isHex?: boolean;
  negate?: boolean;
  nocase?: boolean;
  depth?: number;
  offset?: number;
  distance?: number;
  within?: number;
};

export type YARAString = {
  name: string;
  pattern: string;
  type: string; // text|hex|regex
  nocase?: boolean;
  wide?: boolean;
  ascii?: boolean;
};

export type IDSRule = {
  id: string;
  enabled?: boolean | null; // null/undefined = enabled
  title?: string;
  description?: string;
  proto?: string;
  kind?: string;
  when?: IDSCondition;
  severity?: string;
  message?: string;
  labels?: Record<string, string>;
  // Multi-format fields
  sourceFormat?: string;
  action?: string;
  srcAddr?: string;
  dstAddr?: string;
  srcPort?: string;
  dstPort?: string;
  contentMatches?: ContentMatch[];
  yaraStrings?: YARAString[];
  references?: string[];
  cve?: string[];
  mitreAttackIDs?: string[];
  rawSource?: string;
  conversionNotes?: string[];
};

export type RuleGroup = {
  id: string;
  name: string;
  description?: string;
  filter?: string;
  enabled: boolean;
  ruleCount?: number;
};

export type IDSConfig = {
  enabled?: boolean;
  rules?: IDSRule[];
  ruleGroups?: RuleGroup[];
};

export type IDSImportResult = {
  imported: number;
  skipped: number;
  total: number;
  format: string;
};

export type IDSRuleSource = {
  id: string;
  name: string;
  description: string;
  url: string;
  format: string;
  license: string;
  licenseNote?: string;
};

export type RulesetPreview = {
  ruleset: string;
  snapshot?: unknown;
  engineStatus?: unknown;
  engineStatusError?: string;
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
  objects?: Array<{ id?: string; name?: string; type?: string; [k: string]: unknown }>;
  routing?: { gateways?: unknown[]; routes?: unknown[]; policyRouting?: unknown[] };
  dataplane?: DataPlaneConfig;
  export?: { targets?: Array<{ name?: string; format?: string; destination?: string; [k: string]: unknown }> };
  pcap?: { enabled?: boolean; filter?: unknown; forwardTargets?: unknown[] };
  firewall?: {
    defaultAction?: "ALLOW" | "DENY";
    rules?: FirewallRule[];
    nat?: NATConfig;
  };
  ids?: { rules?: unknown[]; enabled?: boolean; [k: string]: unknown };
  services?: unknown;
};

export type ConfigBackup = {
  id: string;
  name: string;
  createdAt: string;
  redacted: boolean;
  size: number;
  idsRuleCount?: number;
};

export async function fetchHealth(signal?: AbortSignal): Promise<HealthResponse | null> {
  try {
    const res = await fetchWithSession("/api/v1/health", {
      cache: "no-store",
    }, signal);
    if (!res.ok) return null;
    return (await res.json()) as HealthResponse;
  } catch (e) {
    if (e instanceof DOMException && e.name === "AbortError") throw e;
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
) : Promise<ApiResult<DataPlaneConfig>> {
  return await postJSONResult<DataPlaneConfig>("/api/v1/dataplane", cfg);
}

export async function getPcapConfig(): Promise<PcapConfig | null> {
  return await getJSON<PcapConfig>("/api/v1/pcap/config");
}

export async function setPcapConfig(cfg: PcapConfig): Promise<ApiResult<PcapConfig>> {
  return await postJSONResult<PcapConfig>("/api/v1/pcap/config", cfg);
}

export async function startPcap(cfg: PcapConfig): Promise<ApiResult<PcapStatus>> {
  return await postJSONResult<PcapStatus>("/api/v1/pcap/start", cfg);
}

export async function stopPcap(): Promise<ApiResult<PcapStatus>> {
  return await postJSONResult<PcapStatus>("/api/v1/pcap/stop", {});
}

export async function getPcapStatus(): Promise<PcapStatus | null> {
  return await getJSON<PcapStatus>("/api/v1/pcap/status");
}

export async function getRulesetPreview(): Promise<RulesetPreview | null> {
  return await getJSON<RulesetPreview>("/api/v1/dataplane/ruleset");
}

export async function listPcaps(): Promise<PcapItem[]> {
  const res = await getJSON<PcapItem[]>("/api/v1/pcap/list");
  return res ?? [];
}

export async function uploadPcap(file: File): Promise<ApiResult<PcapItem>> {
  try {
    const form = new FormData();
    form.append("file", file, file.name);
    const res = await fetchWithSession("/api/v1/pcap/upload", {
      method: "POST",
      headers: authHeaders(),
      body: form,
    });
    if (handleUnauthorized(res)) return { ok: false, error: "Unauthorized" };
    clearAuthExpired();
    if (!res.ok) return { ok: false, error: await parseErrorBody(res) };
    return { ok: true, data: (await res.json()) as PcapItem, warning: parseWarningHeader(res) };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : "Network error" };
  }
}

export function downloadPcapURL(name: string): string {
  return `/api/v1/pcap/download/${encodeURIComponent(name)}`;
}

export async function deletePcap(name: string): Promise<ApiResult<void>> {
  return await deleteJSONResult(`/api/v1/pcap/${encodeURIComponent(name)}`);
}

export async function tagPcap(req: PcapTagRequest): Promise<ApiResult<{ status?: string }>> {
  return await postJSONResult<{ status?: string }>("/api/v1/pcap/tag", req);
}

export async function replayPcap(req: PcapReplayRequest): Promise<ApiResult<{ status?: string }>> {
  return await postJSONResult<{ status?: string }>("/api/v1/pcap/replay", req);
}

async function getJSON<T>(path: string, signal?: AbortSignal): Promise<T | null> {
  try {
    const res = await fetchWithSession(path, {
      cache: "no-store",
      headers: authHeaders(),
    }, signal);
    if (handleUnauthorized(res)) return null;
    // Any non-401 response means auth middleware passed — session is valid.
    clearAuthExpired();
    if (!res.ok) return null;
    return (await res.json()) as T;
  } catch (e) {
    if (e instanceof DOMException && e.name === "AbortError") throw e;
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
    clearAuthExpired();
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
    if (handleUnauthorized(res)) return null;
    clearAuthExpired();
    if (!res.ok) return null;
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
    if (handleUnauthorized(res)) return null;
    clearAuthExpired();
    if (!res.ok) return null;
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
    clearAuthExpired();
    return res.ok;
  } catch {
    return false;
  }
}

async function parseErrorBody(res: Response): Promise<string> {
	try {
		const body = await res.json();
		return body.error || body.message || res.statusText;
	} catch {
		return res.statusText;
	}
}

async function parseSuccessBody<T>(res: Response): Promise<T> {
  const text = await res.text();
  if (!text.trim()) {
    return undefined as T;
  }
  return JSON.parse(text) as T;
}

function parseWarningHeader(res: Response): string | undefined {
  const warning = (res.headers.get("x-containd-warnings") || "").trim();
  return warning || undefined;
}

async function postJSONResult<T>(path: string, payload: unknown): Promise<ApiResult<T>> {
  try {
    const res = await fetchWithSession(path, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...authHeaders() },
      body: JSON.stringify(payload),
    });
    if (handleUnauthorized(res)) return { ok: false, error: "Unauthorized" };
    clearAuthExpired();
    if (!res.ok) return { ok: false, error: await parseErrorBody(res) };
    return { ok: true, data: await parseSuccessBody<T>(res), warning: parseWarningHeader(res) };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : "Network error" };
  }
}

async function patchJSONResult<T>(path: string, payload: unknown): Promise<ApiResult<T>> {
  try {
    const res = await fetchWithSession(path, {
      method: "PATCH",
      headers: { "Content-Type": "application/json", ...authHeaders() },
      body: JSON.stringify(payload),
    });
    if (handleUnauthorized(res)) return { ok: false, error: "Unauthorized" };
    clearAuthExpired();
    if (!res.ok) return { ok: false, error: await parseErrorBody(res) };
    return { ok: true, data: await parseSuccessBody<T>(res), warning: parseWarningHeader(res) };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : "Network error" };
  }
}

async function deleteJSONResult(path: string): Promise<ApiResult<void>> {
  try {
    const res = await fetchWithSession(path, {
      method: "DELETE",
      headers: authHeaders(),
    });
    if (handleUnauthorized(res)) return { ok: false, error: "Unauthorized" };
    clearAuthExpired();
    if (!res.ok) return { ok: false, error: await parseErrorBody(res) };
    return { ok: true, data: undefined, warning: parseWarningHeader(res) };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : "Network error" };
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
      clearAuthExpired();
      setLastAuthError(null);
    }
    return res;
  },
  logout: async () => {
    const ok = await postJSON<{ status: string }>("/api/v1/auth/logout", {});
    clearLocalAuth();
    return ok;
  },
  me: async () => {
    const u = await getJSON<User>("/api/v1/auth/me");
    if (u?.role) setStoredRole(u.role);
    if (u) {
      clearAuthExpired();
      setLastAuthError(null);
    }
    return u;
  },
  meStatus: async () => {
    const res = await getJSONWithStatus<User>("/api/v1/auth/me");
    if (res.data?.role) setStoredRole(res.data.role);
    if (res.status === 200) {
      clearAuthExpired();
      setLastAuthError(null);
    }
    return res;
  },
  updateMe: (patch: UpdateMeRequest) =>
    patchJSONResult<User>("/api/v1/auth/me", patch),
  changeMyPassword: (currentPassword: string, newPassword: string) =>
    postJSONResult<{ status: string }>("/api/v1/auth/me/password", {
      currentPassword,
      newPassword,
    } as ChangePasswordRequest),

  // Users
  listUsers: () => getJSON<User[]>("/api/v1/users"),
  createUser: (u: Omit<User, "id"> & { password: string }) =>
    postJSONResult<User>("/api/v1/users", u),
  updateUser: (id: string, patch: Partial<User>) =>
    patchJSONResult<User>(`/api/v1/users/${encodeURIComponent(id)}`, patch),
  setUserPassword: (id: string, password: string) =>
    postJSONResult<{ status: string }>(
      `/api/v1/users/${encodeURIComponent(id)}/password`,
      { password },
    ),
  deleteUser: (id: string) =>
    deleteJSONResult(`/api/v1/users/${encodeURIComponent(id)}`),

  listZones: (signal?: AbortSignal) => getJSON<Zone[]>("/api/v1/zones", signal),
  createZone: (z: Zone) => postJSONResult<Zone>("/api/v1/zones", z),
  updateZone: (name: string, z: Partial<Zone>) =>
    patchJSONResult<Zone>(`/api/v1/zones/${encodeURIComponent(name)}`, z),
  deleteZone: (name: string) =>
    deleteJSONResult(`/api/v1/zones/${encodeURIComponent(name)}`),
  getSecurityConduits: (signal?: AbortSignal) =>
    getJSON<ConduitMap>("/api/v1/security/conduits", signal),

  listInterfaces: (signal?: AbortSignal) => getJSON<Interface[]>("/api/v1/interfaces", signal),
  listInterfaceState: (signal?: AbortSignal) => getJSON<InterfaceState[]>("/api/v1/interfaces/state", signal),
  assignInterfaces: (mode: "auto" | "explicit", mappings?: Record<string, string>) =>
    postJSONResult<{ interfaces: Interface[] }>("/api/v1/interfaces/assign", {
      mode,
      mappings: mappings ?? {},
    }),
  reconcileInterfacesReplace: () =>
    postJSONResult<{ status: string }>("/api/v1/interfaces/reconcile", { confirm: "REPLACE" }),
  createInterface: (i: Interface) =>
    postJSONResult<Interface>("/api/v1/interfaces", i),
  updateInterface: (name: string, i: Partial<Interface>) =>
    patchJSONResult<Interface>(`/api/v1/interfaces/${encodeURIComponent(name)}`, i),
  deleteInterface: (name: string) =>
    deleteJSONResult(`/api/v1/interfaces/${encodeURIComponent(name)}`),

  getRouting: (signal?: AbortSignal) => getJSON<RoutingConfig>("/api/v1/routing", signal),
  getOSRouting: (signal?: AbortSignal) => getJSON<OSRoutingSnapshot>("/api/v1/routing/os", signal),
  setRouting: (cfg: RoutingConfig) => postJSONResult<RoutingConfig>("/api/v1/routing", cfg),
  reconcileRoutingReplace: () =>
    postJSONResult<{ status: string }>("/api/v1/routing/reconcile", { confirm: "REPLACE" }),

  listFirewallRules: (signal?: AbortSignal) => getJSON<FirewallRule[]>("/api/v1/firewall/rules", signal),
  createFirewallRule: (r: FirewallRule) =>
    postJSONResult<FirewallRule>("/api/v1/firewall/rules", r),
  updateFirewallRule: (id: string, r: Partial<FirewallRule>) =>
    patchJSONResult<FirewallRule>(`/api/v1/firewall/rules/${encodeURIComponent(id)}`, r),
  deleteFirewallRule: (id: string) =>
    deleteJSONResult(`/api/v1/firewall/rules/${encodeURIComponent(id)}`),
  getNAT: () => getJSON<NATConfig>("/api/v1/firewall/nat"),
  setNAT: (cfg: NATConfig) => postJSONResult<NATConfig>("/api/v1/firewall/nat", cfg),
  blockHostTemp: (ip: string, ttlSeconds?: number) =>
    postJSONResult<{ status: string }>("/api/v1/dataplane/blocks/host", {
      ip,
      ttlSeconds,
    }),
  blockFlowTemp: (req: {
    srcIp: string;
    dstIp: string;
    proto: string;
    dstPort: string;
    ttlSeconds?: number;
  }) =>
    postJSONResult<{ status: string }>("/api/v1/dataplane/blocks/flow", req),

  listAssets: () => getJSON<Asset[]>("/api/v1/assets"),
  createAsset: (a: Asset) => postJSONResult<Asset>("/api/v1/assets", a),
  updateAsset: (id: string, a: Partial<Asset>) =>
    patchJSONResult<Asset>(`/api/v1/assets/${encodeURIComponent(id)}`, a),
  deleteAsset: (id: string) =>
    deleteJSONResult(`/api/v1/assets/${encodeURIComponent(id)}`),

  // IDS / Rules
  getIDS: () => getJSON<IDSConfig>("/api/v1/ids/rules"),
  setIDS: (cfg: IDSConfig) => postJSONResult<IDSConfig>("/api/v1/ids/rules", cfg),
  convertSigma: (sigmaYAML: string) =>
    postJSON<IDSRule>("/api/v1/ids/convert/sigma", { sigmaYAML }),
  importIDSRules: async (file: File, format?: string): Promise<ApiResult<IDSImportResult>> => {
    const form = new FormData();
    form.append("file", file);
    if (format) form.append("format", format);
    try {
      const res = await fetchWithSession("/api/v1/ids/import", {
        method: "POST",
        body: form,
        credentials: "include",
        headers: authHeaders(),
      });
      if (handleUnauthorized(res)) return { ok: false, error: "Unauthorized" };
      clearAuthExpired();
      if (!res.ok) return { ok: false, error: await parseErrorBody(res) };
      return { ok: true, data: (await res.json()) as IDSImportResult };
    } catch (e) {
      return { ok: false, error: e instanceof Error ? e.message : "Network error" };
    }
  },
  exportIDSRules: async (format: string): Promise<boolean> => {
    const res = await fetch(`${API_BASE}/api/v1/ids/export?format=${encodeURIComponent(format)}`, {
      credentials: "include",
      headers: authHeaders(),
    });
    if (!res.ok) return false;
    const blob = await res.blob();
    const ext: Record<string, string> = { suricata: ".rules", snort: ".rules", yara: ".yar", sigma: ".yml" };
    const now = new Date();
    const yy = String(now.getFullYear()).slice(2);
    const mm = String(now.getMonth() + 1).padStart(2, "0");
    const dd = String(now.getDate()).padStart(2, "0");
    const filename = `${format}-${yy}${mm}${dd}${ext[format] || ".txt"}`;
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    return true;
  },
  getIDSSources: () => getJSON<IDSRuleSource[]>("/api/v1/ids/sources"),

  listCLICommands: () => getJSON<string[]>("/api/v1/cli/commands"),
  executeCLI: (line: string) =>
    postJSON<CLIExecuteResponse>("/api/v1/cli/execute", { line }),
  completeCLI: (line: string) =>
    getJSON<string[]>(`/api/v1/cli/complete?line=${encodeURIComponent(line)}`),

  // Config lifecycle
  getRunningConfig: () => getJSON<ConfigBundle>("/api/v1/config"),
  getCandidateConfig: () => getJSON<ConfigBundle>("/api/v1/config/candidate"),
  setCandidateConfig: (cfg: ConfigBundle) =>
    postJSONResult<{ status: string }>("/api/v1/config/candidate", cfg),
  diffConfig: () =>
    getJSON<{ running: ConfigBundle | null; candidate: ConfigBundle | null }>(
      "/api/v1/config/diff",
    ),
  exportConfig: (redacted = true) =>
    getJSON<ConfigBundle>(`/api/v1/config/export?redacted=${redacted ? "1" : "0"}`),
  importConfig: (cfg: ConfigBundle) =>
    postJSONResult<{ status: string }>("/api/v1/config/import", cfg),
  listConfigBackups: () => getJSON<ConfigBackup[]>("/api/v1/config/backups"),
  createConfigBackup: (req: { name?: string; redacted: boolean }) =>
    postJSONResult<ConfigBackup>("/api/v1/config/backups", req),
  deleteConfigBackup: (id: string) =>
    deleteJSONResult(`/api/v1/config/backups/${encodeURIComponent(id)}`),
  downloadConfigBackup: async (id: string) => {
    const res = await fetchWithSession(`/api/v1/config/backups/${encodeURIComponent(id)}`, {
      headers: { ...authHeaders() },
      cache: "no-store",
    });
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
    postJSONResult<{ status: string; count: number }>("/api/v1/ids/restore", rules),
  commit: () => postJSONResult<{ status: string }>("/api/v1/config/commit", {}),
  commitConfirmed: (ttlSeconds?: number) =>
    postJSONResult<{ status: string }>(
      "/api/v1/config/commit_confirmed",
      ttlSeconds ? { ttl_seconds: ttlSeconds } : {},
    ),
  confirmCommit: () =>
    postJSONResult<{ status: string }>("/api/v1/config/confirm", {}),
  rollback: () => postJSONResult<{ status: string }>("/api/v1/config/rollback", {}),

  // Audit
  listAudit: () => getJSON<AuditRecord[]>("/api/v1/audit"),

  // Dashboard (aggregated)
  getDashboard: (signal?: AbortSignal) => getJSON<DashboardData>("/api/v1/dashboard", signal),

  // System TLS
  getTLSInfo: () => getJSON<TLSInfo>("/api/v1/system/tls"),
  setTLSCert: (certPEM: string, keyPEM: string) =>
    postJSONResult<{ status: string }>("/api/v1/system/tls/cert", { certPEM, keyPEM }),
  setTrustedCA: (pem: string) =>
    postJSONResult<{ status: string }>("/api/v1/system/tls/trusted-ca", { pem }),

  // Proxies
  getForwardProxy: () =>
    getJSON<ForwardProxyConfig>("/api/v1/services/proxy/forward"),
  setForwardProxy: (cfg: ForwardProxyConfig) =>
    postJSONResult<ForwardProxyConfig>("/api/v1/services/proxy/forward", cfg),
  getReverseProxy: () =>
    getJSON<ReverseProxyConfig>("/api/v1/services/proxy/reverse"),
  setReverseProxy: (cfg: ReverseProxyConfig) =>
    postJSONResult<ReverseProxyConfig>("/api/v1/services/proxy/reverse", cfg),
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
  setAV: (cfg: AVConfig) => postJSONResult<AVConfig>("/api/v1/services/av", cfg),
  runAVUpdate: () => postJSONResult<{ status: string }>("/api/v1/services/av/update", {}),
  listAVDefs: () => getJSON<{ files: string[]; path?: string }>("/api/v1/services/av/defs"),
  uploadAVDef: async (file: File): Promise<ApiResult<{ status: string; file: string }>> => {
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
      return { ok: true, data: (await res.json()) as { status: string; file: string } };
    } catch (e) {
      return { ok: false, error: e instanceof Error ? e.message : "Network error" };
    }
  },
  deleteAVDef: async (file: string): Promise<ApiResult<{ status: string; file: string }>> => {
    const params = new URLSearchParams({ file });
    try {
      const res = await fetchWithSession(`/api/v1/services/av/defs?${params.toString()}`, {
        method: "DELETE",
        headers: authHeaders(),
      });
      if (handleUnauthorized(res)) return { ok: false, error: "Unauthorized" };
      clearAuthExpired();
      if (!res.ok) return { ok: false, error: await parseErrorBody(res) };
      return { ok: true, data: (await res.json()) as { status: string; file: string } };
    } catch (e) {
      return { ok: false, error: e instanceof Error ? e.message : "Network error" };
    }
  },
  getDNS: () => getJSON<DNSConfig>("/api/v1/services/dns"),
  setDNS: (cfg: DNSConfig) => postJSONResult<DNSConfig>("/api/v1/services/dns", cfg),
  getNTP: () => getJSON<NTPConfig>("/api/v1/services/ntp"),
  setNTP: (cfg: NTPConfig) => postJSONResult<NTPConfig>("/api/v1/services/ntp", cfg),
  getDHCP: () => getJSON<DHCPConfig>("/api/v1/services/dhcp"),
  setDHCP: (cfg: DHCPConfig) => postJSONResult<DHCPConfig>("/api/v1/services/dhcp", cfg),
  listDHCPLeases: () => getJSON<{ leases: DHCPLease[] }>("/api/v1/dhcp/leases"),
  getVPN: () => getJSON<VPNConfig>("/api/v1/services/vpn"),
  setVPN: (cfg: VPNConfig) => postJSONResult<VPNConfig>("/api/v1/services/vpn", cfg),
  uploadOpenVPNProfile: (name: string, ovpn: string) =>
    postJSONResult<OpenVPNProfileUploadResponse>("/api/v1/services/vpn/openvpn/profile", { name, ovpn }),
  listOpenVPNClients: () =>
    getJSON<{ clients: string[] }>("/api/v1/services/vpn/openvpn/clients"),
  createOpenVPNClient: (name: string) =>
    postJSONResult<{ name: string }>("/api/v1/services/vpn/openvpn/clients", { name }),
  downloadOpenVPNClientURL: (name: string) =>
    `/api/v1/services/vpn/openvpn/clients/${encodeURIComponent(name)}`,
  getWireGuardStatus: (iface?: string) =>
    getJSON<WireGuardStatus>(
      `/api/v1/services/vpn/wireguard/status${iface ? `?iface=${encodeURIComponent(iface)}` : ""}`,
    ),

  // Telemetry
  listEvents: (limit = 500, signal?: AbortSignal) =>
    getJSON<TelemetryEvent[]>(`/api/v1/events?limit=${limit}`, signal),
  listFlows: (limit = 200, signal?: AbortSignal) =>
    getJSON<FlowSummary[]>(`/api/v1/flows?limit=${limit}`, signal),
  getEvent: (id: number) =>
    getJSON<TelemetryEvent>(`/api/v1/events/${id}`),

  // Simulation
  getSimulationStatus: (signal?: AbortSignal) =>
    getJSON<{ running: boolean }>("/api/v1/simulation", signal),
  startSimulation: () =>
    postJSON<{ running: boolean }>("/api/v1/simulation", { action: "start" }),
  stopSimulation: () =>
    postJSON<{ running: boolean }>("/api/v1/simulation", { action: "stop" }),

  // Sessions / Conntrack
  listConntrack: (limit = 200) =>
    getJSON<ConntrackEntry[]>(`/api/v1/conntrack?limit=${limit}`),
  killConntrack: (req: { proto: string; src: string; dst: string; sport?: number; dport?: number }) =>
    postJSON<{ status: string }>("/api/v1/conntrack/kill", req),
};
