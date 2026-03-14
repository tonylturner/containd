export type HealthResponse = {
  status: string;
  component: string;
  build?: string;
  time?: string;
};

/** Discriminated result type for mutation API calls that surfaces backend error messages. */
export type ApiResult<T> =
  | { ok: true; data: T; warning?: string }
  | { ok: false; error: string };

// This file is the stable UI API facade. Keep shared public types and the
// exported `api` surface here, but place endpoint families in `api-*.ts`
// domain modules and generic transport/session helpers in api-core/request.

export {
  clearLocalAuth,
  getLastAuthError,
  getSessionToken,
  getStoredRole,
  isAdmin,
} from "./api-core";
export {
  deletePcap,
  downloadPcapURL,
  fetchDataPlane,
  getPcapConfig,
  getPcapStatus,
  getRulesetPreview,
  listPcaps,
  replayPcap,
  setDataPlane,
  setPcapConfig,
  startPcap,
  stopPcap,
  tagPcap,
  uploadPcap,
} from "./api-dataplane";
import { consoleAPI } from "./api-console";
import { dataplaneAPI } from "./api-dataplane";
import { networkAPI } from "./api-network";
import { policyAPI } from "./api-policy";
import { authAPI } from "./api-auth";
import { configAPI } from "./api-config";
import { servicesAPI } from "./api-services";

import {
  fetchWithSession,
} from "./api-core";
import {
} from "./api-request";

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
  counts: {
    assets: number;
    zones: number;
    interfaces: number;
    rules: number;
    icsRules: number;
  };
  eventStats: {
    total: number;
    idsAlerts: number;
    modbusWrites: number;
    avDetections: number;
    avBlocks: number;
  };
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
  mfaEnabled?: boolean;
  mfaRequired?: boolean;
  mfaGraceUntil?: string;
  labMode?: boolean;
  createdAt?: string;
  updatedAt?: string;
};

export type LoginResponse = {
  token: string;
  expiresAt: string;
  user: User;
};

export type MFALoginChallenge = {
  mfaRequired: true;
  mfaMethod: string;
  mfaChallengeToken: string;
  user: User;
};

export type LoginStartResponse = LoginResponse | MFALoginChallenge;

export type MFAEnrollResponse = {
  secret: string;
  otpauthURL: string;
  qrDataURL: string;
  challengeToken: string;
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

export type MFADisableRequest = {
  currentPassword: string;
  code: string;
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
  objects?: Array<{
    id?: string;
    name?: string;
    type?: string;
    [k: string]: unknown;
  }>;
  routing?: {
    gateways?: unknown[];
    routes?: unknown[];
    policyRouting?: unknown[];
  };
  dataplane?: DataPlaneConfig;
  export?: {
    targets?: Array<{
      name?: string;
      format?: string;
      destination?: string;
      [k: string]: unknown;
    }>;
  };
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

export async function fetchHealth(
  signal?: AbortSignal,
): Promise<HealthResponse | null> {
  try {
    const res = await fetchWithSession(
      "/api/v1/health",
      {
        cache: "no-store",
      },
      signal,
    );
    if (!res.ok) return null;
    return (await res.json()) as HealthResponse;
  } catch (e) {
    if (e instanceof DOMException && e.name === "AbortError") throw e;
    return null;
  }
}

export const api = {
  ...authAPI,

  ...configAPI,
  ...networkAPI,
  ...policyAPI,
  ...dataplaneAPI,
  ...servicesAPI,
  ...consoleAPI,
};
