/** Discriminated result type for mutation API calls that surfaces backend error messages. */
export type ApiResult<T> =
  | { ok: true; data: T; warning?: string }
  | ApiFailure;

/**
 * A refused or failed call. `retryAfter` is the server's Retry-After in
 * seconds, set when it said when to try again (a 429 rate limit or lock).
 */
export type ApiFailure = { ok: false; error: string; retryAfter?: number };

// This file is the stable UI API facade. Keep shared public types and the
// exported `api` surface here, but place endpoint families in `api-*.ts`
// domain modules and generic transport/session helpers in api-core/request.

export {
  apiURL,
  clearLocalAuth,
  getLastAuthError,
  getSessionToken,
  getStoredRole,
  isAdmin,
} from "./api-core";
export {
  fetchDataPlane,
  getICSCoverage,
  getInstalledRulesetStatus,
  getRulesetPreview,
  setDataPlane,
} from "./api-dataplane";
export {
  deletePcap,
  downloadPcapURL,
  getPcapConfig,
  getPcapStatus,
  listPcaps,
  replayPcap,
  setPcapConfig,
  startPcap,
  stopPcap,
  tagPcap,
  uploadPcap,
} from "./api-pcap";
export type {
  PcapConfig,
  PcapFilter,
  PcapForwardTarget,
  PcapItem,
  PcapReplayRequest,
  PcapStatus,
  PcapTagRequest,
} from "./api-pcap";
export type {
  InstalledRulesetStatus,
  RulesetPreview,
  SchedulePlannerStatus,
} from "./api-dataplane";
export type {
  FirewallRule,
  FirewallRuleCreate,
  FirewallRulePatch,
  Position,
  ForwardPlacement,
  ForwardPublishResult,
  ForwardDeleteResult,
  ICSPredicate,
  ICSPredicatePatch,
  IdentityBinding,
  IEC104Class,
  IOARange,
  Protocol,
  RateLimit,
  RuleAction,
  RuleCount,
  RuleCounters,
  RulePreview,
  RuleSchedule,
  RuleWarning,
  RuleWarningPredicate,
} from "./api-firewall";
export type {
  ICSCoverageReason,
  ICSCoverageReport,
  ICSCoverageRule,
  ICSCoverageState,
  ICSEnforcementHealth,
} from "./api-ics-coverage";
export { iec104SessionID, parseICSEvidence } from "./api-iec104";
export { fetchHealth } from "./api-health";
export { getEvidenceStatus } from "./api-evidence";
export type { AuditPersistenceStatus, EvidenceStatus, EvidenceState } from "./api-evidence";
export type {
  EnforcementHealth,
  HealthResponse,
  IEC104EnforcementHealth,
  ManagementRecoveryHealth,
} from "./api-health";
export type { IEC104Inventory } from "./api-inventory";
export type { TrustedCAUploadResult } from "./api-policy";
export type { AVDefinition, AVDefinitionList } from "./api-services";
export type {
  OpenVPNConfig,
  OpenVPNManagedClientConfig,
  OpenVPNManagedServerConfig,
  OpenVPNProfileUploadResponse,
  VPNConfig,
  WGPeer,
  WireGuardConfig,
  WireGuardPeerStatus,
  WireGuardStatus,
} from "./api-vpn";
export type {
  ContentMatch,
  IDSCondition,
  IDSConfig,
  IDSImportResult,
  IDSRule,
  IDSRuleSource,
  RuleGroup,
  YARAString,
} from "./api-ids";
export type {
  AVStatus, DHCPStatus, DNSStatus, NTPStatus, ProxyStatus, ProxyTelemetryStatus,
  ServiceMeter, ServicesStatus, SyslogAuditForwarder, SyslogAuditStatus, SyslogStatus, VPNStatus,
} from "./api-service-status";
import { inventoryAPI } from "./api-inventory";
import { consoleAPI } from "./api-console";
import { dataplaneAPI } from "./api-dataplane";
import { firewallAPI } from "./api-firewall";
import { networkAPI } from "./api-network";
import { policyAPI } from "./api-policy";
import { authAPI } from "./api-auth";
import { configAPI } from "./api-config";
import { servicesAPI } from "./api-services";
import { vpnAPI } from "./api-vpn";
import { idsAPI } from "./api-ids";

import type { FirewallRule } from "./api-firewall";
import type { HealthResponse } from "./api-health";

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
  dpiMode?: "" | "monitor" | "enforce";
  dpiProtocols?: Record<string, boolean>;
  dpiIcsProtocols?: Record<string, boolean>;
  dpiIcsParsing?: Record<string, "tolerant" | "strict">;
  dpiExclusions?: DPIExclusion[];
  nflogGroup?: number;
  nfqueueGroup?: number;
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
  from: string;
  to: string;
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
  listenAddress?: string;
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

/**
 * One include entry of the scan selection: connections from sourceZones to
 * destZones on destPorts (ports or N-M ranges, at least one). An empty zone
 * list matches any zone.
 */
export type ScanInclude = {
  sourceZones?: string[];
  destZones?: string[];
  destPorts: string[];
};

/** One exclude entry; sources and destinations are CIDRs. At least one field must be set. */
export type ScanExclude = {
  sourceZones?: string[];
  destZones?: string[];
  sources?: string[];
  destinations?: string[];
  destPorts?: string[];
};

export type ScanDownloadMode = "hold" | "stream_tail";

/** The traffic the scanning gate intercepts; excludes win over includes. */
export type ScanSelection = {
  include?: ScanInclude[];
  exclude?: ScanExclude[];
  downloadMode?: ScanDownloadMode;
  /** Zones whose unscanned traffic passes under a closed fail policy. */
  icsZones?: string[];
  /** Asset IDs whose unscanned traffic passes under a closed fail policy. */
  icsAssets?: string[];
};

export type AVConfig = {
  enabled: boolean;
  mode?: "icap" | "clamav";
  failPolicy?: "open" | "closed";
  maxSizeBytes?: number;
  timeoutSec?: number;
  /** Verdict cache lifetime in nanoseconds; 0 selects 10 minutes. */
  cacheTtl?: number;
  icap?: {
    servers?: { address: string; useTls?: boolean; service?: string }[];
  };
  clamav?: ClamAVConfig;
  /** Scan HTTP responses (downloads). */
  httpDownload?: boolean;
  /** Scan HTTP requests (uploads). */
  httpUpload?: boolean;
  scan?: ScanSelection;
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
  /** Whether the next-start configuration permits managed identity uploads;
   * not the bound listener's mode. */
  managed: boolean;
  /** Listeners management binds at the next start. */
  httpListenAddr?: string;
  httpsListenAddr?: string;
  httpEnabled: boolean;
  httpsEnabled: boolean;
  /** Listeners management has bound now; absent when not bound. */
  boundHttpListenAddr?: string;
  boundHttpsListenAddr?: string;
  /** Whether the next start binds another listener than the bound one;
   * the API compares them, so wildcard spellings of one port are equal. */
  httpListenChanges: boolean;
  httpsListenChanges: boolean;
  /** Files the HTTPS listener serves from the next start; the cert fields
   * describe this certificate. */
  certFile?: string;
  keyFile?: string;
  certSubject?: string;
  certIssuer?: string;
  certNotAfter?: string;
  certDnsNames?: string[];
  certIps?: string[];
  /** Files and certificate the bound HTTPS listener serves now; absent when
   * none is bound. All file paths are cleaned, so equal strings name the
   * same file. */
  servedCertFile?: string;
  servedKeyFile?: string;
  servedCertSubject?: string;
  servedCertNotAfter?: string;
  servedCertDnsNames?: string[];
  servedCertIps?: string[];
  /** Latest identity reload failure; the listener retains its last valid certificate. */
  reloadError?: string;
};

/** Result of a management certificate upload: status "updated" when the
 * bound HTTPS listener serves it at once, "stored" when it is served from
 * the next start, with the reason in warnings. */
export type TLSCertUpload = { status?: string; warnings?: string[] };

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

/**
 * A kernel connection as listed. TCP and UDP tuples carry ports; ICMP and
 * ICMPv6 tuples carry the query identifier, type and code instead.
 */
export type ConntrackEntry = {
  proto: string;
  state?: string;
  src?: string;
  dst?: string;
  sport?: string;
  dport?: string;
  icmpId?: string;
  icmpType?: string;
  icmpCode?: string;
  replySrc?: string;
  replyDst?: string;
  replySport?: string;
  replyDport?: string;
  replyIcmpId?: string;
  replyIcmpType?: string;
  replyIcmpCode?: string;
  mark?: string;
  assured?: boolean;
  timeoutSecs?: number;
  /** Labels of the running TAG rules matching the original tuple; absent when none. */
  tags?: string[];
};

/** `identify` / `identification` event attributes; endpoint arrays use capture order. */
export type IdentificationAttributes = {
  protocol: string;
  identification_state: "confirmed" | "reject" | "identification_incomplete";
  reason: string;
  identification_coverage?: string;
  identification_candidates: string[] | null;
  expected: [string, string];
  service_transport: "tcp" | "udp";
  service_port: number;
  mismatch: boolean;
  binding: "observation" | "legacy" | "none";
  outside_rule_port_scope: boolean | "unknown";
  profile_version: number;
  syn_coverage: [boolean, boolean];
};

/** Passive decoder events have no verdict or auto-ALLOW authority. */
export type ObservationAttributes = {
  observation_only: true;
  binding_source: "observation";
};

export type PcapIdentification = {
  key: string;
  flowId: string;
  /** Client to server from captured SYN roles; otherwise the flow's orientation hint. */
  srcIp: string;
  dstIp: string;
  srcPort: number;
  dstPort: number;
  attributes: IdentificationAttributes;
};

export type TelemetryEvent = {
  /** Exact decimal uint64; never convert event identity to a JavaScript number. */
  id: string;
  flowId: string;
  proto: string;
  kind: string;
  attributes?: Record<string, unknown> & Partial<IdentificationAttributes & ObservationAttributes>;
  timestamp: string;
  srcIp?: string;
  dstIp?: string;
  srcPort?: number;
  dstPort?: number;
  transport?: string;
  /** Content hash, set on AV events. */
  hash?: string;
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
  identification?: IdentificationAttributes;
  eventCount: number;
  avDetected?: boolean;
  avBlocked?: boolean;
  /** IEC 104 session incarnation; set when the group is one IEC session. */
  session_id?: string;
  /** Sorted TAG labels the flow's events carry; absent when none. */
  tags?: string[];
};

/** Event kinds of IEC 104 enforcement evidence. */
export type ICSEvidenceKind = "ics.decision" | "ics.verdict" | "ics.session";

/** `ics.decision` attributes: a rule decision, not a delivery outcome. */
export type ICSDecisionAttributes = {
  session_id: string;
  decision: "allow" | "deny" | "would_allow" | "would_drop";
  ruleId: string;
  scopeId?: string;
  findingCode?: string;
  action?: string;
  mode?: string;
  /**
   * Engine reasons: rule, default, broadcast, malformed (unframeable bytes
   * or a stream fault) and nonconformant (strict parsing rejected decoded
   * content). A reason outside that set is kept raw rather than hidden.
   */
  reason: string;
  /** Sorted conformance finding codes, e.g. iec104.reserved_bits. */
  conformance: string[];
  apdu_id?: string;
  type_id?: number;
  ca?: number;
  ioa?: number;
  select?: boolean;
  direction?: "request" | "response";
};

/** `ics.verdict` attributes: one per aborted session. */
export type ICSVerdictAttributes = {
  session_id: string;
  outcome: "dropped" | "drop_failed";
  apdu_ids: string[];
  trigger_apdu_id?: string;
  error?: string;
};

/** `ics.session` attributes: one per session or enforcement state change. */
export type ICSSessionAttributes = {
  session_id: string;
  outcome:
    | "aborted"
    | "reset_sent"
    | "reset_failed"
    | "reconnected"
    | "enforce_unhealthy"
    | "enforce_healthy";
  target?: "client" | "server";
  error?: string;
};

export type ICSEvidence =
  | { kind: "ics.decision"; attrs: ICSDecisionAttributes }
  | { kind: "ics.verdict"; attrs: ICSVerdictAttributes }
  | { kind: "ics.session"; attrs: ICSSessionAttributes };

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

export const api = {
  ...authAPI,

  ...configAPI,
  ...networkAPI,
  ...firewallAPI,
  ...policyAPI,
  ...dataplaneAPI,
  ...servicesAPI,
  ...vpnAPI,
  ...idsAPI,
  ...consoleAPI,
  ...inventoryAPI,
};
