// Wire types for GET /api/v1/services/status: one entry per service the
// management plane runs, plus the engine's antivirus status. Times are
// RFC 3339 strings.

export const serviceNames = ["syslog", "dns", "ntp", "av", "proxy", "dhcp", "wireguard", "openvpn"] as const;
export type ServiceName = typeof serviceNames[number];
export type ServiceFault = {
  service: ServiceName;
  kind: "config" | "runtime";
  message: string;
};
export type ServiceFaultState = { state?: "faulted"; fault?: ServiceFault };

/** Event meter every management service entry carries. */
export type ServiceMeter = ServiceFaultState & {
  /**
   * Events per minute, oldest first, one entry per minute through the
   * current minute (quiet minutes are 0); empty before the first event.
   */
  sparkline: number[];
  /** Events since management started. */
  count: number;
  /** Average events per minute across `sparkline`. */
  rate_per_min: number;
  errors_sparkline: number[];
  errors_count: number;
  errors_rate_per_min: number;
};

/** Audit delivery of one forwarder, as of its last flush. */
export type SyslogAuditForwarder = {
  /** Destination, as proto://address:port. */
  forwarder: string;
  /** ID of the last audit record it accepted. */
  last_id: number;
  /** Audit records not yet sent to it. */
  backlog: number;
  last_error: string;
  /** Empty before its first delivery. */
  last_sent: string;
};

/**
 * Audit records forwarded over the syslog forwarders, oldest first, each
 * forwarder resuming from its own durable cursor.
 */
export type SyslogAuditStatus = {
  enabled: boolean;
  sent_total: number;
  failed_total: number;
  last_error: string;
  /** Empty before the first flush. */
  last_flush: string;
  /** Records not yet sent, summed over the forwarders. */
  backlog: number;
  forwarders: SyslogAuditForwarder[];
};

/** Independent bounded telemetry stream progress; offsets are exact decimals. */
export type SyslogEventProgress = {
  destination: string;
  source: "engine" | "services";
  epoch: string;
  offset: string;
  backlog: number;
  sent: number;
  failed: number;
  lost: number;
  continuity_unknown: number;
  last_error: string;
  last_success: string;
};

export type SyslogStatus = ServiceMeter & {
  events?: SyslogEventProgress[];
  configured_forwarders: number;
  format: string;
  protos: string[] | null;
  sent_total: number;
  failed_total: number;
  /** Empty before the first flush. */
  last_flush: string;
  last_error: string;
  last_batch: number;
  batch_limit: number;
  hit_limit: boolean;
  flush_interval_sec: number;
  /** Absent from a management plane that does not forward audit records. */
  audit?: SyslogAuditStatus;
};

export type DNSStatus = ServiceMeter & {
  enabled: boolean;
  listen_port: number;
  configured_upstreams: number;
  last_render: string;
  last_error: string;
  installed: boolean;
  binary_path: string;
  supervise: boolean;
  running: boolean;
  pid: number;
  /** Empty when Unbound never started or stopped. */
  last_start: string;
  last_stop: string;
  last_exit: string;
  config_path: string;
  note: string;
};

export type NTPStatus = ServiceMeter & {
  /** Null until an enabled configuration is rendered. */
  min_poll_seconds: number | null;
  max_poll_seconds: number | null;
  /** Null unless a fixed poll interval is rendered. */
  interval_seconds: number | null;
  enabled: boolean;
  servers_count: number;
  last_render: string;
  last_error: string;
  supervise: boolean;
  ntpd_path: string;
  ntpd_name: string;
  running: boolean;
  pid: number;
  /** Empty when the NTP daemon never started or stopped. */
  last_start: string;
  last_stop: string;
  last_exit: string;
};

export type ProxyStatus = ServiceMeter & {
  forward_enabled: boolean;
  reverse_enabled: boolean;
  envoy_path: string;
  nginx_path: string;
  envoy_running: boolean;
  nginx_running: boolean;
  envoy_pid: number;
  nginx_pid: number;
  /** Empty when the proxy never started or stopped. */
  envoy_last_start: string;
  nginx_last_start: string;
  envoy_last_stop: string;
  nginx_last_stop: string;
  envoy_last_exit: string;
  nginx_last_exit: string;
  envoy_last_error: string;
  nginx_last_error: string;
  last_render: string;
  rendered_files: string[];
};

/** Envoy or nginx access-log counters, present once the proxy logged one. */
export type ProxyTelemetryStatus = ServiceMeter & { note: string };

export type DHCPStatus = ServiceMeter & {
  enabled: boolean;
  listen_ifaces: number;
  pools: number;
  reservations: number;
  last_render: string;
  last_error: string;
  note: string;
};

export type VPNStatus = ServiceMeter & {
  wireguard_enabled: boolean;
  openvpn_enabled: boolean;
  openvpn_mode: string;
  wg_peers: number;
  last_render: string;
  last_error: string;
  openvpn_installed: boolean;
  openvpn_binary: string;
  openvpn_supervise: boolean;
  openvpn_running: boolean;
  openvpn_pid: number;
  openvpn_config_path: string;
  /** Empty when OpenVPN never started or stopped. */
  openvpn_last_start: string;
  openvpn_last_stop: string;
  openvpn_last_exit: string;
  openvpn_last_error: string;
  openvpn_server_tunnel: string;
  openvpn_server_endpoint: string;
  note: string;
};

/** One transparent listener of the scanning gate. */
export type AVGateListenerStatus = {
  address: string;
  /** Connections accepted here are masqueraded upstream. */
  masquerade: boolean;
  up: boolean;
  error?: string;
  /** The listener cannot be opened on this host at all. */
  unavailable?: boolean;
};

/**
 * The scanning gate's part of the antivirus status. The state is off while
 * the data plane does not enforce; refuse or pass while a listener or the
 * routing is down, by fail policy; pending while the gate runs but the
 * scanner is not ready; else open.
 */
export type AVGateStatus = {
  state: "off" | "refuse" | "pass" | "pending" | "open";
  /** A scan selection is active. */
  enabled: boolean;
  fail_policy: string;
  /** The admission the kernel currently applies: open, pass or refuse. */
  admit: string;
  admit_error?: string;
  listeners: AVGateListenerStatus[];
  scanner: { ready: boolean; error?: string };
  connections: number;
  routing_error?: string;
  warning?: string;
};

/** The engine scanner's live status, its scans as the meter. */
export type AVRuntimeStatus = ServiceMeter & {
  available: true;
  enabled: boolean;
  mode: string;
  failPolicy: string;
  max_size: number;
  /** Scan timeout in seconds. */
  timeout: number;
  /** Go duration string, such as "10m0s". */
  cache_ttl: string;
  cache_size: number;
  icap_servers: number;
  detections: number;
  definitions_generation: number;
  clamav_socket: string;
  clamav_path: string;
  clamav_running: boolean;
  clamav_pid: number;
  /** Empty when clamd never started or stopped. */
  clamav_last_start: string;
  clamav_last_stop: string;
  clamav_last_exit: string;
  clamav_custom_defs: string;
  freshclam_path: string;
  freshclam_enabled: boolean;
  /** Go duration string; empty when the schedule is invalid. */
  freshclam_interval: string;
  freshclam_last: string;
  freshclam_error: string;
  freshclam_running: boolean;
  freshclam_runs: number;
  last_render: string;
  last_error: string;
  last_test: string;
  trust_revision: string;
  ready: boolean;
  db_version: string;
  ready_error: string;
  /** Absent only when the engine's status predates the scanning gate. */
  gate?: AVGateStatus;
};

/** The engine did not answer its antivirus status request. */
export type AVUnavailableStatus = ServiceFaultState & { available: false; error: string };

export type AVStatus = AVRuntimeStatus | AVUnavailableStatus;

/**
 * Services status. A management entry is absent when management does not
 * run that service; envoy and nginx appear once their access logs counted
 * an event.
 */
export type ServicesStatus = {
  faults: ServiceFault[];
  syslog?: SyslogStatus;
  dns?: DNSStatus;
  ntp?: NTPStatus;
  proxy?: ProxyStatus;
  envoy?: ProxyTelemetryStatus;
  nginx?: ProxyTelemetryStatus;
  dhcp?: DHCPStatus;
  vpn?: VPNStatus;
  wireguard?: ServiceMeter;
  openvpn?: ServiceMeter;
  av: AVStatus;
};
