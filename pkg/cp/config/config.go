// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package config

import "time"

// Config represents the management-plane persistent configuration.
// It intentionally stays narrow until broader models are added.
//
// This file owns the core persisted config model and redaction helpers.
// Domain validation should live in validate*.go siblings rather than growing
// this file with large validation implementations again.
type Config struct {
	SchemaVersion string          `json:"schema_version,omitempty"`
	System        SystemConfig    `json:"system"`
	Interfaces    []Interface     `json:"interfaces"`
	Zones         []Zone          `json:"zones"`
	Assets        []Asset         `json:"assets,omitempty"`
	Objects       []Object        `json:"objects,omitempty"`
	Routing       RoutingConfig   `json:"routing,omitempty"`
	DataPlane     DataPlaneConfig `json:"dataplane,omitempty"`
	Export        ExportConfig    `json:"export,omitempty"`
	PCAP          PCAPConfig      `json:"pcap,omitempty"`
	Firewall      FirewallConfig  `json:"firewall"`
	IDS           IDSConfig       `json:"ids,omitempty"`
	Services      ServicesConfig  `json:"services"`
	Description   string          `json:"description,omitempty"`
	Version       string          `json:"version,omitempty"`
}

// RedactedCopy returns a copy of c with secrets removed.
// Today there are no persisted secrets, but this is a stable hook for future redaction.
func (c *Config) RedactedCopy() *Config {
	if c == nil {
		return nil
	}
	cp := *c
	// Shallow-copy slices/maps that might later contain secrets.
	if c.Assets != nil {
		cp.Assets = append([]Asset(nil), c.Assets...)
	}
	if c.Objects != nil {
		cp.Objects = append([]Object(nil), c.Objects...)
	}
	if c.Zones != nil {
		cp.Zones = append([]Zone(nil), c.Zones...)
	}
	if c.Interfaces != nil {
		cp.Interfaces = append([]Interface(nil), c.Interfaces...)
	}
	if c.Firewall.Rules != nil {
		cp.Firewall.Rules = append([]Rule(nil), c.Firewall.Rules...)
	}
	// Redact known secrets.
	cp.Services.VPN.WireGuard.PrivateKey = ""
	if cp.Services.VPN.OpenVPN.Managed != nil {
		m := *cp.Services.VPN.OpenVPN.Managed
		m.CA = ""
		m.Cert = ""
		m.Key = ""
		m.Password = ""
		cp.Services.VPN.OpenVPN.Managed = &m
	}
	// Future: redact additional Services secrets (proxy upstream creds, TLS keys, etc.).
	return &cp
}

type SystemConfig struct {
	Hostname string `json:"hostname"`
	// Placeholder for future system settings (NTP/DNS/syslog).
	Mgmt MgmtConfig `json:"mgmt,omitempty"`
	SSH  SSHConfig  `json:"ssh,omitempty"`
}

// MgmtConfig controls management plane binding and access.
// By default, mgmt binds on all interfaces (0.0.0.0) so the UI is reachable
// on WAN/DMZ/LAN interfaces in lab deployments. Operators can narrow this later.
type MgmtConfig struct {
	// ListenAddr is the legacy HTTP listen address for management UI/API.
	// Prefer HTTPListenAddr/HTTPSListenAddr for new configs.
	ListenAddr string `json:"listenAddr,omitempty"` // e.g. ":8080", "127.0.0.1:8080"

	EnableHTTP  *bool `json:"enableHTTP,omitempty"`
	EnableHTTPS *bool `json:"enableHTTPS,omitempty"`

	HTTPListenAddr  string `json:"httpListenAddr,omitempty"`  // default ":8080"
	HTTPSListenAddr string `json:"httpsListenAddr,omitempty"` // default ":8443"

	// TLS certificate and key (PEM). If empty, a self-signed cert is generated on first start.
	TLSCertFile string `json:"tlsCertFile,omitempty"` // e.g. "/data/tls/server.crt"
	TLSKeyFile  string `json:"tlsKeyFile,omitempty"`  // e.g. "/data/tls/server.key"

	// TrustedCAFile is an optional PEM bundle of additional trusted CAs for outbound TLS clients.
	// If empty, the OS trust store is used.
	TrustedCAFile string `json:"trustedCAFile,omitempty"` // e.g. "/data/tls/trusted_ca.pem"

	// RedirectHTTPToHTTPS, when enabled, redirects GET/HEAD HTTP requests to HTTPS.
	RedirectHTTPToHTTPS *bool `json:"redirectHTTPToHTTPS,omitempty"`
	// EnableHSTS, when enabled, adds Strict-Transport-Security on HTTPS responses.
	EnableHSTS *bool `json:"enableHSTS,omitempty"`
	// HSTSMaxAgeSeconds controls the Strict-Transport-Security max-age.
	HSTSMaxAgeSeconds int `json:"hstsMaxAgeSeconds,omitempty"`
}

// SSHConfig controls the embedded SSH server (interactive CLI).
type SSHConfig struct {
	// ListenAddr is the address the SSH server listens on (inside the appliance/container).
	// Use ":2222" by default in containers (non-root). Appliances may map it to 22 externally.
	ListenAddr string `json:"listenAddr,omitempty"` // e.g. ":2222", "0.0.0.0:2222", "127.0.0.1:2222"
	// AuthorizedKeysDir is a directory containing OpenSSH authorized_keys files.
	// Implementations may look up keys by username (e.g. "<dir>/<username>.pub").
	AuthorizedKeysDir string `json:"authorizedKeysDir,omitempty"`
	// AllowPassword enables SSH password authentication. Should only be enabled in lab mode.
	AllowPassword bool `json:"allowPassword,omitempty"`
	// Banner is the SSH login banner displayed before authentication.
	Banner string `json:"banner,omitempty"`
	// HostKeyRotationDays controls automatic host key rotation (0 = disabled).
	HostKeyRotationDays int `json:"hostKeyRotationDays,omitempty"`
	// ShellMode controls what users get on SSH login.
	// "appliance" (default): the containd CLI REPL. Type "shell" to enter Linux shell.
	// "linux": a real bash shell. Type "containd" or "configure" to enter the CLI REPL.
	ShellMode string `json:"shellMode,omitempty"`
}

type ServicesConfig struct {
	Syslog SyslogConfig `json:"syslog"`
	DNS    DNSConfig    `json:"dns,omitempty"`
	NTP    NTPConfig    `json:"ntp,omitempty"`
	Proxy  ProxyConfig  `json:"proxy,omitempty"`
	DHCP   DHCPConfig   `json:"dhcp,omitempty"`
	VPN    VPNConfig    `json:"vpn,omitempty"`
	AV     AVConfig     `json:"av,omitempty"`
}

type SyslogConfig struct {
	Forwarders []SyslogForwarder `json:"forwarders"`
	Format     string            `json:"format,omitempty"` // rfc5424|json
	BatchSize  int               `json:"batchSize,omitempty"`
	FlushEvery int               `json:"flushEvery,omitempty"` // seconds
}

type SyslogForwarder struct {
	Address string `json:"address"` // IP or hostname
	Port    int    `json:"port"`
	Proto   string `json:"proto"` // udp|tcp
}

// DNSConfig defines Unbound resolver behavior managed by containd.
type DNSConfig struct {
	Enabled         bool     `json:"enabled"`
	ListenPort      int      `json:"listenPort,omitempty"`      // default 53
	ListenZones     []string `json:"listenZones,omitempty"`     // zones to listen on (future L3 binding)
	UpstreamServers []string `json:"upstreamServers,omitempty"` // forwarders; empty uses root hints
	CacheSizeMB     int      `json:"cacheSizeMB,omitempty"`     // optional cache size
}

// NTPConfig defines NTP client settings managed by containd (chrony or openntpd).
type NTPConfig struct {
	Enabled         bool     `json:"enabled"`
	Servers         []string `json:"servers,omitempty"`         // NTP servers/pools
	IntervalSeconds int      `json:"intervalSeconds,omitempty"` // polling interval hint
}

// ProxyConfig holds forward/reverse proxy settings managed by containd.
type ProxyConfig struct {
	Forward ForwardProxyConfig `json:"forward,omitempty"`
	Reverse ReverseProxyConfig `json:"reverse,omitempty"`
}

// ForwardProxyConfig defines explicit forward proxy behavior (Envoy-based).
type ForwardProxyConfig struct {
	Enabled        bool     `json:"enabled"`
	ListenPort     int      `json:"listenPort,omitempty"` // default 3128 if empty
	ListenZones    []string `json:"listenZones,omitempty"`
	AllowedClients []string `json:"allowedClients,omitempty"` // object/asset IDs
	AllowedDomains []string `json:"allowedDomains,omitempty"` // fqdn patterns
	Upstream       string   `json:"upstream,omitempty"`       // optional upstream proxy URL
	LogRequests    bool     `json:"logRequests,omitempty"`
}

// ReverseProxyConfig defines L7 published services (Nginx-based).
type ReverseProxyConfig struct {
	Enabled bool               `json:"enabled"`
	Sites   []ReverseProxySite `json:"sites,omitempty"`
}

type ReverseProxySite struct {
	Name        string   `json:"name"`
	ListenPort  int      `json:"listenPort"`
	Hostnames   []string `json:"hostnames,omitempty"` // SNI/Host match
	Backends    []string `json:"backends,omitempty"`  // host:port targets
	TLSEnabled  bool     `json:"tlsEnabled,omitempty"`
	CertRef     string   `json:"certRef,omitempty"` // future cert store reference
	Description string   `json:"description,omitempty"`
}

// DHCPConfig defines an embedded DHCPv4 server (LAN-side) managed by containd.
// Runtime integration is phased; this is the persisted configuration model.
type DHCPConfig struct {
	Enabled      bool              `json:"enabled"`
	ListenIfaces []string          `json:"listenIfaces,omitempty"` // logical interface names (e.g. "lan2")
	Pools        []DHCPPool        `json:"pools,omitempty"`        // address pools per interface (optional)
	Reservations []DHCPReservation `json:"reservations,omitempty"` // MAC -> fixed IP per interface
	LeaseSeconds int               `json:"leaseSeconds,omitempty"` // default lease time
	Router       string            `json:"router,omitempty"`       // default gateway handed to clients
	DNSServers   []string          `json:"dnsServers,omitempty"`   // DNS servers handed to clients
	Domain       string            `json:"domain,omitempty"`       // optional domain
}

type DHCPPool struct {
	Iface string `json:"iface"` // logical interface name
	Start string `json:"start"` // start IPv4
	End   string `json:"end"`   // end IPv4
}

// DHCPReservation pins a MAC to a specific IP on an interface.
type DHCPReservation struct {
	Iface string `json:"iface"` // logical interface name
	MAC   string `json:"mac"`   // MAC address (normalized to lower-case)
	IP    string `json:"ip"`    // IPv4 address
}

// RestoreRedactedSecrets fills in empty secret fields in c from existing.
// This prevents round-tripping redacted config from wiping stored secrets.
func (c *Config) RestoreRedactedSecrets(existing *Config) {
	if c == nil || existing == nil {
		return
	}
	c.Services.VPN.RestoreRedactedSecrets(existing.Services.VPN)
}

// RestoreRedactedSecrets fills in empty secret fields in v from existing.
func (v *VPNConfig) RestoreRedactedSecrets(existing VPNConfig) {
	if v.WireGuard.PrivateKey == "" {
		v.WireGuard.PrivateKey = existing.WireGuard.PrivateKey
	}
	if v.OpenVPN.Managed != nil && existing.OpenVPN.Managed != nil {
		m := v.OpenVPN.Managed
		e := existing.OpenVPN.Managed
		if m.CA == "" {
			m.CA = e.CA
		}
		if m.Cert == "" {
			m.Cert = e.Cert
		}
		if m.Key == "" {
			m.Key = e.Key
		}
		if m.Password == "" {
			m.Password = e.Password
		}
	}
}

// RedactedVPNCopy returns a copy of v with secrets removed.
func (v VPNConfig) RedactedVPNCopy() VPNConfig {
	v.WireGuard.PrivateKey = ""
	if v.OpenVPN.Managed != nil {
		m := *v.OpenVPN.Managed
		m.CA = ""
		m.Cert = ""
		m.Key = ""
		m.Password = ""
		v.OpenVPN.Managed = &m
	}
	return v
}

// VPNConfig defines VPN services managed by containd.
type VPNConfig struct {
	WireGuard WireGuardConfig `json:"wireguard,omitempty"`
	OpenVPN   OpenVPNConfig   `json:"openvpn,omitempty"`
}

// WireGuardConfig defines a WireGuard server configuration.
// Keys are secrets and should be redacted in exports by default.
type WireGuardConfig struct {
	Enabled          bool     `json:"enabled"`
	Interface        string   `json:"interface,omitempty"` // e.g. "wg0"
	ListenPort       int      `json:"listenPort,omitempty"`
	ListenZone       string   `json:"listenZone,omitempty"`       // zone name for inbound listener
	ListenInterfaces []string `json:"listenInterfaces,omitempty"` // interface names/devices
	AddressCIDR      string   `json:"addressCIDR,omitempty"`      // e.g. "10.8.0.1/24"
	PrivateKey       string   `json:"privateKey,omitempty"`       // base64, stored encrypted later
	Peers            []WGPeer `json:"peers,omitempty"`
}

type WGPeer struct {
	Name                string   `json:"name,omitempty"`
	PublicKey           string   `json:"publicKey"`
	AllowedIPs          []string `json:"allowedIPs,omitempty"`          // CIDRs
	Endpoint            string   `json:"endpoint,omitempty"`            // host:port (optional)
	PersistentKeepalive int      `json:"persistentKeepalive,omitempty"` // seconds
}

// OpenVPNConfig defines OpenVPN server/client configuration.
type OpenVPNConfig struct {
	Enabled    bool   `json:"enabled"`
	Mode       string `json:"mode,omitempty"`       // server|client (phased)
	ConfigPath string `json:"configPath,omitempty"` // path to a foreground OpenVPN config file (phased)

	// Managed is a structured configuration that containd renders into an OpenVPN config
	// file and supporting credential files. This is preferred over raw profile uploads.
	Managed *OpenVPNManagedClientConfig `json:"managed,omitempty"`

	// Server is a structured OpenVPN server configuration that containd renders into an
	// OpenVPN config file plus a generated local PKI (CA + server cert). Client profiles
	// can be generated from this configuration.
	Server *OpenVPNManagedServerConfig `json:"server,omitempty"`
}

// OpenVPNManagedClientConfig is the initial managed OpenVPN client configuration.
// This is intentionally minimal; additional options (TLS settings, cipher suites, etc.)
// can be added as the product matures.
type OpenVPNManagedClientConfig struct {
	Remote   string `json:"remote,omitempty"` // host or IP
	Port     int    `json:"port,omitempty"`   // default 1194
	Proto    string `json:"proto,omitempty"`  // udp|tcp (default udp)
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"` // stored as a secret; redacted in exports

	// PEM blocks (as strings). These are secrets and should be encrypted at rest later.
	CA   string `json:"ca,omitempty"`
	Cert string `json:"cert,omitempty"`
	Key  string `json:"key,omitempty"`
}

// OpenVPNManagedServerConfig is the initial managed OpenVPN server configuration.
type OpenVPNManagedServerConfig struct {
	ListenPort int    `json:"listenPort,omitempty"` // default 1194
	Proto      string `json:"proto,omitempty"`      // udp|tcp (default udp)
	// ListenZone controls which zone auto-opens the OpenVPN listener (default wan).
	ListenZone string `json:"listenZone,omitempty"`
	// ListenInterfaces restricts auto-open rules to specific interfaces/devices.
	ListenInterfaces []string `json:"listenInterfaces,omitempty"`

	// TunnelCIDR is the VPN client address pool.
	// Example: "10.9.0.0/24"
	TunnelCIDR string `json:"tunnelCIDR,omitempty"`

	// PublicEndpoint is used when generating client profiles. Example: "vpn.example.com"
	PublicEndpoint string `json:"publicEndpoint,omitempty"`

	// PushDNS are DNS servers pushed to clients (optional).
	PushDNS []string `json:"pushDNS,omitempty"`

	// PushRoutes are CIDRs pushed to clients (optional).
	PushRoutes []string `json:"pushRoutes,omitempty"`

	// ClientToClient enables inter-client forwarding inside the VPN.
	ClientToClient bool `json:"clientToClient,omitempty"`
}

type Interface struct {
	Name string `json:"name"`
	// Alias is a user-friendly display name for UI/CLI selection.
	Alias string `json:"alias,omitempty"`
	// Device binds this logical interface to a kernel interface name (e.g. "eth0", "enp3s0").
	// When empty, the logical name may be used as the kernel interface name (legacy behavior).
	Device string `json:"device,omitempty"`
	// Type controls how this interface is realized in the OS.
	// Supported: ""/"physical" (default), "bridge", "vlan".
	Type string `json:"type,omitempty"`
	// Parent is the parent interface for VLAN interfaces (logical interface name or kernel device name).
	Parent string `json:"parent,omitempty"`
	// VLANID is the 802.1Q VLAN ID for VLAN interfaces (1-4094).
	VLANID int `json:"vlanId,omitempty"`
	// Members are bridge members (logical interface names or kernel device names) for bridge interfaces.
	Members []string `json:"members,omitempty"`
	Zone    string   `json:"zone"`
	// AddressMode controls how addresses are acquired on this interface.
	// Supported: "", "static", "dhcp" (dhcp is best-effort via engine when no IPv4 is present).
	AddressMode string   `json:"addressMode,omitempty"`
	Addresses   []string `json:"addresses,omitempty"` // CIDR strings
	// Gateway is an optional next-hop IP for a default route (primarily for "wan").
	Gateway string          `json:"gateway,omitempty"`
	Access  InterfaceAccess `json:"access,omitempty"`
}

// InterfaceState is runtime information about a kernel interface (not persisted).
type InterfaceState struct {
	Name  string   `json:"name"`
	Index int      `json:"index"`
	Up    bool     `json:"up"`
	MTU   int      `json:"mtu,omitempty"`
	MAC   string   `json:"mac,omitempty"`
	Addrs []string `json:"addrs,omitempty"` // CIDR strings
}

// InterfaceAccess controls which plane endpoints are reachable on a given interface.
// Nil values mean "unspecified" and are treated as enabled by default for backward compatibility.
type InterfaceAccess struct {
	Mgmt  *bool `json:"mgmt,omitempty"`  // overall mgmt plane access (HTTP/HTTPS)
	HTTP  *bool `json:"http,omitempty"`  // allow mgmt over HTTP
	HTTPS *bool `json:"https,omitempty"` // allow mgmt over HTTPS
	SSH   *bool `json:"ssh,omitempty"`   // allow SSH CLI
}

// DefaultPhysicalInterfaces returns the appliance's default physical interface names.
// These are seeded into a new config so they show up in UI/CLI without extra flags.
func DefaultPhysicalInterfaces() []string {
	return []string{"wan", "dmz", "lan1", "lan2", "lan3", "lan4", "lan5", "lan6"}
}

// DefaultConfig returns a safe initial config for a fresh appliance.
func DefaultConfig() *Config {
	ifaces := make([]Interface, 0, 8)
	for _, name := range DefaultPhysicalInterfaces() {
		iface := Interface{Name: name}
		switch name {
		case "wan":
			iface.Zone = "wan"
		case "dmz":
			iface.Zone = "dmz"
		case "lan1":
			iface.Zone = "mgmt"
		default:
			// lan2-6
			iface.Zone = "lan"
		}
		ifaces = append(ifaces, iface)
	}
	allowMgmt := Rule{
		ID:          "allow-mgmt-ui",
		Description: "Allow access to management UI/API",
		Protocols:   []Protocol{{Name: "tcp", Port: "8080"}},
		Action:      ActionAllow,
	}
	return &Config{
		Zones: []Zone{
			{Name: "wan", Description: "Default WAN zone"},
			{Name: "dmz", Description: "Default DMZ zone"},
			{Name: "lan", Description: "Default LAN zone"},
			{Name: "mgmt", Description: "Default management zone (assign to a dedicated interface if desired)"},
		},
		Interfaces: ifaces,
		Firewall: FirewallConfig{
			DefaultAction: ActionDeny,
			Rules:         []Rule{allowMgmt},
		},
		Services: ServicesConfig{
			Syslog: SyslogConfig{
				Forwarders: []SyslogForwarder{},
				Format:     "rfc5424",
				BatchSize:  500,
				FlushEvery: 2,
			},
		},
		DataPlane: DataPlaneConfig{
			DPIEnabled: true,
		},
		IDS:  DefaultIDSConfig(),
		PCAP: PCAPConfig{},
	}
}

// DataPlaneConfig controls runtime dataplane behavior; persisted in DB/exports.
type DataPlaneConfig struct {
	CaptureInterfaces []string `json:"captureInterfaces,omitempty"` // interface names for capture
	Enforcement       bool     `json:"enforcement,omitempty"`       // enable nftables apply
	EnforceTable      string   `json:"enforceTable,omitempty"`      // nftables table name
	DPIMock           bool     `json:"dpiMock,omitempty"`           // lab-only DPI inspect-all toggle

	// DPI controls
	DPIEnabled      bool            `json:"dpiEnabled,omitempty"`      // master DPI on/off
	DPIMode         string          `json:"dpiMode,omitempty"`         // "learn" or "enforce" (ICS DPI global mode)
	DPIProtocols    map[string]bool `json:"dpiProtocols,omitempty"`    // per-IT-protocol enable: "dns","tls","http","ssh","smb","ntp","snmp","rdp"
	DPIICSProtocols map[string]bool `json:"dpiIcsProtocols,omitempty"` // per-ICS-protocol enable: "modbus","dnp3","cip","s7comm","mms","bacnet","opcua"
	DPIExclusions   []DPIExclusion  `json:"dpiExclusions,omitempty"`   // IPs/domains excluded from DPI
}

// DPIExclusion represents an IP address, CIDR range, or domain name
// that should be excluded from deep packet inspection.
type DPIExclusion struct {
	Value  string `json:"value"`            // IP, CIDR, or domain
	Type   string `json:"type"`             // "ip", "cidr", "domain"
	Reason string `json:"reason,omitempty"` // optional user note
}

// ExportConfig controls DPI event export to SIEM systems.
type ExportConfig struct {
	Enabled bool   `json:"enabled,omitempty"` // enable DPI event export
	Format  string `json:"format,omitempty"`  // cef, json, syslog
	Target  string `json:"target,omitempty"`  // file:///path, udp://host:514, tcp://host:514
	Filter  string `json:"filter,omitempty"`  // all, ics-only, alerts-only
}

// PCAPConfig controls packet capture storage and forwarding.
type PCAPConfig struct {
	Enabled        bool                `json:"enabled,omitempty"`
	Interfaces     []string            `json:"interfaces,omitempty"`
	Snaplen        int                 `json:"snaplen,omitempty"`
	MaxSizeMB      int                 `json:"maxSizeMB,omitempty"`
	MaxFiles       int                 `json:"maxFiles,omitempty"`
	Mode           string              `json:"mode,omitempty"` // "rolling" or "once"
	Promisc        bool                `json:"promisc,omitempty"`
	BufferMB       int                 `json:"bufferMB,omitempty"`
	RotateSeconds  int                 `json:"rotateSeconds,omitempty"`
	FilePrefix     string              `json:"filePrefix,omitempty"`
	Filter         PCAPFilter          `json:"filter,omitempty"`
	ForwardTargets []PCAPForwardTarget `json:"forwardTargets,omitempty"`
}

type PCAPFilter struct {
	Src   string `json:"src,omitempty"`
	Dst   string `json:"dst,omitempty"`
	Proto string `json:"proto,omitempty"` // "tcp", "udp", "icmp", "any"
}

type PCAPForwardTarget struct {
	Interface string `json:"interface,omitempty"`
	Enabled   bool   `json:"enabled,omitempty"`
	Host      string `json:"host,omitempty"`
	Port      int    `json:"port,omitempty"`
	Proto     string `json:"proto,omitempty"` // "tcp" or "udp"
}

type Zone struct {
	Name        string          `json:"name"`
	Alias       string          `json:"alias,omitempty"`
	Description string          `json:"description,omitempty"`
	SLTarget    int             `json:"slTarget,omitempty"`
	Consequence string          `json:"consequence,omitempty"`
	SLOverrides map[string]bool `json:"slOverrides,omitempty"`
}

type ObjectType string

const (
	ObjectHost    ObjectType = "HOST"
	ObjectSubnet  ObjectType = "SUBNET"
	ObjectGroup   ObjectType = "GROUP"
	ObjectService ObjectType = "SERVICE"
)

// Object defines reusable hosts/subnets/groups/services for policy references.
type Object struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Type        ObjectType `json:"type"`
	Addresses   []string   `json:"addresses,omitempty"` // hosts/subnets
	Members     []string   `json:"members,omitempty"`   // groups (object IDs)
	Protocols   []Protocol `json:"protocols,omitempty"` // services
	Tags        []string   `json:"tags,omitempty"`
	Description string     `json:"description,omitempty"`
}

// AssetType enumerates common OT/ICS asset categories.
type AssetType string

const (
	AssetPLC       AssetType = "PLC"
	AssetHMI       AssetType = "HMI"
	AssetSIS       AssetType = "SIS"
	AssetRTU       AssetType = "RTU"
	AssetHistorian AssetType = "HISTORIAN"
	AssetEWS       AssetType = "EWS"
	AssetGateway   AssetType = "GATEWAY"
	AssetLaptop    AssetType = "LAPTOP"
	AssetOther     AssetType = "OTHER"
)

type Criticality string

const (
	CriticalityLow      Criticality = "LOW"
	CriticalityMedium   Criticality = "MEDIUM"
	CriticalityHigh     Criticality = "HIGH"
	CriticalityCritical Criticality = "CRITICAL"
)

// Asset is a first-class OT/ICS device record.
type Asset struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Alias       string      `json:"alias,omitempty"`
	Type        AssetType   `json:"type"`
	Zone        string      `json:"zone,omitempty"`
	IPs         []string    `json:"ips,omitempty"`
	Hostnames   []string    `json:"hostnames,omitempty"`
	Criticality Criticality `json:"criticality,omitempty"`
	Tags        []string    `json:"tags,omitempty"`
	Description string      `json:"description,omitempty"`
}

type FirewallConfig struct {
	DefaultAction Action    `json:"defaultAction"`
	Rules         []Rule    `json:"rules"`
	NAT           NATConfig `json:"nat,omitempty"`
}

// NATConfig defines minimal NAT behavior.
// Phase-1 baseline:
// - SNAT masquerade for selected source zones egressing a zone
// - DNAT port forwards (ingress zone + protocol/port -> destination IP:port)
type NATConfig struct {
	Enabled      bool          `json:"enabled"`
	EgressZone   string        `json:"egressZone,omitempty"`  // default "wan"
	SourceZones  []string      `json:"sourceZones,omitempty"` // default ["lan","dmz"] when enabled
	PortForwards []PortForward `json:"portForwards,omitempty"`
}

// PortForward defines a simple DNAT rule for inbound traffic.
// Note: a corresponding firewall allow rule is still required for traffic to pass (forward chain).
type PortForward struct {
	ID             string   `json:"id"`
	Enabled        bool     `json:"enabled"`
	Description    string   `json:"description,omitempty"`
	IngressZone    string   `json:"ingressZone"` // e.g. "wan"
	Proto          string   `json:"proto"`       // "tcp" or "udp"
	ListenPort     int      `json:"listenPort"`
	DestIP         string   `json:"destIp"`                   // IPv4 only for now
	DestPort       int      `json:"destPort,omitempty"`       // 0 => same as listenPort
	AllowedSources []string `json:"allowedSources,omitempty"` // optional CIDR allowlist
}

// RoutingConfig defines static routes and basic policy routing rules.
// In early phases we support IPv4 only.
type RoutingConfig struct {
	Gateways []Gateway     `json:"gateways,omitempty"`
	Routes   []StaticRoute `json:"routes,omitempty"`
	Rules    []PolicyRule  `json:"rules,omitempty"`
}

// Gateway is a named next-hop definition that can be referenced by routes.
// In early phases this is an IPv4-only convenience for UI/CLI; it is resolved at apply-time.
type Gateway struct {
	Name        string `json:"name"`
	Alias       string `json:"alias,omitempty"`
	Address     string `json:"address"`         // IPv4
	Iface       string `json:"iface,omitempty"` // OS device name preferred; may also be a logical name
	Description string `json:"description,omitempty"`
}

// StaticRoute is a route entry for a given table (0 means main).
// Dst accepts CIDR or "default".
type StaticRoute struct {
	Dst     string `json:"dst"`               // CIDR or "default"
	Gateway string `json:"gateway,omitempty"` // next hop IP
	Iface   string `json:"iface,omitempty"`   // logical interface name or kernel device
	Table   int    `json:"table,omitempty"`   // 0=main
	Metric  int    `json:"metric,omitempty"`
}

// PolicyRule selects a routing table based on L3 selectors (Phase-1: src/dst CIDR).
type PolicyRule struct {
	Priority int    `json:"priority,omitempty"` // 0 => auto
	Src      string `json:"src,omitempty"`      // CIDR
	Dst      string `json:"dst,omitempty"`      // CIDR
	Table    int    `json:"table"`              // 1..252 recommended; 0 invalid for rules
}

// IDSConfig holds native IDS rules that match on normalized DPI events.
type IDSConfig struct {
	Enabled    bool        `json:"enabled"`
	Rules      []IDSRule   `json:"rules,omitempty"`
	RuleGroups []RuleGroup `json:"ruleGroups,omitempty"`
}

// RuleGroup is a named set of IDS rules that can be enabled/disabled as a unit.
type RuleGroup struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Filter      string `json:"filter,omitempty"` // e.g. "sourceFormat:suricata AND proto:modbus"
	Enabled     bool   `json:"enabled"`
	RuleCount   int    `json:"ruleCount,omitempty"` // computed, not persisted
}

// IDSRule is a normalized event rule that supports native, Suricata, Snort,
// YARA and Sigma formats.  The struct carries the superset of fields needed
// to round-trip rules through all formats.
type IDSRule struct {
	ID          string            `json:"id"`
	Enabled     *bool             `json:"enabled,omitempty"` // nil = enabled (default on)
	Title       string            `json:"title,omitempty"`
	Description string            `json:"description,omitempty"`
	Proto       string            `json:"proto,omitempty"` // optional quick filter
	Kind        string            `json:"kind,omitempty"`  // optional quick filter
	When        IDSCondition      `json:"when,omitempty"`
	Severity    string            `json:"severity,omitempty"` // low|medium|high|critical
	Message     string            `json:"message,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`

	// Multi-format fields ────────────────────────────────────────────
	SourceFormat string `json:"sourceFormat,omitempty"` // native|suricata|snort|yara|sigma
	Action       string `json:"action,omitempty"`       // alert|drop|pass|reject (Suricata/Snort)

	// Network fields (Suricata/Snort header)
	SrcAddr string `json:"srcAddr,omitempty"`
	DstAddr string `json:"dstAddr,omitempty"`
	SrcPort string `json:"srcPort,omitempty"`
	DstPort string `json:"dstPort,omitempty"`

	// Content matching (Suricata/Snort content keywords)
	ContentMatches []ContentMatch `json:"contentMatches,omitempty"`

	// YARA string definitions
	YARAStrings []YARAString `json:"yaraStrings,omitempty"`

	// Enrichment / cross-references
	References     []string `json:"references,omitempty"`
	CVE            []string `json:"cve,omitempty"`
	MITREAttackIDs []string `json:"mitreAttackIDs,omitempty"`

	// Round-trip preservation
	RawSource       string   `json:"rawSource,omitempty"`
	ConversionNotes []string `json:"conversionNotes,omitempty"`
}

// ContentMatch represents a Suricata/Snort content keyword with modifiers.
type ContentMatch struct {
	Pattern  string `json:"pattern"`
	IsHex    bool   `json:"isHex,omitempty"`
	Negate   bool   `json:"negate,omitempty"`
	Nocase   bool   `json:"nocase,omitempty"`
	Depth    int    `json:"depth,omitempty"`
	Offset   int    `json:"offset,omitempty"`
	Distance int    `json:"distance,omitempty"`
	Within   int    `json:"within,omitempty"`
}

// YARAString represents a named string definition in a YARA rule.
type YARAString struct {
	Name    string `json:"name"` // e.g. "$hex_modbus"
	Pattern string `json:"pattern"`
	Type    string `json:"type"` // text|hex|regex
	Nocase  bool   `json:"nocase,omitempty"`
	Wide    bool   `json:"wide,omitempty"`
	ASCII   bool   `json:"ascii,omitempty"`
}

type IDSCondition struct {
	All   []IDSCondition `json:"all,omitempty"`
	Any   []IDSCondition `json:"any,omitempty"`
	Not   *IDSCondition  `json:"not,omitempty"`
	Field string         `json:"field,omitempty"` // e.g. "attr.function_code"
	Op    string         `json:"op,omitempty"`    // equals|contains|in|regex|gt|lt
	Value any            `json:"value,omitempty"`
}

type Action string

const (
	ActionAllow Action = "ALLOW"
	ActionDeny  Action = "DENY"
)

// ScheduleConfig restricts a firewall rule to a recurring time window.
type ScheduleConfig struct {
	DaysOfWeek []string `json:"daysOfWeek,omitempty"` // e.g. ["Monday","Tuesday"]
	StartTime  string   `json:"startTime,omitempty"`  // HH:MM
	EndTime    string   `json:"endTime,omitempty"`    // HH:MM
	Timezone   string   `json:"timezone,omitempty"`   // IANA timezone, e.g. "America/New_York"
}

type Rule struct {
	ID           string          `json:"id"`
	Description  string          `json:"description,omitempty"`
	SourceZones  []string        `json:"sourceZones,omitempty"`
	DestZones    []string        `json:"destZones,omitempty"`
	Sources      []string        `json:"sources,omitempty"`      // CIDR strings
	Destinations []string        `json:"destinations,omitempty"` // CIDR strings
	Protocols    []Protocol      `json:"protocols,omitempty"`
	Identities   []string        `json:"identities,omitempty"`
	ICS          ICSPredicate    `json:"ics,omitempty"`
	Schedule     *ScheduleConfig `json:"schedule,omitempty"`
	Action       Action          `json:"action"`
	Log          bool            `json:"log,omitempty"` // log matching traffic
}

type Protocol struct {
	Name string `json:"name"`           // e.g. tcp, udp, icmp
	Port string `json:"port,omitempty"` // single or range "80", "443", "1000-2000"
}

// ICSPredicate captures ICS-specific primitives for rules.
// All seven supported ICS protocols are covered: modbus, dnp3, cip, s7comm, mms, bacnet, opcua.
type ICSPredicate struct {
	Protocol      string   `json:"protocol,omitempty"`      // modbus, dnp3, cip, s7comm, mms, bacnet, opcua
	FunctionCode  []uint8  `json:"functionCode,omitempty"`  // function/service codes (all protocols)
	UnitID        *uint8   `json:"unitId,omitempty"`        // optional Modbus unit id
	Addresses     []string `json:"addresses,omitempty"`     // register/address ranges as strings
	ObjectClasses []uint16 `json:"objectClasses,omitempty"` // CIP object classes
	ReadOnly      bool     `json:"readOnly,omitempty"`      // read-only class
	WriteOnly     bool     `json:"writeOnly,omitempty"`     // write-only class
	Direction     string   `json:"direction,omitempty"`     // "request", "response", or "" (both)
	Mode          string   `json:"mode,omitempty"`          // "learn" or "enforce"
}

type AVConfig struct {
	Enabled      bool          `json:"enabled"`
	Mode         string        `json:"mode,omitempty"`            // icap|clamav
	FailPolicy   string        `json:"failPolicy,omitempty"`      // open|closed
	FailOpenICS  bool          `json:"failOpenIcs,omitempty"`     // force fail-open for ICS protocols
	BlockTTL     int           `json:"blockTtlSeconds,omitempty"` // seconds to keep dynamic blocks on malware
	MaxSizeBytes int64         `json:"maxSizeBytes,omitempty"`    // 0 = unlimited
	TimeoutSec   int           `json:"timeoutSec,omitempty"`      // ICAP scan timeout
	CacheTTL     time.Duration `json:"cacheTtl,omitempty"`        // verdict cache TTL
	ICAP         ICAPConfig    `json:"icap,omitempty"`
	ClamAV       ClamAVConfig  `json:"clamav,omitempty"`
	HTTPDownload bool          `json:"httpDownload,omitempty"` // scan HTTP responses
	HTTPUpload   bool          `json:"httpUpload,omitempty"`   // scan HTTP requests/uploads
}

type ICAPConfig struct {
	Servers []ICAPServer `json:"servers,omitempty"`
	// Future: service-specific toggles (REQMOD/RESPMOD).
}

type ICAPServer struct {
	Address string `json:"address"` // host:port
	UseTLS  bool   `json:"useTls,omitempty"`
	Service string `json:"service,omitempty"` // e.g., avscan or reqmod/respmod URI
}

type ClamAVConfig struct {
	SocketPath       string `json:"socketPath,omitempty"`       // e.g., /var/run/clamav/clamd.sock
	UpdateSchedule   string `json:"updateSchedule,omitempty"`   // cron-ish or interval string
	CustomDefsPath   string `json:"customDefsPath,omitempty"`   // directory for custom .ndb/yara rules
	FreshclamEnabled bool   `json:"freshclamEnabled,omitempty"` // enable automatic updates
}
