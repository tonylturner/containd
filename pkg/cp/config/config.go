// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package config

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Config represents the management-plane persistent configuration.
// It intentionally stays narrow until broader models are added.
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

// NTPConfig defines OpenNTPD client settings managed by containd.
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
	Enabled        bool              `json:"enabled"`
	ListenIfaces   []string          `json:"listenIfaces,omitempty"`   // logical interface names (e.g. "lan2")
	Pools          []DHCPPool        `json:"pools,omitempty"`          // address pools per interface (optional)
	Reservations   []DHCPReservation `json:"reservations,omitempty"`   // MAC -> fixed IP per interface
	LeaseSeconds   int               `json:"leaseSeconds,omitempty"`   // default lease time
	Router         string            `json:"router,omitempty"`         // default gateway handed to clients
	DNSServers     []string          `json:"dnsServers,omitempty"`     // DNS servers handed to clients
	Domain         string            `json:"domain,omitempty"`         // optional domain
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
	DPIEnabled       bool            `json:"dpiEnabled,omitempty"`       // master DPI on/off
	DPIMode          string          `json:"dpiMode,omitempty"`          // "learn" or "enforce" (ICS DPI global mode)
	DPIProtocols     map[string]bool `json:"dpiProtocols,omitempty"`     // per-IT-protocol enable: "dns","tls","http","ssh","smb","ntp","snmp","rdp"
	DPIICSProtocols  map[string]bool `json:"dpiIcsProtocols,omitempty"`  // per-ICS-protocol enable: "modbus","dnp3","cip","s7comm","mms","bacnet","opcua"
	DPIExclusions    []DPIExclusion  `json:"dpiExclusions,omitempty"`    // IPs/domains excluded from DPI
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
	Enabled bool   `json:"enabled,omitempty"`             // enable DPI event export
	Format  string `json:"format,omitempty"`              // cef, json, syslog
	Target  string `json:"target,omitempty"`              // file:///path, udp://host:514, tcp://host:514
	Filter  string `json:"filter,omitempty"`              // all, ics-only, alerts-only
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
	Filter      string `json:"filter,omitempty"`   // e.g. "sourceFormat:suricata AND proto:modbus"
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
	References    []string `json:"references,omitempty"`
	CVE           []string `json:"cve,omitempty"`
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
	Name    string `json:"name"`              // e.g. "$hex_modbus"
	Pattern string `json:"pattern"`
	Type    string `json:"type"`              // text|hex|regex
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
	EndTime    string   `json:"endTime,omitempty"`     // HH:MM
	Timezone   string   `json:"timezone,omitempty"`    // IANA timezone, e.g. "America/New_York"
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

// Validate performs basic consistency checks on the config.
func (c *Config) Validate() error {
	if c == nil {
		return errors.New("config is nil")
	}
	if err := UpgradeInPlace(c); err != nil {
		return err
	}
	if err := validateHostname(c.System.Hostname); err != nil {
		return err
	}
	if err := validateMgmt(c.System.Mgmt); err != nil {
		return err
	}
	if err := validateSSH(c.System.SSH); err != nil {
		return err
	}
	if err := validateZones(c.Zones); err != nil {
		return err
	}
	if err := validateInterfaces(c.Interfaces, c.Zones); err != nil {
		return err
	}
	if err := validateFirewall(c.Firewall, c.Zones, c.Interfaces); err != nil {
		return err
	}
	if err := validateAssets(c.Assets, c.Zones); err != nil {
		return err
	}
	if err := validateObjects(c.Objects); err != nil {
		return err
	}
	if err := validateRouting(c.Routing, c.Interfaces, c.Zones); err != nil {
		return err
	}
	if err := validateDataPlane(c.DataPlane); err != nil {
		return err
	}
	if err := validatePCAP(c.PCAP); err != nil {
		return err
	}
	if err := validateIDS(c.IDS); err != nil {
		return err
	}
	if err := validateServices(c.Services, c.Interfaces, c.Zones); err != nil {
		return err
	}
	return nil
}

func validateHostname(h string) error {
	if h == "" {
		return nil
	}
	if len(h) > 253 {
		return fmt.Errorf("hostname too long: %d", len(h))
	}
	return nil
}

func validateMgmt(m MgmtConfig) error {
	if m.ListenAddr != "" && len(m.ListenAddr) > 128 {
		return fmt.Errorf("mgmt.listenAddr too long")
	}
	if m.HTTPListenAddr != "" && len(m.HTTPListenAddr) > 128 {
		return fmt.Errorf("mgmt.httpListenAddr too long")
	}
	if m.HTTPSListenAddr != "" && len(m.HTTPSListenAddr) > 128 {
		return fmt.Errorf("mgmt.httpsListenAddr too long")
	}
	if m.TLSCertFile != "" && len(m.TLSCertFile) > 256 {
		return fmt.Errorf("mgmt.tlsCertFile too long")
	}
	if m.TLSKeyFile != "" && len(m.TLSKeyFile) > 256 {
		return fmt.Errorf("mgmt.tlsKeyFile too long")
	}
	if m.TrustedCAFile != "" && len(m.TrustedCAFile) > 256 {
		return fmt.Errorf("mgmt.trustedCAFile too long")
	}
	if m.HSTSMaxAgeSeconds < 0 || m.HSTSMaxAgeSeconds > 10*365*24*60*60 {
		return fmt.Errorf("mgmt.hstsMaxAgeSeconds out of range")
	}
	// We accept anything net/http can listen on; detailed parsing later.
	return nil
}

func validateSSH(s SSHConfig) error {
	if s.ListenAddr != "" && len(s.ListenAddr) > 128 {
		return fmt.Errorf("ssh.listenAddr too long")
	}
	if s.AuthorizedKeysDir != "" && len(s.AuthorizedKeysDir) > 256 {
		return fmt.Errorf("ssh.authorizedKeysDir too long")
	}
	return nil
}

func validateZones(zones []Zone) error {
	seen := map[string]struct{}{}
	seenLower := map[string]struct{}{}
	aliasSeen := map[string]struct{}{}
	for _, z := range zones {
		if z.Name == "" {
			return errors.New("zone name cannot be empty")
		}
		if _, exists := seen[z.Name]; exists {
			return fmt.Errorf("duplicate zone: %s", z.Name)
		}
		seen[z.Name] = struct{}{}
		seenLower[strings.ToLower(z.Name)] = struct{}{}
		if strings.TrimSpace(z.Alias) != "" {
			if z.Alias != strings.TrimSpace(z.Alias) {
				return fmt.Errorf("zone %s alias has leading/trailing whitespace", z.Name)
			}
			key := strings.ToLower(z.Alias)
			if _, ok := aliasSeen[key]; ok {
				return fmt.Errorf("duplicate zone alias: %s", z.Alias)
			}
			if _, ok := seenLower[key]; ok {
				return fmt.Errorf("zone alias conflicts with zone name: %s", z.Alias)
			}
			aliasSeen[key] = struct{}{}
		}
	}
	return nil
}

func validateInterfaces(ifaces []Interface, zones []Zone) error {
	zoneSet := map[string]struct{}{}
	for _, z := range zones {
		zoneSet[z.Name] = struct{}{}
	}
	seen := map[string]struct{}{}
	seenLower := map[string]struct{}{}
	aliasSeen := map[string]struct{}{}
	seenDevices := map[string]struct{}{}
	// Validate cross-interface references for bridges/VLANs.
	byName := map[string]Interface{}
	for _, iface := range ifaces {
		if strings.TrimSpace(iface.Name) != "" {
			byName[iface.Name] = iface
		}
	}
	for _, iface := range ifaces {
		if iface.Name == "" {
			return errors.New("interface name cannot be empty")
		}
		if _, exists := seen[iface.Name]; exists {
			return fmt.Errorf("duplicate interface: %s", iface.Name)
		}
		seen[iface.Name] = struct{}{}
		seenLower[strings.ToLower(iface.Name)] = struct{}{}
		if strings.TrimSpace(iface.Alias) != "" {
			if iface.Alias != strings.TrimSpace(iface.Alias) {
				return fmt.Errorf("interface %s alias has leading/trailing whitespace", iface.Name)
			}
			key := strings.ToLower(iface.Alias)
			if _, ok := aliasSeen[key]; ok {
				return fmt.Errorf("duplicate interface alias: %s", iface.Alias)
			}
			if _, ok := seenLower[key]; ok {
				return fmt.Errorf("interface alias conflicts with interface name: %s", iface.Alias)
			}
			aliasSeen[key] = struct{}{}
		}
		if strings.TrimSpace(iface.Device) != "" {
			if iface.Device != strings.TrimSpace(iface.Device) {
				return fmt.Errorf("interface %s device has leading/trailing whitespace", iface.Name)
			}
			if _, exists := seenDevices[iface.Device]; exists {
				return fmt.Errorf("duplicate interface device binding: %s", iface.Device)
			}
			seenDevices[iface.Device] = struct{}{}
		}
		if iface.Zone != "" {
			if _, ok := zoneSet[iface.Zone]; !ok {
				return fmt.Errorf("interface %s references unknown zone %s", iface.Name, iface.Zone)
			}
		}
		if t := strings.ToLower(strings.TrimSpace(iface.Type)); t != "" && t != "physical" && t != "bridge" && t != "vlan" {
			return fmt.Errorf("interface %s has invalid type %q", iface.Name, iface.Type)
		}
		if t := strings.ToLower(strings.TrimSpace(iface.Type)); t == "bridge" {
			if len(iface.Members) == 0 {
				return fmt.Errorf("interface %s type bridge requires members", iface.Name)
			}
			for _, m := range iface.Members {
				m = strings.TrimSpace(m)
				if m == "" {
					return fmt.Errorf("interface %s has empty bridge member", iface.Name)
				}
				if m == iface.Name {
					return fmt.Errorf("interface %s cannot include itself as a bridge member", iface.Name)
				}
				if ref, ok := byName[m]; ok && strings.ToLower(strings.TrimSpace(ref.Type)) == "bridge" {
					return fmt.Errorf("interface %s bridge member %q is also a bridge (nested bridges not supported)", iface.Name, m)
				}
			}
		}
		if t := strings.ToLower(strings.TrimSpace(iface.Type)); t == "vlan" {
			if strings.TrimSpace(iface.Parent) == "" {
				return fmt.Errorf("interface %s type vlan requires parent", iface.Name)
			}
			if iface.VLANID < 1 || iface.VLANID > 4094 {
				return fmt.Errorf("interface %s has invalid vlanId %d (expected 1-4094)", iface.Name, iface.VLANID)
			}
		}
		if m := strings.ToLower(strings.TrimSpace(iface.AddressMode)); m != "" && m != "static" && m != "dhcp" {
			return fmt.Errorf("interface %s has invalid addressMode %q", iface.Name, iface.AddressMode)
		}
		if strings.TrimSpace(iface.Gateway) != "" {
			if iface.Gateway != strings.TrimSpace(iface.Gateway) {
				return fmt.Errorf("interface %s gateway has leading/trailing whitespace", iface.Name)
			}
			if ip := net.ParseIP(iface.Gateway); ip == nil {
				return fmt.Errorf("interface %s has invalid gateway %q", iface.Name, iface.Gateway)
			}
		}
		for _, addr := range iface.Addresses {
			if _, _, err := net.ParseCIDR(addr); err != nil {
				return fmt.Errorf("interface %s has invalid CIDR %q: %w", iface.Name, addr, err)
			}
		}
	}
	return nil
}

func zoneIfaceMap(ifaces []Interface) map[string][]string {
	out := map[string][]string{}
	seen := map[string]map[string]struct{}{}
	for _, iface := range ifaces {
		z := strings.TrimSpace(iface.Zone)
		if z == "" {
			continue
		}
		name := strings.TrimSpace(iface.Name)
		if strings.TrimSpace(iface.Device) != "" {
			name = strings.TrimSpace(iface.Device)
		}
		if name == "" {
			continue
		}
		if _, ok := seen[z]; !ok {
			seen[z] = map[string]struct{}{}
		}
		if _, ok := seen[z][name]; ok {
			continue
		}
		seen[z][name] = struct{}{}
		out[z] = append(out[z], name)
	}
	for z := range out {
		sort.Strings(out[z])
	}
	return out
}

func validateFirewall(f FirewallConfig, zones []Zone, ifaces []Interface) error {
	zoneSet := map[string]struct{}{}
	for _, z := range zones {
		zoneSet[z.Name] = struct{}{}
	}
	zoneIfaces := zoneIfaceMap(ifaces)
	if err := validateNAT(f.NAT, zoneSet, zoneIfaces); err != nil {
		return err
	}
	ruleIDs := map[string]struct{}{}
	for _, r := range f.Rules {
		if r.ID == "" {
			return errors.New("firewall rule ID cannot be empty")
		}
		if _, exists := ruleIDs[r.ID]; exists {
			return fmt.Errorf("duplicate firewall rule ID: %s", r.ID)
		}
		ruleIDs[r.ID] = struct{}{}
		if r.Action != ActionAllow && r.Action != ActionDeny {
			return fmt.Errorf("rule %s has invalid action %q", r.ID, r.Action)
		}
		for _, z := range append(r.SourceZones, r.DestZones...) {
			if z == "" {
				return fmt.Errorf("rule %s has empty zone reference", r.ID)
			}
			if _, ok := zoneSet[z]; !ok {
				return fmt.Errorf("rule %s references unknown zone %s", r.ID, z)
			}
		}
		for _, cidr := range append(r.Sources, r.Destinations...) {
			if isSpecialCIDRToken(cidr) {
				continue
			}
			if _, _, err := net.ParseCIDR(cidr); err != nil {
				return fmt.Errorf("rule %s has invalid CIDR %q: %w", r.ID, cidr, err)
			}
		}
		for _, p := range r.Protocols {
			if p.Name == "" {
				return fmt.Errorf("rule %s has protocol with empty name", r.ID)
			}
		}
		for _, id := range r.Identities {
			if strings.TrimSpace(id) == "" {
				return fmt.Errorf("rule %s has empty identity", r.ID)
			}
		}
		if err := validateICSPredicate(r.ICS, r.ID); err != nil {
			return err
		}
		if err := validateSchedule(r.Schedule, r.ID); err != nil {
			return err
		}
	}
	return nil
}

var validDays = map[string]struct{}{
	"Sunday": {}, "Monday": {}, "Tuesday": {}, "Wednesday": {},
	"Thursday": {}, "Friday": {}, "Saturday": {},
}

func validateSchedule(s *ScheduleConfig, ruleID string) error {
	if s == nil {
		return nil
	}
	for _, d := range s.DaysOfWeek {
		if _, ok := validDays[d]; !ok {
			return fmt.Errorf("rule %s schedule has invalid day %q", ruleID, d)
		}
	}
	if s.StartTime != "" {
		if err := validateHHMM(s.StartTime); err != nil {
			return fmt.Errorf("rule %s schedule startTime: %w", ruleID, err)
		}
	}
	if s.EndTime != "" {
		if err := validateHHMM(s.EndTime); err != nil {
			return fmt.Errorf("rule %s schedule endTime: %w", ruleID, err)
		}
	}
	if s.Timezone != "" {
		if _, err := time.LoadLocation(s.Timezone); err != nil {
			return fmt.Errorf("rule %s schedule timezone %q: %w", ruleID, s.Timezone, err)
		}
	}
	return nil
}

func validateHHMM(s string) error {
	if len(s) != 5 || s[2] != ':' {
		return fmt.Errorf("invalid time format %q, expected HH:MM", s)
	}
	h, err := strconv.Atoi(s[:2])
	if err != nil || h < 0 || h > 23 {
		return fmt.Errorf("invalid hour in %q", s)
	}
	m, err := strconv.Atoi(s[3:])
	if err != nil || m < 0 || m > 59 {
		return fmt.Errorf("invalid minute in %q", s)
	}
	return nil
}

func isSpecialCIDRToken(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "vpn:any", "vpn:all", "vpn:*":
		return true
	case "vpn:wireguard", "vpn:wg":
		return true
	case "vpn:openvpn", "vpn:ovpn":
		return true
	default:
		return false
	}
}

func validateNAT(n NATConfig, zoneSet map[string]struct{}, zoneIfaces map[string][]string) error {
	// Validate SNAT fields only when enabled.
	if n.Enabled {
		egress := strings.TrimSpace(n.EgressZone)
		if egress == "" {
			egress = "wan"
		}
		if _, ok := zoneSet[egress]; !ok {
			return fmt.Errorf("nat.egressZone references unknown zone %s", egress)
		}
		srcZones := n.SourceZones
		if len(srcZones) == 0 {
			srcZones = defaultNATSourceZones(zoneSet, egress)
		}
		for _, z := range srcZones {
			z = strings.TrimSpace(z)
			if z == "" {
				continue
			}
			if _, ok := zoneSet[z]; !ok {
				return fmt.Errorf("nat.sourceZones references unknown zone %s", z)
			}
		}
	}
	// Validate DNAT port forwards regardless of SNAT enabled state.
	if err := validatePortForwards(n.PortForwards, zoneSet, zoneIfaces); err != nil {
		return err
	}
	return nil
}

type portForwardBinding struct {
	id    string
	any   bool
	cidrs []*net.IPNet
}

func validatePortForwards(pfs []PortForward, zoneSet map[string]struct{}, zoneIfaces map[string][]string) error {
	if len(pfs) == 0 {
		return nil
	}
	ids := map[string]struct{}{}
	bindings := map[string][]portForwardBinding{}     // ingress|proto|listenPort
	ifaceBindings := map[string][]portForwardBinding{} // iface|proto|listenPort
	for _, pf := range pfs {
		if strings.TrimSpace(pf.ID) == "" {
			return fmt.Errorf("nat.portForwards[].id cannot be empty")
		}
		if _, ok := ids[pf.ID]; ok {
			return fmt.Errorf("duplicate nat.portForwards id: %s", pf.ID)
		}
		ids[pf.ID] = struct{}{}

		ingress := strings.TrimSpace(pf.IngressZone)
		if ingress == "" {
			return fmt.Errorf("port-forward %s ingressZone cannot be empty", pf.ID)
		}
		if _, ok := zoneSet[ingress]; !ok {
			return fmt.Errorf("port-forward %s ingressZone references unknown zone %s", pf.ID, ingress)
		}

		proto := strings.ToLower(strings.TrimSpace(pf.Proto))
		if proto != "tcp" && proto != "udp" {
			return fmt.Errorf("port-forward %s proto must be tcp or udp", pf.ID)
		}
		if pf.ListenPort <= 0 || pf.ListenPort > 65535 {
			return fmt.Errorf("port-forward %s listenPort out of range: %d", pf.ID, pf.ListenPort)
		}
		if strings.TrimSpace(pf.DestIP) == "" {
			return fmt.Errorf("port-forward %s destIp cannot be empty", pf.ID)
		}
		ip := net.ParseIP(strings.TrimSpace(pf.DestIP))
		if ip == nil || ip.To4() == nil {
			return fmt.Errorf("port-forward %s destIp must be an IPv4 address: %q", pf.ID, pf.DestIP)
		}
		if pf.DestPort != 0 && (pf.DestPort < 1 || pf.DestPort > 65535) {
			return fmt.Errorf("port-forward %s destPort out of range: %d", pf.ID, pf.DestPort)
		}
		allowed, err := parseIPv4CIDRs(pf.AllowedSources)
		if err != nil {
			return fmt.Errorf("port-forward %s has invalid allowedSources: %w", pf.ID, err)
		}

		binding := portForwardBinding{
			id:    pf.ID,
			any:   len(allowed) == 0,
			cidrs: allowed,
		}

		zoneKey := fmt.Sprintf("%s|%s|%d", ingress, proto, pf.ListenPort)
		if err := ensureNoOverlap(bindings, zoneKey, binding, fmt.Sprintf("ingress %s %s/%d", ingress, proto, pf.ListenPort)); err != nil {
			return err
		}
		bindings[zoneKey] = append(bindings[zoneKey], binding)

		ifaces := zoneIfaces[ingress]
		for _, iface := range ifaces {
			ifaceKey := fmt.Sprintf("%s|%s|%d", iface, proto, pf.ListenPort)
			if err := ensureNoOverlap(ifaceBindings, ifaceKey, binding, fmt.Sprintf("interface %s %s/%d", iface, proto, pf.ListenPort)); err != nil {
				return err
			}
			ifaceBindings[ifaceKey] = append(ifaceBindings[ifaceKey], binding)
		}
	}
	return nil
}

func ensureNoOverlap(bindings map[string][]portForwardBinding, key string, next portForwardBinding, context string) error {
	for _, existing := range bindings[key] {
		if !bindingsOverlap(existing, next) {
			continue
		}
		return fmt.Errorf("port-forward %s overlaps with %s on %s", next.id, existing.id, context)
	}
	return nil
}

func bindingsOverlap(a, b portForwardBinding) bool {
	if a.any || b.any {
		return true
	}
	for _, ac := range a.cidrs {
		for _, bc := range b.cidrs {
			if cidrOverlap(ac, bc) {
				return true
			}
		}
	}
	return false
}

func parseIPv4CIDRs(in []string) ([]*net.IPNet, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make([]*net.IPNet, 0, len(in))
	for _, raw := range in {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		ip, cidr, err := net.ParseCIDR(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q", raw)
		}
		if ip == nil || ip.To4() == nil {
			return nil, fmt.Errorf("non-IPv4 CIDR %q", raw)
		}
		out = append(out, cidr)
	}
	return out, nil
}

func cidrOverlap(a, b *net.IPNet) bool {
	if a == nil || b == nil {
		return false
	}
	return a.Contains(b.IP) || b.Contains(a.IP)
}

func defaultNATSourceZones(zoneSet map[string]struct{}, egress string) []string {
	if len(zoneSet) == 0 {
		return nil
	}
	egress = strings.TrimSpace(egress)
	out := make([]string, 0, len(zoneSet))
	zoneLower := map[string]struct{}{}
	for z := range zoneSet {
		if z == "" || strings.EqualFold(z, egress) {
			continue
		}
		zoneLower[strings.ToLower(z)] = struct{}{}
		out = append(out, z)
	}
	sort.Strings(out)
	if len(out) == 0 {
		for _, name := range []string{"lan", "dmz"} {
			if _, ok := zoneLower[name]; ok && !strings.EqualFold(name, egress) {
				out = append(out, name)
			}
		}
		sort.Strings(out)
	}
	return out
}

func validateICSPredicate(p ICSPredicate, ruleID string) error {
	if p.Protocol == "" {
		return nil
	}
	if p.Mode != "" && p.Mode != "learn" && p.Mode != "enforce" {
		return fmt.Errorf("rule %s ics mode invalid %q", ruleID, p.Mode)
	}
	// Placeholder validation: enforce mutual exclusivity for read/write classes.
	if p.ReadOnly && p.WriteOnly {
		return fmt.Errorf("rule %s ics predicate cannot be both readOnly and writeOnly", ruleID)
	}
	// Validate direction if set.
	if p.Direction != "" && p.Direction != "request" && p.Direction != "response" {
		return fmt.Errorf("rule %s ics direction invalid %q", ruleID, p.Direction)
	}
	// If function codes are set, ensure protocol supports them.
	if len(p.FunctionCode) > 0 && p.Protocol != "modbus" && p.Protocol != "dnp3" && p.Protocol != "cip" && p.Protocol != "s7comm" && p.Protocol != "bacnet" && p.Protocol != "opcua" && p.Protocol != "mms" {
		return fmt.Errorf("rule %s ics functionCode only supported for modbus, dnp3, cip, s7comm, bacnet, opcua, and mms currently", ruleID)
	}
	// ObjectClasses only make sense for CIP.
	if len(p.ObjectClasses) > 0 && p.Protocol != "cip" {
		return fmt.Errorf("rule %s ics objectClasses only supported for cip protocol", ruleID)
	}
	return nil
}

func validateAssets(assets []Asset, zones []Zone) error {
	zoneSet := map[string]struct{}{}
	for _, z := range zones {
		zoneSet[z.Name] = struct{}{}
	}
	ids := map[string]struct{}{}
	names := map[string]struct{}{}
	idsLower := map[string]struct{}{}
	namesLower := map[string]struct{}{}
	aliasSeen := map[string]struct{}{}
	for _, a := range assets {
		if a.ID == "" {
			return errors.New("asset id cannot be empty")
		}
		if _, ok := ids[a.ID]; ok {
			return fmt.Errorf("duplicate asset id: %s", a.ID)
		}
		ids[a.ID] = struct{}{}
		idsLower[strings.ToLower(a.ID)] = struct{}{}
		if a.Name == "" {
			return fmt.Errorf("asset %s name cannot be empty", a.ID)
		}
		if _, ok := names[a.Name]; ok {
			return fmt.Errorf("duplicate asset name: %s", a.Name)
		}
		names[a.Name] = struct{}{}
		namesLower[strings.ToLower(a.Name)] = struct{}{}
		if strings.TrimSpace(a.Alias) != "" {
			if a.Alias != strings.TrimSpace(a.Alias) {
				return fmt.Errorf("asset %s alias has leading/trailing whitespace", a.ID)
			}
			key := strings.ToLower(a.Alias)
			if _, ok := aliasSeen[key]; ok {
				return fmt.Errorf("duplicate asset alias: %s", a.Alias)
			}
			if _, ok := idsLower[key]; ok {
				return fmt.Errorf("asset alias conflicts with asset id: %s", a.Alias)
			}
			if _, ok := namesLower[key]; ok {
				return fmt.Errorf("asset alias conflicts with asset name: %s", a.Alias)
			}
			aliasSeen[key] = struct{}{}
		}
		if a.Zone != "" {
			if _, ok := zoneSet[a.Zone]; !ok {
				return fmt.Errorf("asset %s references unknown zone %s", a.ID, a.Zone)
			}
		}
		for _, ipStr := range a.IPs {
			if net.ParseIP(ipStr) == nil {
				return fmt.Errorf("asset %s has invalid ip %q", a.ID, ipStr)
			}
		}
		if a.Criticality != "" &&
			a.Criticality != CriticalityLow &&
			a.Criticality != CriticalityMedium &&
			a.Criticality != CriticalityHigh &&
			a.Criticality != CriticalityCritical {
			return fmt.Errorf("asset %s has invalid criticality %q", a.ID, a.Criticality)
		}
		if a.Type != "" &&
			a.Type != AssetPLC &&
			a.Type != AssetHMI &&
			a.Type != AssetSIS &&
			a.Type != AssetRTU &&
			a.Type != AssetHistorian &&
			a.Type != AssetEWS &&
			a.Type != AssetGateway &&
			a.Type != AssetLaptop &&
			a.Type != AssetOther {
			return fmt.Errorf("asset %s has invalid type %q", a.ID, a.Type)
		}
	}
	return nil
}

func validateObjects(objects []Object) error {
	if len(objects) == 0 {
		return nil
	}
	ids := map[string]struct{}{}
	names := map[string]struct{}{}
	idsLower := map[string]struct{}{}
	namesLower := map[string]struct{}{}
	for _, obj := range objects {
		if obj.ID == "" {
			return errors.New("object id cannot be empty")
		}
		if _, ok := ids[obj.ID]; ok {
			return fmt.Errorf("duplicate object id: %s", obj.ID)
		}
		ids[obj.ID] = struct{}{}
		idsLower[strings.ToLower(obj.ID)] = struct{}{}
		if obj.Name == "" {
			return fmt.Errorf("object %s name cannot be empty", obj.ID)
		}
		if _, ok := names[obj.Name]; ok {
			return fmt.Errorf("duplicate object name: %s", obj.Name)
		}
		names[obj.Name] = struct{}{}
		namesLower[strings.ToLower(obj.Name)] = struct{}{}
		switch obj.Type {
		case ObjectHost:
			for _, addr := range obj.Addresses {
				if err := validateObjectHostAddress(addr); err != nil {
					return fmt.Errorf("object %s has invalid host address %q: %w", obj.ID, addr, err)
				}
			}
		case ObjectSubnet:
			for _, addr := range obj.Addresses {
				if err := validateObjectSubnetAddress(addr); err != nil {
					return fmt.Errorf("object %s has invalid subnet %q: %w", obj.ID, addr, err)
				}
			}
		case ObjectGroup:
			// Members validated after IDs are collected.
		case ObjectService:
			if len(obj.Protocols) == 0 {
				return fmt.Errorf("object %s service must include at least one protocol", obj.ID)
			}
			for _, p := range obj.Protocols {
				if strings.TrimSpace(p.Name) == "" {
					return fmt.Errorf("object %s service protocol name cannot be empty", obj.ID)
				}
				if err := validatePortString(p.Port); err != nil {
					return fmt.Errorf("object %s service protocol port %q invalid: %w", obj.ID, p.Port, err)
				}
			}
		default:
			return fmt.Errorf("object %s has invalid type %q", obj.ID, obj.Type)
		}
	}
	for _, obj := range objects {
		if obj.Type != ObjectGroup {
			continue
		}
		for _, member := range obj.Members {
			if member == "" {
				return fmt.Errorf("object %s group member cannot be empty", obj.ID)
			}
			if member == obj.ID {
				return fmt.Errorf("object %s group cannot include itself", obj.ID)
			}
			if _, ok := ids[member]; !ok {
				return fmt.Errorf("object %s references unknown member %s", obj.ID, member)
			}
		}
	}
	if len(idsLower) != len(ids) || len(namesLower) != len(names) {
		return errors.New("object ids and names must be unique case-insensitively")
	}
	return nil
}

func validateObjectHostAddress(addr string) error {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return errors.New("address cannot be empty")
	}
	if strings.Contains(addr, "/") {
		return errors.New("host addresses must not be CIDR")
	}
	if net.ParseIP(addr) != nil {
		return nil
	}
	if strings.ContainsAny(addr, " \t\n") {
		return errors.New("hostname contains whitespace")
	}
	if err := validateHostname(addr); err != nil {
		return err
	}
	return nil
}

func validateObjectSubnetAddress(addr string) error {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return errors.New("subnet cannot be empty")
	}
	if _, _, err := net.ParseCIDR(addr); err != nil {
		return err
	}
	return nil
}

func validatePortString(port string) error {
	port = strings.TrimSpace(port)
	if port == "" {
		return nil
	}
	parts := strings.Split(port, "-")
	if len(parts) > 2 {
		return errors.New("invalid port range")
	}
	start, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil || start < 1 || start > 65535 {
		return fmt.Errorf("invalid port %q", port)
	}
	if len(parts) == 1 {
		return nil
	}
	end, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil || end < 1 || end > 65535 || end < start {
		return fmt.Errorf("invalid port range %q", port)
	}
	return nil
}

func validateRouting(r RoutingConfig, ifaces []Interface, zones []Zone) error {
	if len(r.Gateways) == 0 && len(r.Routes) == 0 && len(r.Rules) == 0 {
		return nil
	}
	ifaceSet := map[string]struct{}{}
	for _, iface := range ifaces {
		if strings.TrimSpace(iface.Name) != "" {
			ifaceSet[iface.Name] = struct{}{}
		}
		if strings.TrimSpace(iface.Device) != "" {
			ifaceSet[iface.Device] = struct{}{}
		}
	}
	zoneSet := map[string]struct{}{}
	for _, z := range zones {
		zoneSet[z.Name] = struct{}{}
	}
	_ = zoneSet

	gwByName := map[string]Gateway{}
	gwNamesLower := map[string]struct{}{}
	gwAliasLower := map[string]struct{}{}
	for _, gw := range r.Gateways {
		name := strings.TrimSpace(gw.Name)
		if name == "" {
			return errors.New("routing.gateways name cannot be empty")
		}
		if _, ok := gwByName[name]; ok {
			return fmt.Errorf("routing.gateways duplicate name %q", name)
		}
		gwNamesLower[strings.ToLower(name)] = struct{}{}
		addr := strings.TrimSpace(gw.Address)
		ip := net.ParseIP(addr)
		if ip == nil || ip.To4() == nil {
			return fmt.Errorf("routing.gateways %s address must be an IPv4 address", name)
		}
		if ifn := strings.TrimSpace(gw.Iface); ifn != "" {
			if _, ok := ifaceSet[ifn]; !ok {
				return fmt.Errorf("routing.gateways %s iface unknown %q", name, gw.Iface)
			}
		}
		if strings.TrimSpace(gw.Alias) != "" {
			if gw.Alias != strings.TrimSpace(gw.Alias) {
				return fmt.Errorf("routing.gateways %s alias has leading/trailing whitespace", name)
			}
			aliasKey := strings.ToLower(gw.Alias)
			if _, ok := gwAliasLower[aliasKey]; ok {
				return fmt.Errorf("routing.gateways duplicate alias %q", gw.Alias)
			}
			if _, ok := gwNamesLower[aliasKey]; ok {
				return fmt.Errorf("routing.gateways alias conflicts with gateway name %q", gw.Alias)
			}
			gwAliasLower[aliasKey] = struct{}{}
		}
		gwByName[name] = gw
	}

	for _, rt := range r.Routes {
		dst := strings.TrimSpace(rt.Dst)
		if dst == "" {
			return errors.New("routing.routes dst cannot be empty")
		}
		if strings.EqualFold(dst, "default") {
			dst = "0.0.0.0/0"
		}
		if _, _, err := net.ParseCIDR(dst); err != nil {
			return fmt.Errorf("routing.routes dst invalid %q: %w", rt.Dst, err)
		}
		if gw := strings.TrimSpace(rt.Gateway); gw != "" {
			if net.ParseIP(gw) == nil {
				if _, ok := gwByName[gw]; !ok {
					return fmt.Errorf("routing.routes gateway invalid %q (must be IP or a defined gateway name)", rt.Gateway)
				}
			}
		}
		if ifn := strings.TrimSpace(rt.Iface); ifn != "" {
			if _, ok := ifaceSet[ifn]; !ok {
				return fmt.Errorf("routing.routes iface unknown %q", rt.Iface)
			}
		}
		if rt.Table < 0 || rt.Table > 252 {
			return fmt.Errorf("routing.routes table out of range: %d", rt.Table)
		}
		if rt.Metric < 0 || rt.Metric > 999999 {
			return fmt.Errorf("routing.routes metric out of range: %d", rt.Metric)
		}
	}

	seenPrio := map[int]struct{}{}
	for _, rule := range r.Rules {
		if rule.Table <= 0 || rule.Table > 252 {
			return fmt.Errorf("routing.rules table out of range: %d", rule.Table)
		}
		if rule.Priority < 0 || rule.Priority > 65535 {
			return fmt.Errorf("routing.rules priority out of range: %d", rule.Priority)
		}
		if rule.Priority != 0 {
			if _, ok := seenPrio[rule.Priority]; ok {
				return fmt.Errorf("routing.rules duplicate priority %d", rule.Priority)
			}
			seenPrio[rule.Priority] = struct{}{}
		}
		if src := strings.TrimSpace(rule.Src); src != "" {
			if _, _, err := net.ParseCIDR(src); err != nil {
				return fmt.Errorf("routing.rules src invalid %q: %w", rule.Src, err)
			}
		}
		if dst := strings.TrimSpace(rule.Dst); dst != "" {
			if _, _, err := net.ParseCIDR(dst); err != nil {
				return fmt.Errorf("routing.rules dst invalid %q: %w", rule.Dst, err)
			}
		}
	}
	return nil
}

func validateDataPlane(dp DataPlaneConfig) error {
	for _, name := range dp.CaptureInterfaces {
		if name == "" {
			return errors.New("dataplane.captureInterfaces cannot include empty name")
		}
	}
	if dp.EnforceTable == "" {
		return nil
	}
	// nftables table names are simple identifiers.
	for _, r := range dp.EnforceTable {
		if !(r == '_' || r == '-' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return fmt.Errorf("dataplane.enforceTable has invalid char %q", r)
		}
	}
	return nil
}

func validatePCAP(p PCAPConfig) error {
	for _, name := range p.Interfaces {
		if strings.TrimSpace(name) == "" {
			return errors.New("pcap.interfaces cannot include empty name")
		}
	}
	if p.Enabled && len(p.Interfaces) == 0 {
		return errors.New("pcap.enabled requires at least one interface")
	}
	if p.Snaplen < 0 {
		return errors.New("pcap.snaplen must be >= 0")
	}
	if p.MaxSizeMB < 0 {
		return errors.New("pcap.maxSizeMB must be >= 0")
	}
	if p.MaxFiles < 0 {
		return errors.New("pcap.maxFiles must be >= 0")
	}
	if p.BufferMB < 0 {
		return errors.New("pcap.bufferMB must be >= 0")
	}
	if p.RotateSeconds < 0 {
		return errors.New("pcap.rotateSeconds must be >= 0")
	}
	if p.Mode != "" && p.Mode != "rolling" && p.Mode != "once" {
		return fmt.Errorf("pcap.mode invalid %q", p.Mode)
	}
	if proto := strings.ToLower(strings.TrimSpace(p.Filter.Proto)); proto != "" && proto != "any" && proto != "tcp" && proto != "udp" && proto != "icmp" {
		return fmt.Errorf("pcap.filter.proto invalid %q", p.Filter.Proto)
	}
	for _, t := range p.ForwardTargets {
		if strings.TrimSpace(t.Interface) == "" {
			return errors.New("pcap.forwardTargets.interface cannot be empty")
		}
		if t.Enabled {
			if strings.TrimSpace(t.Host) == "" {
				return errors.New("pcap.forwardTargets.host is required when enabled")
			}
			if t.Port <= 0 || t.Port > 65535 {
				return fmt.Errorf("pcap.forwardTargets.port out of range: %d", t.Port)
			}
		}
		if t.Proto != "" && t.Proto != "tcp" && t.Proto != "udp" {
			return fmt.Errorf("pcap.forwardTargets.proto invalid %q", t.Proto)
		}
	}
	return nil
}

func validateServices(s ServicesConfig, ifaces []Interface, zones []Zone) error {
	for _, fwd := range s.Syslog.Forwarders {
		if fwd.Address == "" {
			return errors.New("syslog forwarder address is required")
		}
		if fwd.Port <= 0 || fwd.Port > 65535 {
			return fmt.Errorf("syslog forwarder %s has invalid port %d", fwd.Address, fwd.Port)
		}
		if fwd.Proto != "" && fwd.Proto != "udp" && fwd.Proto != "tcp" {
			return fmt.Errorf("syslog forwarder %s has invalid proto %q", fwd.Address, fwd.Proto)
		}
	}
	if s.DNS.ListenPort != 0 && (s.DNS.ListenPort < 1 || s.DNS.ListenPort > 65535) {
		return fmt.Errorf("dns listenPort invalid: %d", s.DNS.ListenPort)
	}
	for _, z := range s.DNS.ListenZones {
		if z == "" {
			return errors.New("dns listenZones cannot include empty")
		}
	}
	for _, u := range s.DNS.UpstreamServers {
		if strings.TrimSpace(u) == "" {
			return errors.New("dns upstreamServers cannot include empty")
		}
	}
	if s.DNS.CacheSizeMB < 0 {
		return errors.New("dns cacheSizeMB cannot be negative")
	}
	for _, srv := range s.NTP.Servers {
		if strings.TrimSpace(srv) == "" {
			return errors.New("ntp servers cannot include empty")
		}
	}
	if s.NTP.IntervalSeconds < 0 {
		return errors.New("ntp intervalSeconds cannot be negative")
	}
	if err := validateProxy(s.Proxy); err != nil {
		return err
	}
	if err := validateDHCP(s.DHCP); err != nil {
		return err
	}
	if err := validateVPN(s.VPN, ifaces, zones); err != nil {
		return err
	}
	if err := validateAV(s.AV); err != nil {
		return err
	}
	return nil
}

func validateAV(cfg AVConfig) error {
	if !cfg.Enabled {
		return nil
	}
	mode := strings.ToLower(strings.TrimSpace(cfg.Mode))
	if mode == "" {
		mode = "icap"
	}
	switch mode {
	case "icap", "clamav":
	default:
		return fmt.Errorf("services.av.mode must be icap or clamav")
	}
	fail := strings.ToLower(strings.TrimSpace(cfg.FailPolicy))
	if fail == "" {
		fail = "open"
	}
	if fail != "open" && fail != "closed" {
		return fmt.Errorf("services.av.failPolicy must be open or closed")
	}
	if mode == "icap" {
		if len(cfg.ICAP.Servers) == 0 {
			return fmt.Errorf("services.av.icap.servers must not be empty when mode=icap")
		}
		for i, s := range cfg.ICAP.Servers {
			if strings.TrimSpace(s.Address) == "" {
				return fmt.Errorf("services.av.icap.servers[%d].address required", i)
			}
		}
	}
	if mode == "clamav" {
		if strings.TrimSpace(cfg.ClamAV.SocketPath) == "" {
			return fmt.Errorf("services.av.clamav.socketPath required when mode=clamav")
		}
	}
	return nil
}

func validateProxy(p ProxyConfig) error {
	if p.Forward.ListenPort != 0 && (p.Forward.ListenPort < 1 || p.Forward.ListenPort > 65535) {
		return fmt.Errorf("forward proxy listenPort invalid: %d", p.Forward.ListenPort)
	}
	for _, z := range p.Forward.ListenZones {
		if z == "" {
			return errors.New("forward proxy listenZones cannot include empty")
		}
	}
	for _, d := range p.Forward.AllowedDomains {
		if d == "" {
			return errors.New("forward proxy allowedDomains cannot include empty")
		}
	}
	for _, s := range p.Reverse.Sites {
		if s.Name == "" {
			return errors.New("reverse proxy site name required")
		}
		if s.ListenPort < 1 || s.ListenPort > 65535 {
			return fmt.Errorf("reverse proxy site %s listenPort invalid: %d", s.Name, s.ListenPort)
		}
		if len(s.Backends) == 0 {
			return fmt.Errorf("reverse proxy site %s must have at least one backend", s.Name)
		}
	}
	return nil
}

func validateDHCP(d DHCPConfig) error {
	ipToUint32 := func(ip net.IP) uint32 {
		ip4 := ip.To4()
		if ip4 == nil {
			return 0
		}
		return (uint32(ip4[0]) << 24) | (uint32(ip4[1]) << 16) | (uint32(ip4[2]) << 8) | uint32(ip4[3])
	}
	for _, n := range d.ListenIfaces {
		if strings.TrimSpace(n) == "" {
			return errors.New("dhcp listenIfaces cannot include empty")
		}
	}
	for _, p := range d.Pools {
		if strings.TrimSpace(p.Iface) == "" {
			return errors.New("dhcp pool iface is required")
		}
		if ip := net.ParseIP(strings.TrimSpace(p.Start)); ip == nil || ip.To4() == nil {
			return fmt.Errorf("dhcp pool %s start invalid: %q", p.Iface, p.Start)
		}
		if ip := net.ParseIP(strings.TrimSpace(p.End)); ip == nil || ip.To4() == nil {
			return fmt.Errorf("dhcp pool %s end invalid: %q", p.Iface, p.End)
		}
	}
	seenRes := map[string]struct{}{}
	poolRanges := map[string][]struct {
		start net.IP
		end   net.IP
	}{}
	for _, p := range d.Pools {
		iface := strings.TrimSpace(p.Iface)
		start := net.ParseIP(strings.TrimSpace(p.Start)).To4()
		end := net.ParseIP(strings.TrimSpace(p.End)).To4()
		if iface != "" && start != nil && end != nil {
			poolRanges[iface] = append(poolRanges[iface], struct {
				start net.IP
				end   net.IP
			}{start: start, end: end})
		}
	}
	for _, r := range d.Reservations {
		if strings.TrimSpace(r.Iface) == "" {
			return errors.New("dhcp reservation iface is required")
		}
		if _, err := net.ParseMAC(strings.ToLower(strings.TrimSpace(r.MAC))); err != nil {
			return fmt.Errorf("dhcp reservation %s mac invalid: %w", r.Iface, err)
		}
		ip := net.ParseIP(strings.TrimSpace(r.IP))
		if ip == nil || ip.To4() == nil {
			return fmt.Errorf("dhcp reservation %s ip invalid: %q", r.Iface, r.IP)
		}
		key := strings.ToLower(strings.TrimSpace(r.Iface) + "|" + strings.ToLower(strings.TrimSpace(r.MAC)))
		if _, ok := seenRes[key]; ok {
			return fmt.Errorf("dhcp reservation duplicate for iface %s mac %s", r.Iface, r.MAC)
		}
		seenRes[key] = struct{}{}
		if ranges, ok := poolRanges[strings.TrimSpace(r.Iface)]; ok {
			inPool := false
			for _, pr := range ranges {
				ipv := ipToUint32(ip)
				if ipv >= ipToUint32(pr.start) && ipv <= ipToUint32(pr.end) {
					inPool = true
					break
				}
			}
			if !inPool {
				return fmt.Errorf("dhcp reservation %s ip %s not in any pool for iface", r.Iface, r.IP)
			}
		}
	}
	if d.LeaseSeconds < 0 {
		return errors.New("dhcp leaseSeconds cannot be negative")
	}
	if d.Router != "" {
		if ip := net.ParseIP(strings.TrimSpace(d.Router)); ip == nil || ip.To4() == nil {
			return fmt.Errorf("dhcp router invalid: %q", d.Router)
		}
	}
	for _, s := range d.DNSServers {
		if ip := net.ParseIP(strings.TrimSpace(s)); ip == nil || ip.To4() == nil {
			return fmt.Errorf("dhcp dnsServers invalid: %q", s)
		}
	}
	return nil
}

func validateVPN(v VPNConfig, ifaces []Interface, zones []Zone) error {
	zoneSet := map[string]struct{}{}
	for _, z := range zones {
		zoneSet[z.Name] = struct{}{}
	}
	ifaceSet := map[string]struct{}{}
	for _, iface := range ifaces {
		if strings.TrimSpace(iface.Name) != "" {
			ifaceSet[iface.Name] = struct{}{}
		}
		if strings.TrimSpace(iface.Device) != "" {
			ifaceSet[iface.Device] = struct{}{}
		}
	}
	wg := v.WireGuard
	if wg.ListenPort != 0 && (wg.ListenPort < 1 || wg.ListenPort > 65535) {
		return fmt.Errorf("vpn.wireguard listenPort invalid: %d", wg.ListenPort)
	}
	if err := validateVPNListenTargets("vpn.wireguard", wg.ListenZone, wg.ListenInterfaces, zoneSet, ifaceSet); err != nil {
		return err
	}
	if wg.AddressCIDR != "" {
		if _, _, err := net.ParseCIDR(strings.TrimSpace(wg.AddressCIDR)); err != nil {
			return fmt.Errorf("vpn.wireguard addressCIDR invalid: %q", wg.AddressCIDR)
		}
	}
	for _, p := range wg.Peers {
		if strings.TrimSpace(p.PublicKey) == "" {
			return errors.New("vpn.wireguard peer publicKey is required")
		}
		for _, cidr := range p.AllowedIPs {
			if strings.TrimSpace(cidr) == "" {
				return errors.New("vpn.wireguard allowedIPs cannot include empty")
			}
			if _, _, err := net.ParseCIDR(strings.TrimSpace(cidr)); err != nil {
				return fmt.Errorf("vpn.wireguard peer allowedIPs invalid: %q", cidr)
			}
		}
		if p.PersistentKeepalive < 0 {
			return errors.New("vpn.wireguard persistentKeepalive cannot be negative")
		}
		if p.Endpoint != "" {
			// Accept host:port (hostname or IP).
			if _, _, err := net.SplitHostPort(strings.TrimSpace(p.Endpoint)); err != nil {
				return fmt.Errorf("vpn.wireguard peer endpoint invalid: %q", p.Endpoint)
			}
		}
	}
	if v.OpenVPN.Mode != "" && v.OpenVPN.Mode != "server" && v.OpenVPN.Mode != "client" {
		return fmt.Errorf("vpn.openvpn mode invalid: %q", v.OpenVPN.Mode)
	}
	if v.OpenVPN.Enabled {
		mode := strings.TrimSpace(v.OpenVPN.Mode)
		if mode == "" {
			mode = "client"
		}
		// At least one of {configPath, managed} must be provided.
		if strings.TrimSpace(v.OpenVPN.ConfigPath) == "" && v.OpenVPN.Managed == nil && v.OpenVPN.Server == nil {
			return errors.New("vpn.openvpn enabled but neither configPath nor managed config is set")
		}
		// Managed config is client-only for now.
		if v.OpenVPN.Managed != nil {
			if mode != "client" {
				return errors.New("vpn.openvpn managed config currently supports client mode only")
			}
			m := v.OpenVPN.Managed
			if strings.TrimSpace(m.Remote) == "" {
				return errors.New("vpn.openvpn.managed remote is required")
			}
			port := m.Port
			if port == 0 {
				port = 1194
			}
			if port < 1 || port > 65535 {
				return fmt.Errorf("vpn.openvpn.managed port invalid: %d", m.Port)
			}
			proto := strings.ToLower(strings.TrimSpace(m.Proto))
			if proto == "" {
				proto = "udp"
			}
			if proto != "udp" && proto != "tcp" {
				return fmt.Errorf("vpn.openvpn.managed proto invalid: %q", m.Proto)
			}
			if strings.TrimSpace(m.CA) == "" {
				return errors.New("vpn.openvpn.managed ca is required")
			}
			if strings.TrimSpace(m.Cert) == "" {
				return errors.New("vpn.openvpn.managed cert is required")
			}
			if strings.TrimSpace(m.Key) == "" {
				return errors.New("vpn.openvpn.managed key is required")
			}
			if (strings.TrimSpace(m.Username) != "") != (strings.TrimSpace(m.Password) != "") {
				return errors.New("vpn.openvpn.managed username and password must be set together")
			}
		}
		// Managed server config
		if v.OpenVPN.Server != nil {
			if mode != "server" {
				return errors.New("vpn.openvpn server config requires mode=server")
			}
			s := v.OpenVPN.Server
			port := s.ListenPort
			if port == 0 {
				port = 1194
			}
			if port < 1 || port > 65535 {
				return fmt.Errorf("vpn.openvpn.server listenPort invalid: %d", s.ListenPort)
			}
			proto := strings.ToLower(strings.TrimSpace(s.Proto))
			if proto == "" {
				proto = "udp"
			}
			if proto != "udp" && proto != "tcp" {
				return fmt.Errorf("vpn.openvpn.server proto invalid: %q", s.Proto)
			}
			if strings.TrimSpace(s.TunnelCIDR) == "" {
				return errors.New("vpn.openvpn.server tunnelCIDR is required")
			}
			if _, _, err := net.ParseCIDR(strings.TrimSpace(s.TunnelCIDR)); err != nil {
				return fmt.Errorf("vpn.openvpn.server tunnelCIDR invalid: %q", s.TunnelCIDR)
			}
			if err := validateVPNListenTargets("vpn.openvpn.server", s.ListenZone, s.ListenInterfaces, zoneSet, ifaceSet); err != nil {
				return err
			}
			for _, ipStr := range s.PushDNS {
				if ip := net.ParseIP(strings.TrimSpace(ipStr)); ip == nil || ip.To4() == nil {
					return fmt.Errorf("vpn.openvpn.server pushDNS invalid: %q", ipStr)
				}
			}
			for _, cidr := range s.PushRoutes {
				if strings.TrimSpace(cidr) == "" {
					return errors.New("vpn.openvpn.server pushRoutes cannot include empty")
				}
				if _, _, err := net.ParseCIDR(strings.TrimSpace(cidr)); err != nil {
					return fmt.Errorf("vpn.openvpn.server pushRoutes invalid: %q", cidr)
				}
			}
		}
	}
	return nil
}

func validateVPNListenTargets(prefix, zone string, ifaces []string, zoneSet, ifaceSet map[string]struct{}) error {
	if strings.TrimSpace(zone) != "" {
		if _, ok := zoneSet[zone]; !ok {
			return fmt.Errorf("%s listenZone invalid: %s", prefix, zone)
		}
	}
	for _, name := range ifaces {
		n := strings.TrimSpace(name)
		if n == "" {
			return fmt.Errorf("%s listenInterfaces cannot include empty", prefix)
		}
		if _, ok := ifaceSet[n]; !ok {
			return fmt.Errorf("%s listenInterfaces unknown: %s", prefix, n)
		}
	}
	return nil
}

func validateIDS(ids IDSConfig) error {
	seen := map[string]struct{}{}
	for _, r := range ids.Rules {
		if r.ID == "" {
			return errors.New("ids rule id cannot be empty")
		}
		if _, ok := seen[r.ID]; ok {
			return fmt.Errorf("duplicate ids rule id: %s", r.ID)
		}
		seen[r.ID] = struct{}{}
		if r.Severity != "" {
			switch r.Severity {
			case "low", "medium", "high", "critical":
			default:
				return fmt.Errorf("ids rule %s invalid severity %q", r.ID, r.Severity)
			}
		}
	}
	return nil
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
