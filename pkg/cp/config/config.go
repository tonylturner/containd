package config

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

// Config represents the management-plane persistent configuration.
// It intentionally stays narrow until broader models are added.
type Config struct {
	SchemaVersion string          `json:"schema_version,omitempty"`
	System        SystemConfig    `json:"system"`
	Interfaces    []Interface     `json:"interfaces"`
	Zones         []Zone          `json:"zones"`
	Assets        []Asset         `json:"assets,omitempty"`
	DataPlane     DataPlaneConfig `json:"dataplane,omitempty"`
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
	if c.Zones != nil {
		cp.Zones = append([]Zone(nil), c.Zones...)
	}
	if c.Interfaces != nil {
		cp.Interfaces = append([]Interface(nil), c.Interfaces...)
	}
	if c.Firewall.Rules != nil {
		cp.Firewall.Rules = append([]Rule(nil), c.Firewall.Rules...)
	}
	// Future: redact Services secrets (proxy upstream creds, TLS keys, etc.).
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
}

type ServicesConfig struct {
	Syslog SyslogConfig `json:"syslog"`
	DNS    DNSConfig    `json:"dns,omitempty"`
	NTP    NTPConfig    `json:"ntp,omitempty"`
	Proxy  ProxyConfig  `json:"proxy,omitempty"`
}

type SyslogConfig struct {
	Forwarders []SyslogForwarder `json:"forwarders"`
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

type Interface struct {
	Name      string          `json:"name"`
	// Device binds this logical interface to a kernel interface name (e.g. "eth0", "enp3s0").
	// When empty, the logical name may be used as the kernel interface name (legacy behavior).
	Device    string          `json:"device,omitempty"`
	Zone      string          `json:"zone"`
	Addresses []string        `json:"addresses,omitempty"` // CIDR strings
	Access    InterfaceAccess `json:"access,omitempty"`
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
	}
}

// DataPlaneConfig controls runtime dataplane behavior; persisted in DB/exports.
type DataPlaneConfig struct {
	CaptureInterfaces []string `json:"captureInterfaces,omitempty"` // interface names for capture
	Enforcement       bool     `json:"enforcement,omitempty"`       // enable nftables apply
	EnforceTable      string   `json:"enforceTable,omitempty"`      // nftables table name
	DPIMock           bool     `json:"dpiMock,omitempty"`           // lab-only mock DPI loop
}

type Zone struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
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
	Type        AssetType   `json:"type"`
	Zone        string      `json:"zone,omitempty"`
	IPs         []string    `json:"ips,omitempty"`
	Hostnames   []string    `json:"hostnames,omitempty"`
	Criticality Criticality `json:"criticality,omitempty"`
	Tags        []string    `json:"tags,omitempty"`
	Description string      `json:"description,omitempty"`
}

type FirewallConfig struct {
	DefaultAction Action `json:"defaultAction"`
	Rules         []Rule `json:"rules"`
}

// IDSConfig holds native IDS rules that match on normalized DPI events.
type IDSConfig struct {
	Enabled bool      `json:"enabled"`
	Rules   []IDSRule `json:"rules,omitempty"`
}

// IDSRule is a Sigma-like event rule.
type IDSRule struct {
	ID          string            `json:"id"`
	Title       string            `json:"title,omitempty"`
	Description string            `json:"description,omitempty"`
	Proto       string            `json:"proto,omitempty"` // optional quick filter
	Kind        string            `json:"kind,omitempty"`  // optional quick filter
	When        IDSCondition      `json:"when,omitempty"`
	Severity    string            `json:"severity,omitempty"` // low|medium|high|critical
	Message     string            `json:"message,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
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

type Rule struct {
	ID           string       `json:"id"`
	Description  string       `json:"description,omitempty"`
	SourceZones  []string     `json:"sourceZones,omitempty"`
	DestZones    []string     `json:"destZones,omitempty"`
	Sources      []string     `json:"sources,omitempty"`      // CIDR strings
	Destinations []string     `json:"destinations,omitempty"` // CIDR strings
	Protocols    []Protocol   `json:"protocols,omitempty"`
	ICS          ICSPredicate `json:"ics,omitempty"`
	Action       Action       `json:"action"`
}

type Protocol struct {
	Name string `json:"name"`           // e.g. tcp, udp, icmp
	Port string `json:"port,omitempty"` // single or range "80", "443", "1000-2000"
}

// ICSPredicate captures ICS-specific primitives for rules (placeholder).
// For Phase 2, Modbus fields are supported.
type ICSPredicate struct {
	Protocol     string   `json:"protocol,omitempty"`     // modbus, dnp3, iec104, etc.
	FunctionCode []uint8  `json:"functionCode,omitempty"` // e.g., Modbus function codes
	UnitID       *uint8   `json:"unitId,omitempty"`       // optional Modbus unit id
	Addresses    []string `json:"addresses,omitempty"`    // register/address ranges as strings
	ReadOnly     bool     `json:"readOnly,omitempty"`     // Modbus read-only class
	WriteOnly    bool     `json:"writeOnly,omitempty"`    // Modbus write-only class
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
	if err := validateFirewall(c.Firewall, c.Zones); err != nil {
		return err
	}
	if err := validateAssets(c.Assets, c.Zones); err != nil {
		return err
	}
	if err := validateDataPlane(c.DataPlane); err != nil {
		return err
	}
	if err := validateIDS(c.IDS); err != nil {
		return err
	}
	if err := validateServices(c.Services); err != nil {
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
	for _, z := range zones {
		if z.Name == "" {
			return errors.New("zone name cannot be empty")
		}
		if _, exists := seen[z.Name]; exists {
			return fmt.Errorf("duplicate zone: %s", z.Name)
		}
		seen[z.Name] = struct{}{}
	}
	return nil
}

func validateInterfaces(ifaces []Interface, zones []Zone) error {
	zoneSet := map[string]struct{}{}
	for _, z := range zones {
		zoneSet[z.Name] = struct{}{}
	}
	seen := map[string]struct{}{}
	seenDevices := map[string]struct{}{}
	for _, iface := range ifaces {
		if iface.Name == "" {
			return errors.New("interface name cannot be empty")
		}
		if _, exists := seen[iface.Name]; exists {
			return fmt.Errorf("duplicate interface: %s", iface.Name)
		}
		seen[iface.Name] = struct{}{}
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
		for _, addr := range iface.Addresses {
			if _, _, err := net.ParseCIDR(addr); err != nil {
				return fmt.Errorf("interface %s has invalid CIDR %q: %v", iface.Name, addr, err)
			}
		}
	}
	return nil
}

func validateFirewall(f FirewallConfig, zones []Zone) error {
	zoneSet := map[string]struct{}{}
	for _, z := range zones {
		zoneSet[z.Name] = struct{}{}
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
			if _, _, err := net.ParseCIDR(cidr); err != nil {
				return fmt.Errorf("rule %s has invalid CIDR %q: %v", r.ID, cidr, err)
			}
		}
		for _, p := range r.Protocols {
			if p.Name == "" {
				return fmt.Errorf("rule %s has protocol with empty name", r.ID)
			}
		}
		if err := validateICSPredicate(r.ICS, r.ID); err != nil {
			return err
		}
	}
	return nil
}

func validateICSPredicate(p ICSPredicate, ruleID string) error {
	if p.Protocol == "" {
		return nil
	}
	// Placeholder validation: enforce mutual exclusivity for read/write classes.
	if p.ReadOnly && p.WriteOnly {
		return fmt.Errorf("rule %s ics predicate cannot be both readOnly and writeOnly", ruleID)
	}
	// If function codes are set, ensure protocol is modbus for now.
	if len(p.FunctionCode) > 0 && p.Protocol != "modbus" {
		return fmt.Errorf("rule %s ics functionCode only supported for modbus currently", ruleID)
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
	for _, a := range assets {
		if a.ID == "" {
			return errors.New("asset id cannot be empty")
		}
		if _, ok := ids[a.ID]; ok {
			return fmt.Errorf("duplicate asset id: %s", a.ID)
		}
		ids[a.ID] = struct{}{}
		if a.Name == "" {
			return fmt.Errorf("asset %s name cannot be empty", a.ID)
		}
		if _, ok := names[a.Name]; ok {
			return fmt.Errorf("duplicate asset name: %s", a.Name)
		}
		names[a.Name] = struct{}{}
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

func validateServices(s ServicesConfig) error {
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
