package config

import (
	"errors"
	"fmt"
	"net"
)

// Config represents the management-plane persistent configuration.
// It intentionally stays narrow until broader models are added.
type Config struct {
	SchemaVersion string         `json:"schema_version,omitempty"`
	System        SystemConfig   `json:"system"`
	Interfaces    []Interface    `json:"interfaces"`
	Zones         []Zone         `json:"zones"`
	Assets        []Asset        `json:"assets,omitempty"`
	DataPlane     DataPlaneConfig `json:"dataplane,omitempty"`
	Firewall      FirewallConfig `json:"firewall"`
	Services      ServicesConfig `json:"services"`
	Description   string         `json:"description,omitempty"`
	Version       string         `json:"version,omitempty"`
}

type SystemConfig struct {
	Hostname string `json:"hostname"`
	// Placeholder for future system settings (NTP/DNS/syslog).
	Mgmt MgmtConfig `json:"mgmt,omitempty"`
}

// MgmtConfig controls management plane binding and access.
// By default, mgmt binds on all interfaces (0.0.0.0) so the UI is reachable
// on WAN/DMZ/LAN interfaces in lab deployments. Operators can narrow this later.
type MgmtConfig struct {
	ListenAddr string `json:"listenAddr,omitempty"` // e.g. ":8080", "127.0.0.1:8080"
}

type ServicesConfig struct {
	Syslog SyslogConfig `json:"syslog"`
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
	Name      string   `json:"name"`
	Zone      string   `json:"zone"`
	Addresses []string `json:"addresses,omitempty"` // CIDR strings
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
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Type        AssetType    `json:"type"`
	Zone        string       `json:"zone,omitempty"`
	IPs         []string     `json:"ips,omitempty"`
	Hostnames   []string     `json:"hostnames,omitempty"`
	Criticality Criticality `json:"criticality,omitempty"`
	Tags        []string     `json:"tags,omitempty"`
	Description string       `json:"description,omitempty"`
}

type FirewallConfig struct {
	DefaultAction Action `json:"defaultAction"`
	Rules         []Rule `json:"rules"`
}

type Action string

const (
	ActionAllow Action = "ALLOW"
	ActionDeny  Action = "DENY"
)

type Rule struct {
	ID           string     `json:"id"`
	Description  string     `json:"description,omitempty"`
	SourceZones  []string   `json:"sourceZones,omitempty"`
	DestZones    []string   `json:"destZones,omitempty"`
	Sources      []string   `json:"sources,omitempty"`      // CIDR strings
	Destinations []string   `json:"destinations,omitempty"` // CIDR strings
	Protocols    []Protocol `json:"protocols,omitempty"`
	ICS          ICSPredicate `json:"ics,omitempty"`
	Action       Action     `json:"action"`
}

type Protocol struct {
	Name string `json:"name"`           // e.g. tcp, udp, icmp
	Port string `json:"port,omitempty"` // single or range "80", "443", "1000-2000"
}

// ICSPredicate captures ICS-specific primitives for rules (placeholder).
// For Phase 2, Modbus fields are supported.
type ICSPredicate struct {
	Protocol     string  `json:"protocol,omitempty"`      // modbus, dnp3, iec104, etc.
	FunctionCode []uint8 `json:"functionCode,omitempty"`  // e.g., Modbus function codes
	UnitID       *uint8  `json:"unitId,omitempty"`        // optional Modbus unit id
	Addresses    []string `json:"addresses,omitempty"`    // register/address ranges as strings
	ReadOnly     bool    `json:"readOnly,omitempty"`      // Modbus read-only class
	WriteOnly    bool    `json:"writeOnly,omitempty"`     // Modbus write-only class
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
	if m.ListenAddr == "" {
		return nil
	}
	if len(m.ListenAddr) > 128 {
		return fmt.Errorf("mgmt.listenAddr too long")
	}
	// We accept anything net/http can listen on; detailed parsing later.
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
	for _, iface := range ifaces {
		if iface.Name == "" {
			return errors.New("interface name cannot be empty")
		}
		if _, exists := seen[iface.Name]; exists {
			return fmt.Errorf("duplicate interface: %s", iface.Name)
		}
		seen[iface.Name] = struct{}{}
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
