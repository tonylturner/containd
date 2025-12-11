package config

import (
	"errors"
	"fmt"
	"net"
)

// Config represents the management-plane persistent configuration.
// It intentionally stays narrow until broader models are added.
type Config struct {
	System      SystemConfig    `json:"system"`
	Interfaces  []Interface     `json:"interfaces"`
	Zones       []Zone          `json:"zones"`
	Firewall    FirewallConfig  `json:"firewall"`
	Description string          `json:"description,omitempty"`
	Version     string          `json:"version,omitempty"`
}

type SystemConfig struct {
	Hostname string `json:"hostname"`
	// Placeholder for future system settings (NTP/DNS/syslog).
}

type Interface struct {
	Name      string   `json:"name"`
	Zone      string   `json:"zone"`
	Addresses []string `json:"addresses,omitempty"` // CIDR strings
}

type Zone struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

type FirewallConfig struct {
	DefaultAction Action  `json:"defaultAction"`
	Rules         []Rule  `json:"rules"`
}

type Action string

const (
	ActionAllow Action = "ALLOW"
	ActionDeny  Action = "DENY"
)

type Rule struct {
	ID          string        `json:"id"`
	Description string        `json:"description,omitempty"`
	SourceZones []string      `json:"sourceZones,omitempty"`
	DestZones   []string      `json:"destZones,omitempty"`
	Sources     []string      `json:"sources,omitempty"`     // CIDR strings
	Destinations []string     `json:"destinations,omitempty"` // CIDR strings
	Protocols   []Protocol    `json:"protocols,omitempty"`
	Action      Action        `json:"action"`
}

type Protocol struct {
	Name string `json:"name"`          // e.g. tcp, udp, icmp
	Port string `json:"port,omitempty"` // single or range "80", "443", "1000-2000"
}

// Validate performs basic consistency checks on the config.
func (c *Config) Validate() error {
	if c == nil {
		return errors.New("config is nil")
	}
	if err := validateHostname(c.System.Hostname); err != nil {
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
	}
	return nil
}
