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
	zoneSet := interfaceZoneSet(zones)
	byName := interfaceLookup(ifaces)
	state := newInterfaceValidationState()
	for _, iface := range ifaces {
		if err := validateInterfaceIdentity(iface, zoneSet, state); err != nil {
			return err
		}
		if err := validateInterfaceTypeConfig(iface, byName); err != nil {
			return err
		}
		if err := validateInterfaceAddressing(iface); err != nil {
			return err
		}
	}
	return nil
}

type interfaceValidationState struct {
	seen        map[string]struct{}
	seenLower   map[string]struct{}
	aliasSeen   map[string]struct{}
	seenDevices map[string]struct{}
}

func newInterfaceValidationState() *interfaceValidationState {
	return &interfaceValidationState{
		seen:        map[string]struct{}{},
		seenLower:   map[string]struct{}{},
		aliasSeen:   map[string]struct{}{},
		seenDevices: map[string]struct{}{},
	}
}

func interfaceZoneSet(zones []Zone) map[string]struct{} {
	zoneSet := map[string]struct{}{}
	for _, z := range zones {
		zoneSet[z.Name] = struct{}{}
	}
	return zoneSet
}

func interfaceLookup(ifaces []Interface) map[string]Interface {
	byName := map[string]Interface{}
	for _, iface := range ifaces {
		if name := strings.TrimSpace(iface.Name); name != "" {
			byName[name] = iface
		}
	}
	return byName
}

func validateInterfaceIdentity(iface Interface, zoneSet map[string]struct{}, state *interfaceValidationState) error {
	if iface.Name == "" {
		return errors.New("interface name cannot be empty")
	}
	if _, exists := state.seen[iface.Name]; exists {
		return fmt.Errorf("duplicate interface: %s", iface.Name)
	}
	state.seen[iface.Name] = struct{}{}
	state.seenLower[strings.ToLower(iface.Name)] = struct{}{}
	if err := validateInterfaceAlias(iface, state); err != nil {
		return err
	}
	if err := validateInterfaceDeviceBinding(iface, state); err != nil {
		return err
	}
	if iface.Zone != "" {
		if _, ok := zoneSet[iface.Zone]; !ok {
			return fmt.Errorf("interface %s references unknown zone %s", iface.Name, iface.Zone)
		}
	}
	return nil
}

func validateInterfaceAlias(iface Interface, state *interfaceValidationState) error {
	if strings.TrimSpace(iface.Alias) == "" {
		return nil
	}
	if iface.Alias != strings.TrimSpace(iface.Alias) {
		return fmt.Errorf("interface %s alias has leading/trailing whitespace", iface.Name)
	}
	key := strings.ToLower(iface.Alias)
	if _, ok := state.aliasSeen[key]; ok {
		return fmt.Errorf("duplicate interface alias: %s", iface.Alias)
	}
	if _, ok := state.seenLower[key]; ok {
		return fmt.Errorf("interface alias conflicts with interface name: %s", iface.Alias)
	}
	state.aliasSeen[key] = struct{}{}
	return nil
}

func validateInterfaceDeviceBinding(iface Interface, state *interfaceValidationState) error {
	if strings.TrimSpace(iface.Device) == "" {
		return nil
	}
	if iface.Device != strings.TrimSpace(iface.Device) {
		return fmt.Errorf("interface %s device has leading/trailing whitespace", iface.Name)
	}
	if _, exists := state.seenDevices[iface.Device]; exists {
		return fmt.Errorf("duplicate interface device binding: %s", iface.Device)
	}
	state.seenDevices[iface.Device] = struct{}{}
	return nil
}

func validateInterfaceTypeConfig(iface Interface, byName map[string]Interface) error {
	switch t := strings.ToLower(strings.TrimSpace(iface.Type)); t {
	case "", "physical":
		return nil
	case "bridge":
		return validateBridgeInterface(iface, byName)
	case "vlan":
		return validateVLANInterface(iface)
	default:
		return fmt.Errorf("interface %s has invalid type %q", iface.Name, iface.Type)
	}
}

func validateBridgeInterface(iface Interface, byName map[string]Interface) error {
	if len(iface.Members) == 0 {
		return fmt.Errorf("interface %s type bridge requires members", iface.Name)
	}
	for _, member := range iface.Members {
		member = strings.TrimSpace(member)
		if member == "" {
			return fmt.Errorf("interface %s has empty bridge member", iface.Name)
		}
		if member == iface.Name {
			return fmt.Errorf("interface %s cannot include itself as a bridge member", iface.Name)
		}
		if ref, ok := byName[member]; ok && strings.ToLower(strings.TrimSpace(ref.Type)) == "bridge" {
			return fmt.Errorf("interface %s bridge member %q is also a bridge (nested bridges not supported)", iface.Name, member)
		}
	}
	return nil
}

func validateVLANInterface(iface Interface) error {
	if strings.TrimSpace(iface.Parent) == "" {
		return fmt.Errorf("interface %s type vlan requires parent", iface.Name)
	}
	if iface.VLANID < 1 || iface.VLANID > 4094 {
		return fmt.Errorf("interface %s has invalid vlanId %d (expected 1-4094)", iface.Name, iface.VLANID)
	}
	return nil
}

func validateInterfaceAddressing(iface Interface) error {
	if mode := strings.ToLower(strings.TrimSpace(iface.AddressMode)); mode != "" && mode != "static" && mode != "dhcp" {
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
	bindings := map[string][]portForwardBinding{}
	ifaceBindings := map[string][]portForwardBinding{}
	for _, pf := range pfs {
		ingress, proto, allowed, err := validatePortForwardBasics(pf, ids, zoneSet)
		if err != nil {
			return err
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

func validatePortForwardBasics(pf PortForward, ids map[string]struct{}, zoneSet map[string]struct{}) (string, string, []*net.IPNet, error) {
	if err := validatePortForwardIdentity(pf, ids); err != nil {
		return "", "", nil, err
	}
	ingress, err := validatePortForwardIngress(pf, zoneSet)
	if err != nil {
		return "", "", nil, err
	}
	proto, err := validatePortForwardTransport(pf)
	if err != nil {
		return "", "", nil, err
	}
	if err := validatePortForwardDestination(pf); err != nil {
		return "", "", nil, err
	}
	allowed, err := parseIPv4CIDRs(pf.AllowedSources)
	if err != nil {
		return "", "", nil, fmt.Errorf("port-forward %s has invalid allowedSources: %w", pf.ID, err)
	}
	return ingress, proto, allowed, nil
}

func validatePortForwardIdentity(pf PortForward, ids map[string]struct{}) error {
	if strings.TrimSpace(pf.ID) == "" {
		return fmt.Errorf("nat.portForwards[].id cannot be empty")
	}
	if _, ok := ids[pf.ID]; ok {
		return fmt.Errorf("duplicate nat.portForwards id: %s", pf.ID)
	}
	ids[pf.ID] = struct{}{}
	return nil
}

func validatePortForwardIngress(pf PortForward, zoneSet map[string]struct{}) (string, error) {
	ingress := strings.TrimSpace(pf.IngressZone)
	if ingress == "" {
		return "", fmt.Errorf("port-forward %s ingressZone cannot be empty", pf.ID)
	}
	if _, ok := zoneSet[ingress]; !ok {
		return "", fmt.Errorf("port-forward %s ingressZone references unknown zone %s", pf.ID, ingress)
	}
	return ingress, nil
}

func validatePortForwardTransport(pf PortForward) (string, error) {
	proto := strings.ToLower(strings.TrimSpace(pf.Proto))
	if proto != "tcp" && proto != "udp" {
		return "", fmt.Errorf("port-forward %s proto must be tcp or udp", pf.ID)
	}
	if pf.ListenPort <= 0 || pf.ListenPort > 65535 {
		return "", fmt.Errorf("port-forward %s listenPort out of range: %d", pf.ID, pf.ListenPort)
	}
	return proto, nil
}

func validatePortForwardDestination(pf PortForward) error {
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
	if p.ReadOnly && p.WriteOnly {
		return fmt.Errorf("rule %s ics predicate cannot be both readOnly and writeOnly", ruleID)
	}
	if p.Direction != "" && p.Direction != "request" && p.Direction != "response" {
		return fmt.Errorf("rule %s ics direction invalid %q", ruleID, p.Direction)
	}
	if len(p.FunctionCode) > 0 && p.Protocol != "modbus" && p.Protocol != "dnp3" && p.Protocol != "cip" && p.Protocol != "s7comm" && p.Protocol != "bacnet" && p.Protocol != "opcua" && p.Protocol != "mms" {
		return fmt.Errorf("rule %s ics functionCode only supported for modbus, dnp3, cip, s7comm, bacnet, opcua, and mms currently", ruleID)
	}
	if len(p.ObjectClasses) > 0 && p.Protocol != "cip" {
		return fmt.Errorf("rule %s ics objectClasses only supported for cip protocol", ruleID)
	}
	return nil
}

func validateRouting(r RoutingConfig, ifaces []Interface, zones []Zone) error {
	if len(r.Gateways) == 0 && len(r.Routes) == 0 && len(r.Rules) == 0 {
		return nil
	}
	ifaceSet := routingIfaceSet(ifaces)
	gwByName, err := validateGateways(r.Gateways, ifaceSet)
	if err != nil {
		return err
	}
	if err := validateRoutes(r.Routes, gwByName, ifaceSet); err != nil {
		return err
	}
	return validateRoutingRules(r.Rules)
}

func routingIfaceSet(ifaces []Interface) map[string]struct{} {
	ifaceSet := map[string]struct{}{}
	for _, iface := range ifaces {
		if strings.TrimSpace(iface.Name) != "" {
			ifaceSet[iface.Name] = struct{}{}
		}
		if strings.TrimSpace(iface.Device) != "" {
			ifaceSet[iface.Device] = struct{}{}
		}
	}
	return ifaceSet
}

func validateGateways(gateways []Gateway, ifaceSet map[string]struct{}) (map[string]Gateway, error) {
	gwByName := map[string]Gateway{}
	gwNamesLower := map[string]struct{}{}
	gwAliasLower := map[string]struct{}{}
	for _, gw := range gateways {
		name := strings.TrimSpace(gw.Name)
		if name == "" {
			return nil, errors.New("routing.gateways name cannot be empty")
		}
		if _, ok := gwByName[name]; ok {
			return nil, fmt.Errorf("routing.gateways duplicate name %q", name)
		}
		gwNamesLower[strings.ToLower(name)] = struct{}{}
		addr := strings.TrimSpace(gw.Address)
		ip := net.ParseIP(addr)
		if ip == nil || ip.To4() == nil {
			return nil, fmt.Errorf("routing.gateways %s address must be an IPv4 address", name)
		}
		if ifn := strings.TrimSpace(gw.Iface); ifn != "" {
			if _, ok := ifaceSet[ifn]; !ok {
				return nil, fmt.Errorf("routing.gateways %s iface unknown %q", name, gw.Iface)
			}
		}
		if err := validateGatewayAlias(gw, name, gwNamesLower, gwAliasLower); err != nil {
			return nil, err
		}
		gwByName[name] = gw
	}
	return gwByName, nil
}

func validateGatewayAlias(gw Gateway, name string, gwNamesLower, gwAliasLower map[string]struct{}) error {
	if strings.TrimSpace(gw.Alias) == "" {
		return nil
	}
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
	return nil
}

func validateRoutes(routes []StaticRoute, gwByName map[string]Gateway, ifaceSet map[string]struct{}) error {
	for _, rt := range routes {
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
		if err := validateRouteGateway(rt.Gateway, gwByName); err != nil {
			return err
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
	return nil
}

func validateRouteGateway(gateway string, gwByName map[string]Gateway) error {
	gw := strings.TrimSpace(gateway)
	if gw == "" {
		return nil
	}
	if net.ParseIP(gw) == nil {
		if _, ok := gwByName[gw]; !ok {
			return fmt.Errorf("routing.routes gateway invalid %q (must be IP or a defined gateway name)", gateway)
		}
	}
	return nil
}

func validateRoutingRules(rulesCfg []PolicyRule) error {
	seenPrio := map[int]struct{}{}
	for _, rule := range rulesCfg {
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
	for _, r := range dp.EnforceTable {
		if !(r == '_' || r == '-' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return fmt.Errorf("dataplane.enforceTable has invalid char %q", r)
		}
	}
	return nil
}

func validatePCAP(p PCAPConfig) error {
	if err := validatePCAPInterfaces(p); err != nil {
		return err
	}
	if err := validatePCAPLimits(p); err != nil {
		return err
	}
	if err := validatePCAPMode(p.Mode); err != nil {
		return err
	}
	if err := validatePCAPFilter(p.Filter); err != nil {
		return err
	}
	return validatePCAPForwardTargets(p.ForwardTargets)
}

func validatePCAPInterfaces(p PCAPConfig) error {
	for _, name := range p.Interfaces {
		if strings.TrimSpace(name) == "" {
			return errors.New("pcap.interfaces cannot include empty name")
		}
	}
	if p.Enabled && len(p.Interfaces) == 0 {
		return errors.New("pcap.enabled requires at least one interface")
	}
	return nil
}

func validatePCAPLimits(p PCAPConfig) error {
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
	return nil
}

func validatePCAPMode(mode string) error {
	if mode != "" && mode != "rolling" && mode != "once" {
		return fmt.Errorf("pcap.mode invalid %q", mode)
	}
	return nil
}

func validatePCAPFilter(filter PCAPFilter) error {
	proto := strings.ToLower(strings.TrimSpace(filter.Proto))
	if proto != "" && proto != "any" && proto != "tcp" && proto != "udp" && proto != "icmp" {
		return fmt.Errorf("pcap.filter.proto invalid %q", filter.Proto)
	}
	return nil
}

func validatePCAPForwardTargets(targets []PCAPForwardTarget) error {
	for _, t := range targets {
		if err := validatePCAPForwardTarget(t); err != nil {
			return err
		}
	}
	return nil
}

func validatePCAPForwardTarget(t PCAPForwardTarget) error {
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
	return nil
}
