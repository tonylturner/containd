// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package compile

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/tonylturner/containd/pkg/cp/config"
	dprules "github.com/tonylturner/containd/pkg/dp/rules"
)

// CompileSnapshot compiles a control-plane running config into a data-plane snapshot.
// This currently maps only L3/L4 firewall primitives.
func CompileSnapshot(cfg *config.Config) (dprules.Snapshot, error) {
	if cfg == nil {
		return dprules.Snapshot{}, fmt.Errorf("config is nil")
	}
	if err := cfg.Validate(); err != nil {
		return dprules.Snapshot{}, err
	}

	snap := dprules.Snapshot{
		Version:    cfg.Version,
		Firewall:   make([]dprules.Entry, 0, len(cfg.Firewall.Rules)),
		LocalInput: make([]dprules.LocalServiceRule, 0, 8),
		Default:    dprules.Action(cfg.Firewall.DefaultAction),
		NAT: dprules.NATConfig{
			Enabled:      cfg.Firewall.NAT.Enabled,
			EgressZone:   cfg.Firewall.NAT.EgressZone,
			SourceZones:  append([]string(nil), cfg.Firewall.NAT.SourceZones...),
			PortForwards: make([]dprules.PortForward, 0, len(cfg.Firewall.NAT.PortForwards)),
		},
		IDS: dprules.IDSConfig{
			Enabled: cfg.IDS.Enabled,
			Rules:   make([]dprules.IDSRule, 0, len(cfg.IDS.Rules)),
		},
		ZoneIfaces: make(map[string][]string),
	}
	if snap.NAT.Enabled {
		if strings.TrimSpace(snap.NAT.EgressZone) == "" {
			snap.NAT.EgressZone = "wan"
		}
		if len(snap.NAT.SourceZones) == 0 {
			snap.NAT.SourceZones = defaultNATSourceZones(cfg, snap.NAT.EgressZone)
		}
	}
	for _, pf := range cfg.Firewall.NAT.PortForwards {
		destPort := pf.DestPort
		if destPort == 0 {
			destPort = pf.ListenPort
		}
		snap.NAT.PortForwards = append(snap.NAT.PortForwards, dprules.PortForward{
			ID:             pf.ID,
			Enabled:        pf.Enabled,
			Description:    pf.Description,
			IngressZone:    pf.IngressZone,
			Proto:          pf.Proto,
			ListenPort:     pf.ListenPort,
			DestIP:         pf.DestIP,
			DestPort:       destPort,
			AllowedSources: append([]string(nil), pf.AllowedSources...),
		})
	}
	if snap.Version == "" {
		snap.Version = "compiled-" + cfg.SchemaVersion
	}

	for _, r := range cfg.Firewall.Rules {
		srcs := expandCIDRTokens(append([]string(nil), r.Sources...), cfg)
		dsts := expandCIDRTokens(append([]string(nil), r.Destinations...), cfg)
		entry := dprules.Entry{
			ID:           r.ID,
			SourceZones:  append([]string(nil), r.SourceZones...),
			DestZones:    append([]string(nil), r.DestZones...),
			Sources:      srcs,
			Destinations: dsts,
			Protocols:    make([]dprules.Protocol, 0, len(r.Protocols)),
			Action:       dprules.Action(r.Action),
			Log:          r.Log,
			Identities:   append([]string(nil), r.Identities...),
			ICS: dprules.ICSPredicate{
				Protocol:     r.ICS.Protocol,
				FunctionCode: append([]uint8(nil), r.ICS.FunctionCode...),
				UnitID:       r.ICS.UnitID,
				Addresses:    append([]string(nil), r.ICS.Addresses...),
				ReadOnly:     r.ICS.ReadOnly,
				WriteOnly:    r.ICS.WriteOnly,
				Mode:         r.ICS.Mode,
			},
		}
		if r.Schedule != nil {
			entry.Schedule = dprules.SchedulePredicate{
				DaysOfWeek: append([]string(nil), r.Schedule.DaysOfWeek...),
				StartTime:  r.Schedule.StartTime,
				EndTime:    r.Schedule.EndTime,
				Timezone:   r.Schedule.Timezone,
			}
		}
		for _, p := range r.Protocols {
			entry.Protocols = append(entry.Protocols, dprules.Protocol{Name: p.Name, Port: p.Port})
		}
		snap.Firewall = append(snap.Firewall, entry)
	}

	// Local input allow rules (management plane + VPN listeners).
	snap.LocalInput = append(snap.LocalInput, compileLocalInput(cfg)...)

	// Build deterministic zone->interfaces mapping for nftables bindings.
	for _, iface := range cfg.Interfaces {
		z := iface.Zone
		if z == "" {
			continue
		}
		name := iface.Name
		if strings.TrimSpace(iface.Device) != "" {
			name = iface.Device
		}
		snap.ZoneIfaces[z] = append(snap.ZoneIfaces[z], name)
	}
	for z, ifs := range snap.ZoneIfaces {
		sort.Strings(ifs)
		snap.ZoneIfaces[z] = ifs
	}

	for _, r := range cfg.IDS.Rules {
		dr := dprules.IDSRule{
			ID:          r.ID,
			Enabled:     r.Enabled,
			Title:       r.Title,
			Description: r.Description,
			Proto:       r.Proto,
			Kind:        r.Kind,
			When: dprules.IDSCondition{
				All:   compileIDSConds(r.When.All),
				Any:   compileIDSConds(r.When.Any),
				Not:   compileIDSNot(r.When.Not),
				Field: r.When.Field,
				Op:    r.When.Op,
				Value: r.When.Value,
			},
			Severity:        r.Severity,
			Message:         r.Message,
			Labels:          r.Labels,
			SourceFormat:    r.SourceFormat,
			Action:          r.Action,
			SrcAddr:         r.SrcAddr,
			DstAddr:         r.DstAddr,
			SrcPort:         r.SrcPort,
			DstPort:         r.DstPort,
			References:      r.References,
			CVE:             r.CVE,
			MITREAttackIDs:  r.MITREAttackIDs,
			RawSource:       r.RawSource,
			ConversionNotes: r.ConversionNotes,
		}
		for _, cm := range r.ContentMatches {
			dr.ContentMatches = append(dr.ContentMatches, dprules.ContentMatch{
				Pattern: cm.Pattern, IsHex: cm.IsHex, Negate: cm.Negate,
				Nocase: cm.Nocase, Depth: cm.Depth, Offset: cm.Offset,
				Distance: cm.Distance, Within: cm.Within,
			})
		}
		for _, ys := range r.YARAStrings {
			dr.YARAStrings = append(dr.YARAStrings, dprules.YARAString{
				Name: ys.Name, Pattern: ys.Pattern, Type: ys.Type,
				Nocase: ys.Nocase, Wide: ys.Wide, ASCII: ys.ASCII,
			})
		}
		snap.IDS.Rules = append(snap.IDS.Rules, dr)
	}

	return snap, nil
}

func expandCIDRTokens(in []string, cfg *config.Config) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, raw := range in {
		s := strings.ToLower(strings.TrimSpace(raw))
		switch s {
		case "vpn:any", "vpn:all", "vpn:*":
			out = append(out, vpnCIDRs(cfg)...)
		case "vpn:wireguard", "vpn:wg":
			if cidr := strings.TrimSpace(cfg.Services.VPN.WireGuard.AddressCIDR); cidr != "" {
				out = append(out, cidr)
			}
		case "vpn:openvpn", "vpn:ovpn":
			if cfg.Services.VPN.OpenVPN.Server != nil && strings.TrimSpace(cfg.Services.VPN.OpenVPN.Mode) == "server" {
				if cidr := strings.TrimSpace(cfg.Services.VPN.OpenVPN.Server.TunnelCIDR); cidr != "" {
					out = append(out, cidr)
				}
			}
		default:
			if strings.TrimSpace(raw) != "" {
				out = append(out, strings.TrimSpace(raw))
			}
		}
	}
	out = compactAndSortCIDRs(out)
	return out
}

func vpnCIDRs(cfg *config.Config) []string {
	if cfg == nil {
		return nil
	}
	var out []string
	if cidr := strings.TrimSpace(cfg.Services.VPN.WireGuard.AddressCIDR); cidr != "" {
		out = append(out, cidr)
	}
	if cfg.Services.VPN.OpenVPN.Server != nil && strings.TrimSpace(cfg.Services.VPN.OpenVPN.Mode) == "server" {
		if cidr := strings.TrimSpace(cfg.Services.VPN.OpenVPN.Server.TunnelCIDR); cidr != "" {
			out = append(out, cidr)
		}
	}
	return compactAndSortCIDRs(out)
}

func defaultNATSourceZones(cfg *config.Config, egress string) []string {
	if cfg == nil {
		return nil
	}
	egress = strings.TrimSpace(egress)
	out := make([]string, 0, len(cfg.Zones))
	zoneSet := map[string]struct{}{}
	for _, z := range cfg.Zones {
		name := strings.TrimSpace(z.Name)
		if name == "" {
			continue
		}
		zoneSet[strings.ToLower(name)] = struct{}{}
		if strings.EqualFold(name, egress) {
			continue
		}
		out = append(out, name)
	}
	if len(out) == 0 {
		for _, name := range []string{"lan", "dmz"} {
			if _, ok := zoneSet[name]; ok && !strings.EqualFold(name, egress) {
				out = append(out, name)
			}
		}
	}
	return out
}

func compactAndSortCIDRs(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func compileLocalInput(cfg *config.Config) []dprules.LocalServiceRule {
	if cfg == nil {
		return nil
	}

	var out []dprules.LocalServiceRule
	out = append(out, compileMgmtLocalInput(cfg)...)
	out = append(out, compileInfraServiceLocalInput(cfg)...)
	out = append(out, compileProxyLocalInput(cfg)...)
	out = append(out, compileVPNLocalInput(cfg)...)
	return out
}

func compileMgmtLocalInput(cfg *config.Config) []dprules.LocalServiceRule {
	var out []dprules.LocalServiceRule
	httpPort := listenPortOrDefault(cfg.System.Mgmt.HTTPListenAddr, 8080)
	httpsPort := listenPortOrDefault(cfg.System.Mgmt.HTTPSListenAddr, 8443)
	if strings.TrimSpace(cfg.System.Mgmt.HTTPListenAddr) == "" && strings.TrimSpace(cfg.System.Mgmt.ListenAddr) != "" {
		httpPort = listenPortOrDefault(cfg.System.Mgmt.ListenAddr, 8080)
	}
	sshPort := listenPortOrDefault(cfg.System.SSH.ListenAddr, 2222)

	enableHTTP := cfg.System.Mgmt.EnableHTTP == nil || *cfg.System.Mgmt.EnableHTTP
	enableHTTPS := cfg.System.Mgmt.EnableHTTPS != nil && *cfg.System.Mgmt.EnableHTTPS
	if cfg.System.Mgmt.EnableHTTPS == nil {
		enableHTTPS = strings.TrimSpace(cfg.System.Mgmt.HTTPSListenAddr) != ""
	}

	mgmtHTTPIfaces, mgmtHTTPSIfaces, sshIfaces := localAccessIfaces(cfg.Interfaces, enableHTTP, enableHTTPS)
	sort.Strings(mgmtHTTPIfaces)
	sort.Strings(mgmtHTTPSIfaces)
	sort.Strings(sshIfaces)

	if enableHTTP && httpPort != 0 && len(mgmtHTTPIfaces) > 0 {
		out = append(out, dprules.LocalServiceRule{
			ID:     "auto-allow-mgmt-http",
			Ifaces: mgmtHTTPIfaces,
			Proto:  "tcp",
			Port:   httpPort,
		})
	}
	if enableHTTPS && httpsPort != 0 && len(mgmtHTTPSIfaces) > 0 {
		out = append(out, dprules.LocalServiceRule{
			ID:     "auto-allow-mgmt-https",
			Ifaces: mgmtHTTPSIfaces,
			Proto:  "tcp",
			Port:   httpsPort,
		})
	}
	if sshPort != 0 && len(sshIfaces) > 0 {
		out = append(out, dprules.LocalServiceRule{
			ID:     "auto-allow-ssh",
			Ifaces: sshIfaces,
			Proto:  "tcp",
			Port:   sshPort,
		})
	}
	return out
}

func localAccessIfaces(ifaces []config.Interface, enableHTTP, enableHTTPS bool) ([]string, []string, []string) {
	mgmtHTTPIfaces := make([]string, 0, len(ifaces))
	mgmtHTTPSIfaces := make([]string, 0, len(ifaces))
	sshIfaces := make([]string, 0, len(ifaces))
	for _, iface := range ifaces {
		dev := iface.Name
		if strings.TrimSpace(iface.Device) != "" {
			dev = iface.Device
		}
		if dev == "" {
			continue
		}
		allowMgmt := iface.Access.Mgmt == nil || *iface.Access.Mgmt
		allowHTTP := iface.Access.HTTP == nil || *iface.Access.HTTP
		allowHTTPS := iface.Access.HTTPS == nil || *iface.Access.HTTPS
		allowSSH := iface.Access.SSH == nil || *iface.Access.SSH
		if allowMgmt && enableHTTP && allowHTTP {
			mgmtHTTPIfaces = append(mgmtHTTPIfaces, dev)
		}
		if allowMgmt && enableHTTPS && allowHTTPS {
			mgmtHTTPSIfaces = append(mgmtHTTPSIfaces, dev)
		}
		if allowSSH {
			sshIfaces = append(sshIfaces, dev)
		}
	}
	return mgmtHTTPIfaces, mgmtHTTPSIfaces, sshIfaces
}

func compileInfraServiceLocalInput(cfg *config.Config) []dprules.LocalServiceRule {
	var out []dprules.LocalServiceRule
	if cfg.Services.DNS.Enabled {
		dnsPort := cfg.Services.DNS.ListenPort
		if dnsPort == 0 {
			dnsPort = 53
		}
		out = append(out, compileZoneBoundService("auto-allow-dns-udp", "udp", dnsPort, cfg.Services.DNS.ListenZones)...)
		out = append(out, compileZoneBoundService("auto-allow-dns-tcp", "tcp", dnsPort, cfg.Services.DNS.ListenZones)...)
	}

	// DHCP server: allow UDP/1067 on configured listen interfaces.
	if cfg.Services.DHCP.Enabled && len(cfg.Services.DHCP.ListenIfaces) > 0 {
		ifaces := resolveListenIfaces(cfg.Services.DHCP.ListenIfaces, cfg.Interfaces)
		if len(ifaces) > 0 {
			out = append(out, dprules.LocalServiceRule{
				ID:     "auto-allow-dhcp",
				Ifaces: ifaces,
				Proto:  "udp",
				Port:   1067,
			})
		}
	}
	return out
}

func compileProxyLocalInput(cfg *config.Config) []dprules.LocalServiceRule {
	var out []dprules.LocalServiceRule
	if cfg.Services.Proxy.Forward.Enabled {
		port := cfg.Services.Proxy.Forward.ListenPort
		if port == 0 {
			port = 3128
		}
		out = append(out, compileZoneBoundService("auto-allow-forward-proxy", "tcp", port, cfg.Services.Proxy.Forward.ListenZones)...)
	}

	// Reverse proxy: allow TCP on WAN by default (published apps).
	if cfg.Services.Proxy.Reverse.Enabled {
		for _, site := range cfg.Services.Proxy.Reverse.Sites {
			if site.ListenPort <= 0 || site.ListenPort > 65535 {
				continue
			}
			out = append(out, dprules.LocalServiceRule{
				ID:    "auto-allow-reverse-proxy-" + sanitizeIdent(site.Name),
				Zone:  "wan",
				Proto: "tcp",
				Port:  site.ListenPort,
			})
		}
	}
	return out
}

func compileVPNLocalInput(cfg *config.Config) []dprules.LocalServiceRule {
	var out []dprules.LocalServiceRule
	if cfg.Services.VPN.WireGuard.Enabled && cfg.Services.VPN.WireGuard.ListenPort > 0 {
		rule := dprules.LocalServiceRule{
			ID:    "auto-allow-wireguard",
			Proto: "udp",
			Port:  cfg.Services.VPN.WireGuard.ListenPort,
		}
		applyVPNListenTargets(&rule, cfg.Services.VPN.WireGuard.ListenZone, cfg.Services.VPN.WireGuard.ListenInterfaces, cfg.Interfaces, "wan")
		out = append(out, rule)
	}

	// OpenVPN server (managed): allow inbound to server listen port on wan zone (default).
	if cfg.Services.VPN.OpenVPN.Enabled && strings.TrimSpace(cfg.Services.VPN.OpenVPN.Mode) == "server" && cfg.Services.VPN.OpenVPN.Server != nil {
		port := cfg.Services.VPN.OpenVPN.Server.ListenPort
		if port == 0 {
			port = 1194
		}
		proto := strings.ToLower(strings.TrimSpace(cfg.Services.VPN.OpenVPN.Server.Proto))
		if proto == "" {
			proto = "udp"
		}
		if port > 0 && port <= 65535 && (proto == "udp" || proto == "tcp") {
			rule := dprules.LocalServiceRule{
				ID:    "auto-allow-openvpn",
				Proto: proto,
				Port:  port,
			}
			applyVPNListenTargets(&rule, cfg.Services.VPN.OpenVPN.Server.ListenZone, cfg.Services.VPN.OpenVPN.Server.ListenInterfaces, cfg.Interfaces, "wan")
			out = append(out, rule)
		}
	}
	return out
}

func compileZoneBoundService(id, proto string, port int, zones []string) []dprules.LocalServiceRule {
	if port <= 0 || port > 65535 {
		return nil
	}
	if len(zones) == 0 {
		return []dprules.LocalServiceRule{
			{
				ID:    id,
				Proto: proto,
				Port:  port,
			},
		}
	}
	seen := map[string]struct{}{}
	out := make([]dprules.LocalServiceRule, 0, len(zones))
	for _, z := range zones {
		z = strings.TrimSpace(z)
		if z == "" {
			continue
		}
		if _, ok := seen[z]; ok {
			continue
		}
		seen[z] = struct{}{}
		out = append(out, dprules.LocalServiceRule{
			ID:    id + "-" + sanitizeIdent(z),
			Zone:  z,
			Proto: proto,
			Port:  port,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func applyVPNListenTargets(rule *dprules.LocalServiceRule, zone string, ifaces []string, cfgIfaces []config.Interface, defZone string) {
	resolved := resolveListenIfaces(ifaces, cfgIfaces)
	if len(resolved) > 0 {
		rule.Ifaces = resolved
		return
	}
	zone = strings.TrimSpace(zone)
	if zone == "" {
		zone = defZone
	}
	rule.Zone = zone
}

func resolveListenIfaces(raw []string, ifaces []config.Interface) []string {
	if len(raw) == 0 {
		return nil
	}
	lookup := map[string]string{}
	for _, iface := range ifaces {
		dev := strings.TrimSpace(iface.Device)
		name := strings.TrimSpace(iface.Name)
		if dev == "" {
			dev = name
		}
		if name != "" && dev != "" {
			lookup[name] = dev
		}
		if dev != "" {
			lookup[dev] = dev
		}
	}
	out := make([]string, 0, len(raw))
	seen := map[string]struct{}{}
	for _, item := range raw {
		key := strings.TrimSpace(item)
		if key == "" {
			continue
		}
		dev := lookup[key]
		if dev == "" {
			dev = key
		}
		if _, ok := seen[dev]; ok {
			continue
		}
		seen[dev] = struct{}{}
		out = append(out, dev)
	}
	sort.Strings(out)
	return out
}

func sanitizeIdent(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var out strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' {
			out.WriteRune(r)
			continue
		}
		if r == '-' || r == ' ' {
			out.WriteRune('_')
		}
	}
	if out.Len() == 0 {
		return "id"
	}
	return out.String()
}

func listenPortOrDefault(addr string, def int) int {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return def
	}
	// Accept ":8080", "0.0.0.0:8080", "127.0.0.1:8080", "[::]:8080".
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		// Might be ":8080" (host missing) => SplitHostPort fails unless we add dummy host.
		if strings.HasPrefix(addr, ":") {
			portStr = strings.TrimPrefix(addr, ":")
		} else {
			return def
		}
	}
	p, err := strconv.Atoi(portStr)
	if err != nil || p < 1 || p > 65535 {
		return def
	}
	return p
}

func compileIDSConds(in []config.IDSCondition) []dprules.IDSCondition {
	if len(in) == 0 {
		return nil
	}
	out := make([]dprules.IDSCondition, 0, len(in))
	for _, c := range in {
		out = append(out, dprules.IDSCondition{
			All:   compileIDSConds(c.All),
			Any:   compileIDSConds(c.Any),
			Not:   compileIDSNot(c.Not),
			Field: c.Field,
			Op:    c.Op,
			Value: c.Value,
		})
	}
	return out
}

func compileIDSNot(in *config.IDSCondition) *dprules.IDSCondition {
	if in == nil {
		return nil
	}
	return &dprules.IDSCondition{
		All:   compileIDSConds(in.All),
		Any:   compileIDSConds(in.Any),
		Not:   compileIDSNot(in.Not),
		Field: in.Field,
		Op:    in.Op,
		Value: in.Value,
	}
}
