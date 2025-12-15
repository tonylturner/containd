package compile

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/containd/containd/pkg/cp/config"
	dprules "github.com/containd/containd/pkg/dp/rules"
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
		Version:  cfg.Version,
		Firewall: make([]dprules.Entry, 0, len(cfg.Firewall.Rules)),
		LocalInput: make([]dprules.LocalServiceRule, 0, 8),
		Default:  dprules.Action(cfg.Firewall.DefaultAction),
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
			snap.NAT.SourceZones = []string{"lan", "dmz"}
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
		entry := dprules.Entry{
			ID:           r.ID,
			SourceZones:  append([]string(nil), r.SourceZones...),
			DestZones:    append([]string(nil), r.DestZones...),
			Sources:      append([]string(nil), r.Sources...),
			Destinations: append([]string(nil), r.Destinations...),
			Protocols:    make([]dprules.Protocol, 0, len(r.Protocols)),
			Action:       dprules.Action(r.Action),
			ICS: dprules.ICSPredicate{
				Protocol:     r.ICS.Protocol,
				FunctionCode: append([]uint8(nil), r.ICS.FunctionCode...),
				UnitID:       r.ICS.UnitID,
				Addresses:    append([]string(nil), r.ICS.Addresses...),
				ReadOnly:     r.ICS.ReadOnly,
				WriteOnly:    r.ICS.WriteOnly,
			},
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
		snap.IDS.Rules = append(snap.IDS.Rules, dprules.IDSRule{
			ID:          r.ID,
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
			Severity: r.Severity,
			Message:  r.Message,
			Labels:   r.Labels,
		})
	}

	return snap, nil
}

func compileLocalInput(cfg *config.Config) []dprules.LocalServiceRule {
	if cfg == nil {
		return nil
	}

	var out []dprules.LocalServiceRule

	// Determine ports.
	httpPort := listenPortOrDefault(cfg.System.Mgmt.HTTPListenAddr, 8080)
	httpsPort := listenPortOrDefault(cfg.System.Mgmt.HTTPSListenAddr, 8443)
	// Legacy listenAddr (single HTTP addr); fall back if HTTPListenAddr is empty.
	if strings.TrimSpace(cfg.System.Mgmt.HTTPListenAddr) == "" && strings.TrimSpace(cfg.System.Mgmt.ListenAddr) != "" {
		httpPort = listenPortOrDefault(cfg.System.Mgmt.ListenAddr, 8080)
	}
	sshPort := listenPortOrDefault(cfg.System.SSH.ListenAddr, 2222)

	enableHTTP := cfg.System.Mgmt.EnableHTTP == nil || *cfg.System.Mgmt.EnableHTTP
	enableHTTPS := cfg.System.Mgmt.EnableHTTPS != nil && *cfg.System.Mgmt.EnableHTTPS
	if cfg.System.Mgmt.EnableHTTPS == nil {
		// If unspecified, assume HTTPS enabled when HTTPSListenAddr is set.
		enableHTTPS = strings.TrimSpace(cfg.System.Mgmt.HTTPSListenAddr) != ""
	}

	// Build per-port iface allow-lists honoring per-interface access toggles.
	mgmtHTTPIfaces := make([]string, 0, len(cfg.Interfaces))
	mgmtHTTPSIfaces := make([]string, 0, len(cfg.Interfaces))
	sshIfaces := make([]string, 0, len(cfg.Interfaces))
	for _, iface := range cfg.Interfaces {
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

	// WireGuard: allow inbound to server listen port on wan zone (default).
	if cfg.Services.VPN.WireGuard.Enabled && cfg.Services.VPN.WireGuard.ListenPort > 0 {
		out = append(out, dprules.LocalServiceRule{
			ID:    "auto-allow-wireguard",
			Zone:  "wan",
			Proto: "udp",
			Port:  cfg.Services.VPN.WireGuard.ListenPort,
		})
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
			out = append(out, dprules.LocalServiceRule{
				ID:    "auto-allow-openvpn",
				Zone:  "wan",
				Proto: proto,
				Port:  port,
			})
		}
	}

	return out
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
