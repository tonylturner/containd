package compile

import (
	"fmt"
	"sort"
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
