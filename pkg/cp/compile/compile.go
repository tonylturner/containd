package compile

import (
	"fmt"

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

	return snap, nil
}
