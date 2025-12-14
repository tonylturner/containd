package cli

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/containd/containd/pkg/cp/config"
)

func showNATAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		var nat config.NATConfig
		if err := api.getJSON(ctx, "/api/v1/firewall/nat", &nat); err != nil {
			return err
		}
		t := newTable("FIELD", "VALUE")
		t.addRow("snat_enabled", yesNoStr(nat.Enabled))
		t.addRow("snat_egress_zone", firstNonEmpty(strings.TrimSpace(nat.EgressZone), "wan (default)"))
		if len(nat.SourceZones) == 0 {
			t.addRow("snat_source_zones", "lan, dmz (default)")
		} else {
			zs := append([]string(nil), nat.SourceZones...)
			for i := range zs {
				zs[i] = strings.TrimSpace(zs[i])
			}
			sort.Strings(zs)
			t.addRow("snat_source_zones", strings.Join(zs, ", "))
		}
		t.addRow("port_forwards", fmt.Sprintf("%d", len(nat.PortForwards)))
		t.render(out)
		if out != nil && len(nat.PortForwards) > 0 {
			fmt.Fprintln(out)
			fmt.Fprintln(out, "Port forwards:")
			_ = showPortForwardsAPI(api)(ctx, out, nil)
		}
		return nil
	}
}

func setNATAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if len(args) == 0 {
			return fmt.Errorf("usage: set nat on|off [egress <zone|default>] [sources <z1,z2|default>]")
		}
		var nat config.NATConfig
		_ = api.getJSON(ctx, "/api/v1/firewall/nat", &nat)

		// First arg: on/off/enable/disable
		switch strings.ToLower(strings.TrimSpace(args[0])) {
		case "on", "enable", "enabled", "true", "yes", "1":
			nat.Enabled = true
		case "off", "disable", "disabled", "false", "no", "0":
			nat.Enabled = false
		default:
			return fmt.Errorf("usage: set nat on|off [egress <zone|default>] [sources <z1,z2|default>]")
		}

		i := 1
		for i < len(args) {
			key := strings.ToLower(strings.TrimSpace(args[i]))
			i++
			if i >= len(args) {
				return fmt.Errorf("missing value for %q", key)
			}
			val := strings.TrimSpace(args[i])
			i++
			switch key {
			case "egress", "egress-zone", "egress_zone":
				if strings.EqualFold(val, "default") || val == "-" {
					nat.EgressZone = ""
				} else {
					nat.EgressZone = val
				}
			case "sources", "source-zones", "source_zones":
				if strings.EqualFold(val, "default") || val == "-" {
					nat.SourceZones = nil
					continue
				}
				parts := strings.Split(val, ",")
				var zs []string
				seen := map[string]struct{}{}
				for _, p := range parts {
					p = strings.TrimSpace(p)
					if p == "" {
						continue
					}
					if _, ok := seen[p]; ok {
						continue
					}
					seen[p] = struct{}{}
					zs = append(zs, p)
				}
				nat.SourceZones = zs
			default:
				return fmt.Errorf("unknown option %q (supported: egress, sources)", key)
			}
		}

		return api.postJSON(ctx, "/api/v1/firewall/nat", nat, out)
	}
}
