// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package cli

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func setOutboundQuickstartLANWAN(api *API) Command {
	type ifaceState struct {
		Name  string   `json:"name"`
		Addrs []string `json:"addrs"`
	}
	type iface struct {
		Name   string `json:"name"`
		Device string `json:"device,omitempty"`
		Zone   string `json:"zone,omitempty"`
	}
	type firewallRule struct {
		ID          string   `json:"id"`
		Description string   `json:"description,omitempty"`
		SourceZones []string `json:"sourceZones,omitempty"`
		DestZones   []string `json:"destZones,omitempty"`
		Action      string   `json:"action"`
	}

	firstHostInCIDR := func(cidr string) (string, error) {
		_, ipnet, err := net.ParseCIDR(strings.TrimSpace(cidr))
		if err != nil || ipnet == nil || ipnet.IP == nil {
			return "", fmt.Errorf("invalid cidr %q", cidr)
		}
		ip4 := ipnet.IP.To4()
		if ip4 == nil {
			return "", fmt.Errorf("cidr must be IPv4: %q", cidr)
		}
		ones, bits := ipnet.Mask.Size()
		if bits != 32 {
			return "", fmt.Errorf("cidr must be IPv4: %q", cidr)
		}
		if ones >= 31 {
			return "", fmt.Errorf("cidr too small to infer gateway: %q", cidr)
		}
		netIP := ip4.Mask(ipnet.Mask)
		gw := net.IPv4(netIP[0], netIP[1], netIP[2], netIP[3])
		gw[3]++
		return gw.String(), nil
	}

	pickWAN := func(ifaces []iface) *iface {
		for i := range ifaces {
			if ifaces[i].Name == "wan" {
				return &ifaces[i]
			}
		}
		for i := range ifaces {
			if strings.EqualFold(strings.TrimSpace(ifaces[i].Zone), "wan") {
				return &ifaces[i]
			}
		}
		return nil
	}

	pickWANIPv4CIDR := func(states []ifaceState, dev string) string {
		for _, st := range states {
			if st.Name != dev {
				continue
			}
			for _, addr := range st.Addrs {
				a := strings.TrimSpace(addr)
				if a == "" || !strings.Contains(a, "/") || strings.Contains(a, ":") {
					continue
				}
				if strings.HasPrefix(a, "169.254.") {
					continue
				}
				return a
			}
		}
		return ""
	}

	return func(ctx context.Context, out io.Writer, args []string) error {
		if api == nil {
			return fmt.Errorf("api unavailable")
		}
		if out == nil {
			return nil
		}

		// 1) Determine WAN + infer gateway.
		var ifaces []iface
		if err := api.getJSON(ctx, "/api/v1/interfaces", &ifaces); err != nil {
			return err
		}
		wan := pickWAN(ifaces)
		if wan == nil {
			return fmt.Errorf("could not determine wan interface (expected an interface named 'wan' or in zone 'wan')")
		}
		wanDev := strings.TrimSpace(firstNonEmpty(wan.Device, wan.Name))
		if wanDev == "" {
			return fmt.Errorf("wan interface has no device binding")
		}

		var states []ifaceState
		if err := api.getJSON(ctx, "/api/v1/interfaces/state", &states); err != nil {
			return err
		}
		wanCIDR := pickWANIPv4CIDR(states, wanDev)
		if wanCIDR == "" {
			return fmt.Errorf("could not determine wan IPv4 address for device %q (try restarting so DHCP assigns an IP)", wanDev)
		}
		gwIP, err := firstHostInCIDR(wanCIDR)
		if err != nil {
			return err
		}

		// 2) Routing: ensure gateway + default route.
		var routing config.RoutingConfig
		if err := api.getJSON(ctx, "/api/v1/routing", &routing); err != nil {
			return err
		}
		const gwName = "wan-gw"
		nextGW := config.Gateway{
			Name:        gwName,
			Address:     gwIP,
			Iface:       wanDev,
			Description: "Quick start: WAN default gateway",
		}
		foundGW := false
		for i := range routing.Gateways {
			if routing.Gateways[i].Name == gwName {
				routing.Gateways[i] = nextGW
				foundGW = true
				break
			}
		}
		if !foundGW {
			routing.Gateways = append(routing.Gateways, nextGW)
		}

		isDefault := func(dst string) bool {
			d := strings.ToLower(strings.TrimSpace(dst))
			return d == "default" || d == "0.0.0.0/0"
		}
		foundDefault := false
		for i := range routing.Routes {
			if isDefault(routing.Routes[i].Dst) && routing.Routes[i].Table == 0 {
				routing.Routes[i] = config.StaticRoute{Dst: "default", Gateway: gwName, Iface: wanDev, Table: 0}
				foundDefault = true
				break
			}
		}
		if !foundDefault {
			routing.Routes = append(routing.Routes, config.StaticRoute{Dst: "default", Gateway: gwName, Iface: wanDev, Table: 0})
		}
		if err := api.postJSON(ctx, "/api/v1/routing", routing, nil); err != nil {
			return err
		}

		// 3) NAT: enable SNAT masquerade for lan+mgmt out wan.
		var nat config.NATConfig
		_ = api.getJSON(ctx, "/api/v1/firewall/nat", &nat)
		nat.Enabled = true
		nat.EgressZone = "wan"
		nat.SourceZones = []string{"lan", "mgmt"}
		if err := api.postJSON(ctx, "/api/v1/firewall/nat", nat, nil); err != nil {
			return err
		}

		// 4) Firewall: ensure an ALLOW rule exists for lan+mgmt -> wan.
		var rules []firewallRule
		_ = api.getJSON(ctx, "/api/v1/firewall/rules", &rules)
		const allowID = "allow-lan-mgmt-wan"
		allow := firewallRule{
			ID:          allowID,
			Description: "Quick start: allow LAN/MGMT to WAN",
			SourceZones: []string{"lan", "mgmt"},
			DestZones:   []string{"wan"},
			Action:      "ALLOW",
		}
		exists := false
		for _, r := range rules {
			if r.ID == allowID {
				exists = true
				break
			}
		}
		if exists {
			if err := api.patchJSON(ctx, "/api/v1/firewall/rules/"+urlEscape(allowID), allow, nil); err != nil {
				return err
			}
		} else {
			if err := api.postJSON(ctx, "/api/v1/firewall/rules", allow, nil); err != nil {
				return err
			}
		}

		fmt.Fprintf(out, "ok\n\n")
		fmt.Fprintf(out, "Enabled outbound quick start:\n")
		fmt.Fprintf(out, "- default route via %s (%s on %s)\n", gwName, gwIP, wanDev)
		fmt.Fprintf(out, "- SNAT enabled (sources: lan, mgmt → egress: wan)\n")
		fmt.Fprintf(out, "- firewall rule %q: ALLOW (lan, mgmt) → wan\n", allowID)
		return nil
	}
}

func urlEscape(s string) string {
	// Minimal URL path escaping for IDs.
	r := strings.NewReplacer(
		"%", "%25",
		"/", "%2F",
		"?", "%3F",
		"#", "%23",
		" ", "%20",
	)
	return r.Replace(s)
}

