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

type outboundIfaceState struct {
	Name  string   `json:"name"`
	Addrs []string `json:"addrs"`
}

type outboundIface struct {
	Name   string `json:"name"`
	Device string `json:"device,omitempty"`
	Zone   string `json:"zone,omitempty"`
}

type outboundFirewallRule struct {
	ID          string   `json:"id"`
	Description string   `json:"description,omitempty"`
	SourceZones []string `json:"sourceZones,omitempty"`
	DestZones   []string `json:"destZones,omitempty"`
	Action      string   `json:"action"`
}

const (
	quickstartGatewayName = "wan-gw"
	quickstartAllowRuleID = "allow-lan-mgmt-wan"
)

func setOutboundQuickstartLANWAN(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if api == nil {
			return fmt.Errorf("api unavailable")
		}
		if out == nil {
			return nil
		}

		wanDev, gwIP, err := inferWANGateway(ctx, api)
		if err != nil {
			return err
		}
		if err := applyQuickstartRouting(ctx, api, wanDev, gwIP); err != nil {
			return err
		}
		if err := applyQuickstartNAT(ctx, api); err != nil {
			return err
		}
		if err := ensureQuickstartAllowRule(ctx, api); err != nil {
			return err
		}

		fmt.Fprintf(out, "ok\n\n")
		fmt.Fprintf(out, "Enabled outbound quick start:\n")
		fmt.Fprintf(out, "- default route via %s (%s on %s)\n", quickstartGatewayName, gwIP, wanDev)
		fmt.Fprintf(out, "- SNAT enabled (sources: lan, mgmt → egress: wan)\n")
		fmt.Fprintf(out, "- firewall rule %q: ALLOW (lan, mgmt) → wan\n", quickstartAllowRuleID)
		return nil
	}
}

func inferWANGateway(ctx context.Context, api *API) (string, string, error) {
	var ifaces []outboundIface
	if err := api.getJSON(ctx, "/api/v1/interfaces", &ifaces); err != nil {
		return "", "", err
	}
	wan := pickWAN(ifaces)
	if wan == nil {
		return "", "", fmt.Errorf("could not determine wan interface (expected an interface named 'wan' or in zone 'wan')")
	}
	wanDev := strings.TrimSpace(firstNonEmpty(wan.Device, wan.Name))
	if wanDev == "" {
		return "", "", fmt.Errorf("wan interface has no device binding")
	}
	var states []outboundIfaceState
	if err := api.getJSON(ctx, "/api/v1/interfaces/state", &states); err != nil {
		return "", "", err
	}
	wanCIDR := pickWANIPv4CIDR(states, wanDev)
	if wanCIDR == "" {
		return "", "", fmt.Errorf("could not determine wan IPv4 address for device %q (try restarting so DHCP assigns an IP)", wanDev)
	}
	gwIP, err := firstHostInCIDR(wanCIDR)
	if err != nil {
		return "", "", err
	}
	return wanDev, gwIP, nil
}

func applyQuickstartRouting(ctx context.Context, api *API, wanDev, gwIP string) error {
	var routing config.RoutingConfig
	if err := api.getJSON(ctx, "/api/v1/routing", &routing); err != nil {
		return err
	}
	nextGW := config.Gateway{
		Name:        quickstartGatewayName,
		Address:     gwIP,
		Iface:       wanDev,
		Description: "Quick start: WAN default gateway",
	}
	foundGW := false
	for i := range routing.Gateways {
		if routing.Gateways[i].Name == quickstartGatewayName {
			routing.Gateways[i] = nextGW
			foundGW = true
			break
		}
	}
	if !foundGW {
		routing.Gateways = append(routing.Gateways, nextGW)
	}
	foundDefault := false
	for i := range routing.Routes {
		if isDefaultQuickstartRoute(routing.Routes[i].Dst) && routing.Routes[i].Table == 0 {
			routing.Routes[i] = config.StaticRoute{Dst: "default", Gateway: quickstartGatewayName, Iface: wanDev, Table: 0}
			foundDefault = true
			break
		}
	}
	if !foundDefault {
		routing.Routes = append(routing.Routes, config.StaticRoute{Dst: "default", Gateway: quickstartGatewayName, Iface: wanDev, Table: 0})
	}
	return api.postJSON(ctx, "/api/v1/routing", routing, nil)
}

func isDefaultQuickstartRoute(dst string) bool {
	d := strings.ToLower(strings.TrimSpace(dst))
	return d == "default" || d == "0.0.0.0/0"
}

func applyQuickstartNAT(ctx context.Context, api *API) error {
	var nat config.NATConfig
	_ = api.getJSON(ctx, "/api/v1/firewall/nat", &nat)
	nat.Enabled = true
	nat.EgressZone = "wan"
	nat.SourceZones = []string{"lan", "mgmt"}
	return api.postJSON(ctx, "/api/v1/firewall/nat", nat, nil)
}

func ensureQuickstartAllowRule(ctx context.Context, api *API) error {
	var rules []outboundFirewallRule
	_ = api.getJSON(ctx, "/api/v1/firewall/rules", &rules)
	allow := outboundFirewallRule{
		ID:          quickstartAllowRuleID,
		Description: "Quick start: allow LAN/MGMT to WAN",
		SourceZones: []string{"lan", "mgmt"},
		DestZones:   []string{"wan"},
		Action:      "ALLOW",
	}
	for _, r := range rules {
		if r.ID == quickstartAllowRuleID {
			return api.patchJSON(ctx, "/api/v1/firewall/rules/"+urlEscape(quickstartAllowRuleID), allow, nil)
		}
	}
	return api.postJSON(ctx, "/api/v1/firewall/rules", allow, nil)
}

func firstHostInCIDR(cidr string) (string, error) {
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
	netIP := ip4.Mask(ipnet.Mask).To4()
	if netIP == nil {
		return "", fmt.Errorf("cidr must be IPv4: %q", cidr)
	}
	gw := append(net.IP(nil), netIP...)
	gw[3]++
	return gw.String(), nil
}

func pickWAN(ifaces []outboundIface) *outboundIface {
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

func pickWANIPv4CIDR(states []outboundIfaceState, dev string) string {
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
