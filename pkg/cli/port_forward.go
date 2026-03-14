// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package cli

import (
	"context"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func showPortForwardsAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if out == nil {
			return nil
		}
		if len(args) != 0 {
			return fmt.Errorf("usage: show port-forwards")
		}
		var nat config.NATConfig
		if err := api.getJSON(ctx, "/api/v1/firewall/nat", &nat); err != nil {
			return err
		}
		pfs := append([]config.PortForward(nil), nat.PortForwards...)
		sort.Slice(pfs, func(i, j int) bool { return pfs[i].ID < pfs[j].ID })

		t := newTable("ID", "EN", "INGRESS", "PROTO", "LISTEN", "DEST", "SOURCES", "DESC")
		if len(pfs) == 0 {
			t.addRow("—", "—", "—", "—", "—", "—", "—", "—")
			t.render(out)
			return nil
		}
		for _, pf := range pfs {
			destPort := pf.DestPort
			if destPort == 0 {
				destPort = pf.ListenPort
			}
			dest := strings.TrimSpace(pf.DestIP)
			if destPort > 0 {
				dest = fmt.Sprintf("%s:%d", dest, destPort)
			}
			src := "any"
			if len(pf.AllowedSources) > 0 {
				src = strings.Join(pf.AllowedSources, ",")
			}
			t.addRow(
				pf.ID,
				yesNoStr(pf.Enabled),
				pf.IngressZone,
				pf.Proto,
				strconv.Itoa(pf.ListenPort),
				dest,
				src,
				emptyDash(pf.Description),
			)
		}
		t.render(out)
		return nil
	}
}

func setPortForwardAddAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if api == nil {
			return fmt.Errorf("api unavailable")
		}
		pf, err := parsePortForwardAddArgs(args)
		if err != nil {
			return err
		}
		if err := addPortForward(ctx, api, pf); err != nil {
			return err
		}
		if out != nil {
			_ = showPortForwardsAPI(api)(ctx, out, nil)
		}
		return nil
	}
}

func parsePortForwardAddArgs(args []string) (config.PortForward, error) {
	if len(args) < 5 {
		return config.PortForward{}, fmt.Errorf("usage: set port-forward add <id> <ingress_zone> <tcp|udp> <listen_port> <dest_ip[:dest_port]> [sources <cidr1,cidr2>] [desc <text>] [off]")
	}
	pf := config.PortForward{
		ID:          strings.TrimSpace(args[0]),
		Enabled:     true,
		IngressZone: strings.TrimSpace(args[1]),
		Proto:       strings.ToLower(strings.TrimSpace(args[2])),
	}
	if err := validatePortForwardIdentity(&pf, args[3]); err != nil {
		return config.PortForward{}, err
	}
	if err := parsePortForwardDest(&pf, args[4]); err != nil {
		return config.PortForward{}, err
	}
	if err := applyPortForwardOptions(&pf, args[5:]); err != nil {
		return config.PortForward{}, err
	}
	return pf, nil
}

func validatePortForwardIdentity(pf *config.PortForward, listenPortArg string) error {
	if pf.ID == "" {
		return fmt.Errorf("id is required")
	}
	if pf.IngressZone == "" {
		return fmt.Errorf("ingress_zone is required")
	}
	if pf.Proto != "tcp" && pf.Proto != "udp" {
		return fmt.Errorf("proto must be tcp or udp")
	}
	lp, err := strconv.Atoi(strings.TrimSpace(listenPortArg))
	if err != nil || lp < 1 || lp > 65535 {
		return fmt.Errorf("invalid listen_port %q", listenPortArg)
	}
	pf.ListenPort = lp
	return nil
}

func parsePortForwardDest(pf *config.PortForward, destArg string) error {
	destArg = strings.TrimSpace(destArg)
	if destArg == "" {
		return fmt.Errorf("dest is required")
	}
	if strings.Contains(destArg, ":") {
		host, portStr, err := net.SplitHostPort(destArg)
		if err != nil {
			return fmt.Errorf("invalid dest %q", destArg)
		}
		pf.DestIP = strings.TrimSpace(host)
		dp, err := strconv.Atoi(strings.TrimSpace(portStr))
		if err != nil || dp < 1 || dp > 65535 {
			return fmt.Errorf("invalid dest_port %q", portStr)
		}
		pf.DestPort = dp
	} else {
		pf.DestIP = destArg
	}
	if ip := net.ParseIP(strings.TrimSpace(pf.DestIP)); ip == nil || ip.To4() == nil {
		return fmt.Errorf("dest_ip must be an IPv4 address")
	}
	return nil
}

func applyPortForwardOptions(pf *config.PortForward, args []string) error {
	for i := 0; i < len(args); {
		key := strings.ToLower(strings.TrimSpace(args[i]))
		switch key {
		case "off", "disabled", "disable":
			pf.Enabled = false
			i++
		case "sources", "source", "src":
			value, next, err := optionValue(key, args, i)
			if err != nil {
				return err
			}
			sources, err := parseAllowedSourceCIDRs(value)
			if err != nil {
				return err
			}
			pf.AllowedSources = sources
			i = next
		case "desc", "description":
			value, next, err := optionValue(key, args, i)
			if err != nil {
				return err
			}
			pf.Description = strings.TrimSpace(value)
			i = next
		default:
			return fmt.Errorf("unexpected token %q", args[i])
		}
	}
	return nil
}

func optionValue(key string, args []string, i int) (string, int, error) {
	i++
	if i >= len(args) {
		return "", i, fmt.Errorf("missing value for %q", key)
	}
	return strings.TrimSpace(args[i]), i + 1, nil
}

func parseAllowedSourceCIDRs(value string) ([]string, error) {
	if value == "" || value == "-" || strings.EqualFold(value, "any") {
		return nil, nil
	}
	parts := strings.Split(value, ",")
	var outCIDRs []string
	seen := map[string]struct{}{}
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(p); err != nil {
			return nil, fmt.Errorf("invalid sources CIDR %q", p)
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		outCIDRs = append(outCIDRs, p)
	}
	return outCIDRs, nil
}

func addPortForward(ctx context.Context, api *API, pf config.PortForward) error {
	var nat config.NATConfig
	_ = api.getJSON(ctx, "/api/v1/firewall/nat", &nat)
	for _, existing := range nat.PortForwards {
		if existing.ID == pf.ID {
			return fmt.Errorf("port-forward already exists: %s", pf.ID)
		}
	}
	nat.PortForwards = append(nat.PortForwards, pf)
	return api.postJSON(ctx, "/api/v1/firewall/nat", nat, nil)
}

func setPortForwardDelAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if api == nil {
			return fmt.Errorf("api unavailable")
		}
		if len(args) != 1 || strings.TrimSpace(args[0]) == "" {
			return fmt.Errorf("usage: set port-forward del <id>")
		}
		id := strings.TrimSpace(args[0])

		var nat config.NATConfig
		if err := api.getJSON(ctx, "/api/v1/firewall/nat", &nat); err != nil {
			return err
		}
		filtered := make([]config.PortForward, 0, len(nat.PortForwards))
		removed := false
		for _, pf := range nat.PortForwards {
			if pf.ID == id {
				removed = true
				continue
			}
			filtered = append(filtered, pf)
		}
		if !removed {
			return fmt.Errorf("port-forward not found: %s", id)
		}
		nat.PortForwards = filtered
		if err := api.postJSON(ctx, "/api/v1/firewall/nat", nat, nil); err != nil {
			return err
		}
		if out != nil {
			_ = showPortForwardsAPI(api)(ctx, out, nil)
		}
		return nil
	}
}

func setPortForwardEnableAPI(api *API, enabled bool) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if api == nil {
			return fmt.Errorf("api unavailable")
		}
		if len(args) != 1 || strings.TrimSpace(args[0]) == "" {
			if enabled {
				return fmt.Errorf("usage: set port-forward enable <id>")
			}
			return fmt.Errorf("usage: set port-forward disable <id>")
		}
		id := strings.TrimSpace(args[0])

		var nat config.NATConfig
		if err := api.getJSON(ctx, "/api/v1/firewall/nat", &nat); err != nil {
			return err
		}
		updated := false
		for i := range nat.PortForwards {
			if nat.PortForwards[i].ID == id {
				nat.PortForwards[i].Enabled = enabled
				updated = true
				break
			}
		}
		if !updated {
			return fmt.Errorf("port-forward not found: %s", id)
		}
		if err := api.postJSON(ctx, "/api/v1/firewall/nat", nat, nil); err != nil {
			return err
		}
		if out != nil {
			_ = showPortForwardsAPI(api)(ctx, out, nil)
		}
		return nil
	}
}
