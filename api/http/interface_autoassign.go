// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"fmt"
	"net"
	"os"
	"sort"
	"strings"

	"github.com/tonylturner/containd/pkg/cp/config"
)

type autoAssignOptions struct {
	AllowFallback     bool
	DefaultRouteIface string
}

type autoAssignCandidate struct {
	name   string
	index  int
	hasMAC bool
}

func defaultInterfaceOrder() []string {
	return config.DefaultPhysicalInterfaces()
}

func defaultAutoAssignSubnets() map[string]string {
	return map[string]string{
		"wan":  envAnyOrDefault("192.168.240.0/24", "CONTAIND_AUTO_WAN_SUBNET", "CONTAIND_WAN_SUBNET"),
		"dmz":  envAnyOrDefault("192.168.241.0/24", "CONTAIND_AUTO_DMZ_SUBNET", "CONTAIND_DMZ_SUBNET"),
		"lan1": envAnyOrDefault("192.168.242.0/24", "CONTAIND_AUTO_LAN1_SUBNET", "CONTAIND_LAN1_SUBNET"),
		"lan2": envAnyOrDefault("192.168.243.0/24", "CONTAIND_AUTO_LAN2_SUBNET", "CONTAIND_LAN2_SUBNET"),
		"lan3": envAnyOrDefault("192.168.244.0/24", "CONTAIND_AUTO_LAN3_SUBNET", "CONTAIND_LAN3_SUBNET"),
		"lan4": envAnyOrDefault("192.168.245.0/24", "CONTAIND_AUTO_LAN4_SUBNET", "CONTAIND_LAN4_SUBNET"),
		"lan5": envAnyOrDefault("192.168.246.0/24", "CONTAIND_AUTO_LAN5_SUBNET", "CONTAIND_LAN5_SUBNET"),
		"lan6": envAnyOrDefault("192.168.247.0/24", "CONTAIND_AUTO_LAN6_SUBNET", "CONTAIND_LAN6_SUBNET"),
	}
}

func interfaceDeviceSet(state []config.InterfaceState) map[string]struct{} {
	out := map[string]struct{}{}
	for _, st := range state {
		if strings.TrimSpace(st.Name) == "" {
			continue
		}
		out[st.Name] = struct{}{}
	}
	return out
}

func buildAutoAssignCandidates(state []config.InterfaceState) ([]autoAssignCandidate, map[string]config.InterfaceState) {
	candidates := make([]autoAssignCandidate, 0, len(state))
	stateByName := make(map[string]config.InterfaceState, len(state))
	for _, st := range state {
		name := strings.TrimSpace(st.Name)
		if name == "" {
			continue
		}
		stateByName[name] = st
		if name == "lo" || !isAutoAssignableDevice(name, st.MAC) {
			continue
		}
		mac := strings.TrimSpace(strings.ToLower(st.MAC))
		hasMAC := mac != "" && mac != "00:00:00:00:00:00"
		candidates = append(candidates, autoAssignCandidate{name: name, index: st.Index, hasMAC: hasMAC})
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].hasMAC != candidates[j].hasMAC {
			return candidates[i].hasMAC
		}
		if candidates[i].index > 0 && candidates[j].index > 0 && candidates[i].index != candidates[j].index {
			return candidates[i].index < candidates[j].index
		}
		return candidates[i].name < candidates[j].name
	})
	return candidates, stateByName
}

func computeDefaultInterfaceAssignments(ifaces []config.Interface, state []config.InterfaceState, opts autoAssignOptions) (map[string]string, error) {
	order := defaultInterfaceOrder()
	ifaceByName, needed := defaultLogicalInterfaces(ifaces, order)
	if needed == 0 {
		return nil, fmt.Errorf("no default interfaces present")
	}

	candidates, stateByName := buildAutoAssignCandidates(state)
	if len(candidates) < needed {
		return nil, fmt.Errorf("not enough eligible kernel interfaces (%d) for defaults (%d)", len(candidates), needed)
	}

	assignments := map[string]string{}
	usedDev := map[string]bool{}
	assignByNamePrefix(order, ifaceByName, candidates, assignments, usedDev)
	assignBySubnet(order, ifaceByName, candidates, stateByName, assignments, usedDev, defaultAutoAssignSubnets())
	assignDefaultRouteWAN(ifaceByName, opts, stateByName, assignments, usedDev)
	if err := assignFallbackDefaults(order, ifaceByName, candidates, assignments, usedDev, opts.AllowFallback); err != nil {
		return nil, err
	}
	return assignments, nil
}

func defaultLogicalInterfaces(ifaces []config.Interface, order []string) (map[string]config.Interface, int) {
	ifaceByName := map[string]config.Interface{}
	needed := 0
	for _, iface := range ifaces {
		ifaceByName[iface.Name] = iface
	}
	for _, logical := range order {
		if _, ok := ifaceByName[logical]; ok {
			needed++
		}
	}
	return ifaceByName, needed
}

func assignByNamePrefix(order []string, ifaceByName map[string]config.Interface, candidates []autoAssignCandidate, assignments map[string]string, usedDev map[string]bool) {
	for _, logical := range order {
		if _, ok := ifaceByName[logical]; !ok {
			continue
		}
		for _, cand := range candidates {
			if usedDev[cand.name] {
				continue
			}
			if cand.name == logical || strings.HasPrefix(cand.name, logical) {
				assignments[logical] = cand.name
				usedDev[cand.name] = true
				break
			}
		}
	}
}

func assignBySubnet(order []string, ifaceByName map[string]config.Interface, candidates []autoAssignCandidate, stateByName map[string]config.InterfaceState, assignments map[string]string, usedDev map[string]bool, subnetByLogical map[string]string) {
	for _, logical := range order {
		if _, ok := ifaceByName[logical]; !ok {
			continue
		}
		if _, already := assignments[logical]; already {
			continue
		}
		cidr := strings.TrimSpace(subnetByLogical[logical])
		if cidr == "" {
			continue
		}
		for _, cand := range candidates {
			if usedDev[cand.name] {
				continue
			}
			st, ok := stateByName[cand.name]
			if !ok {
				continue
			}
			if ifaceHasIPv4InCIDR(st.Addrs, cidr) {
				assignments[logical] = cand.name
				usedDev[cand.name] = true
				break
			}
		}
	}
}

func assignDefaultRouteWAN(ifaceByName map[string]config.Interface, opts autoAssignOptions, stateByName map[string]config.InterfaceState, assignments map[string]string, usedDev map[string]bool) {
	if _, ok := ifaceByName["wan"]; !ok {
		return
	}
	if _, already := assignments["wan"]; already {
		return
	}
	defDev := strings.TrimSpace(opts.DefaultRouteIface)
	if defDev == "" || usedDev[defDev] {
		return
	}
	if st, ok := stateByName[defDev]; ok && isAutoAssignableDevice(defDev, st.MAC) {
		assignments["wan"] = defDev
		usedDev[defDev] = true
	}
}

func assignFallbackDefaults(order []string, ifaceByName map[string]config.Interface, candidates []autoAssignCandidate, assignments map[string]string, usedDev map[string]bool, allowFallback bool) error {
	for _, logical := range order {
		if _, ok := ifaceByName[logical]; !ok {
			continue
		}
		if _, already := assignments[logical]; already {
			continue
		}
		if !allowFallback {
			return fmt.Errorf("unable to safely auto-bind default interfaces")
		}
		for _, cand := range candidates {
			if usedDev[cand.name] {
				continue
			}
			assignments[logical] = cand.name
			usedDev[cand.name] = true
			break
		}
		if _, ok := assignments[logical]; !ok {
			return fmt.Errorf("not enough eligible kernel interfaces to complete auto-assign")
		}
	}
	return nil
}

func isAutoAssignableDevice(name string, mac string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" || name == "lo" {
		return false
	}
	skipPrefixes := []string{
		"erspan", "gre", "gretap", "ipip", "sit", "ip6tnl",
		"tun", "tap",
		"veth", "br", "docker", "cni", "flannel", "calico",
		"vxlan", "geneve",
		"wg", "tailscale",
		"virbr", "vmnet", "utun",
		"dummy", "ifb", "nlmon",
	}
	for _, p := range skipPrefixes {
		if strings.HasPrefix(name, p) {
			return false
		}
	}
	return true
}

func envAnyOrDefault(def string, keys ...string) string {
	for _, key := range keys {
		if v := strings.TrimSpace(os.Getenv(key)); v != "" {
			return v
		}
	}
	return def
}

func ifaceHasIPv4InCIDR(addrs []string, cidr string) bool {
	cidr = strings.TrimSpace(cidr)
	if cidr == "" {
		return false
	}
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil || ipnet == nil {
		return false
	}
	for _, a := range addrs {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		var ip net.IP
		if strings.Contains(a, "/") {
			var ipnet2 *net.IPNet
			ip, ipnet2, err = net.ParseCIDR(a)
			if err != nil || ipnet2 == nil {
				continue
			}
		} else {
			ip = net.ParseIP(a)
			if ip == nil {
				continue
			}
		}
		ip4 := ip.To4()
		if ip4 == nil {
			continue
		}
		if ip4[0] == 169 && ip4[1] == 254 {
			continue
		}
		if ipnet.Contains(ip4) {
			return true
		}
	}
	return false
}

func autoBindDefaultInterfaceDevices(cfg *config.Config) bool {
	if cfg == nil || len(cfg.Interfaces) == 0 {
		return false
	}
	state, err := collectLocalInterfaceState()
	if err != nil {
		return false
	}
	return autoBindDefaultInterfaceDevicesFromState(cfg, state, detectKernelDefaultRouteIface())
}

func autoBindDefaultInterfaceDevicesFromState(cfg *config.Config, state []config.InterfaceState, defaultRouteIface string) bool {
	if cfg == nil || len(cfg.Interfaces) == 0 {
		return false
	}
	assignments, err := computeDefaultInterfaceAssignments(cfg.Interfaces, state, autoAssignOptions{
		AllowFallback:     false,
		DefaultRouteIface: defaultRouteIface,
	})
	if err != nil || len(assignments) == 0 {
		return false
	}
	if !shouldRepairDefaultInterfaceBindings(cfg.Interfaces, state, assignments) {
		return false
	}
	changed := false
	for i := range cfg.Interfaces {
		if dev, ok := assignments[cfg.Interfaces[i].Name]; ok && strings.TrimSpace(cfg.Interfaces[i].Device) != dev {
			cfg.Interfaces[i].Device = dev
			changed = true
		}
	}
	return changed
}

func collectLocalInterfaceState() ([]config.InterfaceState, error) {
	sysIfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]config.InterfaceState, 0, len(sysIfaces))
	for _, si := range sysIfaces {
		addrs, _ := si.Addrs()
		ss := make([]string, 0, len(addrs))
		for _, a := range addrs {
			ss = append(ss, a.String())
		}
		out = append(out, config.InterfaceState{
			Name:  si.Name,
			Index: si.Index,
			Up:    si.Flags&net.FlagUp != 0,
			MTU:   si.MTU,
			MAC:   si.HardwareAddr.String(),
			Addrs: ss,
		})
	}
	return out, nil
}

func shouldRepairDefaultInterfaceBindings(ifaces []config.Interface, state []config.InterfaceState, assignments map[string]string) bool {
	defaultNames := defaultInterfaceOrder()
	defaultSet := map[string]struct{}{}
	ifaceByName := map[string]config.Interface{}
	for _, name := range defaultNames {
		defaultSet[name] = struct{}{}
	}
	for _, iface := range ifaces {
		if _, ok := defaultSet[iface.Name]; !ok {
			return false
		}
		ifaceByName[iface.Name] = iface
	}

	for _, name := range defaultNames {
		if iface, ok := ifaceByName[name]; ok && strings.TrimSpace(iface.Device) == "" {
			return true
		}
	}

	candidates, _ := buildAutoAssignCandidates(state)
	idxOrder := map[string]string{}
	idx := 0
	for _, name := range defaultNames {
		if _, ok := ifaceByName[name]; !ok {
			continue
		}
		if idx >= len(candidates) {
			return false
		}
		idxOrder[name] = candidates[idx].name
		idx++
	}

	looksLikeLegacyIndexBinding := true
	needsRepair := false
	for _, name := range defaultNames {
		iface, ok := ifaceByName[name]
		if !ok {
			continue
		}
		cur := strings.TrimSpace(iface.Device)
		if cur != idxOrder[name] {
			looksLikeLegacyIndexBinding = false
		}
		if want := strings.TrimSpace(assignments[name]); want != "" && cur != want {
			needsRepair = true
		}
	}
	return looksLikeLegacyIndexBinding && needsRepair
}
