// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build linux

package netcfg

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/tonylturner/containd/pkg/cp/config"
	"golang.org/x/sys/unix"
)

type interfaceResolver struct {
	byName map[string]config.Interface
}

func newInterfaceResolver(ifaces []config.Interface) interfaceResolver {
	byName := make(map[string]config.Interface, len(ifaces))
	for _, iface := range ifaces {
		if name := strings.TrimSpace(iface.Name); name != "" {
			byName[name] = iface
		}
	}
	return interfaceResolver{byName: byName}
}

func (r interfaceResolver) resolveDev(ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return ""
	}
	if iface, ok := r.byName[ref]; ok {
		if dev := strings.TrimSpace(iface.Device); dev != "" {
			return dev
		}
		return strings.TrimSpace(iface.Name)
	}
	return ref
}

func (r interfaceResolver) deviceFor(iface config.Interface) string {
	if dev := strings.TrimSpace(iface.Device); dev != "" {
		return dev
	}
	return strings.TrimSpace(iface.Name)
}

func applyInterfaces(ctx context.Context, ifaces []config.Interface, opts ApplyOptions) error {
	if shouldEnableForwarding(ifaces) {
		if err := enableForwarding(); err != nil {
			return err
		}
	}

	resolver := newInterfaceResolver(ifaces)
	bridgeMembers, err := prepareVirtualInterfaces(ifaces, resolver)
	if err != nil {
		return err
	}
	for _, iface := range ifaces {
		if err := applyInterfaceConfig(ctx, iface, bridgeMembers, resolver, opts); err != nil {
			return err
		}
	}
	return nil
}

func prepareVirtualInterfaces(ifaces []config.Interface, resolver interfaceResolver) (map[string]string, error) {
	bridgeMembers := map[string]string{}
	for _, iface := range ifaces {
		dev := resolver.deviceFor(iface)
		if dev == "" {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(iface.Type)) {
		case "", "physical":
			continue
		case "bridge":
			if err := ensureBridgeInterface(dev, iface, resolver, bridgeMembers); err != nil {
				return nil, err
			}
		case "vlan":
			if err := ensureVLANInterface(dev, iface, resolver); err != nil {
				return nil, err
			}
		default:
			// validated earlier
		}
	}
	return bridgeMembers, nil
}

func ensureBridgeInterface(dev string, iface config.Interface, resolver interfaceResolver, bridgeMembers map[string]string) error {
	if err := ensureBridge(dev); err != nil {
		return fmt.Errorf("ensure bridge %s: %w", dev, err)
	}
	if err := setLinkUp(dev); err != nil {
		return fmt.Errorf("set link up %s: %w", dev, err)
	}
	br, err := net.InterfaceByName(dev)
	if err != nil {
		return fmt.Errorf("bridge %s not found after create: %w", dev, err)
	}
	for _, member := range iface.Members {
		memberDev := resolver.resolveDev(member)
		if memberDev == "" {
			continue
		}
		bridgeMembers[memberDev] = dev
		if err := setLinkUp(memberDev); err != nil {
			return fmt.Errorf("set link up %s: %w", memberDev, err)
		}
		if err := setLinkMaster(memberDev, br.Index); err != nil {
			return fmt.Errorf("attach %s to bridge %s: %w", memberDev, dev, err)
		}
	}
	return nil
}

func ensureVLANInterface(dev string, iface config.Interface, resolver interfaceResolver) error {
	parentDev := resolver.resolveDev(iface.Parent)
	if parentDev == "" {
		return fmt.Errorf("vlan %s missing parent", iface.Name)
	}
	parent, err := net.InterfaceByName(parentDev)
	if err != nil {
		return fmt.Errorf("vlan %s parent %s not found: %w", iface.Name, parentDev, err)
	}
	if err := ensureVLAN(dev, parent.Index, iface.VLANID); err != nil {
		return fmt.Errorf("ensure vlan %s: %w", dev, err)
	}
	if err := setLinkUp(dev); err != nil {
		return fmt.Errorf("set link up %s: %w", dev, err)
	}
	return nil
}

func applyInterfaceConfig(ctx context.Context, iface config.Interface, bridgeMembers map[string]string, resolver interfaceResolver, opts ApplyOptions) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	dev := resolver.deviceFor(iface)
	if dev == "" {
		return nil
	}
	if err := validateBridgeMemberConfig(iface, dev, bridgeMembers); err != nil {
		return err
	}
	if bridgeMembers[dev] != "" {
		return nil
	}
	if strings.EqualFold(strings.TrimSpace(iface.AddressMode), "dhcp") {
		return applyDHCPInterface(ctx, iface, dev)
	}
	if len(iface.Addresses) == 0 {
		return nil
	}
	return applyStaticInterface(ctx, iface, dev, opts)
}

func validateBridgeMemberConfig(iface config.Interface, dev string, bridgeMembers map[string]string) error {
	if br := bridgeMembers[dev]; br != "" && (len(iface.Addresses) > 0 || strings.TrimSpace(iface.Gateway) != "") {
		return fmt.Errorf("interface %s (%s) is a bridge member of %s; assign addresses to the bridge instead", iface.Name, dev, br)
	}
	return nil
}

func applyDHCPInterface(ctx context.Context, iface config.Interface, dev string) error {
	if err := setLinkUp(dev); err != nil {
		return fmt.Errorf("set link up %s: %w", dev, err)
	}
	nic, err := net.InterfaceByName(dev)
	if err != nil {
		return fmt.Errorf("interface %s (%s) not found: %w", iface.Name, dev, err)
	}
	existing, _ := listAddrs(nic.Index, unix.AF_INET)
	if hasUsableIPv4(existing) {
		return nil
	}
	lease, err := dhcpAcquireV4(ctx, dev, 5)
	if err != nil {
		return fmt.Errorf("dhcp on %s: %w", dev, err)
	}
	_, ipnet, err := net.ParseCIDR(strings.TrimSpace(lease.AddrCIDR))
	if err != nil || ipnet == nil {
		return fmt.Errorf("dhcp on %s: invalid lease cidr %q", dev, lease.AddrCIDR)
	}
	if err := addAddr(nic.Index, ipnet); err != nil {
		return fmt.Errorf("dhcp add addr %s %s: %w", dev, ipnet.String(), err)
	}
	if gw := strings.TrimSpace(lease.RouterIP); gw != "" {
		if err := addDefaultRoute(nic.Index, gw); err != nil {
			return fmt.Errorf("dhcp add default route %s via %s: %w", dev, gw, err)
		}
	}
	return nil
}

func hasUsableIPv4(existing []*net.IPNet) bool {
	for _, ipnet := range existing {
		if ipnet == nil || ipnet.IP == nil {
			continue
		}
		ip4 := ipnet.IP.To4()
		if ip4 == nil || strings.HasPrefix(ip4.String(), "169.254.") {
			continue
		}
		return true
	}
	return false
}

func applyStaticInterface(ctx context.Context, iface config.Interface, dev string, opts ApplyOptions) error {
	nic, err := net.InterfaceByName(dev)
	if err != nil {
		return fmt.Errorf("interface %s (%s) not found: %w", iface.Name, dev, err)
	}
	if err := setLinkUp(dev); err != nil {
		return fmt.Errorf("set link up %s: %w", dev, err)
	}
	desired, desiredV4, err := desiredInterfaceAddrs(ctx, iface)
	if err != nil {
		return err
	}
	if err := replaceInterfaceAddrsIfNeeded(nic.Index, dev, desired, desiredV4, opts); err != nil {
		return err
	}
	if gw := strings.TrimSpace(iface.Gateway); gw != "" {
		if err := addDefaultRoute(nic.Index, gw); err != nil {
			return fmt.Errorf("add default route %s via %s: %w", dev, gw, err)
		}
	}
	return nil
}

func desiredInterfaceAddrs(ctx context.Context, iface config.Interface) (map[string]struct{}, map[string]struct{}, error) {
	desired := map[string]struct{}{}
	desiredV4 := map[string]struct{}{}
	for _, cidr := range iface.Addresses {
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		default:
		}
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil || ipnet == nil || ipnet.IP == nil {
			return nil, nil, fmt.Errorf("interface %s invalid CIDR %q", iface.Name, cidr)
		}
		desired[ipnet.String()] = struct{}{}
		if ipnet.IP.To4() != nil {
			desiredV4[ipnet.String()] = struct{}{}
		}
	}
	return desired, desiredV4, nil
}

func replaceInterfaceAddrsIfNeeded(ifIndex int, dev string, desired, desiredV4 map[string]struct{}, opts ApplyOptions) error {
	for cidr := range desired {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil || ipnet == nil {
			return fmt.Errorf("interface %s invalid desired CIDR %q", dev, cidr)
		}
		if err := addAddr(ifIndex, ipnet); err != nil {
			return fmt.Errorf("add addr %s %s: %w", dev, ipnet.String(), err)
		}
	}

	replaceV4 := len(desiredV4) > 0
	if !opts.Replace && !replaceV4 {
		return nil
	}
	existing, err := listAddrs(ifIndex, unix.AF_UNSPEC)
	if err != nil {
		return fmt.Errorf("list addrs %s: %w", dev, err)
	}
	for _, ipnet := range existing {
		if skipAddrDeletion(ipnet, desired, replaceV4, opts) {
			continue
		}
		if err := delAddr(ifIndex, ipnet); err != nil {
			return fmt.Errorf("del addr %s %s: %w", dev, ipnet.String(), err)
		}
	}
	return nil
}

func skipAddrDeletion(ipnet *net.IPNet, desired map[string]struct{}, replaceV4 bool, opts ApplyOptions) bool {
	if ipnet == nil {
		return true
	}
	if _, ok := desired[ipnet.String()]; ok {
		return true
	}
	if ipnet.IP != nil && ipnet.IP.To4() == nil {
		if ipnet.IP.To16() != nil && ipnet.IP.IsLinkLocalUnicast() {
			return true
		}
		if !opts.Replace && replaceV4 {
			return true
		}
	}
	return false
}

func shouldEnableForwarding(ifaces []config.Interface) bool {
	seen := map[string]struct{}{}
	for _, iface := range ifaces {
		if strings.TrimSpace(iface.Zone) == "" {
			continue
		}
		dev := strings.TrimSpace(iface.Device)
		if dev == "" {
			dev = strings.TrimSpace(iface.Name)
		}
		if dev == "" {
			continue
		}
		seen[dev] = struct{}{}
		if len(seen) >= 2 {
			return true
		}
	}
	return false
}
