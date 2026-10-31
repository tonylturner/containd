// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build linux

package netcfg

import (
	"context"
	"errors"
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
	addressApplyMu.Lock()
	defer addressApplyMu.Unlock()
	owned, err := loadAddressOwnership()
	if err != nil {
		return err
	}
	// Prove persistence is writable before changing any addresses.
	if err := owned.save(); err != nil {
		return fmt.Errorf("save address ownership: %w", err)
	}
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
		if err := applyInterfaceConfig(ctx, iface, bridgeMembers, resolver, opts, owned); err != nil {
			return err
		}
	}
	// Removed bindings also have empty intent, but explicit Replace never
	// broadens to foreign addresses on devices absent from the configuration.
	configured := map[string]bool{}
	for _, iface := range ifaces {
		configured[resolver.deviceFor(iface)] = true
	}
	live, err := net.Interfaces()
	if err != nil {
		return err
	}
	devices := map[string]*net.Interface{}
	for i := range live {
		devices[live[i].Name] = &live[i]
	}
	for _, a := range append([]ownedAddress(nil), owned.Addresses...) {
		if configured[a.Device] {
			continue
		}
		if opts.Reservation != nil && a.Device == opts.Reservation.Device {
			continue
		}
		nic := devices[a.Device]
		if nic == nil {
			// Deleted devices cannot retain their old addresses.
			if err := owned.forget(a); err != nil {
				return err
			}
			continue
		}
		configured[a.Device] = true
		if err := deleteStaleInterfaceAddrs(nic, nil, ApplyOptions{}, owned); err != nil {
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

func applyInterfaceConfig(ctx context.Context, iface config.Interface, bridgeMembers map[string]string, resolver interfaceResolver, opts ApplyOptions, owned *addressOwnership) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	dev := resolver.deviceFor(iface)
	if dev == "" {
		return nil
	}
	if opts.Reservation != nil && dev == opts.Reservation.Device {
		return nil
	}
	if err := validateBridgeMemberConfig(iface, dev, bridgeMembers); err != nil {
		return err
	}
	if bridgeMembers[dev] != "" {
		return nil
	}
	if strings.EqualFold(strings.TrimSpace(iface.AddressMode), "dhcp") {
		return applyDHCPInterface(ctx, iface, dev, owned)
	}
	return applyStaticInterface(ctx, iface, dev, opts, owned)
}

func validateBridgeMemberConfig(iface config.Interface, dev string, bridgeMembers map[string]string) error {
	if br := bridgeMembers[dev]; br != "" && (len(iface.Addresses) > 0 || strings.TrimSpace(iface.Gateway) != "") {
		return fmt.Errorf("interface %s (%s) is a bridge member of %s; assign addresses to the bridge instead", iface.Name, dev, br)
	}
	return nil
}

func applyDHCPInterface(ctx context.Context, iface config.Interface, dev string, owned *addressOwnership) error {
	if err := setLinkUp(dev); err != nil {
		return fmt.Errorf("set link up %s: %w", dev, err)
	}
	nic, err := net.InterfaceByName(dev)
	if err != nil {
		return fmt.Errorf("interface %s (%s) not found: %w", iface.Name, dev, err)
	}
	existing, err := listAddrs(nic.Index, unix.AF_INET)
	if err != nil {
		return fmt.Errorf("list DHCP addresses %s: %w", dev, err)
	}
	if hasUsableIPv4(existing) {
		return nil
	}
	lease, err := dhcpAcquireV4(ctx, dev, 5)
	if err != nil {
		return fmt.Errorf("dhcp on %s: %w", dev, err)
	}
	ipnet, err := parseAddressCIDR(lease.AddrCIDR)
	if err != nil || ipnet == nil {
		return fmt.Errorf("dhcp on %s: invalid lease cidr %q", dev, lease.AddrCIDR)
	}
	if err := owned.add(nic, ipnet); err != nil {
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

func applyStaticInterface(ctx context.Context, iface config.Interface, dev string, opts ApplyOptions, owned *addressOwnership) error {
	// Unbound logical roles may not exist yet.
	if len(iface.Addresses) == 0 {
		hasOwned := false
		for _, a := range owned.Addresses {
			hasOwned = hasOwned || a.Device == dev
		}
		if !hasOwned {
			return nil
		}
		opts.Replace = false
	}
	nic, err := net.InterfaceByName(dev)
	if err != nil {
		return fmt.Errorf("interface %s (%s) not found: %w", iface.Name, dev, err)
	}
	if err := setLinkUp(dev); err != nil {
		return fmt.Errorf("set link up %s: %w", dev, err)
	}
	desired, err := desiredInterfaceAddrs(ctx, iface)
	if err != nil {
		return err
	}
	if err := replaceInterfaceAddrsIfNeeded(nic, desired, opts, owned); err != nil {
		return err
	}
	if gw := strings.TrimSpace(iface.Gateway); gw != "" {
		if err := addDefaultRoute(nic.Index, gw); err != nil {
			return fmt.Errorf("add default route %s via %s: %w", dev, gw, err)
		}
	}
	return nil
}

func desiredInterfaceAddrs(ctx context.Context, iface config.Interface) (map[string]struct{}, error) {
	desired := map[string]struct{}{}
	for _, cidr := range iface.Addresses {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		ipnet, err := parseAddressCIDR(cidr)
		if err != nil || ipnet == nil || ipnet.IP == nil {
			return nil, fmt.Errorf("interface %s invalid CIDR %q", iface.Name, cidr)
		}
		desired[ipnet.String()] = struct{}{}
	}
	return desired, nil
}

func replaceInterfaceAddrsIfNeeded(nic *net.Interface, desired map[string]struct{}, opts ApplyOptions, owned *addressOwnership) error {
	// Delete stale addresses before installing the new ones: removing an IPv4
	// primary also removes its same-subnet secondaries on kernels without
	// promote_secondaries. Adding the desired host first can therefore lose it.
	if err := deleteStaleInterfaceAddrs(nic, desired, opts, owned); err != nil {
		return err
	}
	for cidr := range desired {
		ipnet, err := parseAddressCIDR(cidr)
		if err != nil || ipnet == nil {
			return fmt.Errorf("interface %s invalid desired CIDR %q", nic.Name, cidr)
		}
		if err := owned.add(nic, ipnet); err != nil {
			return fmt.Errorf("add addr %s %s: %w", nic.Name, ipnet.String(), err)
		}
	}
	return nil
}

func deleteStaleInterfaceAddrs(nic *net.Interface, desired map[string]struct{}, opts ApplyOptions, owned *addressOwnership) (err error) {
	existing, err := listAddrs(nic.Index, unix.AF_UNSPEC)
	if err != nil {
		return fmt.Errorf("list addrs %s: %w", nic.Name, err)
	}
	// Drop ownership records for addresses no longer present before any new
	// exclusive creates; EEXIST must never adopt a previously foreign address.
	present := map[string]bool{}
	for _, ipnet := range existing {
		present[ipnet.String()] = true
	}
	for _, a := range append([]ownedAddress(nil), owned.Addresses...) {
		if a.Device == nic.Name && (!present[a.CIDR] || a != addressKey(nic, a.CIDR)) {
			if err := owned.forget(a); err != nil {
				return err
			}
		}
	}
	var restore func() error
	defer func() {
		if restore != nil {
			err = errors.Join(err, restore())
		}
	}()
	for _, ipnet := range existing {
		if skipAddrDeletion(ipnet, desired, owned.owns(nic, ipnet.String()), opts) {
			continue
		}
		if ipnet.IP.To4() != nil && restore == nil {
			restore, err = preserveIPv4Secondaries(nic.Name)
			if err != nil {
				return err
			}
		}
		// Revoke durable ownership before deletion: a crash must not leave a
		// deletion record that could later claim a foreign re-use of this tuple.
		if err := owned.forget(addressKey(nic, ipnet.String())); err != nil {
			return err
		}
		if err := delAddr(nic.Index, ipnet); err != nil {
			return fmt.Errorf("del addr %s %s: %w", nic.Name, ipnet.String(), err)
		}
	}
	return nil
}

func skipAddrDeletion(ipnet *net.IPNet, desired map[string]struct{}, owned bool, opts ApplyOptions) bool {
	if ipnet == nil {
		return true
	}
	if _, ok := desired[ipnet.String()]; ok {
		return true
	}
	if ipnet.IP.IsLinkLocalUnicast() {
		return true
	}
	if opts.Reservation != nil && ipnet.IP.Equal(net.IP(opts.Reservation.Local.Addr().AsSlice())) {
		return true
	}
	return !opts.Replace && !owned
}

func shouldEnableForwarding(ifaces []config.Interface) bool {
	return RequiresIPv4Forwarding(ifaces)
}
