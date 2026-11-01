// SPDX-License-Identifier: Apache-2.0
package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/tonylturner/containd/pkg/common/mgmtpath"
)

func managementConflict(field string) error {
	return fmt.Errorf("%s conflicts with reserved management path", field)
}

// ValidateManagementReservation is pure: no environment, kernel or profile-file
// reads. Call before persistence and before replay side effects. Config.Validate
// remains the ordinary structural validator and must also be called.
func ValidateManagementReservation(c *Config, r *mgmtpath.Reservation) error {
	if err := validateManagementCore(c, r); err != nil {
		return err
	}
	if c == nil {
		return nil
	}
	return ValidateManagementServices(c.Services, r)
}

func validateManagementCore(c *Config, r *mgmtpath.Reservation) error {
	if r == nil {
		return nil
	}
	if c == nil {
		return managementConflict("config")
	}
	checks := []error{ValidateManagementInterfaces(c.Interfaces, r), ValidateManagementRouting(c.Routing, r), ValidateManagementNAT(c.Firewall.NAT, c.Interfaces, r), ValidateManagementListeners(c.System, r), ValidateManagementDataPlane(c.DataPlane, r)}
	for _, err := range checks {
		if err != nil {
			return err
		}
	}
	return nil
}

// ValidateManagementInterfaces permits exactly one unaddressed physical binding.
// Names, zones and access flags are not pinned. No other row may reuse that NIC,
// directly or through logical references in parent/member fields.
func ValidateManagementInterfaces(ifaces []Interface, r *mgmtpath.Reservation) error {
	if r == nil {
		return nil
	}
	devices := map[string]string{}
	for _, v := range ifaces {
		devices[strings.TrimSpace(v.Name)] = managementDevice(v)
	}
	resolve := func(s string) string {
		s = strings.TrimSpace(s)
		if d, ok := devices[s]; ok {
			return d
		}
		return s
	}
	count := 0
	for i, v := range ifaces {
		field := fmt.Sprintf("interfaces[%d]", i)
		if managementDevice(v) == r.Device {
			count++
			typ := strings.ToLower(strings.TrimSpace(v.Type))
			if typ != "" && typ != "physical" {
				return managementConflict(field + ".type")
			}
			if len(v.Addresses) > 0 || strings.TrimSpace(v.AddressMode) != "" && !strings.EqualFold(strings.TrimSpace(v.AddressMode), "static") {
				return managementConflict(field + ".addresses/addressMode")
			}
		} else if strings.TrimSpace(v.Name) == r.Device {
			return managementConflict(field + ".name")
		}
		if resolve(v.Parent) == r.Device {
			return managementConflict(field + ".parent")
		}
		for _, m := range v.Members {
			if resolve(m) == r.Device {
				return managementConflict(field + ".members")
			}
		}
		for _, s := range v.Addresses {
			if managementLocalAddress(s, r, false) {
				return managementConflict(field + ".addresses")
			}
		}
	}
	if count != 1 {
		return managementConflict("interfaces.device (requires exactly one reserved physical binding)")
	}
	return nil
}
func managementDevice(v Interface) string {
	if d := strings.TrimSpace(v.Device); d != "" {
		return d
	}
	return strings.TrimSpace(v.Name)
}

// ValidateManagementRouting rejects only explicit rules preceding or tying the
// trusted pin. Zero is auto priority, not the kernel priority zero.
func ValidateManagementRouting(v RoutingConfig, r *mgmtpath.Reservation) error {
	if r == nil {
		return nil
	}
	// Partial APIs do not run Config.Validate. Enforce its numeric domains
	// before netcfg narrows priorities to uint32 and route tables to uint8:
	// wrapping a priority to 0 or writing a broad route into table 255 would
	// bypass the priority-1 pin, despite looking like a later rule/normal route.
	for i, route := range v.Routes {
		if route.Table < 0 || route.Table > 252 {
			return managementConflict(fmt.Sprintf("routing.routes[%d].table", i))
		}
	}
	for i, rule := range v.Rules {
		if rule.Priority < 0 || rule.Priority > 65535 {
			return managementConflict(fmt.Sprintf("routing.rules[%d].priority", i))
		}
		if rule.Priority == 0 || rule.Priority > mgmtpath.PinPriority {
			continue
		}
		if !managementSelector(rule.Src, r.Local.Addr()) {
			continue
		}
		for _, a := range r.Sources {
			if managementSelector(rule.Dst, a) {
				return managementConflict(fmt.Sprintf("routing.rules[%d].priority", i))
			}
		}
	}
	return nil
}
func managementSelector(s string, a netip.Addr) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return true
	}
	_, p, err := net.ParseCIDR(s)
	if err == nil {
		return p.Contains(net.IP(a.AsSlice()))
	}
	// Invalid selectors cannot establish disjointness at a partial API boundary.
	return true
}
func managementLocalAddress(s string, r *mgmtpath.Reservation, coverLocal bool) bool {
	ip, p, err := net.ParseCIDR(strings.TrimSpace(s))
	if err != nil {
		return false
	}
	a, ok := netip.AddrFromSlice(ip)
	return ok && (a.Unmap() == r.Local.Addr() || r.IsSource(a.Unmap())) || coverLocal && p.Contains(net.IP(r.Local.Addr().AsSlice()))
}

// ValidateManagementWireGuard includes disabled configurations: disabling deletes
// its named device. AllowedIPs routes remain free; the reply pin precedes them.
func ValidateManagementWireGuard(w WireGuardConfig, r *mgmtpath.Reservation) error {
	if r == nil {
		return nil
	}
	name := strings.TrimSpace(w.Interface)
	if name == "" {
		name = "wg0"
	}
	if name == r.Device {
		return managementConflict("services.vpn.wireguard.interface")
	}
	if managementLocalAddress(w.AddressCIDR, r, true) {
		return managementConflict("services.vpn.wireguard.addressCIDR")
	}
	return nil
}

// ValidateManagementServices covers every structured service address/listener.
// External OpenVPN and remote-assigned addresses are handled by the runtime guard,
// not by inspecting files or predicting pushed addresses/routes here.
func ValidateManagementServices(s ServicesConfig, r *mgmtpath.Reservation) error {
	if r == nil {
		return nil
	}
	var errs []error
	for _, name := range ServiceNames() {
		if err := validateManagementService(s, name, r); err != nil {
			errs = append(errs, &ServiceConfigError{Service: name, Err: err})
		}
	}
	return errors.Join(errs...)
}

func validateManagementService(s ServicesConfig, name string, r *mgmtpath.Reservation) error {
	if r == nil {
		return nil
	}
	switch name {
	case ServiceWireGuard:
		return ValidateManagementWireGuard(s.VPN.WireGuard, r)
	case ServiceOpenVPN:
		if o := s.VPN.OpenVPN; o.Server != nil {
			p, err := netip.ParsePrefix(strings.TrimSpace(o.Server.TunnelCIDR))
			// OpenVPN's `server network mask` assigns network+1, not the supplied host bits.
			if err == nil && (p.Contains(r.Local.Addr()) || r.IsSource(p.Masked().Addr().Next())) {
				return managementConflict("services.vpn.openvpn.server.tunnelCIDR")
			}
			if o.Enabled && strings.EqualFold(o.Server.Proto, "tcp") && managementPort(o.Server.ListenPort, 1194) == int(r.Port) {
				return managementConflict("services.vpn.openvpn.server.listenPort")
			}
		}

	case ServiceProxy:
		if s.Proxy.Forward.Enabled && managementPort(s.Proxy.Forward.ListenPort, 3128) == int(r.Port) {
			return managementConflict("services.proxy.forward.listenPort")
		}
		if s.Proxy.Reverse.Enabled {
			for i, v := range s.Proxy.Reverse.Sites {
				if v.ListenPort == int(r.Port) {
					return managementConflict(fmt.Sprintf("services.proxy.reverse.sites[%d].listenPort", i))
				}
			}
		}

	case ServiceDNS:
		if s.DNS.Enabled && managementPort(s.DNS.ListenPort, 53) == int(r.Port) {
			return managementConflict("services.dns.listenPort")
		}

	case ServiceDHCP:
		if s.DHCP.Enabled {
			protected := append([]netip.Addr{r.Local.Addr()}, r.Sources...)
			for i, p := range s.DHCP.Pools {
				lo, e1 := netip.ParseAddr(p.Start)
				hi, e2 := netip.ParseAddr(p.End)
				if e1 == nil && e2 == nil {
					for _, a := range protected {
						if lo.Compare(a) <= 0 && hi.Compare(a) >= 0 {
							return managementConflict(fmt.Sprintf("services.dhcp.pools[%d]", i))
						}
					}
				}
			}
			for i, v := range s.DHCP.Reservations {
				a, err := netip.ParseAddr(v.IP)
				if err == nil && (a == r.Local.Addr() || r.IsSource(a)) {
					return managementConflict(fmt.Sprintf("services.dhcp.reservations[%d].ip", i))
				}
			}
		}

	}
	return nil
}

func managementPort(p, d int) int {
	if p == 0 {
		return d
	}
	return p
}

// ValidateManagementListeners checks both HTTP aliases even if env precedence
// would hide an attempted change. It resolves the listeners without the
// environment; runtime startup also checks effective env binds.
func ValidateManagementListeners(s SystemConfig, r *mgmtpath.Reservation) error {
	if r == nil {
		return nil
	}
	m := s.Mgmt
	l := ResolveManagementListeners(&Config{System: s}, noEnv)
	if !l.HTTP.Enabled {
		return managementConflict("system.mgmt.enableHTTP")
	}
	if m.RedirectHTTPToHTTPS != nil && *m.RedirectHTTPToHTTPS {
		return managementConflict("system.mgmt.redirectHTTPToHTTPS")
	}
	for _, v := range []struct{ field, addr string }{{"listenAddr", m.ListenAddr}, {"httpListenAddr", m.HTTPListenAddr}} {
		if v.addr != "" {
			if err := r.ValidateListen(v.addr); err != nil {
				return managementConflict("system.mgmt." + v.field)
			}
		}
	}
	if m.ListenAddr == "" && m.HTTPListenAddr == "" {
		if err := r.ValidateListen(l.HTTP.Addr); err != nil {
			return err
		}
	}
	if l.HTTPS.Enabled && ManagementListenerConflictsHTTP(l.HTTPS.Addr, l.HTTP.Addr, true, r) {
		return managementConflict("system.mgmt.httpsListenAddr")
	}
	if ManagementListenerConflictsHTTP(l.SSH.Addr, l.HTTP.Addr, false, r) {
		return managementConflict("system.ssh.listenAddr")
	}
	return nil
}

// noEnv is an environment that sets no listener variable.
func noEnv(string) string { return "" }

// ManagementListenerConflictsHTTP also protects the HTTP socket, not just its
// reserved destination IP. A wildcard HTTP bind claims every local IPv4 address;
// an exact bind additionally starts management's 127.0.0.1 convenience listener.
// withLoopback identifies HTTPS, which also starts a convenience listener.
func ManagementListenerConflictsHTTP(addr, httpAddr string, withLoopback bool, r *mgmtpath.Reservation) bool {
	if r == nil {
		return false
	}
	if ManagementListenerOverlaps(addr, r) {
		return true
	}
	host, port, err := net.SplitHostPort(addr)
	p, pe := strconv.ParseUint(port, 10, 16)
	if err != nil || pe != nil || p != uint64(r.Port) {
		return false
	}
	httpHost, _, err := net.SplitHostPort(httpAddr)
	if err != nil {
		return false // HTTP validation reports the malformed primary bind.
	}
	// HTTPS always also claims the loopback port.
	if withLoopback {
		return true
	}
	a, ae := netip.ParseAddr(host)
	ipv4 := ae != nil || a.Unmap().Is4()
	return httpHost == "" || httpHost == "0.0.0.0" && ipv4 || ae == nil && a.Unmap() == netip.MustParseAddr("127.0.0.1")
}

// ManagementListenerOverlaps is also used for environment-resolved listeners.
// DNS names cannot prove a disjoint bind in an environment-free validator.
func ManagementListenerOverlaps(addr string, r *mgmtpath.Reservation) bool {
	if r == nil {
		return false
	}
	host, port, err := net.SplitHostPort(addr)
	p, pe := strconv.ParseUint(port, 10, 16)
	if err != nil || pe != nil || p != uint64(r.Port) {
		return false
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		return true
	}
	a, err := netip.ParseAddr(host)
	return err != nil || a.Unmap() == r.Local.Addr()
}

func ValidateManagementNAT(n NATConfig, ifaces []Interface, r *mgmtpath.Reservation) error {
	if r == nil {
		return nil
	}
	zones := map[string][]string{}
	for _, v := range ifaces {
		zones[strings.TrimSpace(v.Zone)] = append(zones[strings.TrimSpace(v.Zone)], managementDevice(v))
	}
	for i, p := range n.PortForwards {
		if r.DNATOverlaps(p.Enabled, p.Proto, p.ListenPort, zones[strings.TrimSpace(p.IngressZone)], p.AllowedSources) {
			return managementConflict(fmt.Sprintf("firewall.nat.portForwards[%d]", i))
		}
	}
	return nil
}

func ValidateManagementDataPlane(d DataPlaneConfig, r *mgmtpath.Reservation) error {
	if r != nil && !d.Enforcement {
		return managementConflict("dataplane.enforcement")
	}
	return nil
}
