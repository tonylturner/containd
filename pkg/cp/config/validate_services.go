// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package config

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/tonylturner/containd/pkg/dp/ics"
)

// ValidateServiceConfigs checks all ServicesConfig sections, even if an
// unrelated configuration error would make Config.Validate return early.
// IDS rules and cross-service firewall/scan selection checks still belong to
// Config.Validate: these faults can invalidate dataplane policy.
func ValidateServiceConfigs(c *Config) error {
	if c == nil {
		return errors.New("config is nil")
	}
	return validateServices(c.Services, c.Interfaces, c.Zones)
}

func validateServices(s ServicesConfig, ifaces []Interface, zones []Zone) error {
	zoneSet, ifaceSet := vpnValidationSets(ifaces, zones)
	var errs []error
	check := func(service string, err error) {
		if err != nil {
			errs = append(errs, &ServiceConfigError{Service: service, Err: err})
		}
	}
	check(ServiceSyslog, validateSyslogService(s.Syslog))
	check(ServiceDNS, validateDNSService(s.DNS))
	check(ServiceNTP, validateNTPService(s.NTP))
	check(ServiceProxy, validateProxy(s.Proxy))
	check(ServiceProxy, validateProxyZones(s.Proxy, zoneSet))
	check(ServiceDHCP, validateDHCP(s.DHCP))
	if s.DHCP.Enabled {
		check(ServiceDHCP, validateDHCPListenIfaceNames(s.DHCP.ListenIfaces, ifaces))
	}
	check(ServiceWireGuard, validateWireGuard(s.VPN.WireGuard, zoneSet, ifaceSet))
	check(ServiceOpenVPN, validateOpenVPN(s.VPN.OpenVPN, zoneSet, ifaceSet))
	check(ServiceAV, validateAV(s.AV))
	return errors.Join(errs...)
}

func validateProxyZones(p ProxyConfig, zones map[string]struct{}) error {
	for _, name := range p.Forward.ListenZones {
		if _, ok := zones[name]; !ok {
			return fmt.Errorf("forward proxy listenZones references unknown zone %q", name)
		}
	}
	return nil
}

func validateSyslogService(cfg SyslogConfig) error {
	for _, fwd := range cfg.Forwarders {
		if fwd.Address == "" {
			return errors.New("syslog forwarder address is required")
		}
		if fwd.Port <= 0 || fwd.Port > 65535 {
			return fmt.Errorf("syslog forwarder %s has invalid port %d", fwd.Address, fwd.Port)
		}
		if fwd.Proto != "" && fwd.Proto != "udp" && fwd.Proto != "tcp" {
			return fmt.Errorf("syslog forwarder %s has invalid proto %q", fwd.Address, fwd.Proto)
		}
	}
	return nil
}

func validateDNSService(cfg DNSConfig) error {
	if cfg.ListenPort != 0 && (cfg.ListenPort < 1 || cfg.ListenPort > 65535) {
		return fmt.Errorf("dns listenPort invalid: %d", cfg.ListenPort)
	}
	for _, z := range cfg.ListenZones {
		if z == "" {
			return errors.New("dns listenZones cannot include empty")
		}
	}
	for _, u := range cfg.UpstreamServers {
		if err := ValidateUnboundForwarder(u); err != nil {
			return fmt.Errorf("dns upstreamServers: %w", err)
		}
	}
	if cfg.CacheSizeMB < 0 {
		return errors.New("dns cacheSizeMB cannot be negative")
	}
	return nil
}

func validateNTPService(cfg NTPConfig) error {
	for _, srv := range cfg.Servers {
		if err := ValidateChronyServer(srv); err != nil {
			return fmt.Errorf("ntp servers: %w", err)
		}
	}
	if cfg.IntervalSeconds < 0 {
		return errors.New("ntp intervalSeconds cannot be negative")
	}
	return nil
}

func validateAV(cfg AVConfig) error {
	if cfg.BackendDisabled {
		return nil
	}
	if cfg.ClamAV.SocketPath != "" {
		if err := ValidateClamdSocketPath(cfg.ClamAV.SocketPath); err != nil {
			return err
		}
	}
	if !cfg.Enabled {
		return nil
	}
	mode := strings.ToLower(strings.TrimSpace(cfg.Mode))
	if mode == "" {
		mode = "clamav"
	}
	switch mode {
	case "icap", "clamav":
	default:
		return fmt.Errorf("services.av.mode must be icap or clamav")
	}
	if fail := cfg.EffectiveFailPolicy(); fail != "open" && fail != "closed" {
		return fmt.Errorf("services.av.failPolicy must be open or closed")
	}
	if mode == "icap" {
		if err := validateICAPServers(cfg.ICAP.Servers); err != nil {
			return err
		}
	}
	if cfg.TimeoutSec < 0 || cfg.TimeoutSec > maxAVTimeoutSec {
		return fmt.Errorf("services.av.timeoutSec must be between 0 (default) and %d", maxAVTimeoutSec)
	}
	if cfg.MaxSizeBytes < 0 || cfg.MaxSizeBytes > maxAVScanBytes {
		return fmt.Errorf("services.av.maxSizeBytes must be between 0 (no limit) and %d", maxAVScanBytes)
	}
	if cfg.CacheTTL < 0 {
		return errors.New("services.av.cacheTtl must not be negative; 0 selects 10m")
	}
	if mode == "clamav" {
		if _, err := cfg.ClamAV.UpdateInterval(); err != nil {
			return err
		}
	}
	return nil
}

// validateICAPServers requires exactly one server, since scans go to one
// server without failover, with a host:port address.
func validateICAPServers(servers []ICAPServer) error {
	switch len(servers) {
	case 0:
		return errors.New("services.av.icap.servers must not be empty when mode=icap")
	case 1:
	default:
		return fmt.Errorf("services.av.icap.servers must hold exactly one server when mode=icap (got %d); failover is not supported", len(servers))
	}
	addr := strings.TrimSpace(servers[0].Address)
	if addr == "" {
		return errors.New("services.av.icap.servers[0].address required")
	}
	if host, port, err := net.SplitHostPort(addr); err != nil || host == "" || port == "" {
		return fmt.Errorf("services.av.icap.servers[0].address %q must be host:port", addr)
	}
	return nil
}

// UpdateInterval parses UpdateSchedule, the FreshClam interval. It is a
// positive Go duration such as "4h", not a cron expression. A blank schedule
// returns zero, which selects the engine's default interval.
func (c ClamAVConfig) UpdateInterval() (time.Duration, error) {
	s := strings.TrimSpace(c.UpdateSchedule)
	if s == "" {
		return 0, nil
	}
	if d, err := time.ParseDuration(s); err == nil && d > 0 {
		return d, nil
	}
	return 0, fmt.Errorf("services.av.clamav.updateSchedule %q must be a positive duration such as 4h", s)
}

const (
	// maxAVTimeoutSec bounds the per-scan and per-probe deadline.
	maxAVTimeoutSec = 300
	// maxAVScanBytes is clamd's default StreamMaxLength (100 MiB); clamd
	// rejects larger INSTREAM payloads.
	maxAVScanBytes = 100 << 20
)

func validateProxy(p ProxyConfig) error {
	if len(p.Forward.AllowedClients) > 0 {
		return errors.New("forward proxy allowedClients not supported yet; clear this field")
	}
	if p.Forward.Upstream != "" {
		return errors.New("forward proxy upstream not supported yet; clear this field")
	}
	if p.Forward.ListenPort != 0 && (p.Forward.ListenPort < 1 || p.Forward.ListenPort > 65535) {
		return fmt.Errorf("forward proxy listenPort invalid: %d", p.Forward.ListenPort)
	}
	for _, z := range p.Forward.ListenZones {
		if err := ValidateProxyListenZone(z); err != nil {
			return fmt.Errorf("forward proxy listenZones: %w", err)
		}
	}
	for _, d := range p.Forward.AllowedDomains {
		if err := ValidateProxyHostname(d); err != nil {
			return fmt.Errorf("forward proxy allowedDomains: %w", err)
		}
	}
	for _, s := range p.Reverse.Sites {
		if err := ValidateProxySiteID(s.Name); err != nil {
			return fmt.Errorf("reverse proxy site name: %w", err)
		}
		for _, host := range s.Hostnames {
			if err := ValidateProxyHostname(host); err != nil {
				return fmt.Errorf("reverse proxy hostnames: %w", err)
			}
		}
		for _, backend := range s.Backends {
			if err := ValidateProxyBackend(backend); err != nil {
				return fmt.Errorf("reverse proxy backends: %w", err)
			}
		}
		if s.TLSEnabled || s.CertRef != "" {
			if err := ValidateProxyCertRef(s.CertRef); err != nil {
				return fmt.Errorf("reverse proxy certRef: %w", err)
			}
		}
		if s.ListenPort < 1 || s.ListenPort > 65535 {
			return fmt.Errorf("reverse proxy site %s listenPort invalid: %d", s.Name, s.ListenPort)
		}
		if len(s.Backends) == 0 {
			return fmt.Errorf("reverse proxy site %s must have at least one backend", s.Name)
		}
	}
	return nil
}

func validateDHCP(d DHCPConfig) error {
	if err := validateDHCPListenIfaces(d.ListenIfaces); err != nil {
		return err
	}
	poolRanges, err := validateDHCPSPools(d.Pools)
	if err != nil {
		return err
	}
	if err := validateDHCPReservations(d.Reservations, poolRanges); err != nil {
		return err
	}
	return validateDHCPGlobals(d)
}

func validateDHCPListenIfaces(listenIfaces []string) error {
	for _, n := range listenIfaces {
		if strings.TrimSpace(n) == "" {
			return errors.New("dhcp listenIfaces cannot include empty")
		}
	}
	return nil
}

func validateDHCPSPools(pools []DHCPPool) (map[string][]struct {
	start net.IP
	end   net.IP
}, error) {
	poolRanges := map[string][]struct {
		start net.IP
		end   net.IP
	}{}
	for _, p := range pools {
		if strings.TrimSpace(p.Iface) == "" {
			return nil, errors.New("dhcp pool iface is required")
		}
		start := net.ParseIP(strings.TrimSpace(p.Start)).To4()
		if start == nil {
			return nil, fmt.Errorf("dhcp pool %s start invalid: %q", p.Iface, p.Start)
		}
		end := net.ParseIP(strings.TrimSpace(p.End)).To4()
		if end == nil {
			return nil, fmt.Errorf("dhcp pool %s end invalid: %q", p.Iface, p.End)
		}
		iface := strings.TrimSpace(p.Iface)
		poolRanges[iface] = append(poolRanges[iface], struct {
			start net.IP
			end   net.IP
		}{start: start, end: end})
	}
	return poolRanges, nil
}

func validateDHCPReservations(reservations []DHCPReservation, poolRanges map[string][]struct {
	start net.IP
	end   net.IP
}) error {
	seenRes := map[string]struct{}{}
	for _, r := range reservations {
		if err := validateDHCPReservationIdentity(r, seenRes); err != nil {
			return err
		}
		if err := validateDHCPReservationPool(r, poolRanges); err != nil {
			return err
		}
	}
	return nil
}

func validateDHCPReservationIdentity(r DHCPReservation, seenRes map[string]struct{}) error {
	if strings.TrimSpace(r.Iface) == "" {
		return errors.New("dhcp reservation iface is required")
	}
	if _, err := net.ParseMAC(strings.ToLower(strings.TrimSpace(r.MAC))); err != nil {
		return fmt.Errorf("dhcp reservation %s mac invalid: %w", r.Iface, err)
	}
	ip := net.ParseIP(strings.TrimSpace(r.IP))
	if ip == nil || ip.To4() == nil {
		return fmt.Errorf("dhcp reservation %s ip invalid: %q", r.Iface, r.IP)
	}
	key := strings.ToLower(strings.TrimSpace(r.Iface) + "|" + strings.ToLower(strings.TrimSpace(r.MAC)))
	if _, ok := seenRes[key]; ok {
		return fmt.Errorf("dhcp reservation duplicate for iface %s mac %s", r.Iface, r.MAC)
	}
	seenRes[key] = struct{}{}
	return nil
}

func validateDHCPReservationPool(r DHCPReservation, poolRanges map[string][]struct {
	start net.IP
	end   net.IP
}) error {
	ranges, ok := poolRanges[strings.TrimSpace(r.Iface)]
	if !ok {
		return nil
	}
	ip := net.ParseIP(strings.TrimSpace(r.IP))
	if ip == nil {
		return nil
	}
	ipv := ipToUint32(ip)
	for _, pr := range ranges {
		if ipv >= ipToUint32(pr.start) && ipv <= ipToUint32(pr.end) {
			return nil
		}
	}
	return fmt.Errorf("dhcp reservation %s ip %s not in any pool for iface", r.Iface, r.IP)
}

func validateDHCPGlobals(d DHCPConfig) error {
	if d.LeaseSeconds < 0 {
		return errors.New("dhcp leaseSeconds cannot be negative")
	}
	if d.Router != "" {
		if ip := net.ParseIP(strings.TrimSpace(d.Router)); ip == nil || ip.To4() == nil {
			return fmt.Errorf("dhcp router invalid: %q", d.Router)
		}
	}
	for _, s := range d.DNSServers {
		if ip := net.ParseIP(strings.TrimSpace(s)); ip == nil || ip.To4() == nil {
			return fmt.Errorf("dhcp dnsServers invalid: %q", s)
		}
	}
	return nil
}

func ipToUint32(ip net.IP) uint32 {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	return (uint32(ip4[0]) << 24) | (uint32(ip4[1]) << 16) | (uint32(ip4[2]) << 8) | uint32(ip4[3])
}

func vpnValidationSets(ifaces []Interface, zones []Zone) (map[string]struct{}, map[string]struct{}) {
	zoneSet := map[string]struct{}{}
	for _, z := range zones {
		zoneSet[z.Name] = struct{}{}
	}
	ifaceSet := map[string]struct{}{}
	for _, iface := range ifaces {
		if strings.TrimSpace(iface.Name) != "" {
			ifaceSet[iface.Name] = struct{}{}
		}
		if strings.TrimSpace(iface.Device) != "" {
			ifaceSet[iface.Device] = struct{}{}
		}
	}
	return zoneSet, ifaceSet
}

func validateWireGuard(wg WireGuardConfig, zoneSet, ifaceSet map[string]struct{}) error {
	if wg.ListenPort != 0 && (wg.ListenPort < 1 || wg.ListenPort > 65535) {
		return fmt.Errorf("vpn.wireguard listenPort invalid: %d", wg.ListenPort)
	}
	if err := validateVPNListenTargets("vpn.wireguard", wg.ListenZone, wg.ListenInterfaces, zoneSet, ifaceSet); err != nil {
		return err
	}
	if wg.AddressCIDR != "" {
		if _, _, err := net.ParseCIDR(strings.TrimSpace(wg.AddressCIDR)); err != nil {
			return fmt.Errorf("vpn.wireguard addressCIDR invalid: %q", wg.AddressCIDR)
		}
	}
	for _, peer := range wg.Peers {
		if err := validateWireGuardPeer(peer); err != nil {
			return err
		}
	}
	return nil
}

func validateWireGuardPeer(peer WGPeer) error {
	if strings.TrimSpace(peer.PublicKey) == "" {
		return errors.New("vpn.wireguard peer publicKey is required")
	}
	for _, cidr := range peer.AllowedIPs {
		if strings.TrimSpace(cidr) == "" {
			return errors.New("vpn.wireguard allowedIPs cannot include empty")
		}
		if _, _, err := net.ParseCIDR(strings.TrimSpace(cidr)); err != nil {
			return fmt.Errorf("vpn.wireguard peer allowedIPs invalid: %q", cidr)
		}
	}
	if peer.PersistentKeepalive < 0 {
		return errors.New("vpn.wireguard persistentKeepalive cannot be negative")
	}
	if peer.Endpoint != "" {
		if _, _, err := net.SplitHostPort(strings.TrimSpace(peer.Endpoint)); err != nil {
			return fmt.Errorf("vpn.wireguard peer endpoint invalid: %q", peer.Endpoint)
		}
	}
	return nil
}

func validateOpenVPN(vpn OpenVPNConfig, zoneSet, ifaceSet map[string]struct{}) error {
	if vpn.Mode != "" && vpn.Mode != "server" && vpn.Mode != "client" {
		return fmt.Errorf("vpn.openvpn mode invalid: %q", vpn.Mode)
	}
	if !vpn.Enabled {
		return validateOpenVPNSinks(vpn)
	}
	mode := strings.TrimSpace(vpn.Mode)
	if mode == "" {
		mode = "client"
	}
	if strings.TrimSpace(vpn.ConfigPath) == "" && vpn.Managed == nil && vpn.Server == nil {
		return errors.New("vpn.openvpn enabled but neither configPath nor managed config is set")
	}
	if vpn.Managed != nil {
		if err := validateManagedOpenVPN(vpn.Managed, mode); err != nil {
			return err
		}
	}
	if vpn.Server != nil {
		if err := validateOpenVPNServer(vpn.Server, mode, zoneSet, ifaceSet); err != nil {
			return err
		}
	}
	return nil
}

func validateManagedOpenVPN(m *OpenVPNManagedClientConfig, mode string) error {
	if mode != "client" {
		return errors.New("vpn.openvpn managed config currently supports client mode only")
	}
	if err := validateOpenVPNManagedSinks(m); err != nil {
		return err
	}
	if m.Remote == "" {
		return errors.New("vpn.openvpn.managed remote is required")
	}
	if strings.TrimSpace(m.CA) == "" {
		return errors.New("vpn.openvpn.managed ca is required")
	}
	if strings.TrimSpace(m.Cert) == "" {
		return errors.New("vpn.openvpn.managed cert is required")
	}
	if strings.TrimSpace(m.Key) == "" {
		return errors.New("vpn.openvpn.managed key is required")
	}
	if (m.Username != "") != (m.Password != "") {
		return errors.New("vpn.openvpn.managed username and password must be set together")
	}
	return nil
}

func validateOpenVPNServer(s *OpenVPNManagedServerConfig, mode string, zoneSet, ifaceSet map[string]struct{}) error {
	if mode != "server" {
		return errors.New("vpn.openvpn server config requires mode=server")
	}
	if err := validateOpenVPNServerSinks(s); err != nil {
		return err
	}
	if s.TunnelCIDR == "" {
		return errors.New("vpn.openvpn.server tunnelCIDR is required")
	}
	return validateVPNListenTargets("vpn.openvpn.server", s.ListenZone, s.ListenInterfaces, zoneSet, ifaceSet)
}

func validateVPNPort(label string, port, def int) error {
	if port == 0 {
		port = def
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("%s invalid: %d", label, port)
	}
	return nil
}

func validateVPNProto(label, proto string) error {
	if proto == "" {
		proto = "udp"
	}
	if proto != "udp" && proto != "tcp" {
		return fmt.Errorf("%s invalid: %q", label, proto)
	}
	return nil
}

func validateVPNListenTargets(prefix, zone string, ifaces []string, zoneSet, ifaceSet map[string]struct{}) error {
	if strings.TrimSpace(zone) != "" {
		if _, ok := zoneSet[zone]; !ok {
			return fmt.Errorf("%s listenZone invalid: %s", prefix, zone)
		}
	}
	for _, name := range ifaces {
		n := strings.TrimSpace(name)
		if n == "" {
			return fmt.Errorf("%s listenInterfaces cannot include empty", prefix)
		}
		if _, ok := ifaceSet[n]; !ok {
			return fmt.Errorf("%s listenInterfaces unknown: %s", prefix, n)
		}
	}
	return nil
}

func validateIDS(ids IDSConfig) error {
	seen := map[string]struct{}{}
	for _, r := range ids.Rules {
		if err := ics.ValidateIDS(r.ID, r.Proto); err != nil {
			return err
		}
		if r.ID == "" {
			return errors.New("ids rule id cannot be empty")
		}
		if _, ok := seen[r.ID]; ok {
			return fmt.Errorf("duplicate ids rule id: %s", r.ID)
		}
		seen[r.ID] = struct{}{}
		if r.Severity != "" {
			switch r.Severity {
			case "low", "medium", "high", "critical":
			default:
				return fmt.Errorf("ids rule %s invalid severity %q", r.ID, r.Severity)
			}
		}
	}
	return nil
}
