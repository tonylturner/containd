// SPDX-License-Identifier: Apache-2.0
package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path"
	"strings"
)

// Check dormant supplied values too, without requiring an incomplete disabled
// service to have the material needed to start.
func validateOpenVPNSinks(v OpenVPNConfig) error {
	if v.Managed != nil {
		if err := validateOpenVPNManagedSinks(v.Managed); err != nil {
			return err
		}
	}
	if v.Server != nil {
		return validateOpenVPNServerSinks(v.Server)
	}
	return nil
}

func validateOpenVPNManagedSinks(m *OpenVPNManagedClientConfig) error {
	if m.Remote != "" {
		if err := ValidateOpenVPNRemote(m.Remote); err != nil {
			return fmt.Errorf("vpn.openvpn.managed remote: %w", err)
		}
	}
	for _, credential := range []string{m.Username, m.Password} {
		if credential != "" {
			if err := ValidateOpenVPNAuthLine(credential); err != nil {
				return err
			}
		}
	}
	if err := validateVPNPort("vpn.openvpn.managed port", m.Port, 1194); err != nil {
		return err
	}
	return validateVPNProto("vpn.openvpn.managed proto", m.Proto)
}

func validateOpenVPNServerSinks(s *OpenVPNManagedServerConfig) error {
	if s.PublicEndpoint != "" {
		if err := ValidateOpenVPNRemote(s.PublicEndpoint); err != nil {
			return fmt.Errorf("vpn.openvpn.server publicEndpoint: %w", err)
		}
	}
	if err := validateVPNPort("vpn.openvpn.server listenPort", s.ListenPort, 1194); err != nil {
		return err
	}
	if err := validateVPNProto("vpn.openvpn.server proto", s.Proto); err != nil {
		return err
	}
	if s.TunnelCIDR != "" {
		if _, _, err := net.ParseCIDR(s.TunnelCIDR); err != nil {
			return errors.New("vpn.openvpn.server tunnelCIDR invalid")
		}
	}
	for _, dns := range s.PushDNS {
		ip, err := netip.ParseAddr(dns)
		if err != nil || !ip.Is4() {
			return errors.New("vpn.openvpn.server pushDNS must be IPv4")
		}
	}
	for _, route := range s.PushRoutes {
		if _, _, err := net.ParseCIDR(route); err != nil {
			return errors.New("vpn.openvpn.server pushRoutes must be CIDRs")
		}
	}
	return nil
}

// ValidateOpenVPNRemote accepts a host/IP without a port, scope or options.
// The same grammar applies to downloaded profiles' public endpoint.
func ValidateOpenVPNRemote(s string) error { return ValidateDaemonHost(s) }

// ValidateOpenVPNAuthLine accepts one non-empty auth-file record. Spaces,
// punctuation and Unicode are legitimate credentials, not daemon directives.
// Never include the rejected credential in diagnostics.
func ValidateOpenVPNAuthLine(s string) error {
	if s == "" || strings.ContainsAny(s, "\r\n\x00") {
		return errors.New("auth credential must be one non-empty line without CR, LF or NUL")
	}
	return nil
}

// ValidateUnboundForwarder accepts IPv4 or unbracketed IPv6, optionally followed
// by @decimal-port. Hostnames, TLS #auth-name suffixes and scopes are unsupported.
func ValidateUnboundForwarder(s string) error {
	host, port, hasPort := strings.Cut(s, "@")
	ip, err := netip.ParseAddr(host)
	if err != nil || ip.Zone() != "" {
		return errors.New("forwarder must be an IP address optionally followed by @port")
	}
	if hasPort {
		return validateDaemonPort(port)
	}
	return nil
}

// ValidateChronyServer accepts a host/IP only; options and pools are not input.
func ValidateChronyServer(s string) error { return ValidateDaemonHost(s) }

// ValidateClamdSocketPath accepts a clean absolute POSIX path made of ASCII
// filename components. No whitespace, comments, quoting or traversal is allowed.
func ValidateClamdSocketPath(s string) error {
	if s == "/" || !path.IsAbs(s) || path.Clean(s) != s {
		return errors.New("clamd socketPath must be a clean absolute file path")
	}
	for _, part := range strings.Split(s[1:], "/") {
		if part == "." || part == ".." {
			return errors.New("clamd socketPath cannot contain traversal")
		}
		for i := range len(part) {
			if !asciiAlnum(part[i]) && !strings.ContainsRune("._-", rune(part[i])) {
				return errors.New("clamd socketPath contains an unsafe filename character")
			}
		}
	}
	return nil
}
