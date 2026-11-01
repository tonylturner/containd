// SPDX-License-Identifier: Apache-2.0
package config

import (
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

func asciiAlnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// ValidateDaemonHost accepts literal IPv4/unbracketed IPv6 (without a scope)
// or ASCII DNS labels, optionally with a trailing root dot. It never resolves,
// trims or otherwise changes input. Ports and wildcard patterns are not hosts.
func ValidateDaemonHost(s string) error {
	if ip, err := netip.ParseAddr(s); err == nil && ip.Zone() == "" {
		return nil
	}
	host := strings.TrimSuffix(s, ".")
	if host == "" || len(host) > 253 {
		return errors.New("host must be an IP address or ASCII DNS name")
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || !asciiAlnum(label[0]) || !asciiAlnum(label[len(label)-1]) {
			return errors.New("host has an invalid DNS label")
		}
		for i := range len(label) {
			if !asciiAlnum(label[i]) && label[i] != '-' {
				return errors.New("host has an invalid DNS character")
			}
		}
	}
	return nil
}

func validateDaemonPort(s string) error {
	if s == "" {
		return errors.New("port is required")
	}
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return errors.New("port must be decimal in 1..65535")
		}
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 65535 {
		return errors.New("port must be decimal in 1..65535")
	}
	return nil
}

// ValidateProxyBackend accepts DNS/IPv4:port or [IPv6]:port, with a numeric
// port in 1..65535. URLs, scoped IPs and daemon parameters are not supported.
func ValidateProxyBackend(s string) error {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return errors.New("backend must be host:port (bracket IPv6)")
	}
	if strings.HasPrefix(s, "[") {
		ip, err := netip.ParseAddr(host)
		if err != nil || !ip.Is6() || ip.Zone() != "" {
			return errors.New("backend brackets require an unscoped IPv6 address")
		}
	}
	if err := ValidateDaemonHost(host); err != nil {
		return err
	}
	return validateDaemonPort(port)
}
