// SPDX-License-Identifier: Apache-2.0
package config

// Service names identify independently configurable runtime units.
const (
	ServiceSyslog    = "syslog"
	ServiceDNS       = "dns"
	ServiceNTP       = "ntp"
	ServiceAV        = "av"
	ServiceProxy     = "proxy"
	ServiceDHCP      = "dhcp"
	ServiceWireGuard = "wireguard"
	ServiceOpenVPN   = "openvpn"
	ServiceIDS       = "ids"
)

// ServiceConfigError identifies a configuration fault confined to one service.
// Err must not contain credentials; validators should describe the field rather
// than echo secret input.
type ServiceConfigError struct {
	Service string
	Err     error
}

func (e *ServiceConfigError) Error() string { return e.Service + ": " + e.Err.Error() }
func (e *ServiceConfigError) Unwrap() error { return e.Err }
