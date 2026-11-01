// SPDX-License-Identifier: Apache-2.0
package config

import "errors"

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

// SplitServiceFaults inspects every joined branch, not just the first match:
// a mixed error must never be mistaken for a service-only failure.
func SplitServiceFaults(err error) ([]*ServiceConfigError, error) {
	if err == nil {
		return nil, nil
	}
	if fault, ok := err.(*ServiceConfigError); ok {
		return []*ServiceConfigError{fault}, nil
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		var faults []*ServiceConfigError
		var other []error
		for _, child := range joined.Unwrap() {
			f, e := SplitServiceFaults(child)
			faults = append(faults, f...)
			other = append(other, e)
		}
		return faults, errors.Join(other...)
	}
	if child := errors.Unwrap(err); child != nil {
		faults, other := SplitServiceFaults(child)
		if other == nil {
			return faults, nil
		}
		return faults, err
	}
	return nil, err
}

// ServiceFault is a sanitized diagnostic in status, previews and boot records.
type ServiceFault struct {
	Service string `json:"service"`
	Kind    string `json:"kind"` // config | runtime
	Message string `json:"message"`
}
