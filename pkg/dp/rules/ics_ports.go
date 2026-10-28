// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package rules

import "github.com/tonylturner/containd/pkg/dp/ics"

// ICSDecoderPortIn reports the lowest decoder port inside the closed port
// range lo..hi, whatever its transport: the scan selection intercepts TCP
// and refuses to cover any port a decoder claims, so an error can name the
// protocol and port a range covers.
func ICSDecoderPortIn(lo, hi uint16) (ics.DecoderPort, bool) {
	return ics.DecoderPortIn(lo, hi)
}

// IsICSDecoderPort reports whether port is the fixed server port of the
// named decoder (modbus, dnp3, cip or iec104) on any transport.
func IsICSDecoderPort(protocol string, port uint16) bool {
	return ics.IsDecoderPort(protocol, port)
}
