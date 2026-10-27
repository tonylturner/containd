// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package rules

import (
	"strconv"
	"strings"
)

// ICSDecoderPort is one fixed TCP server port an industrial protocol decoder
// claims. The decoders recognise sessions by these ports alone, so the set is
// shared by control-plane validation, the scan selection and the engine
// rather than repeated as literals.
type ICSDecoderPort struct {
	Protocol string
	Port     uint16
}

// String formats the port as protocol/port, the form validation errors use.
func (p ICSDecoderPort) String() string {
	return p.Protocol + "/" + strconv.Itoa(int(p.Port))
}

var icsDecoderPorts = []ICSDecoderPort{
	{Protocol: "modbus", Port: 502},
	{Protocol: "cip", Port: 2222},
	{Protocol: "iec104", Port: 2404},
	{Protocol: "dnp3", Port: 20000},
	{Protocol: "cip", Port: 44818},
}

// ICSDecoderPorts lists every decoder port in ascending port order. The
// slice is a copy; callers may keep it.
func ICSDecoderPorts() []ICSDecoderPort {
	return append([]ICSDecoderPort(nil), icsDecoderPorts...)
}

// ICSDecoderPortIn reports the first decoder port inside the closed port
// range lo..hi, so an error can name the protocol and port a range covers.
func ICSDecoderPortIn(lo, hi uint16) (ICSDecoderPort, bool) {
	for _, p := range icsDecoderPorts {
		if lo <= p.Port && p.Port <= hi {
			return p, true
		}
	}
	return ICSDecoderPort{}, false
}

// IsICSDecoderPort reports whether port is the fixed server port of the
// named decoder (modbus, dnp3, cip or iec104).
func IsICSDecoderPort(protocol string, port uint16) bool {
	protocol = strings.ToLower(protocol)
	for _, p := range icsDecoderPorts {
		if p.Protocol == protocol && p.Port == port {
			return true
		}
	}
	return false
}
