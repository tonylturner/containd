// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package ics

import (
	"strconv"
	"strings"
)

// Fixed server ports the industrial protocol decoders claim, untyped so
// they compare with uint16 flow ports and int socket ports alike. The decoders
// recognise sessions by these ports alone, so the set is shared by the
// decoders, flow orientation, anomaly detection, enforcement and control
// plane validation rather than repeated as literals.
const (
	ModbusPort      = 502   // Modbus/TCP
	CIPImplicitPort = 2222  // EtherNet/IP implicit (I/O) messaging over UDP
	IEC104Port      = 2404  // IEC 60870-5-104 (clause 5)
	DNP3Port        = 20000 // DNP3 over TCP
	CIPPort         = 44818 // EtherNet/IP explicit messaging over TCP
)

// IP protocol numbers of the decoder transports, as flow keys carry them.
const (
	TCP uint8 = 6
	UDP uint8 = 17
)

// DecoderPort is one fixed server port of a decoder on one transport.
type DecoderPort struct {
	Protocol  string // decoder name: modbus, dnp3, iec104 or cip
	Transport uint8  // TCP or UDP
	Port      uint16
}

// String formats the port as protocol/port, the form validation errors use.
func (p DecoderPort) String() string {
	return p.Protocol + "/" + strconv.Itoa(int(p.Port))
}

// decoderPorts is kept in ascending port order; DecoderPortIn relies on it.
var decoderPorts = []DecoderPort{
	{Protocol: "modbus", Transport: TCP, Port: ModbusPort},
	{Protocol: "cip", Transport: UDP, Port: CIPImplicitPort},
	{Protocol: "iec104", Transport: TCP, Port: IEC104Port},
	{Protocol: "dnp3", Transport: TCP, Port: DNP3Port},
	{Protocol: "cip", Transport: TCP, Port: CIPPort},
}

// DecoderPorts lists every decoder port in ascending port order. The slice
// is a copy; callers may keep it.
func DecoderPorts() []DecoderPort {
	return append([]DecoderPort(nil), decoderPorts...)
}

// DecoderPortIn reports the lowest decoder port inside the closed port
// range lo..hi, whatever its transport, so an error can name the protocol
// and port a range covers.
func DecoderPortIn(lo, hi uint16) (DecoderPort, bool) {
	for _, p := range decoderPorts {
		if lo <= p.Port && p.Port <= hi {
			return p, true
		}
	}
	return DecoderPort{}, false
}

// IsDecoderPort reports whether port is a fixed server port of the named
// decoder on any transport. The name is matched case-insensitively.
func IsDecoderPort(protocol string, port uint16) bool {
	protocol = strings.ToLower(protocol)
	for _, p := range decoderPorts {
		if p.Protocol == protocol && p.Port == port {
			return true
		}
	}
	return false
}

// IsDecoderPortOn reports whether port is a decoder port on the transport
// with IP protocol number transport (TCP or UDP).
func IsDecoderPortOn(transport uint8, port uint16) bool {
	for _, p := range decoderPorts {
		if p.Transport == transport && p.Port == port {
			return true
		}
	}
	return false
}
