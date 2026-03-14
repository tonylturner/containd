// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engine

import (
	"fmt"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/ics/bacnet"
	"github.com/tonylturner/containd/pkg/dp/ics/cip"
	"github.com/tonylturner/containd/pkg/dp/ics/dnp3"
	"github.com/tonylturner/containd/pkg/dp/ics/iec61850"
	"github.com/tonylturner/containd/pkg/dp/ics/modbus"
	"github.com/tonylturner/containd/pkg/dp/ics/opcua"
	"github.com/tonylturner/containd/pkg/dp/ics/s7comm"
	"github.com/tonylturner/containd/pkg/dp/itdpi"
)

// DefaultDecoders returns the standard set of DPI decoders for both ICS and
// IT protocols. Used by the engine and by offline analysis (PCAP-to-policy).
func DefaultDecoders() []dpi.Decoder {
	return []dpi.Decoder{
		modbus.NewDecoder(),
		dnp3.NewDecoder(),
		cip.NewDecoder(),
		iec61850.NewMMSDecoder(),
		s7comm.NewDecoder(),
		bacnet.NewDecoder(),
		opcua.NewDecoder(),
		itdpi.NewDNSDecoder(),
		itdpi.NewTLSDecoder(),
		itdpi.NewHTTPDecoder(),
		itdpi.NewSSHDecoder(),
		itdpi.NewSMBDecoder(),
		itdpi.NewNTPDecoder(),
		itdpi.NewSNMPDecoder(),
		itdpi.NewRDPDecoder(),
		itdpi.NewICSMarker(),
		itdpi.NewPortDetector(),
	}
}

var itDecoderProto = map[string]string{
	"*itdpi.DNSDecoder":  "dns",
	"*itdpi.TLSDecoder":  "tls",
	"*itdpi.HTTPDecoder": "http",
	"*itdpi.SSHDecoder":  "ssh",
	"*itdpi.SMBDecoder":  "smb",
	"*itdpi.NTPDecoder":  "ntp",
	"*itdpi.SNMPDecoder": "snmp",
	"*itdpi.RDPDecoder":  "rdp",
}

var icsDecoderProto = map[string]string{
	"*modbus.Decoder":      "modbus",
	"*dnp3.Decoder":        "dnp3",
	"*cip.Decoder":         "cip",
	"*s7comm.Decoder":      "s7comm",
	"*iec61850.MMSDecoder": "mms",
	"*bacnet.Decoder":      "bacnet",
	"*opcua.Decoder":       "opcua",
}

// FilterDecoders returns decoders filtered by the per-protocol toggle maps.
// Utility decoders (ICSMarker, PortDetector) are always included.
func FilterDecoders(itProtos, icsProtos map[string]bool) []dpi.Decoder {
	all := DefaultDecoders()
	if len(itProtos) == 0 && len(icsProtos) == 0 {
		return all
	}
	var out []dpi.Decoder
	for _, d := range all {
		typeName := fmt.Sprintf("%T", d)
		if protoKey, isIT := itDecoderProto[typeName]; isIT {
			enabled, configured := itProtos[protoKey]
			if !configured || enabled {
				out = append(out, d)
			}
			continue
		}
		if protoKey, isICS := icsDecoderProto[typeName]; isICS {
			enabled, configured := icsProtos[protoKey]
			if !configured || enabled {
				out = append(out, d)
			}
			continue
		}
		out = append(out, d)
	}
	return out
}
