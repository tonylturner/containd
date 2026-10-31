// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engine

import (
	"fmt"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/ics/cip"
	"github.com/tonylturner/containd/pkg/dp/ics/dnp3"
	"github.com/tonylturner/containd/pkg/dp/ics/iec104"
	"github.com/tonylturner/containd/pkg/dp/ics/modbus"
	"github.com/tonylturner/containd/pkg/dp/itdpi"
)

// DefaultDecoders returns the standard set of DPI decoders for both ICS and
// IT protocols. Each call creates independent decoder state.
func DefaultDecoders() []dpi.Decoder {
	return []dpi.Decoder{
		modbus.NewDecoder(),
		dnp3.NewDecoder(),
		iec104.NewDecoder(),
		cip.NewDecoder(),
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

// NewDecoders creates an offline-owned registry with exactly the captured
// enabled decoder types. It never shares state with live inspection or silently
// substitutes a default registry when an enabled decoder has no factory.
func (s InspectionSnapshot) NewDecoders() ([]dpi.Decoder, error) {
	factories := map[string]dpi.Decoder{}
	for _, decoder := range DefaultDecoders() {
		factories[fmt.Sprintf("%T", decoder)] = decoder
	}
	result := make([]dpi.Decoder, 0, len(s.Decoders))
	for _, decoder := range s.Decoders {
		name := fmt.Sprintf("%T", decoder)
		fresh, ok := factories[name]
		if !ok {
			return nil, fmt.Errorf("offline decoder factory unavailable for %s", name)
		}
		result = append(result, fresh)
	}
	return result, nil
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
	"*modbus.Decoder": "modbus",
	"*dnp3.Decoder":   "dnp3",
	"*cip.Decoder":    "cip",
	"*iec104.Decoder": "iec104",
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
