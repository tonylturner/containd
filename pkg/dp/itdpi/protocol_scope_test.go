// SPDX-License-Identifier: Apache-2.0
package itdpi

import (
	"testing"

	"github.com/tonylturner/containd/pkg/dp/dpi"
)

func TestRemovedProtocolICSMarker(t *testing.T) {
	for _, proto := range []string{"s7comm", "s7", "mms", "iec61850", "goose", "bacnet", "opcua", "http", "rdp"} {
		got := MarkICS(dpi.Event{Proto: proto})
		if got.Attributes["ics"] != nil {
			t.Fatalf("marked unsupported/IT protocol %s as ICS", proto)
		}
	}
	for _, proto := range []string{"modbus", "dnp3", "iec104", "cip", "ics"} {
		attrs := map[string]any{"field": "preserved"}
		got := MarkICS(dpi.Event{Proto: proto, Attributes: attrs})
		if got.Attributes["ics"] != true || got.Attributes["field"] != "preserved" || attrs["ics"] != nil {
			t.Fatalf("marker did not clone and mark %s", proto)
		}
	}
}
