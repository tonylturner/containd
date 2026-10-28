// SPDX-License-Identifier: Apache-2.0

package ics

import (
	"fmt"
	"testing"
)

func TestProtocolRejectionMessages(t *testing.T) {
	for _, name := range []string{"enip", " ENiP ", "s7comm", "s7", "mms", "iec61850", "goose", "bacnet", "opcua"} {
		suffix := " is not supported; supported: modbus, dnp3, iec104, cip"
		if name == "enip" || name == " ENiP " {
			suffix = `: EtherNet/IP is decoded as "cip"; match encapsulation commands with enip_command`
		}
		for _, boundary := range []struct {
			scope string
			err   error
		}{
			{"rule test ics protocol", ValidateRule("test", name)},
			{"ids rule test proto", ValidateIDS("test", name)},
			{"signature test protocol", ValidateSignature("test", name)},
			{"dataplane.dpiIcsProtocols: protocol", ValidateToggles(map[string]bool{name: true})},
			{"dataplane.dpiIcsProtocols: protocol", ValidateToggles(map[string]bool{name: false})},
		} {
			want := fmt.Sprintf("%s %q%s", boundary.scope, name, suffix)
			if boundary.err == nil || boundary.err.Error() != want {
				t.Errorf("%s/%q: got %v, want %s", boundary.scope, name, boundary.err, want)
			}
		}
	}
}
