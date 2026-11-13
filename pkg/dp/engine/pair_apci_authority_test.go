// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"testing"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/ics/iec104"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// Reserved APCI flags are observations in tolerant parsing, not a different
// GI procedure. Strict policy still vetoes their decoder findings separately.
func TestDS34IECAPCIObservationalAuthority(t *testing.T) {
	for _, reserved := range []bool{false, true} {
		name := "clean"
		if reserved {
			name = "reserved-flag"
		}
		t.Run(name, func(t *testing.T) {
			wire := apdu(100, 6, 1, 0, 20)
			if reserved {
				wire[4] |= 1
			}
			decoded, err := iec104.NewDecoder().ParseStream(nil, dpi.StreamView{Session: name, Dir: dpi.ClientToServer, Role: dpi.ClientToServer, Bytes: wire})
			if err != nil || len(decoded.Frames) != 1 {
				t.Fatal("lost complete GI framing", err)
			}
			class, _, _, why := (iecPairAdapter{}).Classify(decoded.Frames[0], dpi.ClientToServer)
			if class != rules.ClassRequest || why != pairOK {
				t.Fatalf("typed authority rejected observational APCI finding: class=%s reason=%s", class, why)
			}
		})
	}
}
