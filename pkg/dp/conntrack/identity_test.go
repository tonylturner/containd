// SPDX-License-Identifier: Apache-2.0

package conntrack

import (
	"net/netip"
	"strings"
	"testing"
)

func TestIdentityZeroTimeoutExplainsExpiry(t *testing.T) {
	original := Tuple{Family: 2, Protocol: 6, Source: netip.MustParseAddrPort("192.0.2.1:41000"),
		Destination: netip.MustParseAddrPort("198.51.100.1:502")}
	reply := Tuple{Family: 2, Protocol: 6, Source: original.Destination, Destination: original.Source}
	e := Evidence{Original: original, Reply: reply, TimeoutSeconds: 60}
	if err := e.Validate(original); err != nil {
		t.Fatal(err)
	}
	e.TimeoutSeconds = 0
	if err := e.Validate(original); err == nil || !strings.Contains(err.Error(), "expired (zero timeout)") {
		t.Fatalf("zero timeout: %v", err)
	}
}
