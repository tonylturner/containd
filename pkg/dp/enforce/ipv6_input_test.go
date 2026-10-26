// SPDX-License-Identifier: Apache-2.0
package enforce

import (
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

func TestIPv6InputNeighborDiscovery(t *testing.T) {
	text, err := NewCompiler().CompileFirewall(&rules.Snapshot{})
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(text, "chain input {")
	input := text[start:]
	input = input[:strings.Index(input, "  }")]
	if !strings.Contains(input, "meta l4proto ipv6-icmp icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, destination-unreachable, packet-too-big, time-exceeded, parameter-problem } accept;") {
		t.Fatalf("missing IPv6 neighbor discovery and path-MTU errors: %s", input)
	}
}
