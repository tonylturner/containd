// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"bytes"
	"fmt"
	"net/netip"
)

// EngineAPIPath is the one network path, besides loopback, on which the
// input chain admits the engine's unauthenticated API: its listener's
// address on the interface that holds it. It is process-owned, like the
// management reservation, and never comes from configuration.
type EngineAPIPath struct {
	Device string
	Addr   netip.Addr
	Port   uint16
}

// match is the nft match for requests on the path.
func (p *EngineAPIPath) match() string {
	family := "ip"
	if p.Addr.Is6() {
		family = "ip6"
	}
	return fmt.Sprintf("iifname %q %s daddr %s tcp dport %d", p.Device, family, p.Addr, p.Port)
}

// replyMatch is the nft match for the engine's replies on the path.
func (p *EngineAPIPath) replyMatch() string {
	family := "ip"
	if p.Addr.Is6() {
		family = "ip6"
	}
	return fmt.Sprintf("oifname %q %s saddr %s tcp sport %d", p.Device, family, p.Addr, p.Port)
}

// writeEngineAPIInput admits the engine API path. Loopback needs no rule of
// its own, and an API listening on loopback or on every address gets none:
// only an address the operator bound it to marks a trusted path.
func (c *Compiler) writeEngineAPIInput(b *bytes.Buffer) {
	if p := c.EngineAPI; p != nil {
		fmt.Fprintf(b, "    %s accept;\n", p.match())
	}
}
