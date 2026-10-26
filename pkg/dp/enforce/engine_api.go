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

// matches are the nft matches for requests on the path and for the
// engine's replies.
func (p *EngineAPIPath) matches() (request, reply string, err error) {
	dev, err := ifnameLiteral(p.Device)
	if err != nil {
		return "", "", fmt.Errorf("engine API path: %w", err)
	}
	ip := familyKeyword[0]
	if p.Addr.Is6() {
		ip = familyKeyword[1]
	}
	request = fmt.Sprintf("iifname %s %s daddr %s tcp dport %d", dev, ip, p.Addr, p.Port)
	reply = fmt.Sprintf("oifname %s %s saddr %s tcp sport %d", dev, ip, p.Addr, p.Port)
	return request, reply, nil
}

// writeEngineAPIInput admits the engine API path. Loopback needs no rule of
// its own, and an API listening on loopback or on every address gets none:
// only an address the operator bound it to marks a trusted path.
func (c *Compiler) writeEngineAPIInput(b *bytes.Buffer) error {
	p := c.EngineAPI
	if p == nil {
		return nil
	}
	request, _, err := p.matches()
	if err != nil {
		return err
	}
	fmt.Fprintf(b, "    %s accept;\n", request)
	return nil
}
