// SPDX-License-Identifier: Apache-2.0
package enforce

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/tonylturner/containd/pkg/common/mgmtpath"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func (c *Compiler) writeManagementInput(b *bytes.Buffer) {
	r := c.ManagementReservation
	if r == nil {
		return
	}
	sources := make([]string, 0, len(r.Sources))
	for _, a := range r.Sources {
		sources = append(sources, a.String())
	}
	fmt.Fprintf(b, "    iifname %q ip saddr { %s } ip daddr %s tcp dport %d accept;\n", r.Device, strings.Join(sources, ", "), r.Local.Addr(), r.Port)
}

// ValidateManagementSnapshot runs before kernel application or snapshot swapping.
func ValidateManagementSnapshot(s *rules.Snapshot, r *mgmtpath.Reservation) error {
	if s == nil || r == nil {
		return nil
	}
	for i, p := range s.NAT.PortForwards {
		if r.DNATOverlaps(p.Enabled, p.Proto, p.ListenPort, s.ZoneIfaces[strings.TrimSpace(p.IngressZone)], p.AllowedSources) {
			return fmt.Errorf("nat.portForwards[%d] conflicts with reserved management path", i)
		}
	}
	return nil
}
