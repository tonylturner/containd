// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/tonylturner/containd/pkg/dp/markabi"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// Port forwarding translates only; ordered policy supplies every grant.
func (c *Compiler) writePreroutingChain(buf *bytes.Buffer, snap *rules.Snapshot) error {
	var lines []string
	for _, id := range forwardIDs(snap) {
		f := snap.ForwardMatches[id]
		if !activeForward(f) {
			continue
		}
		for _, dev := range sortedUnique(f.IngressDevices) {
			lit, err := ifnameLiteral(dev)
			if err != nil {
				return err
			}
			lines = append(lines, joinClauses([]string{"iifname " + lit,
				publicDestination(f, dev, "ip daddr"), forwardSources(f, "ip saddr"),
				fmt.Sprintf("%s dport %d counter ct mark set ct mark | 0x%08x dnat ip to %s", f.Protocol, f.ListenPort, markabi.OwnedForwardCtBit, f.Backend)}))
		}
	}
	if len(lines) == 0 {
		return nil
	}
	buf.WriteString("  chain prerouting {\n    type nat hook prerouting priority dstnat;\n    policy accept;\n")
	for _, l := range lines {
		fmt.Fprintln(buf, "    "+l+";")
	}
	buf.WriteString("  }\n")
	return nil
}

// natMasqueradeZones returns the zones the postrouting chain masquerades
// between: the egress zone (default wan) and the source zones (default lan
// and dmz), trimmed.
func natMasqueradeZones(snap *rules.Snapshot) (egress string, srcZones []string) {
	egress = strings.TrimSpace(snap.NAT.EgressZone)
	if egress == "" {
		egress = "wan"
	}
	for _, z := range snap.NAT.SourceZones {
		srcZones = append(srcZones, strings.TrimSpace(z))
	}
	if len(srcZones) == 0 {
		srcZones = []string{"lan", "dmz"}
	}
	return egress, srcZones
}

func (c *Compiler) writePostroutingChain(buf *bytes.Buffer, snap *rules.Snapshot) error {
	if !snap.NAT.Enabled || len(snap.ZoneIfaces) == 0 {
		return nil
	}
	egress, srcZones := natMasqueradeZones(snap)
	buf.WriteString("  chain postrouting {\n")
	buf.WriteString("    type nat hook postrouting priority srcnat;\n")
	buf.WriteString("    policy accept;\n")
	if c.SteersGate() {
		// The gate's upstream legs are locally generated: no ingress
		// interface, so the lines below never match them. Their socket
		// mark says whether their selection was masqueraded.
		buf.WriteString("    " + gateUpstreamMasquerade() + ";\n")
	}
	// The destination's egress interface is selected by routing, not by a
	// conventional zone name. Restrict return-path SNAT to each DNAT target.
	for _, id := range forwardIDs(snap) {
		for _, match := range forwardMatchClauses(snap.ForwardMatches[id], targetGateInput) {
			fmt.Fprintln(buf, "    "+match+" masquerade;")
		}
	}
	for _, z := range srcZones {
		if len(snap.ZoneIfaces[z]) == 0 || len(snap.ZoneIfaces[egress]) == 0 {
			continue
		}
		srcSet := zoneSetName(z)
		egSet := zoneSetName(egress)
		buf.WriteString(fmt.Sprintf("    iifname @%s oifname @%s masquerade;\n", srcSet, egSet))
	}
	buf.WriteString("  }\n")
	return nil
}
