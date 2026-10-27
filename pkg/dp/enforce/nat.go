// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"bytes"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

func (c *Compiler) writeDNATAccepts(buf *bytes.Buffer, snap *rules.Snapshot) error {
	if len(snap.NAT.PortForwards) == 0 || len(snap.ZoneIfaces) == 0 {
		return nil
	}
	pfs := append([]rules.PortForward(nil), snap.NAT.PortForwards...)
	sort.Slice(pfs, func(i, j int) bool { return pfs[i].ID < pfs[j].ID })
	for _, pf := range pfs {
		if len(snap.ZoneIfaces[strings.TrimSpace(pf.IngressZone)]) == 0 {
			continue
		}
		line, err := compileDNATAccept(pf)
		if err != nil {
			return err
		}
		if line != "" {
			buf.WriteString("    " + line + ";\n")
		}
	}
	return nil
}

func (c *Compiler) writePreroutingChain(buf *bytes.Buffer, snap *rules.Snapshot) error {
	if len(snap.NAT.PortForwards) == 0 || len(snap.ZoneIfaces) == 0 {
		return nil
	}
	entries := append([]rules.PortForward(nil), snap.NAT.PortForwards...)
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	var lines []string
	for _, pf := range entries {
		if len(snap.ZoneIfaces[strings.TrimSpace(pf.IngressZone)]) == 0 {
			continue
		}
		line, err := compilePreroutingDNAT(pf)
		if err != nil {
			return err
		}
		if line != "" {
			lines = append(lines, line)
		}
	}
	if len(lines) == 0 {
		return nil
	}
	buf.WriteString("  chain prerouting {\n    type nat hook prerouting priority dstnat;\n    policy accept;\n")
	for _, line := range lines {
		buf.WriteString("    " + line + ";\n")
	}
	buf.WriteString("  }\n")
	return nil
}

func (c *Compiler) writePostroutingChain(buf *bytes.Buffer, snap *rules.Snapshot) error {
	if !snap.NAT.Enabled || len(snap.ZoneIfaces) == 0 {
		return nil
	}
	egress := strings.TrimSpace(snap.NAT.EgressZone)
	if egress == "" {
		egress = "wan"
	}
	srcZones := snap.NAT.SourceZones
	if len(srcZones) == 0 {
		srcZones = []string{"lan", "dmz"}
	}
	buf.WriteString("  chain postrouting {\n")
	buf.WriteString("    type nat hook postrouting priority srcnat;\n")
	buf.WriteString("    policy accept;\n")
	// The destination's egress interface is selected by routing, not by a
	// conventional zone name. Restrict return-path SNAT to each DNAT target.
	pfs := append([]rules.PortForward(nil), snap.NAT.PortForwards...)
	sort.Slice(pfs, func(i, j int) bool { return pfs[i].ID < pfs[j].ID })
	for _, pf := range pfs {
		if len(snap.ZoneIfaces[strings.TrimSpace(pf.IngressZone)]) == 0 {
			continue
		}
		match, err := compileDNATMatch(pf)
		if err != nil {
			return err
		}
		if match == "" {
			continue
		}
		fmt.Fprintf(buf, "    %s ip daddr %s masquerade;\n", match, strings.TrimSpace(pf.DestIP))
	}
	for _, z := range srcZones {
		z = strings.TrimSpace(z)
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

func compileDNATAccept(pf rules.PortForward) (string, error) {
	match, err := compileDNATMatch(pf)
	if err != nil || match == "" {
		return "", err
	}
	return match + " accept", nil
}

func compileDNATMatch(pf rules.PortForward) (string, error) {
	if net.ParseIP(strings.TrimSpace(pf.DestIP)).To4() == nil {
		return "", nil
	}
	if !pf.Enabled {
		return "", nil
	}
	ingress := strings.TrimSpace(pf.IngressZone)
	if ingress == "" {
		return "", nil
	}
	proto := strings.ToLower(strings.TrimSpace(pf.Proto))
	if proto != "tcp" && proto != "udp" {
		return "", nil
	}
	if pf.ListenPort < 1 || pf.ListenPort > 65535 {
		return "", nil
	}
	dstPort := pf.DestPort
	if dstPort == 0 {
		dstPort = pf.ListenPort
	}
	if dstPort < 1 || dstPort > 65535 {
		return "", nil
	}
	ingSet := zoneSetName(ingress)
	parts := []string{
		fmt.Sprintf("iifname @%s", ingSet),
		"ct status dnat",
		proto + " dport " + strconv.Itoa(dstPort),
	}
	if len(pf.AllowedSources) > 0 {
		validated, err := validateCIDRList(pf.AllowedSources)
		if err != nil {
			return "", fmt.Errorf("port forward %s: invalid AllowedSources: %w", pf.ID, err)
		}
		parts = append(parts, fmt.Sprintf("ip saddr { %s }", strings.Join(validated, ", ")))
	}
	return strings.Join(parts, " "), nil
}

func compilePreroutingDNAT(pf rules.PortForward) (string, error) {
	if !pf.Enabled {
		return "", nil
	}
	ingress := strings.TrimSpace(pf.IngressZone)
	if ingress == "" {
		return "", nil
	}
	proto := strings.ToLower(strings.TrimSpace(pf.Proto))
	if proto != "tcp" && proto != "udp" {
		return "", nil
	}
	if pf.ListenPort <= 0 || pf.ListenPort > 65535 {
		return "", nil
	}
	dstIP := strings.TrimSpace(pf.DestIP)
	if net.ParseIP(dstIP) == nil {
		return "", nil
	}
	dstPort := pf.DestPort
	if dstPort == 0 {
		dstPort = pf.ListenPort
	}
	if dstPort < 1 || dstPort > 65535 {
		return "", nil
	}
	ingSet := zoneSetName(ingress)
	parts := []string{fmt.Sprintf("iifname @%s", ingSet)}
	if len(pf.AllowedSources) > 0 {
		validated, err := validateCIDRList(pf.AllowedSources)
		if err != nil {
			return "", fmt.Errorf("port forward %s: invalid AllowedSources: %w", pf.ID, err)
		}
		parts = append(parts, fmt.Sprintf("ip saddr { %s }", strings.Join(validated, ", ")))
	}
	parts = append(parts, proto, fmt.Sprintf("dport %d", pf.ListenPort), "counter")
	if dstPort > 0 && dstPort != pf.ListenPort {
		parts = append(parts, fmt.Sprintf("dnat ip to %s:%d", dstIP, dstPort))
	} else {
		parts = append(parts, fmt.Sprintf("dnat ip to %s", dstIP))
	}
	return strings.Join(parts, " "), nil
}
