// SPDX-License-Identifier: Apache-2.0

package replay

import (
	"fmt"
	"net"
	"slices"
	"strings"

	"github.com/tonylturner/containd/pkg/dp/capture"
)

// Topology assigns configured zones to RFC 2544 prefixes in config order.
// Keep the returned value immutable while a replay is running.
type Topology struct {
	zones []string
}

func NewTopology(zones []string) Topology {
	return Topology{zones: slices.Clone(zones)}
}

// ResolveZones returns the client/server zones for a capture family. Missing
// default names fall back to the first/second non-mgmt zone in config order;
// with only one usable zone both roles share it and no conduit is charged.
func (t Topology) ResolveZones(family string) (client, server string) {
	wanted := []string{"dmz", "lan"}
	if family == "it" {
		wanted = []string{"lan", "wan"}
	}
	var usable []string
	for _, z := range t.zones {
		if z != "" && z != "mgmt" {
			usable = append(usable, z)
		}
	}
	resolve := func(name string, index int) string {
		if slices.Contains(usable, name) {
			return name
		}
		if len(usable) == 0 {
			return ""
		}
		return usable[min(index, len(usable)-1)]
	}
	return resolve(wanted[0], 0), resolve(wanted[1], 1)
}

// Interface returns the illustrative leaf interface for a configured zone.
func (t Topology) Interface(zone string) string { return "demo:" + zone }

// ZoneAddresses supplies detached-engine zone resolution without OS lookups.
func (t Topology) ZoneAddresses(iface string) ([]net.Addr, error) {
	if !strings.HasPrefix(iface, "demo:") {
		return nil, fmt.Errorf("not a demo interface: %s", iface)
	}
	index := slices.Index(t.zones, strings.TrimPrefix(iface, "demo:"))
	if index < 0 || index > 255 {
		return nil, fmt.Errorf("unknown or unrepresentable demo zone: %s", iface)
	}
	return []net.Addr{&net.IPNet{IP: net.IPv4(198, 18, byte(index), 0), Mask: net.CIDRMask(24, 32)}}, nil
}

func (t Topology) rewrite(c *Capture, pkt capture.Packet, loop uint64) (capture.Packet, string, string, error) {
	client, server := t.ResolveZones(c.Family)
	if client == "" || server == "" {
		return capture.Packet{}, "", "", fmt.Errorf("no non-mgmt demo zones")
	}
	rewrite := func(ip net.IP, port uint16) (net.IP, uint16, string, error) {
		r := c.role(ip)
		if r == nil {
			return nil, 0, "", fmt.Errorf("missing role for %s", ip)
		}
		zone := server
		if r.Role == "client" {
			zone = client
			// Normalize the client endpoint into the demo ephemeral range,
			// including recorded service-bound clients (e.g. source port 502).
			// Server ports, TCP sequence numbers and payload stay unchanged.
			slot, ok := c.ports[port]
			if !ok || len(c.ports) == 0 {
				return nil, 0, "", fmt.Errorf("unverified client port %d", port)
			}
			// Allocate a disjoint block per iteration, rather than adding
			// one to recorded ports (which collides with other recorded
			// connections after only a few iterations). Finite wrap is
			// unavoidable; never split a block across the range boundary.
			width := uint64(len(c.ports))
			port = uint16(20000 + slot + loop%(41000/width)*width)
		}
		index := slices.Index(t.zones, zone)
		if index < 0 || index > 255 {
			return nil, 0, "", fmt.Errorf("unrepresentable demo zone %s", zone)
		}
		return net.IPv4(198, 18, byte(index), r.host), port, zone, nil
	}
	var from, to string
	var err error
	pkt.SrcIP, pkt.SrcPort, from, err = rewrite(pkt.SrcIP, pkt.SrcPort)
	if err != nil {
		return capture.Packet{}, "", "", err
	}
	pkt.DstIP, pkt.DstPort, to, err = rewrite(pkt.DstIP, pkt.DstPort)
	pkt.Interface = t.Interface(from)
	// Only decoded tuple fields change. No decoder verifies IP/TCP/UDP
	// checksums, and Packet carries no raw transport checksum to repair.
	return pkt, from, to, err
}
