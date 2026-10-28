// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package corpus

import (
	"fmt"
	"net"
	"strconv"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dpi"
)

// Role explicitly orients UDP or midstream TCP. Endpoints use IPv4:port.
// Sequence anchors, when supplied, are the first payload sequence after SYN.
type Role struct {
	Transport      string  `json:"transport"`
	Client         string  `json:"client"`
	Server         string  `json:"server"`
	ClientSequence *uint32 `json:"client_sequence,omitempty"`
	ServerSequence *uint32 `json:"server_sequence,omitempty"`
}

func endpoint(ip net.IP, port uint16) string {
	return net.JoinHostPort(ip.String(), strconv.Itoa(int(port)))
}
func tuple(transport, a, b string) string {
	if a > b {
		a, b = b, a
	}
	return transport + "/" + a + "/" + b
}

type connection struct {
	id, client     string
	syn            uint32
	hasSyn, closed bool
	fin            [3]bool
	origin         [3]*uint32
}

func orient(f *Fixture) error {
	roles := map[string]Role{}
	for _, r := range f.Spec.Roles {
		if r.Transport != "tcp" && r.Transport != "udp" {
			return fmt.Errorf("invalid role transport")
		}
		for _, e := range []string{r.Client, r.Server} {
			host, port, err := net.SplitHostPort(e)
			n, pe := strconv.ParseUint(port, 10, 16)
			if err != nil || pe != nil || n == 0 || net.ParseIP(host).To4() == nil || endpoint(net.ParseIP(host), uint16(n)) != e {
				return fmt.Errorf("invalid role endpoint %q", e)
			}
		}
		key := tuple(r.Transport, r.Client, r.Server)
		if _, ok := roles[key]; ok || r.Client == r.Server {
			return fmt.Errorf("duplicate or degenerate role")
		}
		roles[key] = r
	}
	active := map[string]*connection{}
	all := map[string]*connection{}
	serial := 0
	for i := range f.Packets {
		p := &f.Packets[i]
		d := p.Decoded
		a, b := endpoint(d.SrcIP, d.SrcPort), endpoint(d.DstIP, d.DstPort)
		key := tuple(d.Transport, a, b)
		c := active[key]
		r, explicit := roles[key]
		syn := d.TCP.Flags&capture.TCPFlagSYN != 0
		ack := d.TCP.Flags&capture.TCPFlagACK != 0
		opening := d.Transport == "tcp" && syn && !ack
		replace := c != nil && opening && (c.closed || !c.hasSyn || c.syn != d.TCP.Seq)
		if c == nil || replace {
			client := a
			if explicit {
				client = r.Client
			} else if !opening {
				return fmt.Errorf("frame %d requires explicit role", p.Source[0].Frame)
			}
			if d.Transport == "tcp" && !opening && !f.Spec.AllowMidstream {
				return fmt.Errorf("midstream TCP not declared")
			}
			if opening && a != client {
				return fmt.Errorf("SYN disagrees with role")
			}
			serial++
			c = &connection{id: fmt.Sprintf("%s/%d", f.Name, serial), client: client, syn: d.TCP.Seq, hasSyn: opening}
			c.origin[dpi.ClientToServer] = r.ClientSequence
			c.origin[dpi.ServerToClient] = r.ServerSequence
			active[key] = c
			all[c.id] = c
		}
		if c.closed && d.Transport == "tcp" && len(d.Payload) > 0 {
			return fmt.Errorf("data after closed connection without new SYN")
		}
		p.Connection = c.id
		p.Dir = dpi.ServerToClient
		if a == c.client {
			p.Dir = dpi.ClientToServer
		}
		if syn {
			origin := d.TCP.Seq + 1
			if old := c.origin[p.Dir]; old != nil && *old != origin {
				return fmt.Errorf("conflicting SYN sequence or manifest anchor")
			}
			c.origin[p.Dir] = &origin
		}
		if d.TCP.Flags&capture.TCPFlagFIN != 0 {
			c.fin[p.Dir] = true
		}
		if d.TCP.Flags&capture.TCPFlagRST != 0 || c.fin[1] && c.fin[2] {
			c.closed = true
		}
	}
	for i := range f.Packets {
		p := &f.Packets[i]
		if base := all[p.Connection].origin[p.Dir]; base != nil {
			p.Origin = *base
			p.HasOrigin = true
		}
	}
	return nil
}
